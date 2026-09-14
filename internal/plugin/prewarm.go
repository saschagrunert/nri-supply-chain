// Copyright The nri-supply-chain Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package plugin

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/containerd/nri/pkg/api"
	"golang.org/x/sync/semaphore"

	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	prewarmConcurrency = 5
	prewarmTimeout     = 5 * time.Minute
)

type prewarmImage struct {
	imageRef    string
	digest      string
	indexDigest string
	// runtimeDigest is the digest the runtime reports for the image, which
	// is resolved like in CreateContainer when no digest is known.
	runtimeDigest string
	namespace     string
	container     string
	// containerIDs lists the recovered containers running this image. A
	// digest resolved from runtimeDigest identifies the image they run, so
	// it is recorded for them.
	containerIDs []string
}

func (p *Plugin) collectPrewarmImages(
	ctx context.Context, containers []*api.Container, podNS map[string]string,
) []prewarmImage {
	var images []prewarmImage

	seen := make(map[string]int)

	for _, ctr := range containers {
		// Resolve the image like CreateContainer does, so pre-warmed cache
		// entries and recorded digests match what admission looks up.
		imageRef, digest, runtimeDigest := resolveContainerImage(ctr)

		if imageRef == "" {
			continue
		}

		namespace := podNS[ctr.GetPodSandboxId()]

		p.recoverContainerState(ctx, ctr, imageRef, digest, runtimeDigest, namespace)

		// Containers of the same tag can run different images, so both the
		// annotation digest and the runtime digest are part of the key.
		key := imageRef + "\x00" + digest + "\x00" + runtimeDigest + "\x00" + namespace
		if idx, ok := seen[key]; ok {
			images[idx].containerIDs = append(images[idx].containerIDs, ctr.GetId())

			continue
		}

		seen[key] = len(images)

		images = append(images, prewarmImage{
			imageRef:      imageRef,
			digest:        digest,
			indexDigest:   "",
			runtimeDigest: runtimeDigest,
			namespace:     namespace,
			container:     ctr.GetName(),
			containerIDs:  []string{ctr.GetId()},
		})
	}

	return images
}

// recoverContainerState registers a container reported by Synchronize. A
// container that is already tracked keeps its state: Synchronize also runs
// after every NRI reconnect, and resetting the entry would drop throttling,
// cooldowns, and error counters of containers that kept running. A container
// that is not tracked (plugin restart) starts as verified, or as throttled
// when its current limits are the throttled form of the original limits
// recorded at creation, so the next passing verification rolls them back.
func (p *Plugin) recoverContainerState(
	ctx context.Context, ctr *api.Container, imageRef, digest, runtimeDigest, namespace string,
) {
	original, trusted := recoveredOriginalResources(ctx, ctr)

	state := StateVerified
	if trusted && p.looksThrottled(captureLinuxResources(ctr), original) {
		state = StateThrottled

		slog.InfoContext(ctx, "Recovered throttled container",
			"container", ctr.GetId(),
			"image", imageRef,
		)
	}

	unresolvedDigest := ""
	if digest == "" {
		unresolvedDigest = runtimeDigest
	}

	p.containers.StoreIfAbsent(
		ctr.GetId(),
		&containerState{ //nolint:exhaustruct_v5 // zero-value fields intentional
			imageRef:           imageRef,
			digest:             digest,
			unresolvedDigest:   unresolvedDigest,
			namespace:          namespace,
			serviceAccount:     ctr.GetAnnotations()[AnnotationServiceAccountPersist],
			createdAt:          time.Now(),
			state:              state,
			originalResources:  original,
			recoveredOnRestart: !trusted,
		},
	)
}

// recoveredOriginalResources returns the original resource limits of a
// container found at Synchronize. trusted is true when they come from the
// AnnotationOriginalResources recorded at creation; otherwise the current
// limits are returned, which may already be throttled by a previous plugin
// instance.
func recoveredOriginalResources(
	ctx context.Context, ctr *api.Container,
) (resources *api.LinuxResources, trusted bool) {
	value, ok := ctr.GetAnnotations()[AnnotationOriginalResources]
	if !ok {
		return captureLinuxResources(ctr), false
	}

	decoded, err := decodeOriginalResources(value)
	if err != nil {
		slog.WarnContext(ctx, "Ignoring invalid original resources annotation",
			"container", ctr.GetId(),
			"error", err,
		)

		return captureLinuxResources(ctr), false
	}

	return decoded, true
}

type resolveResult struct {
	img prewarmImage
	ok  bool
	// fromRuntimeDigest is set when img.digest was resolved from the digest
	// the runtime reported, rather than taken from annotations or a tag.
	fromRuntimeDigest bool
}

func (p *Plugin) resolvePrewarmDigests(
	ctx context.Context, images []prewarmImage,
) []prewarmImage {
	results := make([]resolveResult, len(images))
	sem := semaphore.NewWeighted(prewarmConcurrency)

	var waitGroup sync.WaitGroup

	for idx := range images {
		if images[idx].digest != "" {
			results[idx] = resolveResult{img: images[idx], ok: true, fromRuntimeDigest: false}

			continue
		}

		acquireErr := sem.Acquire(ctx, 1)
		if acquireErr != nil {
			slog.DebugContext(ctx, "Skipping prewarm, context cancelled",
				"image", images[idx].imageRef,
				"error", acquireErr,
			)

			break
		}

		waitGroup.Add(1)

		go func(index int) {
			defer waitGroup.Done()
			defer sem.Release(1)

			p.resolveOneDigest(ctx, &images[index], &results[index])
		}(idx)
	}

	waitGroup.Wait()

	p.recordRuntimeDigests(results)

	return deduplicateResults(results)
}

// recordRuntimeDigests stores digests resolved from the runtime-reported
// image digest on the recovered containers without one, so the continuous
// verifier re-verifies the image they actually run. Digests taken from
// annotations are already recorded, and digests resolved from a tag only warm
// the cache: the tag's current registry digest need not be the image the
// containers run, so it must not drive remediation. A runtime digest the
// registry could not resolve is not recorded either; the continuous verifier
// resolves it later.
func (p *Plugin) recordRuntimeDigests(results []resolveResult) {
	for idx := range results {
		res := &results[idx]
		if !res.ok || !res.fromRuntimeDigest || res.img.digest == "" {
			continue
		}

		for _, id := range res.img.containerIDs {
			p.containers.UpdateState(id, func(cState *containerState) {
				if cState.digest == "" {
					cState.digest = res.img.digest
					cState.indexDigest = res.img.indexDigest
					cState.unresolvedDigest = ""
				}
			})
		}
	}
}

func (p *Plugin) resolveOneDigest(
	ctx context.Context, img *prewarmImage, result *resolveResult,
) {
	resolveCtx, resolveCancel := context.WithTimeout(ctx, time.Duration(p.fetchTimeout.Load()))
	dig, idxDig, _, unresolved, resolveErr := p.resolveImageDigests(
		resolveCtx, img.imageRef, img.runtimeDigest,
	)

	resolveCancel()

	if resolveErr != nil {
		slog.DebugContext(ctx, "Skipping prewarm, failed to resolve digest",
			"container", img.container,
			"image", img.imageRef,
			"error", resolveErr,
		)

		return
	}

	resolved := *img
	resolved.digest = dig
	resolved.indexDigest = idxDig
	*result = resolveResult{
		img: resolved, ok: true, fromRuntimeDigest: img.runtimeDigest != "" && !unresolved,
	}
}

func deduplicateResults(results []resolveResult) []prewarmImage {
	resolved := make([]prewarmImage, 0, len(results))
	seen := make(map[string]struct{})

	for idx := range results {
		res := &results[idx]
		if !res.ok {
			continue
		}

		// Verification results are cached per image reference, digest and
		// namespace, so only identical triples are redundant.
		key := res.img.imageRef + "\x00" + res.img.digest + "\x00" + res.img.namespace
		if _, exists := seen[key]; exists {
			continue
		}

		seen[key] = struct{}{}

		resolved = append(resolved, res.img)
	}

	return resolved
}

func (p *Plugin) prewarmCache(ctx context.Context, images []prewarmImage) {
	defer func() {
		p.prewarm.markDone()

		if p.prewarm.done != nil {
			p.prewarm.done()
		}
	}()

	start := time.Now()

	ctx, cancel := context.WithTimeout(ctx, prewarmTimeout)
	defer cancel()

	images = p.resolvePrewarmDigests(ctx, images)
	total := len(images)
	slog.InfoContext(ctx, "Pre-warming cache", "images", total)

	verified, cancelled := p.runPrewarmVerifications(ctx, images, total)
	if cancelled {
		p.observePrewarm(start, "cancelled")

		return
	}

	result := "success"
	if int(verified) < total {
		result = "partial"
	}

	p.observePrewarm(start, result)

	slog.InfoContext(ctx, "Pre-warming cache complete",
		"verified", verified,
		"total", total,
		"duration", time.Since(start),
	)
}

func (p *Plugin) runPrewarmVerifications(
	ctx context.Context, images []prewarmImage, total int,
) (int32, bool) {
	sem := semaphore.NewWeighted(prewarmConcurrency)
	verified := atomic.Int32{}

	for idx := range images {
		img := images[idx]

		err := sem.Acquire(ctx, 1)
		if err != nil {
			slog.WarnContext(ctx, "Pre-warm cache cancelled", "error", err)

			return verified.Load(), true
		}

		go func() {
			defer sem.Release(1)

			_, verifyErr := p.verifier.Verify(ctx, &types.VerifyRequest{
				ImageRef:       img.imageRef,
				Digest:         img.digest,
				IndexDigest:    img.indexDigest,
				Namespace:      img.namespace,
				ServiceAccount: "",
			})
			if verifyErr != nil {
				slog.DebugContext(ctx, "Pre-warm verification failed",
					"image", img.imageRef,
					"error", verifyErr,
				)

				return
			}

			count := verified.Add(1)
			slog.DebugContext(ctx, "Pre-warming cache progress",
				"verified", count,
				"total", total,
			)
		}()
	}

	err := sem.Acquire(ctx, prewarmConcurrency)
	if err != nil {
		slog.WarnContext(ctx, "Pre-warm cache wait cancelled", "error", err)

		return verified.Load(), true
	}

	return verified.Load(), false
}

func (p *Plugin) observePrewarm(start time.Time, result string) {
	p.metrics.PrewarmDurationSeconds.WithLabelValues(result).Observe(time.Since(start).Seconds())
}

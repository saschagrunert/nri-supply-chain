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
)

const (
	prewarmConcurrency = 5
	prewarmTimeout     = 5 * time.Minute
)

type prewarmImage struct {
	imageRef    string
	digest      string
	indexDigest string
	namespace   string
	container   string
}

func (p *Plugin) collectPrewarmImages(
	containers []*api.Container, podNS map[string]string,
) []prewarmImage {
	var images []prewarmImage

	seen := make(map[string]struct{})

	for _, ctr := range containers {
		annotations := ctr.GetAnnotations()
		imageRef, digest := resolveImage(annotations)

		if imageRef == "" {
			continue
		}

		namespace := podNS[ctr.GetPodSandboxId()]
		serviceAccount := annotations[AnnotationServiceAccountPersist]

		p.containers.Store(
			ctr.GetId(),
			&containerState{ //nolint:exhaustruct_v5 // zero-value fields intentional
				imageRef:           imageRef,
				digest:             digest,
				namespace:          namespace,
				serviceAccount:     serviceAccount,
				createdAt:          time.Now(),
				state:              StateVerified,
				originalResources:  captureLinuxResources(ctr),
				recoveredOnRestart: true,
			},
		)

		key := imageRef + "\x00" + namespace
		if _, ok := seen[key]; ok {
			continue
		}

		seen[key] = struct{}{}

		images = append(images, prewarmImage{
			imageRef:    imageRef,
			digest:      digest,
			indexDigest: "",
			namespace:   namespace,
			container:   ctr.GetName(),
		})
	}

	return images
}

type resolveResult struct {
	img prewarmImage
	ok  bool
}

func (p *Plugin) resolvePrewarmDigests(
	ctx context.Context, images []prewarmImage,
) []prewarmImage {
	results := make([]resolveResult, len(images))
	sem := semaphore.NewWeighted(prewarmConcurrency)

	var waitGroup sync.WaitGroup

	for idx := range images {
		if images[idx].digest != "" {
			results[idx] = resolveResult{img: images[idx], ok: true}

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

	return deduplicateResults(results)
}

func (p *Plugin) resolveOneDigest(
	ctx context.Context, img *prewarmImage, result *resolveResult,
) {
	resolveCtx, resolveCancel := context.WithTimeout(ctx, time.Duration(p.fetchTimeout.Load()))
	dig, idxDig, resolveErr := p.digestResolver(resolveCtx, img.imageRef)

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
	*result = resolveResult{img: resolved, ok: true}
}

func deduplicateResults(results []resolveResult) []prewarmImage {
	resolved := make([]prewarmImage, 0, len(results))
	seen := make(map[string]struct{})

	for _, res := range results {
		if !res.ok {
			continue
		}

		key := res.img.digest + "\x00" + res.img.namespace
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
		p.prewarmDoneOnce.Do(func() { close(p.prewarmDoneCh) })

		if p.prewarmDone != nil {
			p.prewarmDone()
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

			_, verifyErr := p.verifier.Verify(
				ctx, img.imageRef, img.digest, img.indexDigest, img.namespace, "",
			)
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

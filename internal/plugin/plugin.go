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

// Package plugin implements the NRI hooks for supply chain attestation verification.
package plugin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	"golang.org/x/sync/semaphore"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/registry"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

// ErrMissingAnnotations indicates that required image annotations are absent.
var ErrMissingAnnotations = errors.New("missing image annotations")

// ImageVerifier abstracts the verification engine so tests can substitute a
// mock without depending on the concrete verifier package.
type ImageVerifier interface {
	Verify(
		ctx context.Context,
		imageRef, digest, indexDigest, namespace, serviceAccount string,
	) (*types.Result, error)
	Ready() (ready bool, reason string)
	Enforcing() bool
	EffectiveModeForNamespace(namespace string) config.VerificationMode
	Reload(ctx context.Context, cfg *config.Config) error
	Status() types.StatusResponse
}

// DigestResolveFunc resolves an image reference to its platform-specific digest
// via a registry. When the tag points to a manifest list, indexDigest returns
// the manifest list digest (for attestation lookup); otherwise it is empty.
type DigestResolveFunc func(ctx context.Context, imageRef string) (digest, indexDigest string, err error)

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

const (
	// AnnotationImageName is the CRI-O annotation for the user-specified image reference.
	AnnotationImageName = "io.kubernetes.cri-o.ImageName"
	// AnnotationImage is the CRI-O annotation containing the image ID.
	AnnotationImage = "io.kubernetes.cri-o.Image"
	// AnnotationImageRef is the CRI-O annotation for the resolved image digest.
	AnnotationImageRef = "io.kubernetes.cri-o.ImageRef"
	// AnnotationImageRepoDigests contains the comma-separated digest references.
	AnnotationImageRepoDigests = "io.kubernetes.cri-o.ImageRepoDigests"

	// AnnotationContainerdImage is the containerd annotation for the image name.
	AnnotationContainerdImage = "io.kubernetes.cri.image-name"
	// AnnotationContainerdImageRef is the containerd annotation for the image digest.
	AnnotationContainerdImageRef = "io.kubernetes.cri.image-ref"

	// AnnotationServiceAccount is a CRI runtime annotation for the pod's service account
	// name. This must be injected by the container runtime (e.g. CRI-O) or a webhook;
	// it may be empty if the runtime does not provide it.
	AnnotationServiceAccount = "io.kubernetes.pod.serviceAccount"

	// AnnotationVerified is the annotation key for the verification outcome.
	AnnotationVerified = "supply-chain.nri/verified"
	// AnnotationMode is the annotation key for the effective verification mode.
	AnnotationMode = "supply-chain.nri/mode"
	// AnnotationChecks is the annotation key for comma-separated check results.
	AnnotationChecks = "supply-chain.nri/checks"
)

// Plugin implements the NRI CreateContainer, RemoveContainer, and Configure
// hooks for supply chain attestation verification.
type Plugin struct {
	verifier             ImageVerifier
	metrics              *metrics.Metrics
	configPath           string
	connected            atomic.Bool
	digestResolver       DigestResolveFunc
	fetchTimeout         atomic.Int64 // updated via SetFetchTimeout on reload
	digestResolveTimeout atomic.Int64 // updated via SetDigestResolveTimeout on reload
	prewarmDone          func()
	prewarmMu            sync.Mutex
	prewarmCancel        context.CancelFunc
	transportCache       atomic.Pointer[registry.TransportCache]
	containerTimes       sync.Map // map[string]time.Time (container ID -> creation time)
}

// New creates a new Plugin with the given verifier, metrics, and config file path.
func New(
	v ImageVerifier, met *metrics.Metrics, configPath string,
	fetchTimeout, digestResolveTimeout time.Duration,
	cache *registry.TransportCache,
) *Plugin {
	plug := &Plugin{ //nolint:exhaustruct // zero-value fields are intentional
		verifier:   v,
		metrics:    met,
		configPath: configPath,
	}

	plug.fetchTimeout.Store(int64(fetchTimeout))
	plug.digestResolveTimeout.Store(int64(digestResolveTimeout))

	if cache != nil {
		plug.transportCache.Store(cache)
	}

	plug.digestResolver = plug.registryAwareResolver

	return plug
}

// SetFetchTimeout updates the timeout used when resolving image
// digests via the registry. Called during config reload.
func (p *Plugin) SetFetchTimeout(d time.Duration) {
	p.fetchTimeout.Store(int64(d))
}

// SetDigestResolveTimeout updates the timeout used when resolving an image
// tag to its digest via the registry. Called during config reload.
func (p *Plugin) SetDigestResolveTimeout(d time.Duration) {
	p.digestResolveTimeout.Store(int64(d))
}

// SetTransportCache replaces the plugin's transport cache with a new one,
// typically called during config reload when registries change.
func (p *Plugin) SetTransportCache(cache *registry.TransportCache) {
	if old := p.transportCache.Swap(cache); old != nil {
		old.CloseIdleConnections()
	}
}

// TransportCache returns the current transport cache, or nil if none is set.
func (p *Plugin) TransportCache() *registry.TransportCache {
	return p.transportCache.Load()
}

// Connected returns true if the plugin has successfully connected to the NRI runtime.
func (p *Plugin) Connected() bool {
	return p.connected.Load()
}

// VerifierReady returns true if the verifier is ready to serve requests.
func (p *Plugin) VerifierReady() (ready bool, reason string) {
	return p.verifier.Ready()
}

// SetDisconnected marks the plugin as disconnected from the NRI runtime.
func (p *Plugin) SetDisconnected() {
	p.connected.Store(false)
}

// Configure is called when the plugin connects to the NRI runtime.
func (p *Plugin) Configure(
	ctx context.Context, cfg, rt, version string,
) (stub.EventMask, error) {
	slog.Info("Connected to runtime", "runtime", rt, "version", version)

	if p.configPath == "" && cfg != "" {
		parsed, err := config.LoadFromString(cfg)
		if err != nil {
			return 0, fmt.Errorf("parsing NRI config: %w", err)
		}

		err = parsed.ValidateRuntime()
		if err != nil {
			return 0, fmt.Errorf("validating NRI config: %w", err)
		}

		err = p.verifier.Reload(ctx, parsed)
		if err != nil {
			return 0, fmt.Errorf("applying NRI config: %w", err)
		}
	}

	p.connected.Store(true)

	return 0, nil
}

// Synchronize is called by NRI after Configure to deliver the list of
// running pods and containers. It spawns a background goroutine to
// pre-verify images from existing containers, warming the cache.
func (p *Plugin) Synchronize(
	ctx context.Context, pods []*api.PodSandbox, containers []*api.Container,
) ([]*api.ContainerUpdate, error) {
	podNS := make(map[string]string, len(pods))

	for _, pod := range pods {
		podNS[pod.GetId()] = pod.GetNamespace()
	}

	p.cleanStaleContainerTimes(containers)

	images := p.collectPrewarmImages(containers, podNS)

	if len(images) == 0 {
		return nil, nil
	}

	// Use context.WithoutCancel so the pre-warm goroutine is not
	// interrupted when the ttrpc request context completes.
	// Wrap it with a cancellable context so shutdown can stop prewarm.
	prewarmCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))

	p.prewarmMu.Lock()
	if p.prewarmCancel != nil {
		p.prewarmCancel()
	}

	p.prewarmCancel = cancel
	p.prewarmMu.Unlock()

	go p.prewarmCache(prewarmCtx, images)

	return nil, nil
}

// CancelPrewarm cancels any in-progress cache pre-warming.
func (p *Plugin) CancelPrewarm() {
	p.prewarmMu.Lock()
	cancel := p.prewarmCancel
	p.prewarmMu.Unlock()

	if cancel != nil {
		cancel()
	}
}

// CreateContainer is called for each new container before it is created.
// It verifies supply chain attestations and rejects the container on failure.
//
//nolint:funlen // NRI hook handler with annotation resolution and verification
func (p *Plugin) CreateContainer(
	ctx context.Context, pod *api.PodSandbox, ctr *api.Container,
) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	createdAt := time.Now()
	annotations := ctr.GetAnnotations()
	imageRef, digest := resolveImage(annotations)
	namespace := pod.GetNamespace()
	serviceAccount := pod.GetAnnotations()[AnnotationServiceAccount]

	if slog.Default().Enabled(ctx, slog.LevelDebug) {
		slog.DebugContext(ctx, "NRI container info",
			"container_id", ctr.GetId(),
			"container_name", ctr.GetName(),
			"annotations", filterRelevantAnnotations(annotations),
			"labels", ctr.GetLabels(),
		)
	}

	digest, indexDigest, resolveErr := p.resolveDigestIfMissing(
		ctx, imageRef, digest, namespace, pod, ctr,
	)

	if imageRef == "" || digest == "" {
		mode := p.verifier.EffectiveModeForNamespace(namespace)
		if resolveErr != nil && mode == config.ModeEnforce {
			return nil, nil, fmt.Errorf("supply chain verification: %w", resolveErr)
		}

		adj, _, handleErr := p.handleMissingAnnotations(
			ctx, namespace, pod, ctr, imageRef, digest, len(annotations),
		)
		if handleErr == nil {
			p.containerTimes.Store(ctr.GetId(), createdAt)
		}

		return adj, nil, handleErr
	}

	result, err := p.verifier.Verify(ctx, imageRef, digest, indexDigest, namespace, serviceAccount)
	if err != nil {
		slog.ErrorContext(ctx, "Container rejected",
			"pod", namespace+"/"+pod.GetName(),
			"container", ctr.GetName(),
			"image", imageRef,
			"error", err,
		)

		return nil, nil, fmt.Errorf("supply chain verification: %w", err)
	}

	mode := p.verifier.EffectiveModeForNamespace(namespace)

	slog.InfoContext(ctx, "Container verified",
		"pod", namespace+"/"+pod.GetName(),
		"container", ctr.GetName(),
		"image", imageRef,
		"allowed", result.Allowed,
	)

	p.containerTimes.Store(ctr.GetId(), createdAt)

	adj := buildVerificationAdjustment(result, mode)

	return adj, nil, nil
}

func buildVerificationAdjustment(
	result *types.Result, mode config.VerificationMode,
) *api.ContainerAdjustment {
	if result == nil || mode == config.ModeDisabled {
		return nil
	}

	// In warn mode, the verifier returns Allowed=true after enforcement
	// override. Derive the actual verification outcome from individual
	// check results.
	passed := result.Allowed

	if mode == config.ModeWarn {
		for i := range result.CheckResults {
			if !result.CheckResults[i].Passed {
				passed = false

				break
			}
		}
	}

	adj := &api.ContainerAdjustment{}
	adj.AddAnnotation(AnnotationVerified, strconv.FormatBool(passed))
	adj.AddAnnotation(AnnotationMode, string(mode))

	if len(result.CheckResults) > 0 {
		// Format: comma-separated type:status pairs (e.g., "slsa:pass,vex:warn").
		// Values are restricted to [a-z] so no escaping is needed.
		var buf strings.Builder

		for i, check := range result.CheckResults {
			if i > 0 {
				buf.WriteByte(',')
			}

			buf.WriteString(string(check.Type))
			buf.WriteByte(':')
			buf.WriteString(string(check.Status))
		}

		adj.AddAnnotation(AnnotationChecks, buf.String())
	}

	return adj
}

// RemoveContainer is called when a container is removed from the runtime.
// It records the container lifetime as a histogram metric.
func (p *Plugin) RemoveContainer(
	ctx context.Context,
	pod *api.PodSandbox,
	ctr *api.Container,
) error {
	containerID := ctr.GetId()
	namespace := pod.GetNamespace()

	val, loaded := p.containerTimes.LoadAndDelete(containerID)
	if !loaded {
		return nil
	}

	createdAt, ok := val.(time.Time)
	if !ok {
		return nil
	}

	lifetime := time.Since(createdAt).Seconds()

	p.metrics.ContainerLifetime.WithLabelValues(namespace).Observe(lifetime)

	slog.InfoContext(ctx, "Container removed",
		"container", containerID,
		"namespace", namespace,
		"lifetime_seconds", lifetime,
		"pod", pod.GetName(),
	)

	return nil
}

// cleanStaleContainerTimes removes entries from the containerTimes map for
// containers that are no longer in the active set. This handles containers
// that were removed while the plugin was disconnected.
func (p *Plugin) cleanStaleContainerTimes(active []*api.Container) {
	activeIDs := make(map[string]struct{}, len(active))
	for _, ctr := range active {
		activeIDs[ctr.GetId()] = struct{}{}
	}

	p.containerTimes.Range(func(key, _ any) bool {
		containerID, ok := key.(string)
		if !ok {
			return true
		}

		if _, exists := activeIDs[containerID]; !exists {
			p.containerTimes.Delete(key)
		}

		return true
	})
}

func (p *Plugin) registryAwareResolver(
	ctx context.Context, imageRef string,
) (digest, indexDigest string, err error) {
	digest, indexDigest, fallbackUsed, resolveErr := registry.ResolveWithRegistries(
		ctx, imageRef, p.transportCache.Load(),
	)
	if resolveErr != nil {
		return "", "", fmt.Errorf("resolving digest: %w", resolveErr)
	}

	if fallbackUsed {
		p.metrics.MirrorFallbackTotal.WithLabelValues(registry.Host(imageRef), "digest").Inc()
	}

	return digest, indexDigest, nil
}

//nolint:unparam // second return matches the NRI ContainerAdjustment API contract
func (p *Plugin) handleMissingAnnotations(
	ctx context.Context, namespace string,
	pod *api.PodSandbox, ctr *api.Container,
	imageRef, digest string, annotationCount int,
) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	mode := p.verifier.EffectiveModeForNamespace(namespace)

	if mode == config.ModeEnforce {
		slog.ErrorContext(ctx, "Missing image annotations in enforce mode",
			"pod", namespace+"/"+pod.GetName(),
			"container", ctr.GetName(),
			"image_ref", imageRef,
			"digest", digest,
			"annotation_count", annotationCount,
		)

		return nil, nil, fmt.Errorf(
			"%w for container %s", ErrMissingAnnotations, ctr.GetName(),
		)
	}

	slog.WarnContext(ctx, "Missing image annotations, skipping verification",
		"pod", namespace+"/"+pod.GetName(),
		"container", ctr.GetName(),
		"image_ref", imageRef,
		"digest", digest,
		"annotation_count", annotationCount,
	)

	p.metrics.VerificationSkippedTotal.WithLabelValues("missing_annotations", namespace).Inc()

	if mode == config.ModeWarn {
		adj := &api.ContainerAdjustment{}
		adj.AddAnnotation(AnnotationVerified, "false")
		adj.AddAnnotation(AnnotationMode, string(mode))

		return adj, nil, nil
	}

	return nil, nil, nil
}

func (p *Plugin) resolveDigestIfMissing(
	ctx context.Context,
	imageRef, digest, namespace string,
	pod *api.PodSandbox,
	ctr *api.Container,
) (resolvedDigest, resolvedIndexDigest string, resolveErr error) {
	if imageRef == "" || digest != "" {
		return digest, "", nil
	}

	resolveCtx, cancel := context.WithTimeout(
		ctx, time.Duration(p.digestResolveTimeout.Load()),
	)
	resolved, indexDigest, err := p.digestResolver(resolveCtx, imageRef)

	cancel()

	if err != nil {
		slog.WarnContext(ctx, "Failed to resolve image digest",
			"pod", namespace+"/"+pod.GetName(),
			"container", ctr.GetName(),
			"image", imageRef,
			"error", err,
		)

		return digest, "", fmt.Errorf("resolving digest for %s: %w", imageRef, err)
	}

	return resolved, indexDigest, nil
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

		waitGroup.Add(1)

		go func(index int) {
			defer waitGroup.Done()

			acquireErr := sem.Acquire(ctx, 1)
			if acquireErr != nil {
				slog.DebugContext(ctx, "Skipping prewarm, context cancelled",
					"image", images[index].imageRef,
					"error", acquireErr,
				)

				return
			}

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
		if p.prewarmDone != nil {
			p.prewarmDone()
		}
	}()

	start := time.Now()

	ctx, cancel := context.WithTimeout(ctx, prewarmTimeout)
	defer cancel()

	images = p.resolvePrewarmDigests(ctx, images)
	total := len(images)
	slog.Info("Pre-warming cache", "images", total)

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

	slog.Info("Pre-warming cache complete",
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

func resolveImage(annotations map[string]string) (imageRef, digest string) {
	imageRef, digest = resolveCRIOImage(annotations)

	if imageRef != "" && digest != "" {
		return imageRef, digest
	}

	cImg := annotations[AnnotationContainerdImage]
	cRef := validDigestOrEmpty(annotations[AnnotationContainerdImageRef])

	if cRef == "" && cImg != "" {
		if _, d, ok := strings.Cut(cImg, "@"); ok {
			cRef = validDigestOrEmpty(d)
		}
	}

	if cImg != "" && cRef != "" {
		return cImg, cRef
	}

	if imageRef == "" {
		imageRef = cImg
	}

	if digest == "" {
		digest = cRef
	}

	return imageRef, digest
}

func resolveCRIOImage(annotations map[string]string) (imageRef, digest string) {
	imageRef = annotations[AnnotationImageName]
	if imageRef == "" {
		imageRef = annotations[AnnotationImage]
	}

	if repoDigests := annotations[AnnotationImageRepoDigests]; repoDigests != "" {
		first, _, _ := strings.Cut(repoDigests, ",")
		if _, d, ok := strings.Cut(first, "@"); ok {
			digest = validDigestOrEmpty(d)
		}
	}

	if digest == "" {
		digest = validDigestOrEmpty(annotations[AnnotationImageRef])
	}

	if digest == "" {
		if _, d, ok := strings.Cut(annotations[AnnotationImageRef], "@"); ok {
			digest = validDigestOrEmpty(d)
		}
	}

	return imageRef, digest
}

var relevantAnnotationKeys = []string{ //nolint:gochecknoglobals // static lookup set
	AnnotationImageName,
	AnnotationImage,
	AnnotationImageRef,
	AnnotationImageRepoDigests,
	AnnotationContainerdImage,
	AnnotationContainerdImageRef,
}

func filterRelevantAnnotations(annotations map[string]string) map[string]string {
	filtered := make(map[string]string, len(relevantAnnotationKeys))

	for _, key := range relevantAnnotationKeys {
		if val, ok := annotations[key]; ok {
			filtered[key] = val
		}
	}

	return filtered
}

func validDigestOrEmpty(ref string) string {
	algo, _ := types.ParseDigest(ref)
	if algo == "" {
		return ""
	}

	return ref
}

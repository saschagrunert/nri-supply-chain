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
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"

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
	InvalidateCache(digest, namespace string)
	Status() types.StatusResponse
}

// StubUpdater abstracts the NRI stub's UpdateContainers method so tests
// can substitute a mock without depending on the real NRI connection.
type StubUpdater interface {
	UpdateContainers(updates []*api.ContainerUpdate) ([]*api.ContainerUpdate, error)
}

// DigestResolveFunc resolves an image reference to its platform-specific digest
// via a registry. When the tag points to a manifest list, indexDigest returns
// the manifest list digest (for attestation lookup); otherwise it is empty.
type DigestResolveFunc func(ctx context.Context, imageRef string) (digest, indexDigest string, err error)

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

// AnnotationServiceAccountPersist is the annotation key used to persist the
// pod's service account into container annotations so it survives plugin
// restart and is available during Synchronize.
const AnnotationServiceAccountPersist = "supply-chain.nri/service-account"

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
	prewarmDoneCh        chan struct{} // closed when prewarmCache first completes
	prewarmDoneOnce      sync.Once
	prewarmMu            sync.Mutex
	prewarmCancel        context.CancelFunc
	lastPrewarmImages    []prewarmImage // last known running images, for re-warming after reload
	transportCache       atomic.Pointer[registry.TransportCache]
	containers           *containerRegistry
	reverifyTrigger      chan struct{} // buffered(1); signals on-demand re-verify
	feedTrigger          chan []string // buffered(1); carries feed PURLs for filtered re-verify
	remediationMode      atomic.Pointer[config.RemediationMode]
	remediationConfig    atomic.Pointer[config.RemediationConfig]
	stubUpdater          StubUpdater
	stubMu               sync.RWMutex
	feedMu               sync.Mutex
}

// New creates a new Plugin with the given verifier, metrics, and config file path.
func New(
	v ImageVerifier, met *metrics.Metrics, configPath string,
	fetchTimeout, digestResolveTimeout time.Duration,
	cache *registry.TransportCache,
) *Plugin {
	plug := &Plugin{ //nolint:exhaustruct_v5 // zero-value fields are intentional
		verifier:        v,
		metrics:         met,
		configPath:      configPath,
		containers:      newContainerRegistry(),
		prewarmDoneCh:   make(chan struct{}),
		reverifyTrigger: make(chan struct{}, 1),
		feedTrigger:     make(chan []string, 1),
	}

	plug.fetchTimeout.Store(int64(fetchTimeout))
	plug.digestResolveTimeout.Store(int64(digestResolveTimeout))

	disabledMode := config.RemediationModeDisabled
	plug.remediationMode.Store(&disabledMode)

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
	slog.InfoContext(ctx, "Connected to runtime", "runtime", rt, "version", version)

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

	p.cleanStaleContainers(containers)

	images := p.collectPrewarmImages(containers, podNS)

	p.prewarmMu.Lock()
	p.lastPrewarmImages = images
	p.prewarmMu.Unlock()

	if len(images) == 0 {
		p.prewarmDoneOnce.Do(func() { close(p.prewarmDoneCh) })

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

// PrewarmAfterReload re-triggers cache pre-warming using the last known set
// of running container images. Call after a successful config/policy reload
// to avoid cold-cache verification latency for images already on the node.
func (p *Plugin) PrewarmAfterReload(ctx context.Context) {
	p.prewarmMu.Lock()
	images := p.lastPrewarmImages

	if len(images) == 0 {
		p.prewarmMu.Unlock()

		return
	}

	if p.prewarmCancel != nil {
		p.prewarmCancel()
	}

	prewarmCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	p.prewarmCancel = cancel
	p.prewarmMu.Unlock()

	copied := make([]prewarmImage, len(images))
	copy(copied, images)

	go p.prewarmCache(prewarmCtx, copied)
}

// CreateContainer is called for each new container before it is created.
// It verifies supply chain attestations and rejects the container on failure.
//
//nolint:cyclop,funlen // NRI hook handler with annotation resolution and verification
func (p *Plugin) CreateContainer(
	ctx context.Context, pod *api.PodSandbox, ctr *api.Container,
) (_ *api.ContainerAdjustment, _ []*api.ContainerUpdate, retErr error) {
	createdAt := time.Now()

	defer func() {
		outcome := "success"
		if retErr != nil {
			outcome = "error"
		}

		p.metrics.CreateContainerDuration.WithLabelValues(
			pod.GetNamespace(), outcome,
		).Observe(time.Since(createdAt).Seconds())
	}()

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
			p.containers.Store(
				ctr.GetId(),
				&containerState{ //nolint:exhaustruct_v5 // zero-value fields intentional
					imageRef:       imageRef,
					digest:         digest,
					namespace:      namespace,
					serviceAccount: serviceAccount,
					createdAt:      createdAt,
					state:          StateVerified,
				},
			)

			if adj == nil {
				adj = &api.ContainerAdjustment{}
			}

			adj.AddAnnotation(AnnotationServiceAccountPersist, serviceAccount)
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

	state := &containerState{ //nolint:exhaustruct_v5 // zero-value fields intentional
		imageRef:          imageRef,
		digest:            digest,
		indexDigest:       indexDigest,
		namespace:         namespace,
		serviceAccount:    serviceAccount,
		createdAt:         createdAt,
		state:             StateVerified,
		lastResult:        result,
		originalResources: captureLinuxResources(ctr),
		purls:             extractPURLsFromResult(result),
	}
	p.containers.Store(ctr.GetId(), state)

	adj := buildVerificationAdjustment(result, mode)

	if adj == nil {
		adj = &api.ContainerAdjustment{}
	}

	adj.AddAnnotation(AnnotationServiceAccountPersist, serviceAccount)

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

	cs, loaded := p.containers.LoadAndDelete(containerID)
	if !loaded {
		return nil
	}

	lifetime := time.Since(cs.createdAt).Seconds()

	p.metrics.ContainerLifetime.WithLabelValues(namespace).Observe(lifetime)

	slog.InfoContext(ctx, "Container removed",
		"container", containerID,
		"namespace", namespace,
		"lifetime_seconds", lifetime,
		"pod", pod.GetName(),
	)

	return nil
}

// SetStub stores the NRI stub for use by the continuous verifier's
// UpdateContainers calls. Called once from serve.go after stub creation.
func (p *Plugin) SetStub(s StubUpdater) {
	p.stubMu.Lock()
	p.stubUpdater = s
	p.stubMu.Unlock()
}

// SetRemediationMode updates the current remediation mode. Called during
// config reload.
func (p *Plugin) SetRemediationMode(mode config.RemediationMode) {
	m := mode
	p.remediationMode.Store(&m)
}

// SetRemediationConfig stores the full remediation config for use by the
// continuous verifier. Called during startup and config reload.
func (p *Plugin) SetRemediationConfig(cfg *config.RemediationConfig) {
	c := *cfg
	p.remediationConfig.Store(&c)
}

// TriggerReverify sends a non-blocking signal to the continuous verifier
// to start a re-verification cycle.
func (p *Plugin) TriggerReverify() {
	select {
	case p.reverifyTrigger <- struct{}{}:
	default:
	}
}

// TriggerFeedReverify queues a PURL-filtered re-verification cycle. Only
// containers whose stored PURLs overlap with the given feed PURLs are
// re-verified. If a previous trigger is pending, the PURLs are merged.
// Respects the on_new_cve trigger config; returns immediately when disabled.
func (p *Plugin) TriggerFeedReverify(purls []string) {
	if cfg := p.remediationConfig.Load(); cfg != nil {
		if !cfg.Triggers.OnNewCVE {
			return
		}
	}

	p.feedMu.Lock()
	defer p.feedMu.Unlock()

	select {
	case pending := <-p.feedTrigger:
		purls = append(pending, purls...)
		slices.Sort(purls)
		purls = slices.Compact(purls)
	default:
	}

	select {
	case p.feedTrigger <- purls:
	default:
	}
}

// cleanStaleContainers removes entries from the container registry for
// containers that are no longer in the active set. This handles containers
// that were removed while the plugin was disconnected.
func (p *Plugin) cleanStaleContainers(active []*api.Container) {
	activeIDs := make(map[string]struct{}, len(active))
	for _, ctr := range active {
		activeIDs[ctr.GetId()] = struct{}{}
	}

	p.containers.cleanStale(activeIDs)
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

// captureLinuxResources extracts the container's current Linux resource
// settings for later rollback after throttling.
func captureLinuxResources(ctr *api.Container) *api.LinuxResources {
	linux := ctr.GetLinux()
	if linux == nil {
		return nil
	}

	return deepCopyLinuxResources(linux.GetResources())
}

// extractPURLsFromResult collects PURL strings from SBOM check metadata in
// the verification result.
func extractPURLsFromResult(result *types.Result) []string {
	if result == nil {
		return nil
	}

	for i := range result.CheckResults {
		if result.CheckResults[i].Type != types.CheckTypeSBOM {
			continue
		}

		purls, ok := result.CheckResults[i].Metadata["purls"].([]string)
		if ok && len(purls) > 0 {
			return purls
		}
	}

	return nil
}

func (p *Plugin) getStubUpdater() StubUpdater { //nolint:ireturn // returns concrete value stored in field
	p.stubMu.RLock()
	s := p.stubUpdater
	p.stubMu.RUnlock()

	return s
}

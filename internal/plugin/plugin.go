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
	"sync/atomic"
	"time"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	"github.com/google/go-containerregistry/pkg/name"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/registry"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

var (
	// ErrMissingAnnotations indicates that required image annotations are absent.
	ErrMissingAnnotations = errors.New("missing image annotations")

	// ErrAdmissionTimeout indicates that verification did not complete within
	// the admission deadline. Verification continues in the background.
	ErrAdmissionTimeout = errors.New(
		"supply chain verification did not complete within the admission timeout",
	)

	// ErrRuntimeConfigPending indicates that the configuration passed by the
	// runtime enforces verification but has not been applied (yet), so the
	// container cannot be verified against it.
	ErrRuntimeConfigPending = errors.New(
		"the enforcing configuration passed by the runtime is not applied",
	)

	errEmptyDigest = errors.New("registry returned no digest")
)

// ImageVerifier abstracts the verification engine so tests can substitute a
// mock without depending on the concrete verifier package.
type ImageVerifier interface {
	Verify(ctx context.Context, req *types.VerifyRequest) (*types.Result, error)
	// ShouldVerify reports whether an image needs verification in a
	// namespace; false when verification is disabled for the namespace or
	// the image is excluded or not included.
	ShouldVerify(ctx context.Context, namespace, imageRef string) (verify bool, reason string)
	Ready() (ready bool, reason string)
	Enforcing() bool
	EffectiveModeForNamespace(namespace string) config.VerificationMode
	Reload(ctx context.Context, cfg *config.Config) error
	InvalidateCache(digest, namespace string)
	Status() types.StatusResponse
}

// AdmissionTimeoutProvider is implemented by verifiers that configure the
// bound for the CreateContainer admission. Without it the plugin uses
// DefaultAdmissionTimeout.
type AdmissionTimeoutProvider interface {
	AdmissionTimeout() time.Duration
}

const (
	// DefaultAdmissionTimeout bounds the CreateContainer admission when the
	// verifier does not provide admission_timeout.
	DefaultAdmissionTimeout = 1500 * time.Millisecond

	// admissionSafetyMargin is the minimum time the plugin keeps between its
	// answer and the runtime's own request deadline when that deadline is
	// propagated to the plugin. The margin grows to admissionSafetyDivisor
	// of the remaining time for longer deadlines, so a loaded node still
	// answers in time.
	admissionSafetyMargin = 100 * time.Millisecond

	// admissionSafetyDivisor sets the proportional safety margin (10% of the
	// remaining request time).
	admissionSafetyDivisor = 10
)

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
	// AnnotationIncomplete is set to "true" when verification did not run to
	// completion (e.g. the admission timeout expired in warn mode).
	AnnotationIncomplete = "supply-chain.nri/incomplete"
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
	transportCache       atomic.Pointer[registry.TransportCache]
	containers           *containerRegistry
	prewarm              *prewarmState
	remediation          *remediationState
	runtimeConfig        runtimeConfigState
}

// New creates a new Plugin with the given verifier, metrics, and config file path.
func New(
	v ImageVerifier, met *metrics.Metrics, configPath string,
	fetchTimeout, digestResolveTimeout time.Duration,
	cache *registry.TransportCache,
) *Plugin {
	plug := &Plugin{ //nolint:exhaustruct_v5 // zero-value fields are intentional
		verifier:    v,
		metrics:     met,
		configPath:  configPath,
		containers:  newContainerRegistry(),
		prewarm:     newPrewarmState(),
		remediation: newRemediationState(),
	}

	plug.fetchTimeout.Store(int64(fetchTimeout))
	plug.digestResolveTimeout.Store(int64(digestResolveTimeout))

	if cache != nil {
		plug.transportCache.Store(cache)
	}

	plug.digestResolver = plug.registryAwareResolver

	if met != nil {
		met.NRIConnected.Set(0)
	}

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

// VerifierReady returns true if the verifier is ready to serve requests. It
// is not ready while a configuration passed by the runtime is still being
// applied or failed to apply.
func (p *Plugin) VerifierReady() (ready bool, reason string) {
	if p.runtimeConfig.pending.Load() != nil {
		if failure := p.runtimeConfig.failure.Load(); failure != nil {
			return false, "applying the configuration passed by the runtime failed: " + *failure
		}

		return false, "applying the configuration passed by the runtime"
	}

	return p.verifier.Ready()
}

// SetDisconnected marks the plugin as disconnected from the NRI runtime.
func (p *Plugin) SetDisconnected() {
	p.setConnected(false)
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

		p.applyRuntimeConfig(ctx, cfg, parsed)
	}

	p.setConnected(true)

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

	images := p.collectPrewarmImages(ctx, containers, podNS)

	p.prewarm.mu.Lock()
	p.prewarm.images = images
	p.prewarm.mu.Unlock()

	if len(images) == 0 {
		p.prewarm.markDone()

		return nil, nil
	}

	// Use context.WithoutCancel so the pre-warm goroutine is not
	// interrupted when the ttrpc request context completes.
	// Wrap it with a cancellable context so shutdown can stop prewarm.
	prewarmCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))

	p.prewarm.mu.Lock()
	if p.prewarm.cancel != nil {
		p.prewarm.cancel()
	}

	p.prewarm.cancel = cancel
	p.prewarm.mu.Unlock()

	go p.prewarmCache(prewarmCtx, images)

	return nil, nil
}

// CancelPrewarm cancels any in-progress cache pre-warming.
func (p *Plugin) CancelPrewarm() {
	p.prewarm.mu.Lock()
	cancel := p.prewarm.cancel
	p.prewarm.mu.Unlock()

	if cancel != nil {
		cancel()
	}
}

// PrewarmAfterReload re-triggers cache pre-warming using the last known set
// of running container images. Call after a successful config/policy reload
// to avoid cold-cache verification latency for images already on the node.
func (p *Plugin) PrewarmAfterReload(ctx context.Context) {
	p.prewarm.mu.Lock()
	images := p.prewarm.images

	if len(images) == 0 {
		p.prewarm.mu.Unlock()

		return
	}

	if p.prewarm.cancel != nil {
		p.prewarm.cancel()
	}

	prewarmCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	p.prewarm.cancel = cancel
	p.prewarm.mu.Unlock()

	copied := make([]prewarmImage, len(images))
	copy(copied, images)

	go p.prewarmCache(prewarmCtx, copied)
}

// CreateContainer is called for each new container before it is created.
// It verifies supply chain attestations and rejects the container on failure.
//
// The whole admission is bounded by the admission timeout, which must stay
// below the runtime's NRI request timeout: a plugin that misses the runtime
// deadline is closed and the container is created without a verdict. When
// the admission timeout expires, enforce mode rejects the container while the
// verification keeps running in the background to fill the cache.
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

	// Until an enforcing configuration passed by the runtime is applied, the
	// verifier still runs the previous (by default disabled) configuration.
	if p.pendingEnforcingRuntimeConfig(pod.GetNamespace()) {
		slog.ErrorContext(ctx, "Container rejected",
			"pod", pod.GetNamespace()+"/"+pod.GetName(),
			"container", ctr.GetName(),
			"error", ErrRuntimeConfigPending,
		)

		return nil, nil, fmt.Errorf("supply chain verification: %w", ErrRuntimeConfigPending)
	}

	admissionCtx, cancelAdmission := p.admissionContext(ctx)
	defer cancelAdmission()

	annotations := ctr.GetAnnotations()
	imageRef, digest, runtimeDigest := resolveContainerImage(ctr)
	namespace := pod.GetNamespace()
	serviceAccount := pod.GetAnnotations()[AnnotationServiceAccount]

	if slog.Default().Enabled(ctx, slog.LevelDebug) {
		slog.DebugContext(ctx, "NRI container info",
			"container_id", ctr.GetId(),
			"container_name", ctr.GetName(),
			"annotations", filterRelevantAnnotations(annotations),
			"image_digest", runtimeDigest,
			"labels", ctr.GetLabels(),
		)
	}

	req := &types.VerifyRequest{
		ImageRef:       imageRef,
		Digest:         digest,
		IndexDigest:    "",
		Namespace:      namespace,
		ServiceAccount: serviceAccount,
	}

	// Images that need no verification skip the registry digest lookup;
	// Verify admits them without a digest.
	needsDigest := imageRef != "" && digest == ""
	if needsDigest {
		if verify, reason := p.verifier.ShouldVerify(ctx, namespace, imageRef); !verify {
			slog.DebugContext(ctx, "Skipping digest resolution",
				"image", imageRef, "namespace", namespace, "reason", reason,
			)

			needsDigest = false
		}
	}

	var (
		resolveErr error
		unresolved bool
	)

	if needsDigest {
		req.Digest, req.IndexDigest, unresolved, resolveErr = p.resolveDigestIfMissing(
			admissionCtx, req, runtimeDigest, pod, ctr,
		)
	}

	if imageRef == "" || (req.Digest == "" && needsDigest) {
		return p.admitWithoutDigest(ctx, admissionCtx, req, pod, ctr, createdAt, resolveErr)
	}

	result, err := p.verifier.Verify(admissionCtx, req)

	// The verifier's snapshot may require verification although ShouldVerify
	// saw none needed (e.g. a reload in between): resolve the digest and
	// verify again instead of verifying without a digest.
	if errors.Is(err, types.ErrDigestRequired) && req.Digest == "" {
		req.Digest, req.IndexDigest, unresolved, resolveErr = p.resolveDigestIfMissing(
			admissionCtx, req, runtimeDigest, pod, ctr,
		)
		if req.Digest == "" {
			return p.admitWithoutDigest(ctx, admissionCtx, req, pod, ctr, createdAt, resolveErr)
		}

		result, err = p.verifier.Verify(admissionCtx, req)
	}

	if err != nil {
		err = admissionError(admissionCtx, ctx, err)

		slog.ErrorContext(ctx, "Container rejected",
			"pod", namespace+"/"+pod.GetName(),
			"container", ctr.GetName(),
			"image", imageRef,
			"error", err,
		)

		return nil, nil, fmt.Errorf("supply chain verification: %w", err)
	}

	mode := config.VerificationMode(result.Mode)
	if mode == "" {
		mode = p.verifier.EffectiveModeForNamespace(namespace)
	}

	slog.InfoContext(ctx, "Container verified",
		"pod", namespace+"/"+pod.GetName(),
		"container", ctr.GetName(),
		"image", imageRef,
		"allowed", result.Allowed,
		"verified", result.Verified,
	)

	// A runtime digest that was not resolved (verification was not needed or
	// the registry was unreachable) is resolved by the continuous verifier.
	unresolvedDigest := ""
	if req.Digest == "" || unresolved {
		unresolvedDigest = runtimeDigest
	}

	state := &containerState{ //nolint:exhaustruct_v5 // zero-value fields intentional
		imageRef:          imageRef,
		digest:            req.Digest,
		indexDigest:       req.IndexDigest,
		unresolvedDigest:  unresolvedDigest,
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

	if value, ok := OriginalResourcesAnnotation(state.originalResources); ok {
		adj.AddAnnotation(AnnotationOriginalResources, value)
	}

	return adj, nil, nil
}

// admissionError marks err as an admission timeout when the admission
// deadline expired while the runtime's request was still alive.
func admissionError(admissionCtx, requestCtx context.Context, err error) error {
	if errors.Is(admissionCtx.Err(), context.DeadlineExceeded) && requestCtx.Err() == nil {
		return fmt.Errorf("%w: %w", ErrAdmissionTimeout, err)
	}

	return err
}

func buildVerificationAdjustment(
	result *types.Result, mode config.VerificationMode,
) *api.ContainerAdjustment {
	if result == nil || mode == config.ModeDisabled {
		return nil
	}

	adj := &api.ContainerAdjustment{}
	adj.AddAnnotation(AnnotationVerified, strconv.FormatBool(result.Verified))
	adj.AddAnnotation(AnnotationMode, string(mode))

	if resultIncomplete(result) {
		adj.AddAnnotation(AnnotationIncomplete, "true")
	}

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

// resultIncomplete reports whether verification did not run to completion:
// an internal error, or attestations that could not be fetched.
func resultIncomplete(result *types.Result) bool {
	return result.Incomplete()
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
	p.remediation.stubMu.Lock()
	p.remediation.stub = s
	p.remediation.stubMu.Unlock()
}

// SetRemediationMode updates the current remediation mode. Called during
// config reload.
func (p *Plugin) SetRemediationMode(mode config.RemediationMode) {
	m := mode
	p.remediation.mode.Store(&m)
}

// SetRemediationConfig stores the full remediation config for use by the
// continuous verifier. Called during startup and config reload.
func (p *Plugin) SetRemediationConfig(cfg *config.RemediationConfig) {
	c := *cfg
	p.remediation.cfg.Store(&c)
}

// TriggerReverify sends a non-blocking signal to the continuous verifier
// to start a re-verification cycle.
func (p *Plugin) TriggerReverify() {
	select {
	case p.remediation.reverifyTrigger <- struct{}{}:
	default:
	}
}

// TriggerFeedReverify queues a PURL-filtered re-verification cycle. Only
// containers whose stored PURLs overlap with the given feed PURLs are
// re-verified. If a previous trigger is pending, the PURLs are merged.
// Respects the on_new_cve trigger config; returns immediately when disabled.
func (p *Plugin) TriggerFeedReverify(purls []string) {
	if cfg := p.remediation.cfg.Load(); cfg != nil {
		if !cfg.Triggers.OnNewCVE {
			return
		}
	}

	p.remediation.feedMu.Lock()
	defer p.remediation.feedMu.Unlock()

	select {
	case pending := <-p.remediation.feedTrigger:
		purls = append(pending, purls...)
		slices.Sort(purls)
		purls = slices.Compact(purls)
	default:
	}

	select {
	case p.remediation.feedTrigger <- purls:
	default:
	}
}

// admitWithoutDigest handles a container whose image reference or digest is
// unknown: enforce mode rejects it (reporting a failed digest resolution),
// other modes admit it without verification.
func (p *Plugin) admitWithoutDigest(
	ctx, admissionCtx context.Context, req *types.VerifyRequest,
	pod *api.PodSandbox, ctr *api.Container, createdAt time.Time, resolveErr error,
) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	mode := p.verifier.EffectiveModeForNamespace(req.Namespace)
	if resolveErr != nil && mode == config.ModeEnforce {
		return nil, nil, fmt.Errorf(
			"supply chain verification: %w", admissionError(admissionCtx, ctx, resolveErr),
		)
	}

	adj, _, handleErr := p.handleMissingAnnotations(
		ctx, req.Namespace, pod, ctr, req.ImageRef, req.Digest, len(ctr.GetAnnotations()),
	)
	if handleErr != nil {
		return nil, nil, handleErr
	}

	p.containers.Store(
		ctr.GetId(),
		&containerState{ //nolint:exhaustruct_v5 // zero-value fields intentional
			imageRef:       req.ImageRef,
			digest:         req.Digest,
			namespace:      req.Namespace,
			serviceAccount: req.ServiceAccount,
			createdAt:      createdAt,
			state:          StateSkipped,
		},
	)

	if adj == nil {
		adj = &api.ContainerAdjustment{}
	}

	adj.AddAnnotation(AnnotationServiceAccountPersist, req.ServiceAccount)

	return adj, nil, nil
}

func (p *Plugin) setConnected(connected bool) {
	p.connected.Store(connected)

	if p.metrics == nil {
		return
	}

	if connected {
		p.metrics.NRIConnected.Set(1)
	} else {
		p.metrics.NRIConnected.Set(0)
	}
}

// admissionContext derives the context that bounds a CreateContainer
// admission: the admission timeout, shortened to answer ahead of the
// runtime's request deadline when that deadline is known.
func (p *Plugin) admissionContext(ctx context.Context) (context.Context, context.CancelFunc) {
	budget := DefaultAdmissionTimeout

	if provider, ok := p.verifier.(AdmissionTimeoutProvider); ok {
		if configured := provider.AdmissionTimeout(); configured > 0 {
			budget = configured
		}
	}

	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		margin := max(admissionSafetyMargin, remaining/admissionSafetyDivisor)

		if limit := remaining - margin; limit < budget {
			budget = max(limit, remaining/2) //nolint:mnd // half of a very short deadline
		}
	}

	return context.WithTimeout(ctx, budget)
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
			"annotation_count", annotationCount,
		)

		return nil, nil, fmt.Errorf(
			"%w for container %s in %s/%s",
			ErrMissingAnnotations, ctr.GetName(), namespace, pod.GetName(),
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

// resolveDigestIfMissing resolves the platform and index digests of a
// request without a digest, bounded by the digest resolve timeout. unresolved
// is true when the runtime digest is used as is (see resolveImageDigests).
func (p *Plugin) resolveDigestIfMissing(
	ctx context.Context,
	req *types.VerifyRequest,
	runtimeDigest string,
	pod *api.PodSandbox,
	ctr *api.Container,
) (resolvedDigest, resolvedIndexDigest string, unresolved bool, resolveErr error) {
	if req.ImageRef == "" || req.Digest != "" {
		return req.Digest, req.IndexDigest, false, nil
	}

	resolveCtx, cancel := context.WithTimeout(
		ctx, time.Duration(p.digestResolveTimeout.Load()),
	)
	resolved, indexDigest, fromTag, unresolved, err := p.resolveImageDigests(
		resolveCtx, req.ImageRef, runtimeDigest,
	)

	cancel()

	if err != nil {
		slog.WarnContext(ctx, "Failed to resolve image digest",
			"pod", req.Namespace+"/"+pod.GetName(),
			"container", ctr.GetName(),
			"image", req.ImageRef,
			"error", err,
		)

		return "", "", false, fmt.Errorf("resolving digest for %s: %w", req.ImageRef, err)
	}

	if fromTag && p.verifier.EffectiveModeForNamespace(req.Namespace) == config.ModeEnforce {
		// The registry may point the tag at a different image than the one
		// the runtime runs (e.g. a cached image with IfNotPresent).
		slog.WarnContext(ctx,
			"Runtime did not report the image digest, verifying the digest the registry "+
				"currently resolves the reference to",
			"pod", req.Namespace+"/"+pod.GetName(),
			"container", ctr.GetName(),
			"image", req.ImageRef,
			"digest", resolved,
		)
	}

	return resolved, indexDigest, unresolved, nil
}

// resolveImageDigests resolves the platform manifest digest of an image and,
// for multi-platform images, its index digest, as used for attestation
// lookup. With a runtime digest (which may be an index or a manifest digest)
// the digest-pinned reference is resolved, so the result cannot differ from
// the image the runtime runs; when the registry cannot be reached the runtime
// digest is used as is and unresolved is true. Without a runtime digest the
// tag is resolved and fromTag is true.
func (p *Plugin) resolveImageDigests(
	ctx context.Context, imageRef, runtimeDigest string,
) (digest, indexDigest string, fromTag, unresolved bool, err error) {
	if runtimeDigest == "" {
		digest, indexDigest, err = p.digestResolver(ctx, imageRef)

		return digest, indexDigest, true, false, err
	}

	digest, indexDigest, err = p.resolveRuntimeDigest(ctx, imageRef, runtimeDigest)
	if err != nil {
		slog.WarnContext(ctx,
			"Failed to resolve the runtime image digest, verifying it as the manifest digest",
			"image", imageRef,
			"digest", runtimeDigest,
			"error", err,
		)

		return runtimeDigest, "", false, true, nil
	}

	return digest, indexDigest, false, false, nil
}

// resolveRuntimeDigest resolves the platform manifest and index digests of
// the image the runtime reports by runtimeDigest via the digest-pinned
// reference, without falling back to the runtime digest.
func (p *Plugin) resolveRuntimeDigest(
	ctx context.Context, imageRef, runtimeDigest string,
) (digest, indexDigest string, err error) {
	pinned := pinnedReference(imageRef, runtimeDigest)

	digest, indexDigest, err = p.digestResolver(ctx, pinned)
	if err != nil {
		return "", "", err
	}

	if digest == "" {
		return "", "", fmt.Errorf("%w: %s", errEmptyDigest, pinned)
	}

	return digest, indexDigest, nil
}

// pinnedReference returns the reference of imageRef's repository pinned to
// digest.
func pinnedReference(imageRef, digest string) string {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		repository, _, _ := strings.Cut(imageRef, "@")

		return repository + "@" + digest
	}

	return ref.Context().Name() + "@" + digest
}

// resolveContainerImage returns the image reference and repository digest of
// a container from the runtime annotations or a digest-pinned image name, and
// the digest the runtime reports in the NRI container image. The runtime
// digest can be an image index digest or a manifest digest, so it is only
// used when no repository digest is known, after resolving it (see
// resolveImageDigests).
func resolveContainerImage(ctr *api.Container) (imageRef, digest, runtimeDigest string) {
	imageRef, digest = resolveImage(ctr.GetAnnotations())

	image := ctr.GetImage()

	if imageRef == "" {
		imageRef = image.GetName()
	}

	if digest == "" {
		if _, pinned, ok := strings.Cut(image.GetName(), "@"); ok {
			digest = validDigestOrEmpty(pinned)
		}
	}

	return imageRef, digest, validDigestOrEmpty(image.GetDigest())
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
	p.remediation.stubMu.RLock()
	s := p.remediation.stub
	p.remediation.stubMu.RUnlock()

	return s
}

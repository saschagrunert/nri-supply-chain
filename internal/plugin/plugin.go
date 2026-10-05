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
// config.DefaultAdmissionTimeout.
type AdmissionTimeoutProvider interface {
	AdmissionTimeout() time.Duration
}

const (
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
	// lifetime is cancelled by Close and bounds background work that
	// outlives the NRI request that started it.
	lifetime      context.Context //nolint:containedctx // lifetime of the plugin
	closeLifetime context.CancelFunc
}

// New creates a new Plugin with the given verifier, metrics, and config file
// path. The metrics are required.
func New(
	verif ImageVerifier, met *metrics.Metrics, configPath string,
	fetchTimeout, digestResolveTimeout time.Duration,
	cache *registry.TransportCache,
) *Plugin {
	lifetime, closeLifetime := context.WithCancel(context.Background())

	plug := &Plugin{ //nolint:exhaustruct_v5 // zero-value fields are intentional
		verifier:      verif,
		metrics:       met,
		configPath:    configPath,
		containers:    newContainerRegistry(),
		prewarm:       newPrewarmState(),
		remediation:   newRemediationState(),
		lifetime:      lifetime,
		closeLifetime: closeLifetime,
	}

	plug.fetchTimeout.Store(int64(fetchTimeout))
	plug.digestResolveTimeout.Store(int64(digestResolveTimeout))

	if cache != nil {
		plug.transportCache.Store(cache)
	}

	plug.digestResolver = plug.registryAwareResolver

	met.NRIConnected.Set(0)

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

	prewarmCtx, cancel := p.prewarmContext(ctx)

	p.prewarm.mu.Lock()
	if p.prewarm.cancel != nil {
		p.prewarm.cancel()
	}

	p.prewarm.cancel = cancel
	p.prewarm.mu.Unlock()

	go p.prewarmCache(prewarmCtx, images)

	return nil, nil
}

// Close stops the plugin's background work on shutdown: cache pre-warming
// and retries of a configuration passed by the runtime that failed to apply.
func (p *Plugin) Close() {
	p.closeLifetime()
	p.CancelPrewarm()
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

	prewarmCtx, cancel := p.prewarmContext(ctx)
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

	// The verifier reports denials as errors; a result that does not admit
	// the container is rejected as well, failing closed.
	if err == nil && (result == nil || !result.Allowed) {
		err = deniedResultError(imageRef, result)
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

// deniedResultError describes a verification result that does not admit the
// container although the verifier returned no error.
func deniedResultError(imageRef string, result *types.Result) error {
	reason := "no verification result"
	if result != nil {
		reason = result.Reason
	}

	return fmt.Errorf("%w: %s: %s", types.ErrVerificationFailed, imageRef, reason)
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

	if result.Incomplete() {
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

// StopContainer is called when a container stops. A stopped container never
// runs again (a restart creates a new container), so it is no longer tracked
// and the continuous verifier does not re-verify or update it. It records the
// container lifetime as a histogram metric.
func (p *Plugin) StopContainer(
	ctx context.Context,
	pod *api.PodSandbox,
	ctr *api.Container,
) ([]*api.ContainerUpdate, error) {
	p.untrackContainer(ctx, pod, ctr, "Container stopped")

	return nil, nil
}

// RemoveContainer is called when a container is removed from the runtime,
// including a container whose creation failed after admission. It records
// the lifetime of a container that was not stopped before as a histogram
// metric.
func (p *Plugin) RemoveContainer(
	ctx context.Context,
	pod *api.PodSandbox,
	ctr *api.Container,
) error {
	p.untrackContainer(ctx, pod, ctr, "Container removed")

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

// untrackContainer removes a container from the registry and records its
// lifetime.
func (p *Plugin) untrackContainer(
	ctx context.Context, pod *api.PodSandbox, ctr *api.Container, message string,
) {
	containerID := ctr.GetId()
	namespace := pod.GetNamespace()

	cs, loaded := p.containers.LoadAndDelete(containerID)
	if !loaded {
		return
	}

	lifetime := time.Since(cs.createdAt).Seconds()

	p.metrics.ContainerLifetime.WithLabelValues(namespace).Observe(lifetime)

	slog.InfoContext(ctx, message,
		"container", containerID,
		"namespace", namespace,
		"lifetime_seconds", lifetime,
		"pod", pod.GetName(),
	)
}

// admitWithoutDigest handles a container whose image reference or digest is
// unknown: enforce mode rejects it (reporting a failed digest resolution),
// other modes admit it without verification.
func (p *Plugin) admitWithoutDigest(
	ctx, admissionCtx context.Context, req *types.VerifyRequest,
	pod *api.PodSandbox, ctr *api.Container, createdAt time.Time, resolveErr error,
) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	mode := p.verifier.EffectiveModeForNamespace(req.Namespace)

	var adj *api.ContainerAdjustment

	if resolveErr != nil {
		if mode == config.ModeEnforce {
			return nil, nil, fmt.Errorf(
				"supply chain verification: %w", admissionError(admissionCtx, ctx, resolveErr),
			)
		}

		adj = p.skipUnresolvedDigest(ctx, req, pod, ctr, mode, resolveErr)
	} else {
		var handleErr error

		adj, _, handleErr = p.handleMissingAnnotations(
			ctx, req.Namespace, pod, ctr, req.ImageRef, req.Digest, len(ctr.GetAnnotations()),
		)
		if handleErr != nil {
			return nil, nil, handleErr
		}
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
	budget := config.DefaultAdmissionTimeout

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

	return skippedAdjustment(mode), nil, nil
}

// skipUnresolvedDigest admits a container whose image digest could not be
// resolved outside enforce mode, without verification.
func (p *Plugin) skipUnresolvedDigest(
	ctx context.Context, req *types.VerifyRequest,
	pod *api.PodSandbox, ctr *api.Container,
	mode config.VerificationMode, resolveErr error,
) *api.ContainerAdjustment {
	slog.WarnContext(ctx, "Failed to resolve image digest, skipping verification",
		"pod", req.Namespace+"/"+pod.GetName(),
		"container", ctr.GetName(),
		"image_ref", req.ImageRef,
		"mode", mode,
		"error", resolveErr,
	)

	p.metrics.VerificationSkippedTotal.WithLabelValues(
		"digest_resolution_failed", req.Namespace,
	).Inc()

	return skippedAdjustment(mode)
}

// skippedAdjustment marks a container admitted without verification in warn
// mode; other modes add no verification annotations.
func skippedAdjustment(mode config.VerificationMode) *api.ContainerAdjustment {
	if mode != config.ModeWarn {
		return nil
	}

	adj := &api.ContainerAdjustment{}
	adj.AddAnnotation(AnnotationVerified, "false")
	adj.AddAnnotation(AnnotationMode, string(mode))

	return adj
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

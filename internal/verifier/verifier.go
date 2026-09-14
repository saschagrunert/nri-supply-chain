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

// Package verifier performs supply chain attestation verification on container images.
package verifier

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/registry"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

var (
	// ErrVerificationFailed is returned when supply chain verification fails
	// in enforce mode. It is types.ErrVerificationFailed, so callers that only
	// depend on the types package can detect it.
	ErrVerificationFailed = types.ErrVerificationFailed

	// ErrCircuitBreakerOpen is returned when the circuit breaker is open.
	ErrCircuitBreakerOpen = errors.New("circuit breaker open for image")

	// ErrVerifierStopped is returned for verifications requested while the
	// verifier is shutting down.
	ErrVerifierStopped = errors.New("verifier is stopping")

	// ErrVerificationInProgress is returned to an admission that would join
	// a verification already running for longer than the admission timeout,
	// instead of waiting for it until the admission deadline.
	ErrVerificationInProgress = errors.New("verification already in progress")

	errUnexpectedVerifyResult = errors.New("verifier: unexpected singleflight result type")
)

const (
	maxConcurrentFetches        = 50
	maxConcurrentFetchesPerHost = 10
	warmTimeout                 = 30 * time.Second

	// stopGracePeriod bounds how long Stop waits for in-flight
	// verifications before releasing resources.
	stopGracePeriod = 10 * time.Second
)

// Verifier performs supply chain attestation verification on container images.
type Verifier struct {
	state atomic.Pointer[snapshot]

	// reloadMu serializes whole reloads, including pausing and restarting the
	// OCI policy poller, so concurrent reloads cannot lose the rollback guard
	// or leak pollers. It is never taken by the poller callback.
	reloadMu sync.Mutex
	// mu serializes snapshot replacement (Reload and OCI policy updates).
	mu         sync.Mutex
	nodeName   string
	inflight   singleflight.Group
	flights    flightTracker
	generation atomic.Uint64
	poller     atomic.Pointer[policyPoller]
	// flightStarts maps singleflight keys to the start time of the running
	// verification, so admissions can avoid joining slow verifications.
	flightStarts sync.Map
	// reloadPrepared is a test hook called after a reload prepared its plan.
	reloadPrepared func()
}

// NewFetcher creates an attestation fetcher configured from cfg. When offline
// mode is enabled, a BundleFetcher or FallbackFetcher is returned; otherwise
// an OCIFetcher is created and the Sigstore trusted root is pre-warmed. The
// context bounds the warm-up; pass the application context so startup can be
// cancelled. Tests that need the "no fetcher" code path should pass nil to New
// directly.
func NewFetcher( //nolint:ireturn // returns BundleFetcher, FallbackFetcher, or OCIFetcher
	ctx context.Context, cfg *config.Config, transportCache *registry.TransportCache,
) (attestation.Fetcher, error) {
	return createFetcherForMode(ctx, cfg, transportCache, nil)
}

// New creates a new Verifier with the given configuration, metrics, and attestation fetcher.
// The context is used for the OCI policy poller background goroutine when
// policy source is "oci".
func New(
	ctx context.Context,
	cfg *config.Config, met *metrics.Metrics, fetcher attestation.Fetcher,
) (*Verifier, error) {
	cfgCopy := *cfg

	configureOCICallbacks(fetcher, met)

	setBundleMetricsOnFetcher(fetcher, met)

	loaded, err := loadAndHashPolicies(ctx, &cfgCopy, fetcher, time.Time{})
	if err != nil {
		loaded, err = handleOCIStartupFailure(ctx, &cfgCopy, loaded, err)
		if err != nil {
			return nil, err
		}
	}

	if cfgCopy.Enabled() && len(loaded.policies) > 0 {
		err = validatePoliciesModes(cfgCopy.Verification, loaded.policies)
		if err != nil {
			return nil, err
		}

		WarnEnforceDefaults(ctx, &cfgCopy, loaded.policies)
		WarnWarnModeDefaults(ctx, &cfgCopy, loaded.policies)
	}

	verif := &Verifier{ //nolint:exhaustruct_v5 // zero-value fields are intentional
		nodeName: resolveNodeName(),
	}

	trust := computeTrustFingerprint(&cfgCopy, loaded.policies)

	snap, err := verif.buildSnapshot(ctx, nil, &snapshotInput{
		config:       &cfgCopy,
		policies:     loaded.policies,
		policyHashes: loaded.hashes,
		trust:        trust,
		fetcher:      fetcher,
		fetcherBasis: fetcherBasis{config: &cfgCopy, sigstore: trust.sigstore},
		metrics:      met,
	})
	if err != nil {
		return nil, err
	}

	verif.state.Store(snap)

	if cfgCopy.Policy.Source == config.PolicySourceOCI {
		verif.startPoller(ctx, loaded.policyFetcher, &cfgCopy, loaded.ociDigest)
	}

	return verif, nil
}

func buildAllowlistMap(entries []string) map[string]struct{} {
	if len(entries) == 0 {
		return nil
	}

	allowlist := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		digest := types.ExtractDigest(entry)
		if digest != "" {
			allowlist[digest] = struct{}{}
		}
	}

	if len(allowlist) == 0 {
		return nil
	}

	slog.Debug("Loaded allowlist digests", "count", len(allowlist))

	return allowlist
}

func resolveNodeName() string {
	if name := os.Getenv("NODE_NAME"); name != "" {
		return name
	}

	hostname, err := os.Hostname()
	if err != nil {
		return ""
	}

	slog.Debug("NODE_NAME not set, falling back to hostname",
		"hostname", hostname)

	return hostname
}

func policyHashForNamespace(hashes map[string]string, namespace string) string {
	if h, ok := hashes[namespace]; ok {
		return h
	}

	return hashes[""]
}

// Stop releases resources held by the verifier, including the cache's
// background eviction goroutine and the OCI policy poller. It waits up to
// a short grace period for in-flight verifications so they can write their
// results; use StopContext to control the wait.
func (v *Verifier) Stop() {
	done := make(chan struct{})

	timer := time.AfterFunc(stopGracePeriod, func() { close(done) })
	defer timer.Stop()

	v.stop(done)
}

// StopContext is like Stop but waits for in-flight verifications only until
// ctx is done. Verifications requested after StopContext was called fail
// with ErrVerifierStopped.
func (v *Verifier) StopContext(ctx context.Context) {
	v.stop(ctx.Done())
}

// CurrentConfig returns the current configuration snapshot.
func (v *Verifier) CurrentConfig() *config.Config {
	return v.state.Load().config
}

// AdmissionTimeout returns the configured bound for the NRI CreateContainer
// admission (admission_timeout).
func (v *Verifier) AdmissionTimeout() time.Duration {
	return v.state.Load().config.AdmissionTimeout.Duration
}

// Enforcing returns true if the global verification mode is enforce.
// It does not account for per-namespace mode overrides. Callers that
// need per-namespace semantics should use EffectiveModeForNamespace.
func (v *Verifier) Enforcing() bool {
	return v.state.Load().config.Verification == config.ModeEnforce
}

// EffectiveModeForNamespace returns the verification mode that applies to the
// given namespace, taking per-namespace mode overrides into account.
func (v *Verifier) EffectiveModeForNamespace(namespace string) config.VerificationMode {
	state := v.snap()
	pol := policyForNamespace(state.policies, namespace)

	if pol == nil {
		return state.config.Verification
	}

	return pol.EffectiveMode(state.config.Verification)
}

// ShouldVerify reports whether an image in the given namespace needs
// verification. It returns false, with a reason, when verification is
// disabled for the namespace or the image is excluded or not included by
// the namespace policy. Callers use it to skip expensive preparation such as
// registry digest resolution; Verify applies the same rules.
func (v *Verifier) ShouldVerify(
	ctx context.Context, namespace, imageRef string,
) (verify bool, reason string) {
	state := v.snap()

	if !state.config.Enabled() {
		return false, reasonVerificationDisabled
	}

	pol := policyForNamespace(state.policies, namespace)
	if pol == nil {
		return true, ""
	}

	if pol.EffectiveMode(state.config.Verification) == config.ModeDisabled {
		return false, reasonVerificationDisabled
	}

	if !isIncluded(ctx, pol.Include, imageRef) {
		return false, reasonNotIncluded
	}

	if isExcluded(ctx, pol.Exclude, imageRef) {
		return false, reasonExcluded
	}

	return true, ""
}

const (
	reasonVerificationDisabled = "verification disabled"
	reasonNotIncluded          = "image is not included"
	reasonExcluded             = "image is excluded"
)

// Ready returns true if the verifier is ready to serve requests.
// When not ready, the second return value describes the reason.
func (v *Verifier) Ready() (ready bool, reason string) {
	state := v.state.Load()

	if state.config == nil {
		return false, "no config loaded"
	}

	if !stateReady(state) {
		return false, "no policies loaded"
	}

	if stale, staleReason := v.policiesStale(); stale {
		return false, staleReason
	}

	return true, ""
}

// Status returns the current operational status of the verifier, including
// policy count, namespaces, cache size, and circuit breaker states.
func (v *Verifier) Status() types.StatusResponse {
	state := v.state.Load()

	if state.config == nil {
		return types.StatusResponse{
			Ready:           false,
			Mode:            "",
			Policies:        types.PolicyStatus{Count: 0, Namespaces: []string{}, Source: ""},
			Cache:           types.CacheStatus{Size: 0, MaxSize: 0},
			CircuitBreakers: map[string]string{},
			NRI:             types.NRIStatus{Connected: false},
		}
	}

	ready, _ := v.Ready()
	namespaces := policyNamespaces(state.policies)

	return types.StatusResponse{
		Ready: ready,
		Mode:  string(state.config.Verification),
		Policies: types.PolicyStatus{
			Count:      len(state.policies),
			Namespaces: namespaces,
			Source:     string(state.config.Policy.Source),
		},
		Cache: types.CacheStatus{
			Size:    state.cache.Len(),
			MaxSize: state.cache.MaxSize(),
		},
		CircuitBreakers: state.circuitBreakers.States(),
		NRI:             types.NRIStatus{Connected: false},
	}
}

func stateReady(state *snapshot) bool {
	if state.config == nil {
		return false
	}

	if !state.config.Enabled() {
		return true
	}

	return len(state.policies) > 0
}

func policyNamespaces(policies map[string]*policy.Policy) []string {
	namespaces := make([]string, 0, len(policies))

	for ns := range policies {
		if ns != "" {
			namespaces = append(namespaces, ns)
		}
	}

	slices.Sort(namespaces)

	return namespaces
}

// InvalidateCache removes the cached verification results for a digest in a
// namespace, including results keyed by image reference or policy rule,
// forcing the next Verify call to re-fetch and re-evaluate attestations.
func (v *Verifier) InvalidateCache(digest, namespace string) {
	v.snap().cache.DeleteAll(digest, namespace)
}

// TransportCache returns the transport cache from the current fetcher, or nil
// if verification is disabled or the fetcher has no cache.
func (v *Verifier) TransportCache() *registry.TransportCache {
	state := v.state.Load()

	return transportCacheFromFetcher(state.fetcher)
}

// Verify performs supply chain verification for the given request. When the
// image was resolved from a manifest list, req.IndexDigest should be the
// manifest list digest so attestation lookup can find cosign-attached
// attestations.
//
// The returned result reports the admission decision in Allowed and the
// verification outcome in Verified. In enforce mode a failed verification
// also returns an error wrapping ErrVerificationFailed.
func (v *Verifier) Verify( //nolint:funlen // early-return branches inflate line count
	ctx context.Context, req *types.VerifyRequest,
) (*types.Result, error) {
	state := v.snap()
	imageRef, digest, namespace := req.ImageRef, req.Digest, req.Namespace
	globalMode := state.config.Verification

	info := &auditInfo{
		policyHash:        "",
		nodeName:          v.nodeName,
		podServiceAccount: req.ServiceAccount,
		verificationMode:  string(globalMode),
	}

	if !state.config.Enabled() {
		return skipResult(ctx, state, req, globalMode, reasonVerificationDisabled, info), nil
	}

	if _, ok := state.allowlistDigests[digest]; ok {
		state.metrics.VerificationSkippedTotal.WithLabelValues("allowlisted", namespace).Inc()

		return skipResult(ctx, state, req, globalMode, "image digest is allowlisted", info), nil
	}

	slog.DebugContext(ctx, "Verifying image",
		"image", imageRef, "digest", digest, "namespace", namespace)

	pol := policyForNamespace(state.policies, namespace)
	if pol == nil {
		result, err := handleMissingPolicy(ctx, state.config, imageRef, namespace)
		logResult(ctx, state.auditLogger, imageRef, digest, namespace, result, info)
		recordMetrics(state.metrics, result, namespace)

		return result, err
	}

	info.policyHash = policyHashForNamespace(state.policyHashes, namespace)
	namespaceMode := pol.EffectiveMode(globalMode)

	if !isIncluded(ctx, pol.Include, imageRef) {
		state.metrics.VerificationSkippedTotal.WithLabelValues("not_included", namespace).Inc()

		return skipResult(ctx, state, req, namespaceMode, reasonNotIncluded, info), nil
	}

	if isExcluded(ctx, pol.Exclude, imageRef) {
		state.metrics.VerificationSkippedTotal.WithLabelValues("excluded", namespace).Inc()

		return skipResult(ctx, state, req, namespaceMode, reasonExcluded, info), nil
	}

	// The caller skipped digest resolution because an earlier snapshot did
	// not require verification. Ask for the digest instead of verifying
	// without one.
	if digest == "" {
		return nil, fmt.Errorf("%w: %s", types.ErrDigestRequired, imageRef)
	}

	resolvedPol, ruleIdx := ResolveImagePolicy(ctx, pol, imageRef)
	effectiveMode := resolvedPol.EffectiveMode(globalMode)

	info.verificationMode = string(effectiveMode)

	cacheNS := cacheNamespaceKey(namespace, imageRef, ruleIdx)

	result, err := v.handleCacheHit(
		ctx, state, effectiveMode, imageRef, digest, namespace, cacheNS, info,
	)
	if result != nil || err != nil {
		return result, err
	}

	result, err = v.verifyOnce(ctx, state, resolvedPol, effectiveMode, req, cacheNS, info)
	if err != nil {
		return handleVerifyError(ctx, state, effectiveMode, imageRef, digest, namespace, err, info)
	}

	return applyEnforcement(ctx, effectiveMode, result, imageRef)
}

func (v *Verifier) stop(done <-chan struct{}) {
	v.stopPoller()

	if !v.flights.wait(done, true) {
		slog.Warn("Stopping verifier while verifications are still in flight")
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	snap := v.state.Load()
	snap.cache.Stop()
	closeAuditLogFile(snap.auditLogFile)

	if snap.guacClient != nil {
		snap.guacClient.Close()
	}
}

// skipResult builds the result for an image that is admitted without
// verification (disabled, allowlisted, excluded, not included).
func skipResult(
	ctx context.Context, state *snapshot, req *types.VerifyRequest,
	mode config.VerificationMode, reason string, info *auditInfo,
) *types.Result {
	result := allowResult(
		ctx, state.auditLogger, req.ImageRef, req.Digest, req.Namespace, reason, info,
	)
	result.Verified = true
	result.Mode = string(mode)

	return result
}

// cacheNamespaceKey builds the namespace part of the result cache key. Results
// depend on the image reference (CEL image variables, Notation registry
// scopes, VEX product matching, VSA resource binding) and on the policy rule
// that matched, so both are part of the key. Cache.DeleteAll(digest,
// namespace) removes every key built for a namespace.
func cacheNamespaceKey(namespace, imageRef string, ruleIdx int) string {
	key := namespace + "\x00" + imageRef
	if ruleIdx < 0 {
		return key
	}

	return key + "\x00r" + strconv.Itoa(ruleIdx)
}

func handleVerifyError(
	ctx context.Context, state *snapshot,
	mode config.VerificationMode,
	imageRef, digest, namespace string, err error,
	info *auditInfo,
) (*types.Result, error) {
	state.metrics.VerificationInterruptedTotal.Inc()

	if mode != config.ModeEnforce {
		slog.WarnContext(
			ctx, "Verification error (non-enforce mode, allowing)",
			"image", imageRef,
			"mode", mode,
			"error", err,
		)

		result := allowResult(
			ctx, state.auditLogger, imageRef, digest,
			namespace, fmt.Sprintf("verification error: %s", err), info,
		)
		result.Verified = false
		result.Mode = string(mode)
		//nolint:exhaustruct_v5 // zero-value fields intentional
		result.CheckResults = append(result.CheckResults, types.CheckResult{
			Type:   types.CheckTypeInternal,
			Passed: true,
			Status: types.StatusWarn,
			Detail: fmt.Sprintf("verification error (allowed in %s mode): %s", mode, err),
		})

		return result, nil
	}

	return nil, fmt.Errorf("verification: %w", err)
}

func (v *Verifier) handleCacheHit(
	ctx context.Context, state *snapshot,
	mode config.VerificationMode,
	imageRef, digest, namespace, cacheNS string,
	info *auditInfo,
) (*types.Result, error) {
	cached := state.cache.Get(digest, cacheNS)
	if cached == nil {
		state.metrics.CacheMissesTotal.Inc()

		return nil, nil //nolint:nilnil // nil,nil signals cache miss to the caller
	}

	state.metrics.CacheHitsTotal.Inc()

	if resultShouldUseShorterTTL(cached) {
		state.metrics.CacheFailureHitsTotal.Inc()
	}

	result := cached.Clone()

	logResult(ctx, state.auditLogger, imageRef, digest, namespace, &result, info)
	recordMetrics(state.metrics, &result, namespace)

	return applyEnforcement(ctx, mode, &result, imageRef)
}

// verifyOnce runs the checks for a cache miss, deduplicating concurrent
// requests for the same image, namespace, rule and snapshot generation. The
// verification continues in the background when ctx is done first (e.g. the
// admission deadline expired) so its result still fills the cache.
func (v *Verifier) verifyOnce(
	ctx context.Context, state *snapshot, pol *policy.Policy,
	mode config.VerificationMode, req *types.VerifyRequest, cacheNS string,
	info *auditInfo,
) (*types.Result, error) {
	flightKey := strconv.FormatUint(state.generation, 10) + "\x00" + req.Digest + "\x00" + cacheNS

	err := v.checkJoinable(ctx, state, flightKey)
	if err != nil {
		return nil, err
	}

	flightCh := v.inflight.DoChan(flightKey, func() (any, error) {
		if !v.flights.begin() {
			return nil, ErrVerifierStopped
		}
		defer v.flights.end()

		v.flightStarts.Store(flightKey, time.Now())
		defer v.flightStarts.Delete(flightKey)

		if cached := state.cache.Get(req.Digest, cacheNS); cached != nil {
			return cached, nil
		}

		// Use context.WithoutCancel so the verification completes even if
		// the triggering request is cancelled. Other waiters on DoChan
		// should not inherit this caller's cancellation. A hard timeout
		// bounds resource usage when a registry is unresponsive.
		checkCtx, checkCancel := context.WithTimeout(
			context.WithoutCancel(ctx), state.config.VerificationTimeout.Duration,
		)
		defer checkCancel()

		result, cacheTTL := runChecks(checkCtx, state, pol, mode, req)

		if cacheTTL > 0 {
			state.cache.SetWithTTL(req.Digest, cacheNS, result, cacheTTL)
		}

		return result, nil
	})

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("verification interrupted: %w", ctx.Err())
	case res := <-flightCh:
		return handleFlightResult(ctx, state, res, req.ImageRef, req.Digest, req.Namespace, info)
	}
}

// checkJoinable fails fast when an admission would join a verification that
// has already run for longer than the admission timeout. Waiting for it
// would likely consume the whole admission budget, and the runtime holds a
// node-wide lock while a plugin handles CreateContainer. The running
// verification keeps filling the cache for later attempts. Requests that are
// not bound by an admission deadline (CLI, pre-warming, re-verification)
// always join.
func (v *Verifier) checkJoinable(ctx context.Context, state *snapshot, flightKey string) error {
	budget := state.config.AdmissionTimeout.Duration
	if budget <= 0 {
		return nil
	}

	deadline, bounded := ctx.Deadline()
	if !bounded || time.Until(deadline) > budget {
		return nil
	}

	value, running := v.flightStarts.Load(flightKey)
	if !running {
		return nil
	}

	started, ok := value.(time.Time)
	if !ok {
		return nil
	}

	if age := time.Since(started); age >= budget {
		return fmt.Errorf("%w for %s", ErrVerificationInProgress, age.Round(time.Millisecond))
	}

	return nil
}

func handleFlightResult(
	ctx context.Context, state *snapshot,
	res singleflight.Result,
	imageRef, digest, namespace string,
	info *auditInfo,
) (*types.Result, error) {
	if res.Shared {
		state.metrics.InflightDedupTotal.Inc()
	}

	if res.Err != nil {
		return nil, fmt.Errorf("inflight verification: %w", res.Err)
	}

	shared, ok := res.Val.(*types.Result)
	if !ok {
		return nil, fmt.Errorf("%w: %T", errUnexpectedVerifyResult, res.Val)
	}

	result := shared.Clone()

	logResult(ctx, state.auditLogger, imageRef, digest, namespace, &result, info)
	recordMetrics(state.metrics, &result, namespace)

	return &result, nil
}

func (v *Verifier) snap() *snapshot {
	return v.state.Load()
}

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
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/semaphore"
	"golang.org/x/sync/singleflight"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/cache"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/glob"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/registry"
	"github.com/saschagrunert/nri-supply-chain/internal/slsa"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

var (
	// ErrVerificationFailed is returned when supply chain verification fails in enforce mode.
	ErrVerificationFailed = errors.New("supply chain verification failed")

	// ErrCircuitBreakerOpen is returned when the circuit breaker is open.
	ErrCircuitBreakerOpen = errors.New("circuit breaker open for image")

	errUnexpectedVerifyResult = errors.New("verifier: unexpected singleflight result type")
)

const (
	maxConcurrentFetches        = 50
	maxConcurrentFetchesPerHost = 10
	warmTimeout                 = 30 * time.Second
	maxVerificationTimeout      = 5 * time.Minute
)

type snapshot struct {
	config          *config.Config
	policies        map[string]*policy.Policy
	cache           *cache.Cache
	metrics         *metrics.Metrics
	fetcher         attestation.Fetcher
	circuitBreakers *attestation.CircuitBreakerRegistry
	fetchSem        *semaphore.Weighted
	hostSem         *hostSemMap
	auditLogger     *slog.Logger
}

// Verifier performs supply chain attestation verification on container images.
type Verifier struct {
	state atomic.Pointer[snapshot]

	mu           sync.Mutex // serializes Reload; policyHashes is only accessed under mu
	policyHashes map[string]string
	inflight     singleflight.Group
	inflightWg   sync.WaitGroup
	poller       *policy.Poller
}

// NewFetcher creates a new OCI fetcher configured from cfg and pre-warms the
// Sigstore trusted root. The context bounds the warm-up; pass the application
// context so startup can be cancelled. Tests that need the "no fetcher"
// code path should pass nil to New directly.
func NewFetcher(
	ctx context.Context, cfg *config.Config, transportCache *registry.TransportCache,
) (*attestation.OCIFetcher, error) {
	return createAndWarmFetcher(ctx, cfg, transportCache)
}

// New creates a new Verifier with the given configuration, metrics, and attestation fetcher.
// The context is used for the OCI policy poller background goroutine when
// policy source is "oci".
func New(
	ctx context.Context,
	cfg *config.Config, met *metrics.Metrics, fetcher attestation.Fetcher,
) (*Verifier, error) {
	cfgCopy := *cfg

	if ociFetcher, ok := fetcher.(*attestation.OCIFetcher); ok && ociFetcher != nil {
		ociFetcher.SetStaleRootCallback(met.TrustedRootStaleTotal.Inc)
		ociFetcher.SetMirrorFallbackCallback(func(registryHost string) {
			met.MirrorFallbackTotal.WithLabelValues(registryHost, "attestation").Inc()
		})
	}

	policies, hashes, ociDigest, err := loadAndHashPolicies(ctx, &cfgCopy, fetcher)
	if err != nil {
		return nil, err
	}

	if cfgCopy.Enabled() {
		err = validatePoliciesModes(cfgCopy.Verification, policies)
		if err != nil {
			return nil, err
		}

		WarnEnforceDefaults(&cfgCopy, policies)
	}

	snap := newSnapshot(&cfgCopy, policies, met, fetcher)

	verif := &Verifier{
		state:        atomic.Pointer[snapshot]{},
		mu:           sync.Mutex{},
		policyHashes: hashes,
		inflight:     singleflight.Group{},
		inflightWg:   sync.WaitGroup{},
		poller:       nil,
	}
	verif.state.Store(snap)

	if cfgCopy.Policy.Source == config.PolicySourceOCI {
		verif.startPoller(ctx, &cfgCopy, fetcher, ociDigest)
	}

	return verif, nil
}

func newSnapshot(
	cfg *config.Config,
	policies map[string]*policy.Policy,
	met *metrics.Metrics,
	fetcher attestation.Fetcher,
) *snapshot {
	return &snapshot{
		config:   cfg,
		policies: policies,
		cache: cache.NewWithGauge(
			cfg.CacheTTL.Duration,
			met.CacheEntriesTotal, met.CacheEvictionsTotal,
		),
		metrics: met,
		fetcher: fetcher,
		circuitBreakers: attestation.NewCircuitBreakerRegistry(
			cfg.CircuitBreakerThreshold,
			cfg.CircuitBreakerCooldown.Duration,
		),
		fetchSem:    semaphore.NewWeighted(maxConcurrentFetches),
		hostSem:     &hostSemMap{m: sync.Map{}, count: atomic.Int64{}},
		auditLogger: slog.Default(),
	}
}

// WarnEnforceDefaults logs warnings when enforce mode is used with
// permissive settings that may allow unverified containers through.
func WarnEnforceDefaults(cfg *config.Config, policies map[string]*policy.Policy) {
	if anyEnforceMode(cfg.Verification, policies) {
		warnPermissiveFetchPolicy(cfg)
	}

	for namespace, pol := range policies {
		effectiveMode := pol.EffectiveMode(cfg.Verification)
		if effectiveMode != config.ModeEnforce {
			continue
		}

		label := namespace
		if label == "" {
			label = policy.DefaultPolicyLabel
		}

		warnPermissiveMissingPolicies(label, pol)
	}
}

func anyEnforceMode(
	global config.VerificationMode, policies map[string]*policy.Policy,
) bool {
	if global == config.ModeEnforce {
		return true
	}

	for _, pol := range policies {
		if pol.EffectiveMode(global) == config.ModeEnforce {
			return true
		}
	}

	return false
}

func warnPermissiveFetchPolicy(cfg *config.Config) {
	switch cfg.FetchFailurePolicy {
	case types.ActionDeny:
	case types.ActionWarn, types.ActionAllow:
		slog.Warn(
			"enforce mode with permissive fetch_failure_policy allows containers on fetch failure",
			"fetch_failure_policy",
			cfg.FetchFailurePolicy,
			"circuit_breaker_threshold",
			cfg.CircuitBreakerThreshold,
		)
	}
}

func warnPermissiveMissingPolicies(label string, pol *policy.Policy) {
	if pol.SLSAMissingPolicy() == types.ActionAllow {
		slog.Warn("enforce mode with default SLSA missing_policy=allow allows "+
			"containers without SLSA provenance attestations; consider setting missingPolicy=deny",
			"policy", label,
			"slsa_missing_policy", pol.SLSAMissingPolicy(),
		)
	}

	if pol.VEXMissingPolicy() == types.ActionAllow {
		slog.Warn("enforce mode with default VEX missing_policy=allow allows "+
			"containers without VEX attestations; consider setting vex.missingPolicy=deny",
			"policy", label,
			"vex_missing_policy", pol.VEXMissingPolicy(),
		)
	}

	if pol.Notation != nil && pol.NotationMissingPolicy() == types.ActionAllow {
		slog.Warn("enforce mode with default Notation missing_policy=allow allows "+
			"containers without Notation signatures; consider setting notation.missingPolicy=deny",
			"policy", label,
			"notation_missing_policy", pol.NotationMissingPolicy(),
		)
	}

	if pol.SBOM != nil && pol.SBOMMissingPolicy() == types.ActionAllow {
		slog.Warn("enforce mode with default SBOM missing_policy=allow allows "+
			"containers without SBOM attestations; consider setting sbom.missingPolicy=deny",
			"policy", label,
			"sbom_missing_policy", pol.SBOMMissingPolicy(),
		)
	}

	if pol.VSA != nil && pol.VSAMissingPolicy() == types.ActionAllow {
		slog.Warn("enforce mode with default VSA missing_policy=allow allows "+
			"containers without VSA attestations; consider setting vsa.missingPolicy=deny",
			"policy", label,
			"vsa_missing_policy", pol.VSAMissingPolicy(),
		)
	}
}

// Stop releases resources held by the verifier, including the cache's
// background eviction goroutine and the OCI policy poller. Waits for
// in-flight singleflight verifications to complete before stopping
// the cache so they can write their results.
func (v *Verifier) Stop() {
	v.stopPoller()

	v.inflightWg.Wait()

	v.mu.Lock()
	defer v.mu.Unlock()

	v.state.Load().cache.Stop()
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

// Ready returns true if the verifier is ready to serve requests.
// When not ready, the second return value describes the reason.
func (v *Verifier) Ready() (ready bool, reason string) {
	state := v.state.Load()

	if state.config == nil {
		return false, "no config loaded"
	}

	if !state.config.Enabled() {
		return true, ""
	}

	if len(state.policies) == 0 {
		return false, "no policies loaded"
	}

	return true, ""
}

// TransportCache returns the transport cache from the current fetcher, or nil
// if verification is disabled or the fetcher has no cache.
func (v *Verifier) TransportCache() *registry.TransportCache {
	state := v.state.Load()
	if ociFetcher, ok := state.fetcher.(*attestation.OCIFetcher); ok {
		return ociFetcher.TransportCache()
	}

	return nil
}

// Verify performs supply chain verification for the given image. When the image
// was resolved from a manifest list, indexDigest should be the manifest list
// digest so attestation lookup can find cosign-attached attestations. Pass ""
// when the image is not a manifest list or the index digest is unknown.
func (v *Verifier) Verify(
	ctx context.Context, imageRef, digest, indexDigest, namespace string,
) (*types.Result, error) {
	state := v.snap()

	if !state.config.Enabled() {
		return allowResult(
			ctx, state.auditLogger, imageRef, digest,
			namespace, "verification disabled",
		), nil
	}

	slog.DebugContext(ctx, "Verifying image",
		"image", imageRef, "digest", digest, "namespace", namespace)
	pol := policyForNamespace(state.policies, namespace)

	if pol == nil {
		result, err := handleMissingPolicy(ctx, state.config, imageRef, namespace)
		if result != nil {
			logResult(ctx, state.auditLogger, imageRef, digest, namespace, result)
			recordMetrics(state.metrics, result, namespace)
		}

		return result, err
	}

	if !isIncluded(ctx, pol.Include, imageRef) {
		state.metrics.VerificationSkippedTotal.WithLabelValues("not_included", namespace).Inc()

		return allowResult(
			ctx, state.auditLogger, imageRef, digest,
			namespace, "image is not included",
		), nil
	}

	if isExcluded(ctx, pol.Exclude, imageRef) {
		state.metrics.VerificationSkippedTotal.WithLabelValues("excluded", namespace).Inc()

		return allowResult(
			ctx, state.auditLogger, imageRef, digest,
			namespace, "image is excluded",
		), nil
	}

	resolvedPol, ruleIdx := resolveImagePolicy(ctx, pol, imageRef)
	cacheNS := cacheNamespaceKey(namespace, ruleIdx)
	effectiveMode := resolvedPol.EffectiveMode(state.config.Verification)

	result, err := v.handleCacheHit(ctx, state, effectiveMode, imageRef, digest, namespace, cacheNS)
	if result != nil || err != nil {
		return result, err
	}

	result, err = v.verifyOnce(
		ctx, state, resolvedPol, imageRef, digest, indexDigest, namespace, cacheNS,
	)
	if err != nil {
		return handleVerifyError(ctx, state, effectiveMode, imageRef, digest, namespace, err)
	}

	return applyEnforcement(ctx, effectiveMode, result, imageRef)
}

func cacheNamespaceKey(namespace string, ruleIdx int) string {
	if ruleIdx < 0 {
		return namespace
	}

	return namespace + "\x00r" + strconv.Itoa(ruleIdx)
}

func handleVerifyError(
	ctx context.Context, state *snapshot,
	mode config.VerificationMode,
	imageRef, digest, namespace string, err error,
) (*types.Result, error) {
	if mode != config.ModeEnforce {
		slog.WarnContext(ctx, "Verification error (non-enforce mode, allowing)",
			"image", imageRef,
			"mode", mode,
			"error", err,
		)

		return allowResult(
			ctx, state.auditLogger, imageRef, digest,
			namespace, fmt.Sprintf("verification error: %s", err),
		), nil
	}

	return nil, fmt.Errorf("verification: %w", err)
}

// Reload reloads the verifier's configuration and policies.
func (v *Verifier) Reload(ctx context.Context, cfg *config.Config) error {
	cfgCopy := *cfg

	prev := v.state.Load()

	policies, newHashes, ociDigest, err := loadAndHashPolicies(ctx, &cfgCopy, prev.fetcher)
	if err != nil {
		return err
	}

	newFetcher, err := v.prepareFetcher(ctx, &cfgCopy)
	if err != nil {
		return err
	}

	if cfgCopy.Enabled() {
		err = validatePoliciesModes(cfgCopy.Verification, policies)
		if err != nil {
			return err
		}
	}

	// Stop the old poller before acquiring mu to avoid deadlock: the
	// poller callback (onPolicyUpdate) acquires mu, so stopping under
	// mu would deadlock if the callback is in progress.
	v.stopPoller()

	v.mu.Lock()
	defer v.mu.Unlock()

	// Re-read after lock to use the latest snapshot (onPolicyUpdate may have run).
	current := v.state.Load()

	fetcher := v.applyReload(ctx, current, &cfgCopy, policies, newHashes, newFetcher)

	// Start new poller if source is OCI (old poller already stopped above).
	if cfgCopy.Policy.Source == config.PolicySourceOCI {
		v.startPoller(ctx, &cfgCopy, fetcher, ociDigest)
	}

	if cfgCopy.Enabled() {
		WarnEnforceDefaults(&cfgCopy, policies)
	}

	return nil
}

func (v *Verifier) applyReload( //nolint:ireturn // returns attestation.Fetcher interface
	ctx context.Context,
	current *snapshot,
	cfgCopy *config.Config,
	policies map[string]*policy.Policy,
	newHashes map[string]string,
	newFetcher *attestation.OCIFetcher,
) attestation.Fetcher {
	policiesChanged := !policyHashesEqual(v.policyHashes, newHashes)
	cacheInvalidated := cacheAffectingFieldsChanged(current.config, cfgCopy) || policiesChanged
	newCache := reloadCache(current, cfgCopy, cacheInvalidated)

	logReloadChanges(ctx, current.config, cfgCopy, v.policyHashes, newHashes, cacheInvalidated)
	circuitBreakers := v.reloadCircuitBreakers(current, cfgCopy)
	fetcher := v.reloadFetcher(current, cfgCopy, newFetcher)
	closeOldTransportCache(current, newFetcher)

	hostSem := resetCachesIfChanged(current.hostSem, policiesChanged)

	v.state.Store(&snapshot{
		config:          cfgCopy,
		policies:        policies,
		cache:           newCache,
		metrics:         current.metrics,
		fetcher:         fetcher,
		circuitBreakers: circuitBreakers,
		fetchSem:        current.fetchSem,
		hostSem:         hostSem,
		auditLogger:     current.auditLogger,
	})
	v.policyHashes = newHashes

	return fetcher
}

// stopPoller reads and nil-outs v.poller under v.mu, then stops the
// poller outside the lock. Acquiring and releasing the lock internally
// avoids a data race with Reload (which writes v.poller under v.mu)
// and avoids deadlock (the poller callback acquires v.mu, so Stop must
// not hold it).
func (v *Verifier) stopPoller() {
	v.mu.Lock()
	p := v.poller
	v.poller = nil
	v.mu.Unlock()

	if p != nil {
		p.Stop()
	}
}

func resetCachesIfChanged(prevHostSem *hostSemMap, policiesChanged bool) *hostSemMap {
	if !policiesChanged {
		return prevHostSem
	}

	attestation.ResetSANPatternWarnings()
	slsa.ResetWarnings()
	glob.ResetCache()

	return &hostSemMap{m: sync.Map{}, count: atomic.Int64{}}
}

func (v *Verifier) handleCacheHit(
	ctx context.Context, state *snapshot,
	mode config.VerificationMode,
	imageRef, digest, namespace, cacheNS string,
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

	logResult(ctx, state.auditLogger, imageRef, digest, namespace, &result)
	recordMetrics(state.metrics, &result, namespace)

	return applyEnforcement(ctx, mode, &result, imageRef)
}

func reloadCache(prev *snapshot, cfg *config.Config, invalidated bool) *cache.Cache {
	if !invalidated {
		return prev.cache
	}

	prev.cache.Stop()

	return cache.NewWithGauge(
		cfg.CacheTTL.Duration,
		prev.metrics.CacheEntriesTotal, prev.metrics.CacheEvictionsTotal,
	)
}

// reloadCircuitBreakers returns the existing circuit breaker registry if settings
// are unchanged, or creates a new one. Preserving the registry across reloads
// prevents a burst of retries to failing registries.
func (v *Verifier) reloadCircuitBreakers(
	prev *snapshot, cfg *config.Config,
) *attestation.CircuitBreakerRegistry {
	if prev.circuitBreakers != nil &&
		prev.config.CircuitBreakerThreshold == cfg.CircuitBreakerThreshold &&
		prev.config.CircuitBreakerCooldown.Duration == cfg.CircuitBreakerCooldown.Duration {
		return prev.circuitBreakers
	}

	return attestation.NewCircuitBreakerRegistry(
		cfg.CircuitBreakerThreshold,
		cfg.CircuitBreakerCooldown.Duration,
	)
}

// prepareFetcher creates a new fetcher outside the lock when one is needed
// (first enable or TUF config change). Returns (nil, nil) when the existing
// fetcher can be reused.
func (v *Verifier) prepareFetcher(
	ctx context.Context, cfg *config.Config,
) (*attestation.OCIFetcher, error) {
	if !cfg.Enabled() {
		return nil, nil //nolint:nilnil // nil fetcher means reuse existing
	}

	prev := v.state.Load()

	if prev.fetcher != nil &&
		prev.config.Sigstore.TUFMirror == cfg.Sigstore.TUFMirror &&
		prev.config.Sigstore.TUFRoot == cfg.Sigstore.TUFRoot {
		return nil, nil //nolint:nilnil // no config change, reuse existing
	}

	// nil cache: the fetcher will build its own from cfg.Registries if needed.
	return createAndWarmFetcher(ctx, cfg, nil)
}

func closeOldTransportCache(prev *snapshot, newFetcher *attestation.OCIFetcher) {
	if newFetcher == nil {
		return
	}

	old, ok := prev.fetcher.(*attestation.OCIFetcher)
	if !ok {
		return
	}

	if tc := old.TransportCache(); tc != nil {
		tc.CloseIdleConnections()
	}
}

// reloadFetcher returns the fetcher to use for the new snapshot. If a new
// fetcher was pre-created, it is configured and returned; otherwise the existing
// fetcher is updated with the new rate limit and registries.
func (v *Verifier) reloadFetcher( //nolint:ireturn // returns prev.fetcher which is the Fetcher interface
	prev *snapshot,
	cfg *config.Config,
	newFetcher *attestation.OCIFetcher,
) attestation.Fetcher {
	if !cfg.Enabled() {
		return prev.fetcher
	}

	if newFetcher != nil {
		newFetcher.SetStaleRootCallback(prev.metrics.TrustedRootStaleTotal.Inc)
		newFetcher.SetMirrorFallbackCallback(func(registryHost string) {
			prev.metrics.MirrorFallbackTotal.WithLabelValues(registryHost, "attestation").Inc()
		})

		return newFetcher
	}

	if ociFetcher, ok := prev.fetcher.(*attestation.OCIFetcher); ok {
		ociFetcher.SetRateLimit(cfg.FetchRateLimit)

		if config.RegistriesChanged(prev.config.Registries, cfg.Registries) {
			ociFetcher.SetTransportCache(registry.NewTransportCacheOrNil(cfg.Registries))
		}
	}

	return prev.fetcher
}

func loadAndHashPolicies(
	ctx context.Context,
	cfg *config.Config,
	fetcher attestation.Fetcher,
) (policies map[string]*policy.Policy, hashes map[string]string, ociDigest string, err error) {
	if cfg.Enabled() {
		policies, ociDigest, err = loadPoliciesFromSource(ctx, cfg, fetcher)
		if err != nil {
			return nil, nil, "", err
		}

		err = validatePoliciesRuntime(policies)
		if err != nil {
			return nil, nil, "", err
		}
	}

	hashes, err = hashPolicies(policies)
	if err != nil {
		return nil, nil, "", err
	}

	return policies, hashes, ociDigest, nil
}

func loadPoliciesFromSource(
	ctx context.Context, cfg *config.Config, fetcher attestation.Fetcher,
) (policies map[string]*policy.Policy, ociDigest string, err error) {
	if cfg.Policy.Source != config.PolicySourceOCI {
		policies, err = policy.LoadAll(cfg.PolicyDir)
		if err != nil {
			return nil, "", fmt.Errorf("loading policies: %w", err)
		}

		return policies, "", nil
	}

	policyFetcher := policy.NewOCIFetcher(transportCacheFromFetcher(fetcher))

	result, err := policyFetcher.FetchFromOCI(ctx, cfg.Policy.OCIRef)
	if err != nil {
		return nil, "", fmt.Errorf("loading OCI policies: %w", err)
	}

	slog.Info("Loaded policies from OCI artifact",
		"oci_ref", cfg.Policy.OCIRef,
		"digest", result.Digest,
		"count", len(result.Policies),
	)

	return result.Policies, result.Digest, nil
}

func transportCacheFromFetcher(fetcher attestation.Fetcher) *registry.TransportCache {
	if ociFetcher, ok := fetcher.(*attestation.OCIFetcher); ok && ociFetcher != nil {
		return ociFetcher.TransportCache()
	}

	return nil
}

func (v *Verifier) startPoller(
	ctx context.Context,
	cfg *config.Config,
	fetcher attestation.Fetcher,
	ociDigest string,
) {
	policyFetcher := policy.NewOCIFetcher(transportCacheFromFetcher(fetcher))

	pollerInstance := policy.NewPoller(
		policyFetcher,
		cfg.Policy.OCIRef,
		cfg.Policy.PollInterval.Duration,
		func(policies map[string]*policy.Policy) error {
			return v.onPolicyUpdate(policies)
		},
	)

	pollerInstance.SetCachedDigest(ociDigest)
	pollerInstance.Start(ctx)

	v.poller = pollerInstance
}

func (v *Verifier) onPolicyUpdate(policies map[string]*policy.Policy) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	state := v.state.Load()

	newHashes, err := hashPolicies(policies)
	if err != nil {
		return fmt.Errorf("hashing updated OCI policies: %w", err)
	}

	if policyHashesEqual(v.policyHashes, newHashes) {
		return nil
	}

	if state.config.Enabled() {
		err = validatePoliciesModes(state.config.Verification, policies)
		if err != nil {
			return fmt.Errorf("validating updated OCI policies: %w", err)
		}
	}

	err = validatePoliciesRuntime(policies)
	if err != nil {
		return fmt.Errorf("runtime validation of updated OCI policies: %w", err)
	}

	v.applyPolicyUpdate(state, policies, newHashes)

	return nil
}

func (v *Verifier) applyPolicyUpdate(
	state *snapshot, policies map[string]*policy.Policy, newHashes map[string]string,
) {
	state.cache.Stop()

	attestation.ResetSANPatternWarnings()
	slsa.ResetWarnings()
	glob.ResetCache()

	v.state.Store(&snapshot{
		config:   state.config,
		policies: policies,
		cache: cache.NewWithGauge(
			state.config.CacheTTL.Duration,
			state.metrics.CacheEntriesTotal,
			state.metrics.CacheEvictionsTotal,
		),
		metrics:         state.metrics,
		fetcher:         state.fetcher,
		circuitBreakers: state.circuitBreakers,
		fetchSem:        state.fetchSem,
		hostSem:         &hostSemMap{m: sync.Map{}, count: atomic.Int64{}},
		auditLogger:     state.auditLogger,
	})
	v.policyHashes = newHashes

	if state.config.Enabled() {
		WarnEnforceDefaults(state.config, policies)
	}

	slog.Info("OCI policy update applied",
		"policies_count", len(policies),
	)
}

func createAndWarmFetcher(
	ctx context.Context, cfg *config.Config, transportCache *registry.TransportCache,
) (*attestation.OCIFetcher, error) {
	ociFetcher, err := createFetcher(cfg)
	if err != nil {
		return nil, err
	}

	if cfg.FetchRateLimit > 0 {
		ociFetcher.SetRateLimit(cfg.FetchRateLimit)
	}

	if transportCache != nil {
		ociFetcher.SetTransportCache(transportCache)
	} else if len(cfg.Registries) > 0 {
		ociFetcher.SetTransportCache(registry.NewTransportCache(cfg.Registries))
	}

	warmCtx, warmCancel := context.WithTimeout(ctx, warmTimeout)
	defer warmCancel()

	warmErr := ociFetcher.Warm(warmCtx)
	if warmErr != nil {
		slog.Warn(
			"Failed to pre-warm Sigstore trusted root",
			"error", warmErr,
		)
	}

	return ociFetcher, nil
}

func createFetcher(cfg *config.Config) (*attestation.OCIFetcher, error) {
	if cfg.Sigstore.TUFMirror == "" {
		return attestation.NewOCIFetcher(), nil
	}

	tufRootBytes, err := readTUFRootBytes(cfg.Sigstore.TUFRoot)
	if err != nil {
		return nil, err
	}

	return attestation.NewOCIFetcherWithTUFMirror(cfg.Sigstore.TUFMirror, tufRootBytes), nil
}

func readTUFRootBytes(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}

	data, err := os.ReadFile(path) //nolint:gosec // path is validated by config.ValidateRuntime
	if err != nil {
		return nil, fmt.Errorf("reading custom TUF root %q: %w", path, err)
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("%w: %q", config.ErrTUFRootEmpty, path)
	}

	return data, nil
}

func cacheAffectingFieldsChanged(prev, next *config.Config) bool {
	return prev.Verification != next.Verification ||
		prev.PolicyDir != next.PolicyDir ||
		cacheTimingsChanged(prev, next) ||
		prev.FetchFailurePolicy != next.FetchFailurePolicy ||
		prev.Sigstore.TUFMirror != next.Sigstore.TUFMirror ||
		prev.Sigstore.TUFRoot != next.Sigstore.TUFRoot ||
		config.RegistriesChanged(prev.Registries, next.Registries) ||
		policySourceChanged(prev, next)
}

func cacheTimingsChanged(prev, next *config.Config) bool {
	return prev.CacheTTL.Duration != next.CacheTTL.Duration ||
		prev.CacheFailureTTL.Duration != next.CacheFailureTTL.Duration ||
		prev.FetchTimeout.Duration != next.FetchTimeout.Duration
}

func policySourceChanged(prev, next *config.Config) bool {
	return prev.Policy.Source != next.Policy.Source ||
		prev.Policy.OCIRef != next.Policy.OCIRef
}

func (v *Verifier) verifyOnce(
	ctx context.Context, state *snapshot, pol *policy.Policy,
	imageRef, digest, indexDigest, namespace, cacheNS string,
) (*types.Result, error) {
	flightKey := digest + "\x00" + cacheNS

	flightCh := v.inflight.DoChan(flightKey, func() (any, error) {
		// Add(1) is inside the closure so only the executing goroutine
		// (not shared waiters) increments the counter. There is a narrow
		// race where Stop() could call Wait() before the goroutine
		// reaches Add(1), but the consequence is benign: the goroutine
		// writes to a stopped-but-valid cache and completes normally.
		v.inflightWg.Add(1)
		defer v.inflightWg.Done()

		if cached := state.cache.Get(digest, cacheNS); cached != nil {
			return cached, nil
		}

		// Use context.WithoutCancel so the verification completes even if
		// the triggering request is cancelled. Other waiters on DoChan
		// should not inherit this caller's cancellation. A hard timeout
		// bounds resource usage when a registry is unresponsive.
		checkCtx, checkCancel := context.WithTimeout(
			context.WithoutCancel(ctx), maxVerificationTimeout,
		)
		defer checkCancel()

		result := runChecks(checkCtx, state, pol, imageRef, digest, indexDigest, namespace)

		if resultShouldUseShorterTTL(result) && state.config.CacheFailureTTL.Duration > 0 {
			state.cache.SetWithTTL(digest, cacheNS, result, state.config.CacheFailureTTL.Duration)
		} else {
			state.cache.Set(digest, cacheNS, result)
		}

		return result, nil
	})

	select {
	case <-ctx.Done():
		state.metrics.VerificationInterruptedTotal.Inc()

		return nil, fmt.Errorf("verification interrupted: %w", ctx.Err())
	case res := <-flightCh:
		return handleFlightResult(ctx, state, res, imageRef, digest, namespace)
	}
}

func handleFlightResult(
	ctx context.Context, state *snapshot,
	res singleflight.Result,
	imageRef, digest, namespace string,
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

	logResult(ctx, state.auditLogger, imageRef, digest, namespace, &result)
	recordMetrics(state.metrics, &result, namespace)

	return &result, nil
}

func (v *Verifier) snap() *snapshot {
	return v.state.Load()
}

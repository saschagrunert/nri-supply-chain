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

	// DefaultPolicyLabel is the display label used for the default (namespace-less) policy.
	DefaultPolicyLabel = "default"
)

type snapshot struct {
	config          *config.Config
	policies        map[string]*policy.Policy
	cache           *cache.Cache
	metrics         *metrics.Metrics
	fetcher         attestation.Fetcher
	circuitBreakers *attestation.CircuitBreakerRegistry
	fetchSem        *semaphore.Weighted
	hostSem         *sync.Map
	auditLogger     *slog.Logger
}

// Verifier performs supply chain attestation verification on container images.
type Verifier struct {
	state atomic.Pointer[snapshot]

	mu           sync.Mutex // serializes Reload; policyHashes is only accessed under mu
	policyHashes map[string]string
	inflight     singleflight.Group
	inflightWg   sync.WaitGroup
}

// NewFetcher creates a new OCI fetcher configured from cfg and pre-warms the
// Sigstore trusted root. The context bounds the warm-up; pass the application
// context so startup can be cancelled. Tests that need the "no fetcher"
// code path should pass nil to New directly.
func NewFetcher(ctx context.Context, cfg *config.Config) *attestation.OCIFetcher {
	return createAndWarmFetcher(ctx, cfg)
}

// New creates a new Verifier with the given configuration, metrics, and attestation fetcher.
func New(cfg *config.Config, met *metrics.Metrics, fetcher attestation.Fetcher) (*Verifier, error) {
	cfgCopy := *cfg

	if ociFetcher, ok := fetcher.(*attestation.OCIFetcher); ok && ociFetcher != nil {
		ociFetcher.SetStaleRootCallback(met.TrustedRootStaleTotal.Inc)
	}

	policies, hashes, err := loadAndHashPolicies(&cfgCopy)
	if err != nil {
		return nil, err
	}

	if cfgCopy.Enabled() {
		err = validatePoliciesEnforce(cfgCopy.Verification, policies)
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
	}
	verif.state.Store(snap)

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
		hostSem:     &sync.Map{},
		auditLogger: slog.Default(),
	}
}

// WarnEnforceDefaults logs warnings when enforce mode is used with
// permissive settings that may allow unverified containers through.
func WarnEnforceDefaults(cfg *config.Config, policies map[string]*policy.Policy) {
	if cfg.Verification != config.ModeEnforce {
		return
	}

	switch cfg.FetchFailurePolicy {
	case types.ActionDeny:
	case types.ActionWarn:
		slog.Warn(
			"enforce mode with default fetch_failure_policy=warn allows containers on fetch failure; "+
				"consider setting fetch_failure_policy=deny",
			"fetch_failure_policy",
			cfg.FetchFailurePolicy,
			"circuit_breaker_threshold",
			cfg.CircuitBreakerThreshold,
		)
	case types.ActionAllow:
		slog.Warn(
			"enforce mode with fetch_failure_policy=allow allows containers on fetch failure; "+
				"consider setting fetch_failure_policy=deny",
			"fetch_failure_policy",
			cfg.FetchFailurePolicy,
			"circuit_breaker_threshold",
			cfg.CircuitBreakerThreshold,
		)
	}

	for ns, pol := range policies {
		label := ns
		if label == "" {
			label = DefaultPolicyLabel
		}

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
	}
}

// Stop releases resources held by the verifier, including the cache's
// background eviction goroutine. Waits for in-flight singleflight
// verifications to complete before stopping the cache so they can
// write their results. Acquires mu to serialize with Reload.
func (v *Verifier) Stop() {
	v.inflightWg.Wait()

	v.mu.Lock()
	defer v.mu.Unlock()

	v.state.Load().cache.Stop()
}

// Enforcing returns true if the verifier is in enforce mode.
func (v *Verifier) Enforcing() bool {
	return v.state.Load().config.Verification == config.ModeEnforce
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

	if isExcluded(ctx, pol.Exclude, imageRef) {
		state.metrics.VerificationSkippedTotal.WithLabelValues("excluded", namespace).Inc()

		return allowResult(
			ctx, state.auditLogger, imageRef, digest,
			namespace, "image is excluded",
		), nil
	}

	result, err := v.handleCacheHit(ctx, state, imageRef, digest, namespace)
	if result != nil || err != nil {
		return result, err
	}

	result, err = v.verifyOnce(ctx, state, pol, imageRef, digest, indexDigest, namespace)
	if err != nil {
		return handleVerifyError(ctx, state, imageRef, digest, namespace, err)
	}

	return applyEnforcement(ctx, state.config, result, imageRef)
}

func handleVerifyError(
	ctx context.Context, state *snapshot,
	imageRef, digest, namespace string, err error,
) (*types.Result, error) {
	if state.config.Verification != config.ModeEnforce {
		slog.WarnContext(ctx, "Verification error (warn mode, allowing)",
			"image", imageRef,
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

	policies, newHashes, err := loadAndHashPolicies(&cfgCopy)
	if err != nil {
		return err
	}

	newFetcher := v.prepareFetcher(ctx, &cfgCopy)

	v.mu.Lock()
	defer v.mu.Unlock()

	err = validatePoliciesEnforce(cfgCopy.Verification, policies)
	if err != nil {
		return err
	}

	prev := v.state.Load()
	policiesChanged := !policyHashesEqual(v.policyHashes, newHashes)
	cacheInvalidated := cacheAffectingFieldsChanged(prev.config, &cfgCopy) || policiesChanged
	newCache := reloadCache(prev, &cfgCopy, cacheInvalidated)

	logReloadChanges(ctx, prev.config, &cfgCopy, v.policyHashes, newHashes, cacheInvalidated)

	circuitBreakers := v.reloadCircuitBreakers(prev, &cfgCopy)
	fetcher := v.reloadFetcher(prev, &cfgCopy, newFetcher)

	hostSem := prev.hostSem

	if policiesChanged {
		attestation.ResetSANPatternWarnings()
		slsa.ResetMaxLevelWarnings()
		glob.ResetCache()

		hostSem = &sync.Map{}
	}

	v.state.Store(&snapshot{
		config:          &cfgCopy,
		policies:        policies,
		cache:           newCache,
		metrics:         prev.metrics,
		fetcher:         fetcher,
		circuitBreakers: circuitBreakers,
		fetchSem:        prev.fetchSem,
		hostSem:         hostSem,
		auditLogger:     prev.auditLogger,
	})
	v.policyHashes = newHashes

	WarnEnforceDefaults(&cfgCopy, policies)

	return nil
}

func (v *Verifier) handleCacheHit(
	ctx context.Context, state *snapshot,
	imageRef, digest, namespace string,
) (*types.Result, error) {
	cached := state.cache.Get(digest, namespace)
	if cached == nil {
		state.metrics.CacheMissesTotal.Inc()

		return nil, nil //nolint:nilnil // nil,nil signals cache miss to the caller
	}

	state.metrics.CacheHitsTotal.Inc()

	if resultShouldUseShorterTTL(cached) {
		state.metrics.CacheFailureHitsTotal.Inc()
	}

	result := *cached
	if len(cached.CheckResults) > 0 {
		result.CheckResults = make([]types.CheckResult, len(cached.CheckResults))
		copy(result.CheckResults, cached.CheckResults)
	}

	logResult(ctx, state.auditLogger, imageRef, digest, namespace, &result)
	recordMetrics(state.metrics, &result, namespace)

	return applyEnforcement(ctx, state.config, &result, imageRef)
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
// (first enable). Returns nil when the existing fetcher can be reused.
func (v *Verifier) prepareFetcher(ctx context.Context, cfg *config.Config) *attestation.OCIFetcher {
	if !cfg.Enabled() {
		return nil
	}

	if v.state.Load().fetcher != nil {
		return nil
	}

	return createAndWarmFetcher(ctx, cfg)
}

// reloadFetcher returns the fetcher to use for the new snapshot. If a new
// fetcher was pre-created, it is configured and returned; otherwise the existing
// fetcher is updated with the new rate limit.
func (v *Verifier) reloadFetcher( //nolint:ireturn // returns prev.fetcher which is the Fetcher interface
	prev *snapshot,
	cfg *config.Config,
	newFetcher *attestation.OCIFetcher,
) attestation.Fetcher {
	if !cfg.Enabled() {
		return prev.fetcher
	}

	if prev.fetcher == nil && newFetcher != nil {
		newFetcher.SetStaleRootCallback(prev.metrics.TrustedRootStaleTotal.Inc)

		return newFetcher
	}

	if ociFetcher, ok := prev.fetcher.(*attestation.OCIFetcher); ok {
		ociFetcher.SetRateLimit(cfg.FetchRateLimit)
	}

	return prev.fetcher
}

func loadAndHashPolicies(
	cfg *config.Config,
) (policies map[string]*policy.Policy, hashes map[string]string, err error) {
	if cfg.Enabled() {
		policies, err = policy.LoadAll(cfg.PolicyDir)
		if err != nil {
			return nil, nil, fmt.Errorf("loading policies: %w", err)
		}

		err = validatePoliciesRuntime(policies)
		if err != nil {
			return nil, nil, err
		}
	}

	hashes, err = hashPolicies(policies)
	if err != nil {
		return nil, nil, err
	}

	return policies, hashes, nil
}

func createAndWarmFetcher(ctx context.Context, cfg *config.Config) *attestation.OCIFetcher {
	ociFetcher := attestation.NewOCIFetcher()

	if cfg.FetchRateLimit > 0 {
		ociFetcher.SetRateLimit(cfg.FetchRateLimit)
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

	return ociFetcher
}

func cacheAffectingFieldsChanged(prev, next *config.Config) bool {
	return prev.Verification != next.Verification ||
		prev.PolicyDir != next.PolicyDir ||
		prev.CacheTTL.Duration != next.CacheTTL.Duration ||
		prev.CacheFailureTTL.Duration != next.CacheFailureTTL.Duration ||
		prev.FetchFailurePolicy != next.FetchFailurePolicy ||
		prev.FetchTimeout.Duration != next.FetchTimeout.Duration
}

func (v *Verifier) verifyOnce(
	ctx context.Context, state *snapshot, pol *policy.Policy,
	imageRef, digest, indexDigest, namespace string,
) (*types.Result, error) {
	flightKey := digest + "\x00" + namespace

	flightCh := v.inflight.DoChan(flightKey, func() (any, error) {
		// Add(1) is inside the closure so only the executing goroutine
		// (not shared waiters) increments the counter. There is a narrow
		// race where Stop() could call Wait() before the goroutine
		// reaches Add(1), but the consequence is benign: the goroutine
		// writes to a stopped-but-valid cache and completes normally.
		v.inflightWg.Add(1)
		defer v.inflightWg.Done()

		if cached := state.cache.Get(digest, namespace); cached != nil {
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
			state.cache.SetWithTTL(digest, namespace, result, state.config.CacheFailureTTL.Duration)
		} else {
			state.cache.Set(digest, namespace, result)
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

	result := *shared
	if len(shared.CheckResults) > 0 {
		result.CheckResults = make([]types.CheckResult, len(shared.CheckResults))
		copy(result.CheckResults, shared.CheckResults)
	}

	logResult(ctx, state.auditLogger, imageRef, digest, namespace, &result)
	recordMetrics(state.metrics, &result, namespace)

	return &result, nil
}

func (v *Verifier) snap() *snapshot {
	return v.state.Load()
}

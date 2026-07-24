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

	errUnexpectedSingleflightResult = errors.New("verifier: unexpected singleflight result type")
)

const (
	maxConcurrentFetches   = 50
	defaultPolicyLabel     = "default"
	warmTimeout            = 30 * time.Second
	maxVerificationTimeout = 5 * time.Minute
)

type snapshot struct {
	config          *config.Config
	policies        map[string]*policy.Policy
	cache           *cache.Cache
	metrics         *metrics.Metrics
	fetcher         attestation.Fetcher
	circuitBreakers *attestation.CircuitBreakerRegistry
	fetchSem        *semaphore.Weighted
	auditLogger     *slog.Logger
}

// Verifier performs supply chain attestation verification on container images.
type Verifier struct {
	snapshot // embedded: fields shared with point-in-time snapshots

	mu           sync.RWMutex
	policyHashes map[string]string
	inflight     singleflight.Group
}

// NewFetcher creates a new OCI fetcher configured from cfg and pre-warms the
// Sigstore trusted root. Use this when the caller wants the verifier to have a
// real fetcher; pass the return value to New. Tests that need the "no fetcher"
// code path should pass nil to New directly.
func NewFetcher(cfg *config.Config) *attestation.OCIFetcher {
	return createAndWarmFetcher(context.Background(), cfg)
}

// New creates a new Verifier with the given configuration, metrics, and attestation fetcher.
func New(cfg *config.Config, met *metrics.Metrics, fetcher attestation.Fetcher) (*Verifier, error) {
	cfgCopy := *cfg

	verif := &Verifier{
		mu: sync.RWMutex{},
		snapshot: snapshot{
			config:   &cfgCopy,
			policies: nil,
			cache: cache.NewWithGauge(
				cfgCopy.CacheTTL.Duration,
				met.CacheEntriesTotal, met.CacheEvictionsTotal,
			),
			metrics: met,
			fetcher: fetcher,
			circuitBreakers: attestation.NewCircuitBreakerRegistry(
				cfgCopy.CircuitBreakerThreshold,
				cfgCopy.CircuitBreakerCooldown.Duration,
			),
			fetchSem:    semaphore.NewWeighted(maxConcurrentFetches),
			auditLogger: slog.Default(),
		},
		policyHashes: nil,
		inflight:     singleflight.Group{},
	}

	if ociFetcher, ok := fetcher.(*attestation.OCIFetcher); ok {
		ociFetcher.SetStaleRootCallback(met.TrustedRootStaleTotal.Inc)
	}

	if cfgCopy.Enabled() {
		policies, err := policy.LoadAll(cfgCopy.PolicyDir)
		if err != nil {
			return nil, fmt.Errorf("loading policies: %w", err)
		}

		err = validatePoliciesRuntime(policies)
		if err != nil {
			return nil, err
		}

		err = validatePoliciesEnforce(cfgCopy.Verification, policies)
		if err != nil {
			return nil, err
		}

		hashes, err := hashPolicies(policies)
		if err != nil {
			return nil, err
		}

		verif.policies = policies
		verif.policyHashes = hashes

		WarnEnforceDefaults(&cfgCopy, policies)
	}

	return verif, nil
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
		)
	}

	for ns, pol := range policies {
		label := ns
		if label == "" {
			label = defaultPolicyLabel
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

// Enforcing returns true if the verifier is in enforce mode.
func (v *Verifier) Enforcing() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()

	return v.config.Verification == config.ModeEnforce
}

// Ready returns true if the verifier is ready to serve requests.
// When not ready, the second return value describes the reason.
func (v *Verifier) Ready() (ready bool, reason string) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.config == nil {
		return false, "no config loaded"
	}

	if !v.config.Enabled() {
		return true, ""
	}

	if len(v.policies) == 0 {
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

	if cached := state.cache.Get(digest, namespace); cached != nil {
		state.metrics.CacheHitsTotal.Inc()

		if resultShouldUseShorterTTL(cached) {
			state.metrics.CacheFailureHitsTotal.Inc()
		}

		logResult(ctx, state.auditLogger, imageRef, digest, namespace, cached)
		recordMetrics(state.metrics, cached, namespace)

		return applyEnforcement(ctx, state.config, cached, imageRef)
	}

	state.metrics.CacheMissesTotal.Inc()

	result, err := v.verifyOnce(ctx, &state, pol, imageRef, digest, indexDigest, namespace)
	if err != nil {
		return nil, fmt.Errorf("verification: %w", err)
	}

	return applyEnforcement(ctx, state.config, result, imageRef)
}

// Reload reloads the verifier's configuration and policies.
func (v *Verifier) Reload(ctx context.Context, cfg *config.Config) error {
	cfgCopy := *cfg

	policies, newHashes, err := loadAndHashPolicies(&cfgCopy)
	if err != nil {
		return err
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	err = validatePoliciesEnforce(cfgCopy.Verification, policies)
	if err != nil {
		return err
	}

	policiesChanged := !policyHashesEqual(v.policyHashes, newHashes)

	cacheInvalidated := cacheAffectingFieldsChanged(v.config, &cfgCopy) || policiesChanged

	if cacheInvalidated {
		v.cache = cache.NewWithGauge(
			cfgCopy.CacheTTL.Duration,
			v.metrics.CacheEntriesTotal, v.metrics.CacheEvictionsTotal,
		)
	}

	logReloadChanges(ctx, v.config, &cfgCopy, v.policyHashes, newHashes, cacheInvalidated)

	v.updateCircuitBreakersLocked(&cfgCopy)
	v.updateFetcherLocked(ctx, &cfgCopy)

	v.config = &cfgCopy
	v.policies = policies
	v.policyHashes = newHashes

	if policiesChanged {
		attestation.ResetSANPatternWarnings()
		slsa.ResetMaxLevelWarnings()
		glob.ResetCache()
	}

	WarnEnforceDefaults(&cfgCopy, policies)

	return nil
}

// updateCircuitBreakersLocked replaces the circuit breaker registry only when
// the threshold or cooldown settings change. Preserving the registry across
// reloads prevents a burst of retries to failing registries after a config
// reload that did not change breaker settings.
func (v *Verifier) updateCircuitBreakersLocked(cfg *config.Config) {
	if v.circuitBreakers != nil &&
		v.config.CircuitBreakerThreshold == cfg.CircuitBreakerThreshold &&
		v.config.CircuitBreakerCooldown.Duration == cfg.CircuitBreakerCooldown.Duration {
		return
	}

	v.circuitBreakers = attestation.NewCircuitBreakerRegistry(
		cfg.CircuitBreakerThreshold,
		cfg.CircuitBreakerCooldown.Duration,
	)
}

func (v *Verifier) updateFetcherLocked(ctx context.Context, cfg *config.Config) {
	if !cfg.Enabled() {
		return
	}

	if v.fetcher == nil {
		fetcher := createAndWarmFetcher(ctx, cfg)
		fetcher.SetStaleRootCallback(v.metrics.TrustedRootStaleTotal.Inc)

		v.fetcher = fetcher
	} else if ociFetcher, ok := v.fetcher.(*attestation.OCIFetcher); ok {
		ociFetcher.SetRateLimit(cfg.FetchRateLimit)
	}
}

func loadAndHashPolicies(
	cfg *config.Config,
) (policies map[string]*policy.Policy, hashes map[string]string, err error) {
	if cfg.Enabled() {
		policies, err = policy.LoadAll(cfg.PolicyDir)
		if err != nil {
			return nil, nil, fmt.Errorf("reloading policies: %w", err)
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

		logResult(checkCtx, state.auditLogger, imageRef, digest, namespace, result)
		recordMetrics(state.metrics, result, namespace)

		if resultShouldUseShorterTTL(result) && state.config.CacheFailureTTL.Duration > 0 {
			state.cache.Set(digest, namespace, result, state.config.CacheFailureTTL.Duration)
		} else {
			state.cache.Set(digest, namespace, result)
		}

		return result, nil
	})

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("verification interrupted: %w", ctx.Err())
	case res := <-flightCh:
		if res.Shared {
			state.metrics.InflightDedupTotal.Inc()
		}

		if res.Err != nil {
			return nil, fmt.Errorf("inflight verification: %w", res.Err)
		}

		shared, ok := res.Val.(*types.Result)
		if !ok {
			return nil, fmt.Errorf("%w: %T", errUnexpectedSingleflightResult, res.Val)
		}

		result := *shared
		if len(shared.CheckResults) > 0 {
			result.CheckResults = make([]types.CheckResult, len(shared.CheckResults))
			copy(result.CheckResults, shared.CheckResults)
		}

		return &result, nil
	}
}

func (v *Verifier) snap() snapshot {
	v.mu.RLock()
	defer v.mu.RUnlock()

	return v.snapshot
}

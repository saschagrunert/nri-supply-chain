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

package verifier

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/cache"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/glob"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/registry"
	"github.com/saschagrunert/nri-supply-chain/internal/slsa"
)

// Reload reloads the verifier's configuration and policies.
func (v *Verifier) Reload(ctx context.Context, cfg *config.Config) error {
	cfgCopy := *cfg

	prev := v.state.Load()

	policies, newHashes, policyFetcher, ociDigest, err := loadAndHashPolicies(
		ctx,
		&cfgCopy,
		prev.fetcher,
	)
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

	// applyReload updates the attestation fetcher (newFetcher) in the snapshot.
	// The policy fetcher (policyFetcher) is separate and used only by the poller.
	v.applyReload(ctx, current, &cfgCopy, policies, newHashes, newFetcher)

	// Keep the policy fetcher's transport cache in sync with registry changes.
	registriesChanged := config.RegistriesChanged(
		current.config.Registries, cfgCopy.Registries,
	)

	if policyFetcher != nil && registriesChanged {
		reloaded := v.state.Load()
		policyFetcher.SetTransportCache(
			transportCacheFromFetcher(reloaded.fetcher),
		)
	}

	// Start new poller if source is OCI (old poller already stopped above).
	if cfgCopy.Policy.Source == config.PolicySourceOCI {
		v.startPoller(ctx, policyFetcher, &cfgCopy, ociDigest)
	}

	if cfgCopy.Enabled() {
		WarnEnforceDefaults(ctx, &cfgCopy, policies)
		WarnWarnModeDefaults(ctx, &cfgCopy, policies)
	}

	return nil
}

func (v *Verifier) applyReload(
	ctx context.Context,
	current *snapshot,
	cfgCopy *config.Config,
	policies map[string]*policy.Policy,
	newHashes map[string]string,
	newFetcher *attestation.OCIFetcher,
) {
	policiesChanged := !policyHashesEqual(v.policyHashes, newHashes)
	cacheInvalidated := cacheAffectingFieldsChanged(current.config, cfgCopy) || policiesChanged
	newCache := reloadCache(current, cfgCopy, cacheInvalidated)

	logReloadChanges(ctx, current.config, cfgCopy, v.policyHashes, newHashes, cacheInvalidated)
	circuitBreakers := v.reloadCircuitBreakers(current, cfgCopy)
	fetcher := v.reloadFetcher(current, cfgCopy, newFetcher)
	closeOldTransportCache(current, newFetcher)

	hostSem := resetCachesIfChanged(current.hostSem, policiesChanged)

	v.state.Store(&snapshot{
		config:           cfgCopy,
		policies:         policies,
		policyHashes:     newHashes,
		cache:            newCache,
		metrics:          current.metrics,
		fetcher:          fetcher,
		circuitBreakers:  circuitBreakers,
		fetchSem:         current.fetchSem,
		hostSem:          hostSem,
		auditLogger:      current.auditLogger,
		allowlistDigests: buildAllowlistMap(cfgCopy.AllowlistDigests),
	})
	v.policyHashes = newHashes
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

func resetVerificationCaches() {
	attestation.ResetPEMKeyCache()
	attestation.ResetSANPatternWarnings()
	slsa.ResetWarnings()
	glob.ResetCache()
}

func resetCachesIfChanged(prevHostSem *hostSemMap, policiesChanged bool) *hostSemMap {
	if !policiesChanged {
		return prevHostSem
	}

	resetVerificationCaches()

	return &hostSemMap{m: sync.Map{}, count: atomic.Int64{}}
}

func reloadCache(prev *snapshot, cfg *config.Config, invalidated bool) *cache.Cache {
	if !invalidated {
		return prev.cache
	}

	prev.cache.Stop()

	return cache.NewWithGauge(
		cfg.CacheTTL.Duration, cfg.CacheMaxEntries,
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
		!config.SigstoreConfigChanged(&prev.config.Sigstore, &cfg.Sigstore) {
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
		newFetcher.SetFallbackCallback(prev.metrics.TrustedRootFallbackTotal.Inc)
		newFetcher.SetMirrorFallbackCallback(func(registryHost string) {
			prev.metrics.MirrorFallbackTotal.WithLabelValues(registryHost, "attestation").Inc()
		})

		return newFetcher
	}

	if ociFetcher, ok := prev.fetcher.(*attestation.OCIFetcher); ok {
		ociFetcher.SetRateLimit(cfg.FetchRateLimit)
		ociFetcher.SetMaxAttestationSize(cfg.MaxAttestationSize)

		if config.RegistriesChanged(prev.config.Registries, cfg.Registries) {
			ociFetcher.SetTransportCache(registry.NewTransportCacheOrNil(cfg.Registries))
		}
	}

	return prev.fetcher
}

func handleOCIStartupFailure(
	ctx context.Context,
	cfg *config.Config,
	existingFetcher *policy.OCIFetcher,
	loadErr error,
) (
	policies map[string]*policy.Policy,
	hashes map[string]string,
	policyFetcher *policy.OCIFetcher,
	err error,
) {
	if cfg.Policy.Source != config.PolicySourceOCI || !registry.IsConnectionError(loadErr) {
		return nil, nil, nil, loadErr
	}

	slog.WarnContext(ctx,
		"OCI policy fetch failed at startup, starting in pending state",
		"oci_ref", cfg.Policy.OCIRef,
		"error", loadErr,
	)

	return map[string]*policy.Policy{}, map[string]string{}, existingFetcher, nil
}

func loadAndHashPolicies(
	ctx context.Context,
	cfg *config.Config,
	fetcher attestation.Fetcher,
) (
	policies map[string]*policy.Policy,
	hashes map[string]string,
	policyFetcher *policy.OCIFetcher,
	ociDigest string,
	err error,
) {
	if cfg.Enabled() {
		policies, policyFetcher, ociDigest, err = loadPoliciesFromSource(ctx, cfg, fetcher)
		if err != nil {
			return nil, nil, policyFetcher, "", err
		}

		err = validatePoliciesRuntime(policies)
		if err != nil {
			return nil, nil, nil, "", err
		}
	}

	hashes, err = hashPolicies(policies)
	if err != nil {
		return nil, nil, nil, "", err
	}

	return policies, hashes, policyFetcher, ociDigest, nil
}

func loadPoliciesFromSource(
	ctx context.Context, cfg *config.Config, fetcher attestation.Fetcher,
) (
	policies map[string]*policy.Policy,
	policyFetcher *policy.OCIFetcher,
	ociDigest string,
	err error,
) {
	if cfg.Policy.Source != config.PolicySourceOCI {
		policies, err = policy.LoadAll(cfg.PolicyDir)
		if err != nil {
			return nil, nil, "", fmt.Errorf("loading policies: %w", err)
		}

		return policies, nil, "", nil
	}

	policyFetcher, buildErr := buildPolicyFetcher(cfg, fetcher)
	if buildErr != nil {
		return nil, nil, "", fmt.Errorf("building policy fetcher: %w", buildErr)
	}

	result, err := policyFetcher.FetchFromOCI(ctx, cfg.Policy.OCIRef)
	if err != nil {
		return nil, policyFetcher, "", fmt.Errorf("loading OCI policies: %w", err)
	}

	slog.InfoContext(ctx,
		"Loaded policies from OCI artifact",
		"oci_ref", cfg.Policy.OCIRef,
		"digest", result.Digest,
		"count", len(result.Policies),
	)

	return result.Policies, policyFetcher, result.Digest, nil
}

func buildPolicyFetcher(
	cfg *config.Config, fetcher attestation.Fetcher,
) (*policy.OCIFetcher, error) {
	fetcherTransportCache := transportCacheFromFetcher(fetcher)

	if !cfg.Policy.SignatureVerificationRequired() {
		return policy.NewOCIFetcher(fetcherTransportCache), nil
	}

	sigCfg := &policy.SignatureConfig{
		Issuers:     cfg.Policy.Issuers,
		SANPatterns: cfg.Policy.SANPatterns,
		Keys:        cfg.Policy.Keys,
	}

	fetchTrustedRoot := buildTrustedRootFetchFunc(cfg)

	verifyFn, err := policy.NewSignatureVerifyFunc(
		sigCfg, fetchTrustedRoot, remote.Image, remote.Referrers,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"creating policy signature verifier: %w", err,
		)
	}

	return policy.NewOCIFetcherWithSignatureVerification(
		fetcherTransportCache, verifyFn,
	), nil
}

func (v *Verifier) startPoller(
	ctx context.Context,
	policyFetcher *policy.OCIFetcher,
	cfg *config.Config,
	ociDigest string,
) {
	if policyFetcher == nil {
		slog.WarnContext(ctx, "No policy fetcher available; not starting poller")

		return
	}

	pollerInstance := policy.NewPoller(
		policyFetcher,
		cfg.Policy.OCIRef,
		cfg.Policy.PollInterval.Duration,
		func(policies map[string]*policy.Policy) error {
			return v.onPolicyUpdate(ctx, policies)
		},
	)

	pollerInstance.SetCachedDigest(ociDigest)
	pollerInstance.Start(ctx)

	v.poller = pollerInstance
}

func (v *Verifier) onPolicyUpdate(ctx context.Context, policies map[string]*policy.Policy) error {
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

	v.applyPolicyUpdate(ctx, state, policies, newHashes)

	return nil
}

func (v *Verifier) applyPolicyUpdate(
	ctx context.Context,
	state *snapshot,
	policies map[string]*policy.Policy,
	newHashes map[string]string,
) {
	state.cache.Stop()

	resetVerificationCaches()

	snap := newSnapshot(state.config, policies, newHashes, state.metrics, state.fetcher)
	snap.circuitBreakers = state.circuitBreakers
	snap.fetchSem = state.fetchSem
	snap.auditLogger = state.auditLogger

	v.state.Store(snap)
	v.policyHashes = newHashes

	state.metrics.PolicyReloadsTotal.Inc()

	if state.config.Enabled() {
		WarnEnforceDefaults(ctx, state.config, policies)
		WarnWarnModeDefaults(ctx, state.config, policies)
	}

	slog.Info(
		"OCI policy update applied",
		"policies_count", len(policies),
	)
}

func cacheAffectingFieldsChanged(prev, next *config.Config) bool {
	return prev.Verification != next.Verification ||
		prev.PolicyDir != next.PolicyDir ||
		cacheTimingsChanged(prev, next) ||
		prev.FetchFailurePolicy != next.FetchFailurePolicy ||
		config.SigstoreConfigChanged(&prev.Sigstore, &next.Sigstore) ||
		config.RegistriesChanged(prev.Registries, next.Registries) ||
		policySourceChanged(prev, next) ||
		prev.CacheMaxEntries != next.CacheMaxEntries
}

func cacheTimingsChanged(prev, next *config.Config) bool {
	return prev.CacheTTL.Duration != next.CacheTTL.Duration ||
		prev.CacheFailureTTL.Duration != next.CacheFailureTTL.Duration ||
		prev.FetchTimeout.Duration != next.FetchTimeout.Duration
}

func policySourceChanged(prev, next *config.Config) bool {
	return prev.Policy.Source != next.Policy.Source ||
		prev.Policy.OCIRef != next.Policy.OCIRef ||
		!slices.Equal(prev.Policy.Issuers, next.Policy.Issuers) ||
		!slices.Equal(prev.Policy.SANPatterns, next.Policy.SANPatterns) ||
		!slices.Equal(prev.Policy.Keys, next.Policy.Keys)
}

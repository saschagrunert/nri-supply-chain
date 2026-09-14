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
	"log/slog"
	"os"
	"slices"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/bundle"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/glob"
	"github.com/saschagrunert/nri-supply-chain/internal/guac"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/notation"
	"github.com/saschagrunert/nri-supply-chain/internal/registry"
	"github.com/saschagrunert/nri-supply-chain/internal/slsa"
)

// Reload reloads the verifier's configuration and policies.
func (v *Verifier) Reload(ctx context.Context, cfg *config.Config) error {
	v.reloadMu.Lock()
	defer v.reloadMu.Unlock()

	return v.reload(ctx, cfg)
}

func (v *Verifier) reload(ctx context.Context, cfg *config.Config) error {
	cfgCopy := *cfg

	// Pause OCI policy polling for the whole reload. A poller left running
	// could apply a newer artifact after prepareReload fetched the policies,
	// and the reload would then install the older ones. The poller callback
	// (onPolicyUpdate) acquires mu, so the poller is stopped before taking
	// mu. The new policy fetcher inherits the rollback guard of the stopped
	// one.
	paused := v.stopPoller()

	plan, err := v.prepareReload(ctx, &cfgCopy, pollerRollbackSeed(paused, cfgCopy.Policy.OCIRef))
	if err != nil {
		v.resumePoller(ctx, paused)

		return err
	}

	if v.reloadPrepared != nil {
		v.reloadPrepared()
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	current := v.state.Load()

	next, err := v.buildSnapshot(ctx, current, &snapshotInput{
		config:       &cfgCopy,
		policies:     plan.loaded.policies,
		policyHashes: plan.loaded.hashes,
		trust:        plan.trust,
		fetcher:      v.reloadFetcher(current, &cfgCopy, plan.newFetcher),
		fetcherBasis: reloadFetcherBasis(current, &cfgCopy, plan.trust),
		metrics:      current.metrics,
	})
	if err != nil {
		v.resumePoller(ctx, paused)

		return err
	}

	logReloadChanges(
		ctx, current.config, &cfgCopy, current.policyHashes, plan.loaded.hashes,
		next.generation != current.generation,
	)

	v.state.Store(next)
	retireSnapshot(current, next)
	closeOldTransportCache(current, plan.newFetcher)

	// Keep the policy fetcher's transport cache in sync with registry changes.
	if plan.loaded.policyFetcher != nil &&
		config.RegistriesChanged(current.config.Registries, cfgCopy.Registries) {
		plan.loaded.policyFetcher.SetTransportCache(transportCacheFromFetcher(next.fetcher))
	}

	// Start the new poller if the source is OCI (the old one stays stopped).
	if cfgCopy.Policy.Source == config.PolicySourceOCI {
		v.startPoller(ctx, plan.loaded.policyFetcher, &cfgCopy, plan.loaded.ociDigest)
	}

	if cfgCopy.Enabled() {
		WarnEnforceDefaults(ctx, &cfgCopy, plan.loaded.policies)
		WarnWarnModeDefaults(ctx, &cfgCopy, plan.loaded.policies)
	}

	return nil
}

// resumePoller restarts a poller paused by a reload that failed, so the
// previous configuration keeps receiving OCI policy updates.
func (v *Verifier) resumePoller(ctx context.Context, paused *policyPoller) {
	if paused == nil {
		return
	}

	v.runPoller(ctx, paused)
}

// reloadPlan holds everything a reload prepares before it takes the lock.
type reloadPlan struct {
	loaded     *loadedPolicies
	trust      trustFingerprint
	newFetcher attestation.Fetcher
}

// prepareReload loads and validates policies and creates a new attestation
// fetcher when needed, without modifying the verifier. OCI artifacts older
// than rollbackSeed are rejected.
func (v *Verifier) prepareReload(
	ctx context.Context, cfg *config.Config, rollbackSeed time.Time,
) (*reloadPlan, error) {
	prev := v.state.Load()

	loaded, err := loadAndHashPolicies(ctx, cfg, prev.fetcher, rollbackSeed)
	if err != nil {
		return nil, err
	}

	err = refuseEmptyPolicyReload(cfg, prev.policies, loaded.policies)
	if err != nil {
		return nil, err
	}

	trust := computeTrustFingerprint(cfg, loaded.policies)

	newFetcher, err := v.prepareFetcher(ctx, cfg, trust)
	if err != nil {
		return nil, err
	}

	if cfg.Enabled() {
		err = validatePoliciesModes(cfg.Verification, loaded.policies)
		if err != nil {
			return nil, err
		}
	}

	return &reloadPlan{loaded: loaded, trust: trust, newFetcher: newFetcher}, nil
}

// reloadAuditLogger returns the audit logger for cfg, reusing the previous
// one when the path is unchanged. The previous file is closed by
// retireSnapshot once the new snapshot is published.
func reloadAuditLogger(
	ctx context.Context, prev *snapshot, cfg *config.Config,
) (*slog.Logger, *os.File) {
	if prev.config.AuditLog == cfg.AuditLog {
		return prev.auditLogger, prev.auditLogFile
	}

	logger, auditFile, err := openAuditLogger(cfg.AuditLog)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to open audit log, falling back to default logger",
			"path", cfg.AuditLog, "error", err)

		return slog.Default(), nil
	}

	return logger, auditFile
}

func resetVerificationCaches() {
	attestation.ResetPEMKeyCache()
	attestation.ResetSANPatternWarnings()
	notation.ResetVerifierCache()
	slsa.ResetWarnings()
	glob.ResetCache()
	resetBuilderBindingWarnings()
}

// prepareFetcher creates a new fetcher outside the lock when one is needed
// (first enable or TUF config change). Returns (nil, nil) when the existing
// fetcher can be reused.
func (v *Verifier) prepareFetcher( //nolint:ireturn // may return OCIFetcher, Fetcher, or FallbackFetcher
	ctx context.Context,
	cfg *config.Config,
	trust trustFingerprint,
) (attestation.Fetcher, error) {
	if !cfg.Enabled() {
		return nil, nil //nolint:nilnil // nil fetcher means reuse existing
	}

	prev := v.state.Load()
	basis := &prev.fetcherBasis

	// A replaced custom TUF root file needs a new fetcher even when its path
	// is unchanged.
	sigstoreChanged := config.SigstoreConfigChanged(&basis.config.Sigstore, &cfg.Sigstore) ||
		basis.sigstore != trust.sigstore
	offlineChanged := config.OfflineConfigChanged(&basis.config.Offline, &cfg.Offline)

	if prev.fetcher != nil && !sigstoreChanged && !offlineChanged {
		if !bundleStoreChangedOnDisk(prev.fetcher, cfg) {
			return nil, nil //nolint:nilnil // no config change, reuse existing
		}

		slog.Info("Bundle store changed on disk, recreating fetcher")
	}

	return createFetcherForMode(ctx, cfg, nil, nil)
}

func closeOldTransportCache(prev *snapshot, newFetcher attestation.Fetcher) {
	if newFetcher == nil {
		return
	}

	if tc := transportCacheFromFetcher(prev.fetcher); tc != nil {
		tc.CloseIdleConnections()
	}
}

func ociFetcherFromFetcher(fetcher attestation.Fetcher) *attestation.OCIFetcher {
	if ociFetcher, ok := fetcher.(*attestation.OCIFetcher); ok {
		return ociFetcher
	}

	if fb, ok := fetcher.(*bundle.FallbackFetcher); ok {
		return fb.OCIFetcher()
	}

	return nil
}

func configureOCICallbacks(fetcher attestation.Fetcher, met *metrics.Metrics) {
	ociFetcher := ociFetcherFromFetcher(fetcher)
	if ociFetcher == nil {
		return
	}

	ociFetcher.SetFallbackCallback(met.TrustedRootFallbackTotal.Inc)
	ociFetcher.SetMirrorFallbackCallback(func(registryHost string) {
		met.MirrorFallbackTotal.WithLabelValues(registryHost, "attestation").Inc()
	})
}

func bundleStoreChangedOnDisk(fetcher attestation.Fetcher, cfg *config.Config) bool {
	if cfg.Offline.Mode == config.OfflineModeDisabled {
		return false
	}

	bundleFetcher := bundleFetcherFromFetcher(fetcher)
	if bundleFetcher == nil {
		return false
	}

	store, err := bundle.OpenStore(cfg.Offline.AttestationStore)
	if err != nil {
		return false
	}

	return !bundleFetcher.StoreCreatedAt().Equal(store.Manifest().CreatedAt)
}

func bundleFetcherFromFetcher(fetcher attestation.Fetcher) *bundle.Fetcher {
	if bf, ok := fetcher.(*bundle.Fetcher); ok {
		return bf
	}

	if fb, ok := fetcher.(*bundle.FallbackFetcher); ok {
		if bf, ok := fb.Primary().(*bundle.Fetcher); ok {
			return bf
		}
	}

	return nil
}

func applyOCISettings(
	fetcher attestation.Fetcher, prevCfg, cfg *config.Config,
) {
	ociFetcher := ociFetcherFromFetcher(fetcher)
	if ociFetcher == nil {
		return
	}

	ociFetcher.SetRateLimit(cfg.FetchRateLimit)
	ociFetcher.SetMaxAttestationSize(cfg.MaxAttestationSize)

	if config.RegistriesChanged(prevCfg.Registries, cfg.Registries) {
		ociFetcher.SetTransportCache(
			registry.NewTransportCacheOrNil(cfg.Registries),
		)
	}
}

// reloadFetcherBasis returns the basis of the fetcher reloadFetcher returns.
// With verification disabled the fetcher is kept untouched, so it keeps its
// basis; otherwise it was rebuilt for or updated to cfg.
func reloadFetcherBasis(prev *snapshot, cfg *config.Config, trust trustFingerprint) fetcherBasis {
	if !cfg.Enabled() {
		return prev.fetcherBasis
	}

	return fetcherBasis{config: cfg, sigstore: trust.sigstore}
}

// reloadFetcher returns the fetcher to use for the new snapshot. If a new
// fetcher was pre-created, it is configured and returned; otherwise the existing
// fetcher is updated with the new rate limit and registries.
func (v *Verifier) reloadFetcher( //nolint:ireturn // returns prev.fetcher which is the Fetcher interface
	prev *snapshot,
	cfg *config.Config,
	newFetcher attestation.Fetcher,
) attestation.Fetcher {
	if !cfg.Enabled() {
		return prev.fetcher
	}

	if newFetcher != nil {
		configureOCICallbacks(newFetcher, prev.metrics)
		setBundleMetricsOnFetcher(newFetcher, prev.metrics)

		return newFetcher
	}

	applyOCISettings(prev.fetcher, prev.fetcherBasis.config, cfg)

	return prev.fetcher
}

func cacheAffectingFieldsChanged(prev, next *config.Config) bool {
	return prev.Verification != next.Verification ||
		prev.PolicyDir != next.PolicyDir ||
		cacheTimingsChanged(prev, next) ||
		fetchFailurePolicyChanged(prev, next) ||
		config.SigstoreConfigChanged(&prev.Sigstore, &next.Sigstore) ||
		config.RegistriesChanged(prev.Registries, next.Registries) ||
		policySourceChanged(prev, next) ||
		prev.CacheMaxEntries != next.CacheMaxEntries ||
		guacConfigChanged(prev, next) ||
		config.OfflineConfigChanged(&prev.Offline, &next.Offline)
}

func fetchFailurePolicyChanged(prev, next *config.Config) bool {
	return prev.FetchFailurePolicy != next.FetchFailurePolicy ||
		prev.FetchFailurePolicyExplicit != next.FetchFailurePolicyExplicit
}

func guacConfigChanged(prev, next *config.Config) bool {
	return guacTransportChanged(prev, next) ||
		prev.Guac.FallbackPolicy != next.Guac.FallbackPolicy ||
		prev.Guac.MaxDependencies != next.Guac.MaxDependencies ||
		!slices.Equal(prev.Guac.Checks, next.Guac.Checks)
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

func reloadGUACClient(
	prev *snapshot, cfg *config.Config,
) (*guac.Client, *attestation.CircuitBreaker, error) {
	if !cfg.Guac.Enabled() {
		return nil, nil, nil
	}

	if prev.guacClient != nil && !guacTransportChanged(prev.config, cfg) {
		return prev.guacClient, prev.guacBreaker, nil
	}

	guacClient, err := newGUACClient(cfg)
	if err != nil {
		return nil, nil, err
	}

	return guacClient, attestation.NewCircuitBreaker(
		cfg.CircuitBreakerThreshold,
		cfg.CircuitBreakerCooldown.Duration,
	), nil
}

func guacTransportChanged(prev, next *config.Config) bool {
	return prev.Guac.Endpoint != next.Guac.Endpoint ||
		prev.Guac.AuthTokenPath != next.Guac.AuthTokenPath ||
		prev.Guac.CACertPath != next.Guac.CACertPath ||
		prev.Guac.Timeout.Duration != next.Guac.Timeout.Duration
}

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

	"golang.org/x/sync/semaphore"
	"golang.org/x/sync/singleflight"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/cache"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/registry"
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
)

type snapshot struct {
	config          *config.Config
	policies        map[string]*policy.Policy
	policyHashes    map[string]string // lock-free copy updated with v.policyHashes under v.mu
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

	mu           sync.Mutex // serializes Reload; v.policyHashes (not the snapshot copy) is only accessed under mu
	policyHashes map[string]string
	nodeName     string
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
		ociFetcher.SetFallbackCallback(met.TrustedRootFallbackTotal.Inc)
		ociFetcher.SetMirrorFallbackCallback(func(registryHost string) {
			met.MirrorFallbackTotal.WithLabelValues(registryHost, "attestation").Inc()
		})
	}

	policies, hashes, policyFetcher, ociDigest, err := loadAndHashPolicies(ctx, &cfgCopy, fetcher)
	if err != nil {
		policies, hashes, policyFetcher, err = handleOCIStartupFailure(
			ctx, &cfgCopy, policyFetcher, err,
		)
		if err != nil {
			return nil, err
		}

		ociDigest = ""
	}

	if cfgCopy.Enabled() && len(policies) > 0 {
		err = validatePoliciesModes(cfgCopy.Verification, policies)
		if err != nil {
			return nil, err
		}

		WarnEnforceDefaults(ctx, &cfgCopy, policies)
		WarnWarnModeDefaults(ctx, &cfgCopy, policies)
	}

	snap := newSnapshot(&cfgCopy, policies, hashes, met, fetcher)

	verif := &Verifier{ //nolint:exhaustruct // zero-value fields are intentional
		policyHashes: hashes,
		nodeName:     resolveNodeName(),
	}
	verif.state.Store(snap)

	if cfgCopy.Policy.Source == config.PolicySourceOCI {
		verif.startPoller(ctx, policyFetcher, &cfgCopy, ociDigest)
	}

	return verif, nil
}

func newSnapshot(
	cfg *config.Config,
	policies map[string]*policy.Policy,
	hashes map[string]string,
	met *metrics.Metrics,
	fetcher attestation.Fetcher,
) *snapshot {
	return &snapshot{
		config:       cfg,
		policies:     policies,
		policyHashes: hashes,
		cache: cache.NewWithGauge(
			cfg.CacheTTL.Duration, cfg.CacheMaxEntries,
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

func resolveNodeName() string {
	if name := os.Getenv("NODE_NAME"); name != "" {
		return name
	}

	hostname, err := os.Hostname()
	if err != nil {
		return ""
	}

	return hostname
}

func policyHashForNamespace(hashes map[string]string, namespace string) string {
	if h, ok := hashes[namespace]; ok {
		return h
	}

	return hashes[""]
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

	if stateReady(state) {
		return true, ""
	}

	if state.config == nil {
		return false, "no config loaded"
	}

	return false, "no policies loaded"
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

	ready := stateReady(state)
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
// serviceAccount is the pod's Kubernetes service account name (from NRI pod
// annotations); pass "" when unavailable.
func (v *Verifier) Verify( //nolint:funlen // early-return branches inflate line count
	ctx context.Context, imageRef, digest, indexDigest, namespace, serviceAccount string,
) (*types.Result, error) {
	state := v.snap()

	info := &auditInfo{
		policyHash:        "",
		nodeName:          v.nodeName,
		podServiceAccount: serviceAccount,
		verificationMode:  "",
	}

	if !state.config.Enabled() {
		info.verificationMode = string(config.ModeDisabled)

		return allowResult(
			ctx, state.auditLogger, imageRef, digest,
			namespace, "verification disabled", info,
		), nil
	}

	slog.DebugContext(ctx, "Verifying image",
		"image", imageRef, "digest", digest, "namespace", namespace)
	pol := policyForNamespace(state.policies, namespace)

	if pol == nil {
		info.verificationMode = string(state.config.Verification)

		result, err := handleMissingPolicy(ctx, state.config, imageRef, namespace)
		if result != nil {
			logResult(ctx, state.auditLogger, imageRef, digest, namespace, result, info)
			recordMetrics(state.metrics, result, namespace)
		}

		return result, err
	}

	info.policyHash = policyHashForNamespace(state.policyHashes, namespace)
	info.verificationMode = string(state.config.Verification)

	if !isIncluded(ctx, pol.Include, imageRef) {
		state.metrics.VerificationSkippedTotal.WithLabelValues("not_included", namespace).Inc()

		return allowResult(
			ctx, state.auditLogger, imageRef, digest,
			namespace, "image is not included", info,
		), nil
	}

	if isExcluded(ctx, pol.Exclude, imageRef) {
		state.metrics.VerificationSkippedTotal.WithLabelValues("excluded", namespace).Inc()

		return allowResult(
			ctx, state.auditLogger, imageRef, digest,
			namespace, "image is excluded", info,
		), nil
	}

	resolvedPol, ruleIdx := ResolveImagePolicy(ctx, pol, imageRef)
	effectiveMode := resolvedPol.EffectiveMode(state.config.Verification)

	info.verificationMode = string(effectiveMode)

	cacheNS := cacheNamespaceKey(namespace, ruleIdx)

	result, err := v.handleCacheHit(
		ctx, state, effectiveMode, imageRef, digest, namespace, cacheNS, info,
	)
	if result != nil || err != nil {
		return result, err
	}

	result, err = v.verifyOnce(
		ctx, state, resolvedPol, imageRef, digest, indexDigest, namespace, cacheNS, info,
	)
	if err != nil {
		return handleVerifyError(ctx, state, effectiveMode, imageRef, digest, namespace, err, info)
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
	info *auditInfo,
) (*types.Result, error) {
	if mode != config.ModeEnforce {
		slog.WarnContext(
			ctx, "Verification error (non-enforce mode, allowing)",
			"image", imageRef,
			"mode", mode,
			"error", err,
		)

		return allowResult(
			ctx, state.auditLogger, imageRef, digest,
			namespace, fmt.Sprintf("verification error: %s", err), info,
		), nil
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

func (v *Verifier) verifyOnce(
	ctx context.Context, state *snapshot, pol *policy.Policy,
	imageRef, digest, indexDigest, namespace, cacheNS string,
	info *auditInfo,
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
			context.WithoutCancel(ctx), state.config.VerificationTimeout.Duration,
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
		return handleFlightResult(ctx, state, res, imageRef, digest, namespace, info)
	}
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

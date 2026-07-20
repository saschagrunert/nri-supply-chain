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
	"path"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"golang.org/x/sync/singleflight"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/cache"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/slsa"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
	"github.com/saschagrunert/nri-supply-chain/internal/vex"
	"github.com/saschagrunert/nri-supply-chain/internal/vsa"
)

var (
	// ErrVerificationFailed is returned when supply chain verification fails in enforce mode.
	ErrVerificationFailed = errors.New("supply chain verification failed")

	// ErrCircuitBreakerOpen is returned when the circuit breaker is open.
	ErrCircuitBreakerOpen = errors.New("circuit breaker open for image")
)

type snapshot struct {
	config         *config.Config
	policies       map[string]*policy.Policy
	cache          *cache.Cache
	metrics        *metrics.Metrics
	fetcher        attestation.Fetcher
	circuitBreaker *attestation.CircuitBreaker
}

// Verifier performs supply chain attestation verification on container images.
type Verifier struct {
	mu             sync.RWMutex
	config         *config.Config
	cache          *cache.Cache
	policies       map[string]*policy.Policy
	policyHashes   map[string]string
	metrics        *metrics.Metrics
	fetcher        attestation.Fetcher
	inflight       singleflight.Group
	circuitBreaker *attestation.CircuitBreaker
}

// New creates a new Verifier with the given configuration, metrics, and attestation fetcher.
func New(cfg *config.Config, met *metrics.Metrics, fetcher attestation.Fetcher) (*Verifier, error) {
	cfgCopy := *cfg

	verif := &Verifier{
		mu:           sync.RWMutex{},
		config:       &cfgCopy,
		cache:        cache.NewWithGauge(cfgCopy.CacheTTL.Duration, met.CacheEntriesTotal),
		policies:     nil,
		policyHashes: nil,
		metrics:      met,
		fetcher:      fetcher,
		inflight:     singleflight.Group{},
		circuitBreaker: attestation.NewCircuitBreaker(
			cfgCopy.CircuitBreakerThreshold,
			cfgCopy.CircuitBreakerCooldown.Duration,
		),
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

		hashes, err := hashPolicies(policies)
		if err != nil {
			return nil, err
		}

		verif.policies = policies
		verif.policyHashes = hashes
	}

	return verif, nil
}

// Enforcing returns true if the verifier is in enforce mode.
func (v *Verifier) Enforcing() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()

	return v.config.Verification == config.ModeEnforce
}

// Ready returns true if the verifier is ready to serve requests.
// When not ready, the second return value describes the reason.
//
//nolint:nonamedreturns // gocritic requires names
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

// Verify performs supply chain verification for the given image.
func (v *Verifier) Verify(
	ctx context.Context, imageRef, digest, namespace string,
) (*types.Result, error) {
	state := v.snap()

	if !state.config.Enabled() {
		logAuditDecision(ctx, imageRef, digest, namespace, "allowed", "verification disabled")

		return &types.Result{
			Allowed:      true,
			Reason:       "verification disabled",
			CheckResults: nil,
		}, nil
	}

	slog.DebugContext(ctx, "Verifying image",
		"image", imageRef,
		"digest", digest,
		"namespace", namespace,
	)

	pol := policyForNamespace(state.policies, namespace)

	if pol == nil {
		return handleMissingPolicy(ctx, state.config, imageRef, digest, namespace)
	}

	if isExcluded(ctx, pol.Exclude, imageRef) {
		logAuditDecision(ctx, imageRef, digest, namespace, "allowed", "image is excluded")

		return &types.Result{
			Allowed:      true,
			Reason:       "image is excluded",
			CheckResults: nil,
		}, nil
	}

	if cached := state.cache.Get(digest, namespace); cached != nil {
		state.metrics.CacheHitsTotal.Inc()
		logResult(ctx, imageRef, digest, namespace, cached)

		enforced, err := applyEnforcement(ctx, state.config, cached, imageRef)

		return enforced, err
	}

	state.metrics.CacheMissesTotal.Inc()

	result, err := v.verifyOnce(ctx, &state, pol, imageRef, digest, namespace)
	if err != nil {
		return nil, fmt.Errorf("verification: %w", err)
	}

	return applyEnforcement(ctx, state.config, result, imageRef)
}

func applyEnforcement(
	ctx context.Context, cfg *config.Config,
	result *types.Result, imageRef string,
) (*types.Result, error) {
	if result.Allowed {
		return result, nil
	}

	if cfg.Verification == config.ModeEnforce {
		return result, fmt.Errorf(
			"%w: %s: %s", ErrVerificationFailed, imageRef, result.Reason,
		)
	}

	slog.WarnContext(ctx, "Verification failed (warn mode, allowing)",
		"image", imageRef,
		"reason", result.Reason,
	)

	return &types.Result{
		Allowed:      true,
		Reason:       result.Reason,
		CheckResults: result.CheckResults,
	}, nil
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

	cacheInvalidated := cacheAffectingFieldsChanged(v.config, &cfgCopy) ||
		!policyHashesEqual(v.policyHashes, newHashes)

	if cacheInvalidated {
		v.cache = cache.NewWithGauge(cfgCopy.CacheTTL.Duration, v.metrics.CacheEntriesTotal)
	}

	logReloadChanges(ctx, v.config, &cfgCopy, v.policyHashes, newHashes, cacheInvalidated)

	v.config = &cfgCopy
	v.policies = policies
	v.policyHashes = newHashes

	if v.circuitBreaker == nil ||
		v.circuitBreaker.Threshold() != cfgCopy.CircuitBreakerThreshold ||
		v.circuitBreaker.Cooldown() != cfgCopy.CircuitBreakerCooldown.Duration {
		v.circuitBreaker = attestation.NewCircuitBreaker(
			cfgCopy.CircuitBreakerThreshold,
			cfgCopy.CircuitBreakerCooldown.Duration,
		)
	}

	if cfgCopy.Enabled() {
		if v.fetcher == nil {
			v.fetcher = createAndWarmFetcher(ctx, &cfgCopy)
		} else if ociFetcher, ok := v.fetcher.(*attestation.OCIFetcher); ok {
			ociFetcher.SetRateLimit(cfgCopy.FetchRateLimit)
		}
	}

	return nil
}

//nolint:nonamedreturns // gocritic requires names for multi-value returns
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

	warmErr := ociFetcher.Warm(ctx)
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
		prev.FetchFailurePolicy != next.FetchFailurePolicy ||
		prev.FetchTimeout.Duration != next.FetchTimeout.Duration
}

func (v *Verifier) verifyOnce(
	ctx context.Context, state *snapshot, pol *policy.Policy,
	imageRef, digest, namespace string,
) (*types.Result, error) {
	flightKey := digest + "\x00" + namespace

	flightCh := v.inflight.DoChan(flightKey, func() (any, error) {
		if cached := state.cache.Get(digest, namespace); cached != nil {
			return cached, nil
		}

		// Use context.WithoutCancel so the verification completes even if
		// the triggering request is cancelled. Other waiters on DoChan
		// should not inherit this caller's cancellation.
		checkCtx := context.WithoutCancel(ctx)

		result := runChecks(checkCtx, state, pol, imageRef, digest)

		logResult(checkCtx, imageRef, digest, namespace, result)
		recordMetrics(state.metrics, result)

		state.cache.Set(digest, namespace, result)

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

		shared := res.Val.(*types.Result) //nolint:forcetypeassert // type guaranteed by DoChan closure
		result := *shared

		return &result, nil
	}
}

func (v *Verifier) snap() snapshot {
	v.mu.RLock()
	defer v.mu.RUnlock()

	return snapshot{
		config:         v.config,
		policies:       v.policies,
		cache:          v.cache,
		metrics:        v.metrics,
		fetcher:        v.fetcher,
		circuitBreaker: v.circuitBreaker,
	}
}

func runChecks(
	ctx context.Context, state *snapshot,
	pol *policy.Policy, imageRef, digest string,
) *types.Result {
	if state.fetcher == nil {
		return runChecksWithoutFetcher(pol, state.metrics, imageRef)
	}

	if state.circuitBreaker != nil && !state.circuitBreaker.Allow() {
		return handleFetchError(
			state.config, state.metrics,
			fmt.Errorf("%w: %s", ErrCircuitBreakerOpen, imageRef),
			imageRef,
		)
	}

	attestations, fetchErr := fetchAttestations(ctx, state, imageRef, digest, pol)
	if fetchErr != nil {
		if state.circuitBreaker != nil {
			if tripped := state.circuitBreaker.RecordFailure(); tripped {
				state.metrics.CircuitBreakerTripsTotal.Inc()
				slog.WarnContext(ctx, "Circuit breaker opened after repeated fetch failures")
			}
		}

		return handleFetchError(state.config, state.metrics, fetchErr, imageRef)
	}

	if state.circuitBreaker != nil {
		state.circuitBreaker.RecordSuccess()
	}

	vsaResult := checkVSA(ctx, attestations, pol, imageRef, digest, state.metrics)
	if vsaResult != nil {
		return vsaResult
	}

	return runParallelChecks(ctx, attestations, pol, state.metrics, imageRef, digest)
}

func runChecksWithoutFetcher(
	pol *policy.Policy, met *metrics.Metrics, imageRef string,
) *types.Result {
	detail := "no attestation fetcher configured for image " + imageRef

	slsaResult := handleMissingAttestation(
		pol.ProvenanceMissingPolicy(), "slsa_provenance", detail,
	)

	met.VerificationDuration.WithLabelValues("slsa_provenance").Observe(0)

	vexResult := handleMissingAttestation(
		vexMissingPolicy(pol), "vex", detail,
	)

	met.VerificationDuration.WithLabelValues("vex").Observe(0)

	return combineResults(slsaResult, vexResult)
}

func fetchAttestations(
	ctx context.Context, state *snapshot,
	imageRef, digest string, pol *policy.Policy,
) ([]attestation.VerifiedAttestation, error) {
	opts := attestation.FetchOptions{
		RequireTransparencyLog: pol.Signatures != nil && pol.Signatures.RequireTransparencyLog,
		Timeout:                state.config.FetchTimeout.Duration,
	}

	if pol.Trust != nil {
		opts.TrustedIssuers = pol.Trust.Issuers
		opts.SANPatterns = pol.Trust.SANPatterns

		keys := make([]string, 0, len(pol.Trust.Verifiers))
		for idx := range pol.Trust.Verifiers {
			keys = append(keys, pol.Trust.Verifiers[idx].Key)
		}

		opts.TrustedKeys = keys
	}

	attestations, err := state.fetcher.Fetch(ctx, imageRef, digest, opts)
	if err != nil {
		return nil, fmt.Errorf("fetching attestations: %w", err)
	}

	return attestations, nil
}

func handleFetchError(
	cfg *config.Config, met *metrics.Metrics,
	fetchErr error, imageRef string,
) *types.Result {
	met.FetchErrorsTotal.WithLabelValues("attestation").Inc()

	detail := fmt.Sprintf("attestation fetch failed for %s: %s", imageRef, fetchErr)

	checkResult := handleMissingAttestation(cfg.FetchFailurePolicy, "fetch", detail)

	return &types.Result{
		Allowed:      checkResult.Passed,
		Reason:       checkResult.Detail,
		CheckResults: []types.CheckResult{*checkResult},
	}
}

func checkVSA(
	ctx context.Context, attestations []attestation.VerifiedAttestation,
	pol *policy.Policy, imageRef, digest string, met *metrics.Metrics,
) *types.Result {
	vsaAttestations := filterByPredicate(attestations, attestation.PredicateVSA)
	if len(vsaAttestations) == 0 {
		return nil
	}

	start := time.Now()

	defer func() {
		met.VerificationDuration.WithLabelValues("vsa").Observe(time.Since(start).Seconds())
	}()

	digestRef := buildDigestRef(imageRef, digest)

	var passed *vsa.VerifyResult

	for idx := range vsaAttestations {
		vsaResult, err := vsa.Verify(vsaAttestations[idx].Payload, pol, digestRef)
		if err != nil {
			slog.WarnContext(ctx, "VSA verification error", "error", err)

			continue
		}

		if vsaResult.HardReject {
			return &types.Result{
				Allowed:      false,
				Reason:       vsaResult.Check.Detail,
				CheckResults: []types.CheckResult{*vsaResult.Check},
			}
		}

		if passed == nil && vsaResult.Check.Passed && vsaResult.Check.Status == types.StatusPass {
			passed = vsaResult
		}
	}

	if passed != nil {
		return &types.Result{
			Allowed:      true,
			Reason:       "VSA verification passed, skipping direct verification",
			CheckResults: []types.CheckResult{*passed.Check},
		}
	}

	return nil
}

func runParallelChecks(
	ctx context.Context, attestations []attestation.VerifiedAttestation,
	pol *policy.Policy, met *metrics.Metrics, imageRef, digest string,
) *types.Result {
	var (
		slsaResult *types.CheckResult
		vexResult  *types.CheckResult
		waitGroup  sync.WaitGroup
	)

	waitGroup.Add(2) //nolint:mnd // SLSA + VEX checks

	go func() {
		defer waitGroup.Done()

		slsaResult = runSLSACheck(ctx, attestations, pol, met, imageRef, digest)
	}()

	go func() {
		defer waitGroup.Done()

		vexResult = runVEXCheck(ctx, attestations, pol, met, imageRef, digest)
	}()

	waitGroup.Wait()

	return combineResults(slsaResult, vexResult)
}

func runSLSACheck(
	ctx context.Context,
	attestations []attestation.VerifiedAttestation,
	pol *policy.Policy, met *metrics.Metrics, imageRef, digest string,
) *types.CheckResult {
	start := time.Now()

	defer func() {
		met.VerificationDuration.WithLabelValues("slsa_provenance").Observe(
			time.Since(start).Seconds(),
		)
	}()

	provenanceAtts := filterByPredicate(attestations, attestation.PredicateSLSAProvenanceV1)
	if len(provenanceAtts) == 0 {
		return handleMissingAttestation(
			pol.ProvenanceMissingPolicy(),
			"slsa_provenance",
			"no provenance attestation found for image "+imageRef,
		)
	}

	result, err := slsa.VerifyMultiple(provenanceAtts, pol, digest)
	if err != nil {
		slog.WarnContext(ctx, "SLSA verification error", "error", err)

		return handleMissingAttestation(
			pol.ProvenanceMissingPolicy(),
			"slsa_provenance",
			fmt.Sprintf("SLSA verification error for %s: %s", imageRef, err),
		)
	}

	return result
}

func runVEXCheck(
	ctx context.Context,
	attestations []attestation.VerifiedAttestation,
	pol *policy.Policy, met *metrics.Metrics, imageRef, digest string,
) *types.CheckResult {
	start := time.Now()

	defer func() {
		met.VerificationDuration.WithLabelValues("vex").Observe(
			time.Since(start).Seconds(),
		)
	}()

	vexAtts := filterByPredicate(attestations, attestation.PredicateOpenVEX)
	if len(vexAtts) == 0 {
		return handleMissingAttestation(
			vexMissingPolicy(pol),
			"vex",
			"no VEX attestation found for image "+imageRef,
		)
	}

	payloads := make([][]byte, 0, len(vexAtts))
	for idx := range vexAtts {
		payloads = append(payloads, vexAtts[idx].Payload)
	}

	result, err := vex.VerifyMultiple(ctx, payloads, pol, imageRef, digest)
	if err != nil {
		slog.WarnContext(ctx, "VEX verification error", "error", err)

		return handleMissingAttestation(
			vexMissingPolicy(pol),
			"vex",
			fmt.Sprintf("VEX verification error for %s: %s", imageRef, err),
		)
	}

	return result
}

func combineResults(slsaResult, vexResult *types.CheckResult) *types.Result {
	result := &types.Result{
		Allowed:      true,
		Reason:       "",
		CheckResults: nil,
	}

	if slsaResult != nil {
		result.CheckResults = append(result.CheckResults, *slsaResult)
		applyCheckResult(result, slsaResult)
	}

	if vexResult != nil {
		result.CheckResults = append(result.CheckResults, *vexResult)
		applyCheckResult(result, vexResult)
	}

	return result
}

func applyCheckResult(result *types.Result, check *types.CheckResult) {
	if !check.Passed {
		result.Allowed = false

		if result.Reason == "" {
			result.Reason = check.Detail
		} else {
			result.Reason += "; " + check.Detail
		}

		return
	}

	if check.Status == types.StatusWarn {
		if result.Reason == "" {
			result.Reason = check.Detail
		} else {
			result.Reason += "; " + check.Detail
		}
	}
}

func filterByPredicate(
	attestations []attestation.VerifiedAttestation, predicateType string,
) []attestation.VerifiedAttestation {
	var filtered []attestation.VerifiedAttestation

	for idx := range attestations {
		if attestations[idx].PredicateType == predicateType {
			filtered = append(filtered, attestations[idx])
		}
	}

	return filtered
}

func vexMissingPolicy(pol *policy.Policy) string {
	if pol.VEX != nil && pol.VEX.MissingPolicy != "" {
		return pol.VEX.MissingPolicy
	}

	return policy.ActionAllow
}

func handleMissingAttestation(
	pol, checkType, detail string,
) *types.CheckResult {
	switch pol {
	case policy.ActionDeny:
		return types.FailResult(checkType, detail)
	case policy.ActionWarn:
		return types.WarnResult(checkType, detail)
	case policy.ActionAllow:
		return types.PassResult(checkType, detail)
	default:
		slog.Warn("Unrecognized missing attestation policy, defaulting to deny",
			"policy", pol,
			"check", checkType,
		)

		return types.FailResult(checkType, detail)
	}
}

func logResult(
	ctx context.Context,
	imageRef, digest, namespace string,
	result *types.Result,
) {
	for _, checkResult := range result.CheckResults {
		slog.InfoContext(ctx, "Supply chain audit",
			"image", imageRef,
			"digest", digest,
			"namespace", namespace,
			"allowed", result.Allowed,
			"check", checkResult.Type,
			"status", checkResult.Status,
			"detail", checkResult.Detail,
		)
	}
}

func logAuditDecision(
	ctx context.Context,
	imageRef, digest, namespace, decision, reason string,
) {
	slog.InfoContext(ctx, "Supply chain audit",
		"image", imageRef,
		"digest", digest,
		"namespace", namespace,
		"decision", decision,
		"reason", reason,
	)
}

func recordMetrics(met *metrics.Metrics, result *types.Result) {
	for _, checkResult := range result.CheckResults {
		met.VerificationTotal.WithLabelValues(
			checkResult.Type, checkResult.Status,
		).Inc()
	}
}

func handleMissingPolicy(
	ctx context.Context, cfg *config.Config,
	imageRef, digest, namespace string,
) (*types.Result, error) {
	reason := fmt.Sprintf(
		"no policy found for namespace %q and no default policy configured", namespace,
	)

	logAuditDecision(ctx, imageRef, digest, namespace, "denied", reason)

	return applyEnforcement(ctx, cfg, &types.Result{
		Allowed: false,
		Reason:  reason,
		CheckResults: []types.CheckResult{
			*types.FailResult("policy", "no matching policy found"),
		},
	}, imageRef)
}

func policyForNamespace(
	policies map[string]*policy.Policy, namespace string,
) *policy.Policy {
	if pol, found := policies[namespace]; found {
		return pol
	}

	if pol, found := policies[""]; found {
		return pol
	}

	return nil
}

func buildDigestRef(imageRef, digest string) string {
	if digest == "" || strings.Contains(imageRef, "@") {
		return imageRef
	}

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		slog.Debug("Failed to parse image reference for digest ref",
			"image", imageRef,
			"error", err,
		)

		return imageRef
	}

	return ref.Context().Digest(digest).String()
}

// isExcluded uses path.Match: '*' matches non-'/' characters only, so patterns
// must account for the full registry/namespace/image depth.
func isExcluded(ctx context.Context, excludedImages []string, imageRef string) bool {
	for _, pattern := range excludedImages {
		matched, err := path.Match(pattern, imageRef)
		if err != nil {
			slog.DebugContext(ctx, "Malformed exclude pattern",
				"pattern", pattern,
				"image", imageRef,
				"error", err,
			)

			continue
		}

		if matched {
			return true
		}
	}

	return false
}

func validatePoliciesRuntime(policies map[string]*policy.Policy) error {
	for ns, pol := range policies {
		err := pol.ValidateRuntime()
		if err != nil {
			label := ns
			if label == "" {
				label = "default"
			}

			return fmt.Errorf("policy %q: %w", label, err)
		}
	}

	return nil
}

func hashPolicies(
	policies map[string]*policy.Policy,
) (map[string]string, error) {
	hashes := make(map[string]string, len(policies))

	for namespace, pol := range policies {
		hash, err := pol.Hash()
		if err != nil {
			return nil, fmt.Errorf("policy %q: %w", namespace, err)
		}

		hashes[namespace] = hash
	}

	return hashes, nil
}

func policyHashesEqual(prev, next map[string]string) bool {
	if len(prev) != len(next) {
		return false
	}

	for key, hash := range prev {
		if next[key] != hash {
			return false
		}
	}

	return true
}

func logReloadChanges(
	ctx context.Context,
	prev, next *config.Config,
	prevHashes, nextHashes map[string]string,
	cacheInvalidated bool,
) {
	attrs := []any{
		"cache_invalidated", cacheInvalidated,
	}

	if prev.Verification != next.Verification {
		attrs = append(attrs, "mode_prev", prev.Verification, "mode_next", next.Verification)
	}

	if len(prevHashes) != len(nextHashes) {
		attrs = append(attrs, "policies_prev", len(prevHashes), "policies_next", len(nextHashes))
	} else {
		changed := 0

		for ns, hash := range prevHashes {
			if nextHashes[ns] != hash {
				changed++
			}
		}

		for ns := range nextHashes {
			if _, ok := prevHashes[ns]; !ok {
				changed++
			}
		}

		if changed > 0 {
			attrs = append(attrs, "policies_changed", changed)
		}
	}

	slog.InfoContext(ctx, "Config reload applied", attrs...)
}

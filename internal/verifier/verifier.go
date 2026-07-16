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
	"golang.org/x/sync/errgroup"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/cache"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/slsa"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
	"github.com/saschagrunert/nri-supply-chain/internal/vex"
	"github.com/saschagrunert/nri-supply-chain/internal/vsa"
	"github.com/saschagrunert/nri-supply-chain/policy"
)

// ErrVerificationFailed is returned when supply chain verification fails in enforce mode.
var ErrVerificationFailed = errors.New("supply chain verification failed")

type snapshot struct {
	config   *config.Config
	policies map[string]*policy.Policy
	cache    *cache.Cache
	metrics  *metrics.Metrics
	fetcher  attestation.Fetcher
}

// Verifier performs supply chain attestation verification on container images.
type Verifier struct {
	mu       sync.RWMutex
	config   *config.Config
	cache    *cache.Cache
	policies map[string]*policy.Policy
	metrics  *metrics.Metrics
	fetcher  attestation.Fetcher
}

// New creates a new Verifier with the given configuration, metrics, and attestation fetcher.
func New(cfg *config.Config, met *metrics.Metrics, fetcher attestation.Fetcher) (*Verifier, error) {
	cfgCopy := *cfg

	verif := &Verifier{
		mu:       sync.RWMutex{},
		config:   &cfgCopy,
		cache:    cache.New(cfgCopy.CacheTTL.Duration),
		policies: nil,
		metrics:  met,
		fetcher:  fetcher,
	}

	if cfgCopy.Enabled() {
		policies, err := policy.LoadAll(cfgCopy.PolicyDir)
		if err != nil {
			return nil, fmt.Errorf("loading policies: %w", err)
		}

		verif.policies = policies
	}

	return verif, nil
}

// Verify performs supply chain verification for the given image.
func (v *Verifier) Verify(
	ctx context.Context, imageRef, digest, namespace string,
) (*types.Result, error) {
	state := v.snap()

	if !state.config.Enabled() {
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

	if isExcluded(ctx, pol.Exclude, imageRef) {
		slog.InfoContext(ctx, "Image excluded from verification", "image", imageRef)

		return &types.Result{
			Allowed:      true,
			Reason:       "image is excluded",
			CheckResults: nil,
		}, nil
	}

	if cached := state.cache.Get(digest, namespace); cached != nil {
		state.metrics.CacheHitsTotal.Inc()
		logResult(ctx, imageRef, digest, namespace, cached)

		return cached, nil
	}

	state.metrics.CacheMissesTotal.Inc()

	result := runChecks(ctx, &state, pol, imageRef, digest)

	logResult(ctx, imageRef, digest, namespace, result)
	recordMetrics(state.metrics, result)

	result, err := applyEnforcement(ctx, state.config, result, imageRef)
	state.cache.Set(digest, namespace, result)

	if err != nil {
		return result, err
	}

	return result, nil
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
func (v *Verifier) Reload(cfg *config.Config) error {
	cfgCopy := *cfg

	var policies map[string]*policy.Policy

	if cfgCopy.Enabled() {
		var err error

		policies, err = policy.LoadAll(cfgCopy.PolicyDir)
		if err != nil {
			return fmt.Errorf("reloading policies: %w", err)
		}
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	v.config = &cfgCopy
	v.cache = cache.New(cfgCopy.CacheTTL.Duration)
	v.policies = policies

	if cfgCopy.Enabled() && v.fetcher == nil {
		v.fetcher = attestation.NewOCIFetcher()
	}

	return nil
}

func (v *Verifier) snap() snapshot {
	v.mu.RLock()
	defer v.mu.RUnlock()

	return snapshot{
		config:   v.config,
		policies: v.policies,
		cache:    v.cache,
		metrics:  v.metrics,
		fetcher:  v.fetcher,
	}
}

func runChecks(
	ctx context.Context, state *snapshot,
	pol *policy.Policy, imageRef, digest string,
) *types.Result {
	if state.fetcher == nil {
		return runChecksWithoutFetcher(pol, state.metrics, imageRef)
	}

	attestations, fetchErr := fetchAttestations(ctx, state, imageRef, digest, pol)
	if fetchErr != nil {
		return handleFetchError(state.config, state.metrics, fetchErr, imageRef)
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
		TrustedIssuers:         trustedIssuers(pol),
		TrustedKeys:            trustedKeys(pol),
		SANPatterns:            sanPatterns(pol),
		RequireTransparencyLog: requireTransparencyLog(pol),
		Timeout:                state.config.FetchTimeout.Duration,
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
	)

	grp, ctx := errgroup.WithContext(ctx)

	grp.Go(func() error {
		slsaResult = runSLSACheck(ctx, attestations, pol, met, imageRef, digest)

		return nil
	})

	grp.Go(func() error {
		vexResult = runVEXCheck(ctx, attestations, pol, met, imageRef, digest)

		return nil
	})

	_ = grp.Wait()

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

	provenanceAtts := filterByProvenance(attestations)
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

func filterByProvenance(
	attestations []attestation.VerifiedAttestation,
) []attestation.VerifiedAttestation {
	return filterByPredicate(attestations, attestation.PredicateSLSAProvenanceV1)
}

func trustedIssuers(pol *policy.Policy) []string {
	if pol.Trust != nil {
		return pol.Trust.Issuers
	}

	return nil
}

func trustedKeys(pol *policy.Policy) []string {
	if pol.Trust == nil {
		return nil
	}

	keys := make([]string, 0, len(pol.Trust.Verifiers))
	for idx := range pol.Trust.Verifiers {
		keys = append(keys, pol.Trust.Verifiers[idx].Key)
	}

	return keys
}

func sanPatterns(pol *policy.Policy) []string {
	if pol.Trust != nil {
		return pol.Trust.SANPatterns
	}

	return nil
}

func requireTransparencyLog(pol *policy.Policy) bool {
	return pol.Signatures != nil && pol.Signatures.RequireTransparencyLog
}

func vexMissingPolicy(pol *policy.Policy) string {
	if pol.VEX != nil && pol.VEX.MissingPolicy != "" {
		return pol.VEX.MissingPolicy
	}

	return config.PolicyAllow
}

func handleMissingAttestation(
	pol, checkType, detail string,
) *types.CheckResult {
	switch pol {
	case config.PolicyDeny:
		return &types.CheckResult{
			Type: checkType, Passed: false,
			Status: types.StatusFail, Detail: detail,
		}
	case config.PolicyWarn:
		return &types.CheckResult{
			Type: checkType, Passed: true,
			Status: types.StatusWarn, Detail: detail,
		}
	case config.PolicyAllow:
		return &types.CheckResult{
			Type: checkType, Passed: true,
			Status: types.StatusPass, Detail: detail,
		}
	default:
		return &types.CheckResult{
			Type: checkType, Passed: false,
			Status: types.StatusFail, Detail: detail,
		}
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
			"check", checkResult.Type,
			"status", checkResult.Status,
			"detail", checkResult.Detail,
		)
	}
}

func recordMetrics(met *metrics.Metrics, result *types.Result) {
	for _, checkResult := range result.CheckResults {
		met.VerificationTotal.WithLabelValues(
			checkResult.Type, checkResult.Status,
		).Inc()
	}
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

	return &policy.Policy{
		Trust:      nil,
		Exclude:    nil,
		Provenance: nil,
		VEX:        nil,
		VSA:        nil,
		Signatures: nil,
	}
}

func buildDigestRef(imageRef, digest string) string {
	if digest == "" || strings.Contains(imageRef, "@") {
		return imageRef
	}

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return imageRef
	}

	return ref.Context().Digest(digest).String()
}

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

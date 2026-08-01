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
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	celengine "github.com/saschagrunert/nri-supply-chain/internal/cel"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/notation"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/sbom"
	"github.com/saschagrunert/nri-supply-chain/internal/slsa"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
	"github.com/saschagrunert/nri-supply-chain/internal/vex"
	"github.com/saschagrunert/nri-supply-chain/internal/vsa"
)

func applyEnforcement(
	ctx context.Context, mode config.VerificationMode,
	result *types.Result, imageRef string,
) (*types.Result, error) {
	if result.Allowed {
		return result, nil
	}

	if mode == config.ModeEnforce {
		return result, fmt.Errorf(
			"%w: %s: %s", ErrVerificationFailed, imageRef, result.Reason,
		)
	}

	slog.WarnContext(ctx, "Verification failed (non-enforce mode, allowing)",
		"image", imageRef,
		"mode", mode,
		"reason", result.Reason,
	)

	cloned := result.Clone()
	cloned.Allowed = true

	return &cloned, nil
}

func runChecks(
	ctx context.Context, state *snapshot,
	pol *policy.Policy, imageRef, digest, indexDigest, namespace string,
) *types.Result {
	if state.fetcher == nil {
		return runChecksWithoutFetcher(pol, state.metrics, imageRef)
	}

	parsedRef, parseErr := name.ParseReference(imageRef)
	host := registryHost(parsedRef, parseErr, imageRef)
	breaker := registryBreakerByHost(state.circuitBreakers, host)

	if breaker != nil && !breaker.Allow() {
		return handleFetchError(
			state.config, state.metrics,
			fmt.Errorf("%w: %s", ErrCircuitBreakerOpen, imageRef),
			imageRef, host,
		)
	}

	if state.fetchSem != nil {
		release, semErr := acquireFetchSlots(ctx, state, host)
		if semErr != nil {
			return handleFetchError(state.config, state.metrics, semErr, imageRef, host)
		}

		defer release()
	}

	attestations, attestDigest, fetchErr := timedFetchAttestations(
		ctx, state, imageRef, digest, indexDigest, pol, host,
	)
	if fetchErr != nil {
		recordBreakerFailure(ctx, breaker, state.metrics, host, state.config.FetchFailurePolicy)

		return handleFetchError(state.config, state.metrics, fetchErr, imageRef, host)
	}

	if breaker != nil {
		breaker.RecordSuccess()
	}

	bins := binAttestations(attestations)

	return runVSAAndParallelChecks(
		ctx, &bins, pol, state.metrics, imageRef, attestDigest, namespace, parsedRef,
	)
}

func runVSAAndParallelChecks(
	ctx context.Context, bins *attestationBins,
	pol *policy.Policy, met *metrics.Metrics,
	imageRef, digest, namespace string, parsedRef name.Reference,
) *types.Result {
	vsaResult := checkVSA(ctx, bins.vsa, pol, imageRef, digest, met, parsedRef)
	if vsaResult != nil {
		return vsaResult
	}

	if len(bins.vsa) == 0 {
		denied := checkVSAMissing(pol, imageRef, met)
		if denied != nil {
			return denied
		}
	}

	result := runParallelChecks(ctx, bins, pol, met, imageRef, digest, namespace, parsedRef)

	if len(bins.vsa) == 0 {
		prependVSAWarning(result, pol, "no VSA attestation found for image "+imageRef)
	}

	celCheck := runCELCheck(pol, imageRef, digest, namespace, parsedRef, result)
	if celCheck != nil {
		result.CheckResults = append(result.CheckResults, *celCheck)
		applyCheckResult(result, celCheck)
	}

	return result
}

func registryHost(parsed name.Reference, parseErr error, imageRef string) string {
	if parseErr != nil {
		return imageRef
	}

	return parsed.Context().RegistryStr()
}

func runChecksWithoutFetcher(
	pol *policy.Policy, met *metrics.Metrics, imageRef string,
) *types.Result {
	detail := "no attestation fetcher configured for image " + imageRef

	vsaMissing := pol.VSAMissingPolicy()

	met.VerificationDuration.WithLabelValues(string(types.CheckTypeVSA)).Observe(0)

	if vsaMissing != types.ActionAllow && vsaMissing != types.ActionWarn {
		check := handleMissingAttestation(vsaMissing, types.CheckTypeVSA, detail)

		return &types.Result{
			Allowed:      check.Passed,
			Reason:       check.Detail,
			CheckResults: []types.CheckResult{*check},
		}
	}

	slsaResult := handleMissingAttestation(
		pol.SLSAMissingPolicy(), types.CheckTypeSLSA, detail,
	)

	met.VerificationDuration.WithLabelValues(string(types.CheckTypeSLSA)).Observe(0)

	vexResult := handleMissingAttestation(
		pol.VEXMissingPolicy(), types.CheckTypeVEX, detail,
	)

	met.VerificationDuration.WithLabelValues(string(types.CheckTypeVEX)).Observe(0)

	notationResult := handleMissingAttestation(
		pol.NotationMissingPolicy(), types.CheckTypeNotation, detail,
	)

	met.VerificationDuration.WithLabelValues(string(types.CheckTypeNotation)).Observe(0)

	sbomResult := handleMissingAttestation(
		pol.SBOMMissingPolicy(), types.CheckTypeSBOM, detail,
	)

	met.VerificationDuration.WithLabelValues(string(types.CheckTypeSBOM)).Observe(0)

	result := combineResults(slsaResult, vexResult, notationResult, sbomResult)

	prependVSAWarning(result, pol, detail)

	return result
}

func timedFetchAttestations(
	ctx context.Context, state *snapshot,
	imageRef, digest, indexDigest string, pol *policy.Policy, host string,
) ([]attestation.VerifiedAttestation, string, error) {
	start := time.Now()

	defer func() {
		state.metrics.FetchDuration.WithLabelValues(host).
			Observe(time.Since(start).Seconds())
	}()

	return fetchAttestations(ctx, state, imageRef, digest, indexDigest, pol)
}

func fetchAttestations(
	ctx context.Context, state *snapshot,
	imageRef, digest, indexDigest string, pol *policy.Policy,
) ([]attestation.VerifiedAttestation, string, error) {
	opts := buildFetchOpts(pol, digest, state.config.FetchTimeout.Duration)

	var indexErr error

	// When the image resolved from a manifest list, try the index digest
	// first: cosign attaches attestations to the manifest list digest.
	if indexDigest != "" {
		indexOpts := buildFetchOpts(pol, indexDigest, state.config.FetchTimeout.Duration)

		atts, err := state.fetcher.Fetch(ctx, imageRef, indexOpts)
		if err == nil && len(atts) > 0 {
			return atts, indexDigest, nil
		}

		if err != nil {
			indexErr = err

			slog.DebugContext(ctx,
				"Index digest fetch failed, falling back to platform digest",
				"indexDigest", indexDigest,
				"platformDigest", digest,
				"error", err,
			)
		} else {
			slog.DebugContext(ctx,
				"No attestations on index digest, falling back to platform digest",
				"indexDigest", indexDigest,
				"platformDigest", digest,
			)
		}
	}

	attestations, err := state.fetcher.Fetch(ctx, imageRef, opts)
	if err != nil {
		platformErr := fmt.Errorf("fetching attestations: %w", err)
		if indexErr != nil {
			return nil, digest, errors.Join(
				platformErr,
				fmt.Errorf("index digest fetch also failed: %w", indexErr),
			)
		}

		return nil, digest, platformErr
	}

	return attestations, digest, nil
}

func buildFetchOpts(
	pol *policy.Policy, digest string, timeout time.Duration,
) *attestation.FetchOptions {
	opts := &attestation.FetchOptions{
		RequireTransparencyLog: pol.Signatures != nil && pol.Signatures.RequireTransparencyLog,
		Timeout:                timeout,
		Digest:                 digest,
	}

	if pol.Trust != nil {
		opts.TrustedIssuers = pol.Trust.Issuers
		opts.SANPatterns = pol.Trust.SANPatterns

		totalKeys := 0
		for idx := range pol.Trust.Verifiers {
			totalKeys += len(pol.Trust.Verifiers[idx].Keys)
		}

		keys := make([]string, 0, totalKeys)

		for idx := range pol.Trust.Verifiers {
			keys = append(keys, pol.Trust.Verifiers[idx].Keys...)
		}

		opts.TrustedKeys = keys
	}

	return opts
}

func handleFetchError(
	cfg *config.Config, met *metrics.Metrics,
	fetchErr error, imageRef, host string,
) *types.Result {
	met.FetchErrorsTotal.WithLabelValues("attestation", host).Inc()

	slog.Warn("Attestation fetch failed", "image", imageRef, "host", host, "error", fetchErr)

	detail := "attestation fetch failed for " + imageRef
	if errors.Is(fetchErr, ErrCircuitBreakerOpen) {
		detail += " (circuit breaker open)"
	}

	checkResult := handleMissingAttestation(cfg.FetchFailurePolicy, types.CheckTypeFetch, detail)

	return &types.Result{
		Allowed:      checkResult.Passed,
		Reason:       checkResult.Detail,
		CheckResults: []types.CheckResult{*checkResult},
	}
}

func checkVSA(
	ctx context.Context, vsaAttestations []attestation.VerifiedAttestation,
	pol *policy.Policy, imageRef, digest string, met *metrics.Metrics,
	parsedRef name.Reference,
) *types.Result {
	if len(vsaAttestations) == 0 {
		return nil
	}

	start := time.Now()

	defer func() {
		met.VerificationDuration.WithLabelValues(string(types.CheckTypeVSA)).
			Observe(time.Since(start).Seconds())
	}()

	digestRef := digestRefFromParsed(parsedRef, imageRef, digest)

	var passed *vsa.VerifyResult

	for idx := range vsaAttestations {
		vsaResult, err := vsa.Verify(vsaAttestations[idx].Payload, pol, digestRef, nil)
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

func checkVSAMissing(
	pol *policy.Policy, imageRef string, met *metrics.Metrics,
) *types.Result {
	missingPolicy := pol.VSAMissingPolicy()

	met.VerificationDuration.WithLabelValues(string(types.CheckTypeVSA)).Observe(0)

	if missingPolicy == types.ActionAllow || missingPolicy == types.ActionWarn {
		return nil
	}

	check := handleMissingAttestation(
		missingPolicy,
		types.CheckTypeVSA,
		"no VSA attestation found for image "+imageRef,
	)

	return &types.Result{
		Allowed:      check.Passed,
		Reason:       check.Detail,
		CheckResults: []types.CheckResult{*check},
	}
}

func prependVSAWarning(result *types.Result, pol *policy.Policy, detail string) {
	if pol.VSAMissingPolicy() != types.ActionWarn {
		return
	}

	vsaCheck := handleMissingAttestation(types.ActionWarn, types.CheckTypeVSA, detail)
	result.CheckResults = append(
		[]types.CheckResult{*vsaCheck}, result.CheckResults...,
	)
	applyCheckResult(result, vsaCheck)
}

func runParallelChecks(
	ctx context.Context, bins *attestationBins,
	pol *policy.Policy, met *metrics.Metrics,
	imageRef, digest, namespace string,
	parsedRef name.Reference,
) *types.Result {
	var (
		slsaResult     *types.CheckResult
		vexResult      *types.CheckResult
		notationResult *types.CheckResult
		sbomResult     *types.CheckResult
		waitGroup      sync.WaitGroup
	)

	const numChecks = 4
	waitGroup.Add(numChecks)

	go runParallelSLSA(
		ctx, &waitGroup, &slsaResult,
		bins.slsa, pol, met, imageRef, digest, namespace,
	)

	go runParallelVEX(
		ctx, &waitGroup, &vexResult,
		bins.vex, pol, met, imageRef, digest, namespace, parsedRef,
	)

	go runParallelNotation(
		ctx, &waitGroup, &notationResult,
		bins.notation, pol, met, imageRef, digest, namespace,
	)

	go runParallelSBOM(
		ctx, &waitGroup, &sbomResult,
		bins.sbom, pol, met, imageRef, digest, namespace,
	)

	waitGroup.Wait()

	return combineResults(slsaResult, vexResult, notationResult, sbomResult)
}

func runParallelSLSA(
	ctx context.Context, waitGroup *sync.WaitGroup, result **types.CheckResult,
	atts []attestation.VerifiedAttestation,
	pol *policy.Policy, met *metrics.Metrics,
	imageRef, digest, namespace string,
) {
	defer waitGroup.Done()
	defer func() {
		if r := recover(); r != nil {
			slog.Error("Panic during SLSA check",
				"panic", r, "stack", string(debug.Stack()))

			*result = types.FailResult(
				types.CheckTypeSLSA,
				"internal error during SLSA check", nil,
			)
		}
	}()

	*result = runSLSACheck(ctx, atts, pol, met, imageRef, digest, namespace)
}

func runParallelVEX(
	ctx context.Context, waitGroup *sync.WaitGroup, result **types.CheckResult,
	atts []attestation.VerifiedAttestation,
	pol *policy.Policy, met *metrics.Metrics,
	imageRef, digest, namespace string,
	parsedRef name.Reference,
) {
	defer waitGroup.Done()
	defer func() {
		if r := recover(); r != nil {
			slog.Error("Panic during VEX check",
				"panic", r, "stack", string(debug.Stack()))

			*result = types.FailResult(
				types.CheckTypeVEX,
				"internal error during VEX check", nil,
			)
		}
	}()

	*result = runVEXCheck(ctx, atts, pol, met, imageRef, digest, namespace, parsedRef)
}

func runParallelNotation(
	ctx context.Context, waitGroup *sync.WaitGroup, result **types.CheckResult,
	atts []attestation.VerifiedAttestation,
	pol *policy.Policy, met *metrics.Metrics,
	imageRef, digest, namespace string,
) {
	defer waitGroup.Done()
	defer func() {
		if r := recover(); r != nil {
			slog.Error("Panic during Notation check",
				"panic", r, "stack", string(debug.Stack()))

			*result = types.FailResult(
				types.CheckTypeNotation,
				"internal error during Notation check", nil,
			)
		}
	}()

	*result = runNotationCheck(ctx, atts, pol, met, imageRef, digest, namespace)
}

func runParallelSBOM(
	ctx context.Context, waitGroup *sync.WaitGroup, result **types.CheckResult,
	atts []attestation.VerifiedAttestation,
	pol *policy.Policy, met *metrics.Metrics,
	imageRef, digest, namespace string,
) {
	defer waitGroup.Done()
	defer func() {
		if r := recover(); r != nil {
			slog.Error("Panic during SBOM check",
				"panic", r, "stack", string(debug.Stack()))

			*result = types.FailResult(
				types.CheckTypeSBOM,
				"internal error during SBOM check", nil,
			)
		}
	}()

	*result = runSBOMCheck(ctx, atts, pol, met, imageRef, digest, namespace)
}

func runSBOMCheck(
	ctx context.Context,
	sbomAtts []attestation.VerifiedAttestation,
	pol *policy.Policy, met *metrics.Metrics,
	imageRef, digest, namespace string,
) *types.CheckResult {
	start := time.Now()

	defer func() {
		met.VerificationDuration.WithLabelValues(
			string(types.CheckTypeSBOM),
		).Observe(time.Since(start).Seconds())
	}()

	if len(sbomAtts) == 0 {
		slog.WarnContext(ctx, "No SBOM attestation found",
			"reason", "missing_attestation",
			"image", imageRef,
		)

		return handleMissingAttestation(
			pol.SBOMMissingPolicy(),
			types.CheckTypeSBOM,
			"no SBOM attestation found for image "+imageRef,
		)
	}

	payloads := make([][]byte, 0, len(sbomAtts))
	for idx := range sbomAtts {
		payloads = append(payloads, sbomAtts[idx].Payload)
	}

	result, err := sbom.VerifyMultiple(payloads, pol, digest)
	if err != nil {
		slog.ErrorContext(ctx, "SBOM verification error",
			"error", err,
			"reason", "verification_error",
			"image", imageRef,
		)

		met.VerificationTotal.WithLabelValues(
			string(types.CheckTypeSBOM), "error", namespace,
		).Inc()

		return types.FailResult(
			types.CheckTypeSBOM,
			fmt.Sprintf(
				"SBOM verification error for %s: %s", imageRef, err,
			),
			err,
		)
	}

	return result
}

func runSLSACheck(
	ctx context.Context,
	slsaAtts []attestation.VerifiedAttestation,
	pol *policy.Policy, met *metrics.Metrics, imageRef, digest, namespace string,
) *types.CheckResult {
	start := time.Now()

	defer func() {
		met.VerificationDuration.WithLabelValues(string(types.CheckTypeSLSA)).Observe(
			time.Since(start).Seconds(),
		)
	}()

	if len(slsaAtts) == 0 {
		slog.WarnContext(ctx, "No provenance attestation found",
			"reason", "missing_attestation",
			"image", imageRef,
		)

		return handleMissingAttestation(
			pol.SLSAMissingPolicy(),
			types.CheckTypeSLSA,
			"no provenance attestation found for image "+imageRef,
		)
	}

	result, err := slsa.VerifyMultiple(slsaAtts, pol, digest)
	if err != nil {
		slog.ErrorContext(ctx, "SLSA verification error",
			"error", err,
			"reason", "verification_error",
			"image", imageRef,
		)

		met.VerificationTotal.WithLabelValues(string(types.CheckTypeSLSA), "error", namespace).Inc()

		return types.FailResult(
			types.CheckTypeSLSA,
			fmt.Sprintf("SLSA verification error for %s: %s", imageRef, err),
			err,
		)
	}

	return result
}

func runVEXCheck(
	ctx context.Context,
	vexAtts []attestation.VerifiedAttestation,
	pol *policy.Policy, met *metrics.Metrics, imageRef, digest, namespace string,
	parsedRef name.Reference,
) *types.CheckResult {
	start := time.Now()

	defer func() {
		met.VerificationDuration.WithLabelValues(string(types.CheckTypeVEX)).Observe(
			time.Since(start).Seconds(),
		)
	}()

	if len(vexAtts) == 0 {
		slog.WarnContext(ctx, "No VEX attestation found",
			"reason", "missing_attestation",
			"image", imageRef,
		)

		return handleMissingAttestation(
			pol.VEXMissingPolicy(),
			types.CheckTypeVEX,
			"no VEX attestation found for image "+imageRef,
		)
	}

	payloads := make([][]byte, 0, len(vexAtts))
	for idx := range vexAtts {
		payloads = append(payloads, vexAtts[idx].Payload)
	}

	result, err := vex.VerifyMultiple(ctx, payloads, pol, imageRef, digest, parsedRef)
	if err != nil {
		slog.ErrorContext(ctx, "VEX verification error",
			"error", err,
			"reason", "verification_error",
			"image", imageRef,
		)

		met.VerificationTotal.WithLabelValues(string(types.CheckTypeVEX), "error", namespace).Inc()

		return types.FailResult(
			types.CheckTypeVEX,
			fmt.Sprintf("VEX verification error for %s: %s", imageRef, err),
			err,
		)
	}

	return result
}

func runNotationCheck(
	ctx context.Context,
	notationAtts []attestation.VerifiedAttestation,
	pol *policy.Policy, met *metrics.Metrics,
	imageRef, digest, namespace string,
) *types.CheckResult {
	start := time.Now()

	defer func() {
		met.VerificationDuration.WithLabelValues(
			string(types.CheckTypeNotation),
		).Observe(time.Since(start).Seconds())
	}()

	if len(notationAtts) == 0 {
		slog.WarnContext(ctx, "No Notation signature found",
			"reason", "missing_signature",
			"image", imageRef,
		)

		return handleMissingAttestation(
			pol.NotationMissingPolicy(),
			types.CheckTypeNotation,
			"no Notation signature found for image "+imageRef,
		)
	}

	result, err := notation.VerifyMultiple(
		ctx, notationAtts, imageRef, digest, pol,
	)
	if err != nil {
		slog.ErrorContext(ctx, "Notation verification error",
			"error", err,
			"reason", "verification_error",
			"image", imageRef,
		)

		met.VerificationTotal.WithLabelValues(
			string(types.CheckTypeNotation), "error", namespace,
		).Inc()

		return types.FailResult(
			types.CheckTypeNotation,
			fmt.Sprintf(
				"Notation verification error for %s: %s", imageRef, err,
			),
			err,
		)
	}

	return result
}

func runCELCheck(
	pol *policy.Policy, imageRef, digest, namespace string,
	parsedRef name.Reference, result *types.Result,
) *types.CheckResult {
	if pol.CompiledCEL == nil {
		return nil
	}

	registry, repository := extractRegistryRepo(parsedRef, imageRef)

	var slsaResult, vexResult, sbomResult *types.CheckResult

	for idx := range result.CheckResults {
		switch result.CheckResults[idx].Type {
		case types.CheckTypeSLSA:
			slsaResult = &result.CheckResults[idx]
		case types.CheckTypeVEX:
			vexResult = &result.CheckResults[idx]
		case types.CheckTypeSBOM:
			sbomResult = &result.CheckResults[idx]
		case types.CheckTypeVSA, types.CheckTypeFetch, types.CheckTypePolicy,
			types.CheckTypeCEL, types.CheckTypeNotation:
			// Not used for CEL variable construction.
		}
	}

	vars := celengine.BuildVars(
		imageRef, registry, repository, digest, namespace,
		slsaResult, vexResult, sbomResult,
	)

	return celengine.Evaluate(pol.CompiledCEL, vars)
}

func extractRegistryRepo(
	parsedRef name.Reference, imageRef string,
) (reg, repo string) {
	if parsedRef == nil {
		return imageRef, imageRef
	}

	ctx := parsedRef.Context()
	reg = ctx.RegistryStr()
	repo = ctx.RepositoryStr()

	// Remove registry prefix from full repository path if present.
	repo = strings.TrimPrefix(repo, reg+"/")

	return reg, repo
}

func resultHasFailures(result *types.Result) bool {
	if !result.Allowed {
		return true
	}

	for idx := range result.CheckResults {
		if !result.CheckResults[idx].Passed {
			return true
		}
	}

	return false
}

func resultShouldUseShorterTTL(result *types.Result) bool {
	if resultHasFailures(result) {
		return true
	}

	for idx := range result.CheckResults {
		if result.CheckResults[idx].Type == types.CheckTypeFetch {
			return true
		}
	}

	return false
}

func combineResults(checks ...*types.CheckResult) *types.Result {
	result := &types.Result{
		Allowed:      true,
		Reason:       "",
		CheckResults: nil,
	}

	for _, check := range checks {
		if check == nil {
			continue
		}

		result.CheckResults = append(result.CheckResults, *check)
		applyCheckResult(result, check)
	}

	return result
}

func applyCheckResult(result *types.Result, check *types.CheckResult) {
	if !check.Passed {
		result.Allowed = false
		appendReason(result, check.Detail)

		return
	}

	if check.Status == types.StatusWarn {
		appendReason(result, check.Detail)
	}
}

func appendReason(result *types.Result, detail string) {
	if result.Reason == "" {
		result.Reason = detail
	} else {
		result.Reason += "; " + detail
	}
}

type attestationBins struct {
	vsa      []attestation.VerifiedAttestation
	slsa     []attestation.VerifiedAttestation
	vex      []attestation.VerifiedAttestation
	notation []attestation.VerifiedAttestation
	sbom     []attestation.VerifiedAttestation
}

func binAttestations(attestations []attestation.VerifiedAttestation) attestationBins {
	bins := attestationBins{
		vsa:      make([]attestation.VerifiedAttestation, 0, len(attestations)),
		slsa:     make([]attestation.VerifiedAttestation, 0, len(attestations)),
		vex:      make([]attestation.VerifiedAttestation, 0, len(attestations)),
		notation: make([]attestation.VerifiedAttestation, 0, len(attestations)),
		sbom:     make([]attestation.VerifiedAttestation, 0, len(attestations)),
	}

	for idx := range attestations {
		// Route by signature type first: Notation signatures carry
		// signature manifests, not in-toto attestation payloads.
		if attestations[idx].SignatureType == attestation.SignatureTypeNotation {
			bins.notation = append(bins.notation, attestations[idx])

			continue
		}

		switch attestations[idx].PredicateType {
		case attestation.PredicateVSA:
			bins.vsa = append(bins.vsa, attestations[idx])
		case attestation.PredicateSLSAProvenanceV1:
			bins.slsa = append(bins.slsa, attestations[idx])
		case attestation.PredicateOpenVEX:
			bins.vex = append(bins.vex, attestations[idx])
		case attestation.PredicateCycloneDX:
			bins.vex = append(bins.vex, attestations[idx])
			bins.sbom = append(bins.sbom, attestations[idx])
		case attestation.PredicateSPDX:
			bins.sbom = append(bins.sbom, attestations[idx])
		}
	}

	return bins
}

func handleMissingAttestation(
	pol types.Action, checkType types.CheckType, detail string,
) *types.CheckResult {
	switch pol {
	case types.ActionDeny:
		return types.FailResult(checkType, detail, nil)
	case types.ActionWarn:
		return types.WarnResult(checkType, detail)
	case types.ActionAllow:
		return types.PassResult(checkType, detail)
	default:
		slog.Warn("Unrecognized missing attestation policy, defaulting to deny",
			"policy", pol,
			"check", checkType,
		)

		return types.FailResult(checkType, detail, nil)
	}
}

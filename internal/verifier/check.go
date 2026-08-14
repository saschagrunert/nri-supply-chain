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
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/buildenv"
	celengine "github.com/saschagrunert/nri-supply-chain/internal/cel"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/notation"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/sbom"
	"github.com/saschagrunert/nri-supply-chain/internal/scai"
	"github.com/saschagrunert/nri-supply-chain/internal/slsa"
	"github.com/saschagrunert/nri-supply-chain/internal/source"
	"github.com/saschagrunert/nri-supply-chain/internal/testresult"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
	"github.com/saschagrunert/nri-supply-chain/internal/vex"
	"github.com/saschagrunert/nri-supply-chain/internal/vsa"
	"github.com/saschagrunert/nri-supply-chain/internal/vulnscan"
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
			ctx, state.config, state.metrics,
			fmt.Errorf("%w: %s", ErrCircuitBreakerOpen, imageRef),
			imageRef, host,
		)
	}

	if state.fetchSem != nil {
		release, semErr := acquireFetchSlots(ctx, state, host)
		if semErr != nil {
			recordBreakerFailure(ctx, breaker, state.metrics, host, state.config.FetchFailurePolicy)

			return handleFetchError(ctx, state.config, state.metrics, semErr, imageRef, host)
		}

		defer release()
	}

	attestations, attestDigest, fetchErr := timedFetchAttestations(
		ctx, state, imageRef, digest, indexDigest, pol, host, parsedRef,
	)
	if fetchErr != nil {
		recordBreakerFailure(ctx, breaker, state.metrics, host, state.config.FetchFailurePolicy)

		return handleFetchError(ctx, state.config, state.metrics, fetchErr, imageRef, host)
	}

	if breaker != nil {
		breaker.RecordSuccess()
	}

	bins := binAttestations(ctx, attestations, imageRef)

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

	result := runParallelChecks(ctx, bins, pol, met, imageRef, digest, parsedRef)

	if len(bins.vsa) == 0 {
		prependVSAWarning(result, pol, "no VSA attestation found for image "+imageRef)
	}

	celCheck := runCELCheck(pol, met, imageRef, digest, namespace, parsedRef, result)
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

type missingCheck struct {
	checkType     types.CheckType
	missingPolicy types.Action
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

	missingChecks := []missingCheck{
		{types.CheckTypeSLSA, pol.SLSAMissingPolicy()},
		{types.CheckTypeVEX, pol.VEXMissingPolicy()},
	}

	if pol.Notation != nil {
		missingChecks = append(missingChecks,
			missingCheck{types.CheckTypeNotation, pol.NotationMissingPolicy()},
		)
	}

	missingChecks = append(missingChecks,
		missingCheck{types.CheckTypeSBOM, pol.SBOMMissingPolicy()},
		missingCheck{types.CheckTypeSCAI, pol.SCAIMissingPolicy()},
		missingCheck{types.CheckTypeSource, pol.SourceMissingPolicy()},
		missingCheck{types.CheckTypeBuildEnv, pol.BuildEnvMissingPolicy()},
		missingCheck{types.CheckTypeVulnScan, pol.VulnScanMissingPolicy()},
		missingCheck{types.CheckTypeTestResult, pol.TestResultMissingPolicy()},
	)

	results := make([]*types.CheckResult, 0, len(missingChecks))

	for _, mc := range missingChecks {
		checkResult := handleMissingAttestation(mc.missingPolicy, mc.checkType, detail)
		met.VerificationDuration.WithLabelValues(string(mc.checkType)).Observe(0)

		results = append(results, checkResult)
	}

	result := combineResults(results...)

	prependVSAWarning(result, pol, detail)

	return result
}

func timedFetchAttestations(
	ctx context.Context, state *snapshot,
	imageRef, digest, indexDigest string, pol *policy.Policy,
	host string, parsedRef name.Reference,
) ([]attestation.VerifiedAttestation, string, error) {
	start := time.Now()

	defer func() {
		state.metrics.FetchDuration.WithLabelValues(host).
			Observe(time.Since(start).Seconds())
	}()

	return fetchAttestations(ctx, state, imageRef, digest, indexDigest, pol, parsedRef)
}

func fetchAttestations(
	ctx context.Context, state *snapshot,
	imageRef, digest, indexDigest string, pol *policy.Policy,
	parsedRef name.Reference,
) ([]attestation.VerifiedAttestation, string, error) {
	opts := buildFetchOpts(pol, digest, state.config.FetchTimeout.Duration, parsedRef)

	var indexErr error

	// When the image resolved from a manifest list, try the index digest
	// first: cosign attaches attestations to the manifest list digest.
	if indexDigest != "" {
		indexOpts := buildFetchOpts(pol, indexDigest, state.config.FetchTimeout.Duration, parsedRef)

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
	parsedRef name.Reference,
) *attestation.FetchOptions {
	opts := &attestation.FetchOptions{
		RequireTransparencyLog: pol.Signatures != nil && pol.Signatures.RequireTransparencyLog,
		Timeout:                timeout,
		Digest:                 digest,
		ParsedRef:              parsedRef,
	}

	if pol.Trust != nil {
		opts.TrustedIssuers = pol.Trust.Issuers
		opts.SANPatterns = pol.Trust.SANPatterns

		totalKeys := 0
		for idx := range pol.Trust.Verifiers {
			totalKeys += len(pol.Trust.Verifiers[idx].Keys)
		}

		keys := make([]attestation.TrustedKeyRef, 0, totalKeys)

		for idx := range pol.Trust.Verifiers {
			for _, keyPath := range pol.Trust.Verifiers[idx].Keys {
				keys = append(keys, attestation.TrustedKeyRef{
					Path:      keyPath,
					NotBefore: pol.Trust.Verifiers[idx].NotBeforeTime,
					NotAfter:  pol.Trust.Verifiers[idx].NotAfterTime,
				})
			}
		}

		opts.TrustedKeys = keys
	}

	return opts
}

func handleFetchError(
	ctx context.Context, cfg *config.Config, met *metrics.Metrics,
	fetchErr error, imageRef, host string,
) *types.Result {
	met.FetchErrorsTotal.WithLabelValues("attestation", host).Inc()

	slog.WarnContext(ctx, "Attestation fetch failed",
		"image", imageRef, "host", host, "error", fetchErr,
	)

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
		vsaResult, err := vsa.Verify(ctx, vsaAttestations[idx].Payload, pol, digestRef, nil)
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
	imageRef, digest string,
	parsedRef name.Reference,
) *types.Result {
	checks := []struct {
		checkType types.CheckType
		fn        func() *types.CheckResult
	}{
		{types.CheckTypeSLSA, func() *types.CheckResult {
			return runSLSACheck(ctx, bins.slsa, pol, met, imageRef, digest)
		}},
		{types.CheckTypeVEX, func() *types.CheckResult {
			return runVEXCheck(ctx, bins.vex, pol, met, imageRef, digest, parsedRef)
		}},
		{types.CheckTypeNotation, func() *types.CheckResult {
			return runNotationCheck(ctx, bins.notation, pol, met, imageRef, digest)
		}},
		{types.CheckTypeSBOM, func() *types.CheckResult {
			return runSBOMCheck(ctx, bins.sbom, pol, met, imageRef, digest)
		}},
		{types.CheckTypeSCAI, func() *types.CheckResult {
			return runSCAICheck(ctx, bins.scai, pol, met, imageRef, digest)
		}},
		{types.CheckTypeSource, func() *types.CheckResult {
			return runSourceCheck(ctx, bins.source, pol, met, imageRef, digest)
		}},
		{types.CheckTypeBuildEnv, func() *types.CheckResult {
			return runBuildEnvCheck(ctx, bins.buildenv, pol, met, imageRef, digest)
		}},
		{types.CheckTypeVulnScan, func() *types.CheckResult {
			return runVulnScanCheck(ctx, bins.vulnscan, pol, met, imageRef, digest)
		}},
		{types.CheckTypeTestResult, func() *types.CheckResult {
			return runTestResultCheck(ctx, bins.testresult, pol, met, imageRef, digest)
		}},
	}

	results := make([]*types.CheckResult, len(checks))

	var waitGroup sync.WaitGroup

	for idx, chk := range checks {
		waitGroup.Add(1)

		go runParallelCheck(&waitGroup, &results[idx], chk.checkType, chk.fn)
	}

	waitGroup.Wait()

	return combineResults(results...)
}

func runParallelCheck(
	waitGroup *sync.WaitGroup,
	result **types.CheckResult,
	checkType types.CheckType,
	checkFunc func() *types.CheckResult,
) {
	defer waitGroup.Done()
	defer func() {
		if r := recover(); r != nil {
			slog.Error("Panic during check",
				"type", checkType,
				"panic", r, "stack", string(debug.Stack()))

			*result = types.FailResult(
				checkType,
				"internal error during "+string(checkType)+" check", nil,
			)
		}
	}()

	*result = checkFunc()
}

const (
	reasonMissingAttestation = "missing_attestation"
	reasonMissingSignature   = "missing_signature"
)

type checkRunner struct {
	checkType     types.CheckType
	label         string
	missingPolicy types.Action
	missingLog    string
	missingReason string
	missingDetail string
}

func (cr *checkRunner) run(
	ctx context.Context,
	met *metrics.Metrics,
	imageRef string,
	hasAttestations bool,
	verify func() (*types.CheckResult, error),
) *types.CheckResult {
	start := time.Now()

	defer func() {
		met.VerificationDuration.WithLabelValues(
			string(cr.checkType),
		).Observe(time.Since(start).Seconds())
	}()

	if !hasAttestations {
		logMissingAttestation(
			ctx, cr.missingPolicy,
			cr.missingLog, imageRef, cr.missingReason,
		)

		return handleMissingAttestation(
			cr.missingPolicy,
			cr.checkType,
			cr.missingDetail+imageRef,
		)
	}

	result, err := verify()
	if err != nil {
		slog.ErrorContext(ctx,
			cr.label+" verification error",
			"error", err,
			"reason", "verification_error",
			"image", imageRef,
		)

		return types.FailResult(
			cr.checkType,
			fmt.Sprintf(
				"%s verification error for %s: %s",
				cr.label, imageRef, err,
			),
			err,
		)
	}

	return result
}

func runSBOMCheck(
	ctx context.Context,
	sbomAtts []attestation.VerifiedAttestation,
	pol *policy.Policy, met *metrics.Metrics,
	imageRef, digest string,
) *types.CheckResult {
	runner := &checkRunner{
		checkType:     types.CheckTypeSBOM,
		label:         "SBOM",
		missingPolicy: pol.SBOMMissingPolicy(),
		missingLog:    "No SBOM attestation found",
		missingReason: reasonMissingAttestation,
		missingDetail: "no SBOM attestation found for image ",
	}

	return runner.run(
		ctx, met, imageRef, len(sbomAtts) > 0,
		func() (*types.CheckResult, error) {
			return sbom.VerifyMultiple(ctx, extractPayloads(sbomAtts), pol, digest)
		},
	)
}

func runSCAICheck(
	ctx context.Context,
	scaiAtts []attestation.VerifiedAttestation,
	pol *policy.Policy, met *metrics.Metrics,
	imageRef, digest string,
) *types.CheckResult {
	runner := &checkRunner{
		checkType:     types.CheckTypeSCAI,
		label:         "SCAI",
		missingPolicy: pol.SCAIMissingPolicy(),
		missingLog:    "No SCAI attestation found",
		missingReason: reasonMissingAttestation,
		missingDetail: "no SCAI attestation found for image ",
	}

	return runner.run(
		ctx, met, imageRef, len(scaiAtts) > 0,
		func() (*types.CheckResult, error) {
			return scai.VerifyMultiple(ctx, extractPayloads(scaiAtts), pol, digest)
		},
	)
}

func runSLSACheck(
	ctx context.Context,
	slsaAtts []attestation.VerifiedAttestation,
	pol *policy.Policy, met *metrics.Metrics,
	imageRef, digest string,
) *types.CheckResult {
	runner := &checkRunner{
		checkType:     types.CheckTypeSLSA,
		label:         "SLSA",
		missingPolicy: pol.SLSAMissingPolicy(),
		missingLog:    "No provenance attestation found",
		missingReason: reasonMissingAttestation,
		missingDetail: "no provenance attestation found for image ",
	}

	return runner.run(
		ctx, met, imageRef, len(slsaAtts) > 0,
		func() (*types.CheckResult, error) {
			return slsa.VerifyMultiple(ctx, slsaAtts, pol, digest)
		},
	)
}

func runVEXCheck(
	ctx context.Context,
	vexAtts []attestation.VerifiedAttestation,
	pol *policy.Policy, met *metrics.Metrics,
	imageRef, digest string,
	parsedRef name.Reference,
) *types.CheckResult {
	runner := &checkRunner{
		checkType:     types.CheckTypeVEX,
		label:         "VEX",
		missingPolicy: pol.VEXMissingPolicy(),
		missingLog:    "No VEX attestation found",
		missingReason: reasonMissingAttestation,
		missingDetail: "no VEX attestation found for image ",
	}

	return runner.run(
		ctx, met, imageRef, len(vexAtts) > 0,
		func() (*types.CheckResult, error) {
			return vex.VerifyMultiple(
				ctx, extractPayloads(vexAtts), pol, imageRef, digest, parsedRef,
			)
		},
	)
}

func runNotationCheck(
	ctx context.Context,
	notationAtts []attestation.VerifiedAttestation,
	pol *policy.Policy, met *metrics.Metrics,
	imageRef, digest string,
) *types.CheckResult {
	runner := &checkRunner{
		checkType:     types.CheckTypeNotation,
		label:         "Notation",
		missingPolicy: pol.NotationMissingPolicy(),
		missingLog:    "No Notation signature found",
		missingReason: reasonMissingSignature,
		missingDetail: "no Notation signature found for image ",
	}

	return runner.run(
		ctx, met, imageRef, len(notationAtts) > 0,
		func() (*types.CheckResult, error) {
			return notation.VerifyMultiple(
				ctx, notationAtts, imageRef, digest, pol,
			)
		},
	)
}

func runSourceCheck(
	ctx context.Context,
	sourceAtts []attestation.VerifiedAttestation,
	pol *policy.Policy, met *metrics.Metrics,
	imageRef, digest string,
) *types.CheckResult {
	runner := &checkRunner{
		checkType:     types.CheckTypeSource,
		label:         "Source",
		missingPolicy: pol.SourceMissingPolicy(),
		missingLog:    "No source attestation found",
		missingReason: reasonMissingAttestation,
		missingDetail: "no source attestation found for image ",
	}

	return runner.run(
		ctx, met, imageRef, len(sourceAtts) > 0,
		func() (*types.CheckResult, error) {
			return source.VerifyMultiple(ctx, extractPayloads(sourceAtts), pol, digest)
		},
	)
}

func runBuildEnvCheck(
	ctx context.Context,
	buildenvAtts []attestation.VerifiedAttestation,
	pol *policy.Policy, met *metrics.Metrics,
	imageRef, digest string,
) *types.CheckResult {
	runner := &checkRunner{
		checkType:     types.CheckTypeBuildEnv,
		label:         "BuildEnv",
		missingPolicy: pol.BuildEnvMissingPolicy(),
		missingLog:    "No build environment attestation found",
		missingReason: reasonMissingAttestation,
		missingDetail: "no build environment attestation found for image ",
	}

	return runner.run(
		ctx, met, imageRef, len(buildenvAtts) > 0,
		func() (*types.CheckResult, error) {
			return buildenv.VerifyMultiple(ctx, extractPayloads(buildenvAtts), pol, digest)
		},
	)
}

func runVulnScanCheck(
	ctx context.Context,
	vulnscanAtts []attestation.VerifiedAttestation,
	pol *policy.Policy, met *metrics.Metrics,
	imageRef, digest string,
) *types.CheckResult {
	runner := &checkRunner{
		checkType:     types.CheckTypeVulnScan,
		label:         "VulnScan",
		missingPolicy: pol.VulnScanMissingPolicy(),
		missingLog:    "No vulnerability scan attestation found",
		missingReason: reasonMissingAttestation,
		missingDetail: "no vulnerability scan attestation found for image ",
	}

	return runner.run(
		ctx, met, imageRef, len(vulnscanAtts) > 0,
		func() (*types.CheckResult, error) {
			return vulnscan.VerifyMultiple(ctx, extractPayloads(vulnscanAtts), pol, digest)
		},
	)
}

func runTestResultCheck(
	ctx context.Context,
	testresultAtts []attestation.VerifiedAttestation,
	pol *policy.Policy, met *metrics.Metrics,
	imageRef, digest string,
) *types.CheckResult {
	runner := &checkRunner{
		checkType:     types.CheckTypeTestResult,
		label:         "TestResult",
		missingPolicy: pol.TestResultMissingPolicy(),
		missingLog:    "No test result attestation found",
		missingReason: reasonMissingAttestation,
		missingDetail: "no test result attestation found for image ",
	}

	return runner.run(
		ctx, met, imageRef, len(testresultAtts) > 0,
		func() (*types.CheckResult, error) {
			return testresult.VerifyMultiple(ctx, extractPayloads(testresultAtts), pol, digest)
		},
	)
}

func runCELCheck(
	pol *policy.Policy, met *metrics.Metrics,
	imageRef, digest, namespace string,
	parsedRef name.Reference, result *types.Result,
) *types.CheckResult {
	if pol.CompiledCEL == nil {
		return nil
	}

	registry, repository := extractRegistryRepo(parsedRef, imageRef)

	checkResults := make(map[types.CheckType]*types.CheckResult, len(result.CheckResults))

	for idx := range result.CheckResults {
		checkResults[result.CheckResults[idx].Type] = &result.CheckResults[idx]
	}

	vars := celengine.BuildVars(
		imageRef, registry, repository, digest, namespace,
		checkResults[types.CheckTypeSLSA],
		checkResults[types.CheckTypeVEX],
		checkResults[types.CheckTypeVSA],
		checkResults[types.CheckTypeSBOM],
		checkResults[types.CheckTypeNotation],
		checkResults[types.CheckTypeSCAI],
		checkResults[types.CheckTypeSource],
		checkResults[types.CheckTypeBuildEnv],
		checkResults[types.CheckTypeVulnScan],
		checkResults[types.CheckTypeTestResult],
	)

	timer := prometheus.NewTimer(met.CELEvaluationDuration)
	defer timer.ObserveDuration()

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
	vsa        []attestation.VerifiedAttestation
	slsa       []attestation.VerifiedAttestation
	vex        []attestation.VerifiedAttestation
	notation   []attestation.VerifiedAttestation
	sbom       []attestation.VerifiedAttestation
	scai       []attestation.VerifiedAttestation
	source     []attestation.VerifiedAttestation
	buildenv   []attestation.VerifiedAttestation
	vulnscan   []attestation.VerifiedAttestation
	testresult []attestation.VerifiedAttestation
}

func binAttestations( //nolint:cyclop // additional predicate type adds a branch
	ctx context.Context, attestations []attestation.VerifiedAttestation, imageRef string,
) attestationBins {
	var bins attestationBins

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
		case attestation.PredicateSLSAProvenanceV1, attestation.PredicateSLSAProvenanceV02:
			bins.slsa = append(bins.slsa, attestations[idx])
		case attestation.PredicateOpenVEX:
			bins.vex = append(bins.vex, attestations[idx])
		case attestation.PredicateCycloneDX:
			bins.vex = append(bins.vex, attestations[idx])
			bins.sbom = append(bins.sbom, attestations[idx])
		case attestation.PredicateSPDX:
			bins.sbom = append(bins.sbom, attestations[idx])
		case attestation.PredicateSCAI:
			bins.scai = append(bins.scai, attestations[idx])
		case attestation.PredicateSLSASourceV1:
			bins.source = append(bins.source, attestations[idx])
		case attestation.PredicateBuildEnv:
			bins.buildenv = append(bins.buildenv, attestations[idx])
		case attestation.PredicateVulnScan:
			bins.vulnscan = append(bins.vulnscan, attestations[idx])
		case attestation.PredicateTestResult:
			bins.testresult = append(bins.testresult, attestations[idx])
		case attestation.PredicateCosignSignature:
			slog.DebugContext(ctx,
				"Skipping bare cosign signature attestation",
				"image", imageRef,
			)
		default:
			slog.WarnContext(ctx,
				"Skipping attestation with unrecognized predicate type",
				"predicateType", attestations[idx].PredicateType,
				"image", imageRef,
			)
		}
	}

	return bins
}

func logMissingAttestation(
	ctx context.Context, pol types.Action, msg, imageRef, reason string,
) {
	attrs := []any{
		"reason", reason,
		"image", imageRef,
	}

	if pol == types.ActionAllow {
		slog.DebugContext(ctx, msg, attrs...)
	} else {
		slog.WarnContext(ctx, msg, attrs...)
	}
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

func extractPayloads(atts []attestation.VerifiedAttestation) [][]byte {
	payloads := make([][]byte, 0, len(atts))
	for idx := range atts {
		payloads = append(payloads, atts[idx].Payload)
	}

	return payloads
}

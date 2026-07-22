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
	"sync"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/slsa"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
	"github.com/saschagrunert/nri-supply-chain/internal/vex"
	"github.com/saschagrunert/nri-supply-chain/internal/vsa"
)

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

func runChecks(
	ctx context.Context, state *snapshot,
	pol *policy.Policy, imageRef, digest, namespace string,
) *types.Result {
	if state.fetcher == nil {
		return runChecksWithoutFetcher(pol, state.metrics, imageRef)
	}

	host := registryHost(imageRef)
	breaker := registryBreakerByHost(state.circuitBreakers, host)

	if breaker != nil && !breaker.Allow() {
		return handleFetchError(
			state.config, state.metrics,
			fmt.Errorf("%w: %s", ErrCircuitBreakerOpen, imageRef),
			imageRef, host,
		)
	}

	if state.fetchSem != nil {
		semErr := state.fetchSem.Acquire(ctx, 1)
		if semErr != nil {
			return handleFetchError(
				state.config, state.metrics,
				fmt.Errorf("fetch concurrency limit: %w", semErr),
				imageRef, host,
			)
		}

		defer state.fetchSem.Release(1)
	}

	attestations, fetchErr := fetchAttestations(ctx, state, imageRef, digest, pol)
	if fetchErr != nil {
		recordBreakerFailure(ctx, breaker, state.metrics, host, state.config.FetchFailurePolicy)

		return handleFetchError(state.config, state.metrics, fetchErr, imageRef, host)
	}

	if breaker != nil {
		breaker.RecordSuccess()
	}

	bins := binAttestations(attestations)

	vsaResult := checkVSA(ctx, bins.vsa, pol, imageRef, digest, state.metrics)
	if vsaResult != nil {
		return vsaResult
	}

	return runParallelChecks(ctx, &bins, pol, state.metrics, imageRef, digest, namespace)
}

func runChecksWithoutFetcher(
	pol *policy.Policy, met *metrics.Metrics, imageRef string,
) *types.Result {
	detail := "no attestation fetcher configured for image " + imageRef

	slsaResult := handleMissingAttestation(
		pol.SLSAMissingPolicy(), "slsa", detail,
	)

	met.VerificationDuration.WithLabelValues("slsa").Observe(0)

	vexResult := handleMissingAttestation(
		pol.VEXMissingPolicy(), "vex", detail,
	)

	met.VerificationDuration.WithLabelValues("vex").Observe(0)

	return combineResults(slsaResult, vexResult)
}

func fetchAttestations(
	ctx context.Context, state *snapshot,
	imageRef, digest string, pol *policy.Policy,
) ([]attestation.VerifiedAttestation, error) {
	opts := &attestation.FetchOptions{
		RequireTransparencyLog: pol.Signatures != nil && pol.Signatures.RequireTransparencyLog,
		Timeout:                state.config.FetchTimeout.Duration,
		Digest:                 digest,
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
	fetchErr error, imageRef, host string,
) *types.Result {
	met.FetchErrorsTotal.WithLabelValues("attestation", host).Inc()

	detail := fmt.Sprintf("attestation fetch failed for %s: %s", imageRef, fetchErr)

	checkResult := handleMissingAttestation(cfg.FetchFailurePolicy, "fetch", detail)

	return &types.Result{
		Allowed:      checkResult.Passed,
		Reason:       checkResult.Detail,
		CheckResults: []types.CheckResult{*checkResult},
	}
}

func checkVSA(
	ctx context.Context, vsaAttestations []attestation.VerifiedAttestation,
	pol *policy.Policy, imageRef, digest string, met *metrics.Metrics,
) *types.Result {
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
	ctx context.Context, bins *attestationBins,
	pol *policy.Policy, met *metrics.Metrics, imageRef, digest, namespace string,
) *types.Result {
	var (
		slsaResult *types.CheckResult
		vexResult  *types.CheckResult
		waitGroup  sync.WaitGroup
	)

	const numChecks = 2

	waitGroup.Add(numChecks)

	go func() {
		defer waitGroup.Done()

		slsaResult = runSLSACheck(ctx, bins.slsa, pol, met, imageRef, digest, namespace)
	}()

	go func() {
		defer waitGroup.Done()

		vexResult = runVEXCheck(ctx, bins.vex, pol, met, imageRef, digest, namespace)
	}()

	waitGroup.Wait()

	return combineResults(slsaResult, vexResult)
}

func runSLSACheck(
	ctx context.Context,
	slsaAtts []attestation.VerifiedAttestation,
	pol *policy.Policy, met *metrics.Metrics, imageRef, digest, namespace string,
) *types.CheckResult {
	start := time.Now()

	defer func() {
		met.VerificationDuration.WithLabelValues("slsa").Observe(
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
			"slsa",
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

		met.VerificationTotal.WithLabelValues("slsa", "error", namespace).Inc()

		return handleMissingAttestation(
			pol.SLSAMissingPolicy(),
			"slsa",
			fmt.Sprintf("SLSA verification error for %s: %s", imageRef, err),
		)
	}

	return result
}

func runVEXCheck(
	ctx context.Context,
	vexAtts []attestation.VerifiedAttestation,
	pol *policy.Policy, met *metrics.Metrics, imageRef, digest, namespace string,
) *types.CheckResult {
	start := time.Now()

	defer func() {
		met.VerificationDuration.WithLabelValues("vex").Observe(
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
		slog.ErrorContext(ctx, "VEX verification error",
			"error", err,
			"reason", "verification_error",
			"image", imageRef,
		)

		met.VerificationTotal.WithLabelValues("vex", "error", namespace).Inc()

		return handleMissingAttestation(
			pol.VEXMissingPolicy(),
			"vex",
			fmt.Sprintf("VEX verification error for %s: %s", imageRef, err),
		)
	}

	return result
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
		if result.CheckResults[idx].Type == "fetch" {
			return true
		}
	}

	return false
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

type attestationBins struct {
	vsa  []attestation.VerifiedAttestation
	slsa []attestation.VerifiedAttestation
	vex  []attestation.VerifiedAttestation
}

func binAttestations(attestations []attestation.VerifiedAttestation) attestationBins {
	var bins attestationBins

	for idx := range attestations {
		switch attestations[idx].PredicateType {
		case attestation.PredicateVSA:
			bins.vsa = append(bins.vsa, attestations[idx])
		case attestation.PredicateSLSAProvenanceV1:
			bins.slsa = append(bins.slsa, attestations[idx])
		case attestation.PredicateOpenVEX:
			bins.vex = append(bins.vex, attestations[idx])
		}
	}

	return bins
}

func handleMissingAttestation(
	pol policy.Action, checkType, detail string,
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

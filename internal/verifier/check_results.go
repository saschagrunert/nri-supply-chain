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

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
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

func checkVSAMissing(
	pol *policy.Policy, imageRef string, met *metrics.Metrics,
) *types.Result {
	missingPolicy := pol.MissingPolicyFor(types.CheckTypeVSA)

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

func appendVSAWarning(result *types.Result, pol *policy.Policy, detail string) {
	if pol.MissingPolicyFor(types.CheckTypeVSA) != types.ActionWarn {
		return
	}

	vsaCheck := handleMissingAttestation(types.ActionWarn, types.CheckTypeVSA, detail)
	result.CheckResults = append(result.CheckResults, *vsaCheck)
	applyCheckResult(result, vsaCheck)
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
		CheckResults: make([]types.CheckResult, 0, len(checks)),
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

func logMissingAttestation(
	ctx context.Context, msg, imageRef, reason string,
) {
	slog.DebugContext(ctx, msg,
		"reason", reason,
		"image", imageRef,
	)
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

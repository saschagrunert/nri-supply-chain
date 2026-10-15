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
	"slices"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

// WarnWarnModeDefaults logs a warning when warn mode is used with all
// permissive defaults, which means no enforcement happens at all.
func WarnWarnModeDefaults(
	ctx context.Context, cfg *config.Config, policies map[string]*policy.Policy,
) {
	for namespace, pol := range policies {
		effectiveMode := pol.EffectiveMode(cfg.Verification)
		if effectiveMode != config.ModeWarn {
			continue
		}

		if !allMissingPoliciesAllow(pol) {
			continue
		}

		if cfg.FetchFailurePolicy != types.ActionWarn &&
			cfg.FetchFailurePolicy != types.ActionAllow {
			continue
		}

		label := namespace
		if label == "" {
			label = policy.DefaultPolicyLabel
		}

		slog.WarnContext(ctx,
			"warn mode with all-permissive defaults provides no enforcement;"+
				" set missing policies to deny or switch to enforce mode",
			"policy", label,
			"fetch_failure_policy", cfg.FetchFailurePolicy,
		)
	}
}

func allMissingPoliciesAllow(pol *policy.Policy) bool {
	for _, ct := range types.AttestationCheckTypes {
		if pol.MissingPolicyFor(ct) != types.ActionAllow {
			return false
		}
	}

	return true
}

// WarnEnforceDefaults logs warnings when enforce mode is used with
// permissive settings that may allow unverified containers through.
func WarnEnforceDefaults(
	ctx context.Context, cfg *config.Config, policies map[string]*policy.Policy,
) {
	if anyEnforceMode(cfg.Verification, policies) {
		warnPermissiveFetchPolicy(ctx, cfg)
	}

	for namespace, pol := range policies {
		effectiveMode := pol.EffectiveMode(cfg.Verification)
		if effectiveMode != config.ModeEnforce {
			continue
		}

		label := namespace
		if label == "" {
			label = policy.DefaultPolicyLabel
		}

		warnPermissiveMissingPolicies(ctx, label, pol)
		warnKeyOnlyWithoutTLog(ctx, label, pol)
	}
}

func anyEnforceMode(
	global config.VerificationMode, policies map[string]*policy.Policy,
) bool {
	if global == config.ModeEnforce {
		return true
	}

	for _, pol := range policies {
		if pol.EffectiveMode(global) == config.ModeEnforce {
			return true
		}
	}

	return false
}

func warnPermissiveFetchPolicy(ctx context.Context, cfg *config.Config) {
	switch cfg.FetchFailurePolicy {
	case types.ActionDeny:
	case types.ActionWarn, types.ActionAllow:
		slog.WarnContext(ctx,
			"enforce mode with permissive fetch_failure_policy allows containers on fetch failure",
			"fetch_failure_policy",
			cfg.FetchFailurePolicy,
			"circuit_breaker_threshold",
			cfg.CircuitBreakerThreshold,
		)
	}
}

// alwaysWarnedCheckTypes are the checks whose permissive missing policy is
// reported even without a policy section, because provenance and VEX are
// the attestations every policy is expected to cover.
//
//nolint:gochecknoglobals // immutable lookup table
var alwaysWarnedCheckTypes = []types.CheckType{types.CheckTypeSLSA, types.CheckTypeVEX}

// missingPolicyArtifacts names the attestations each check type admits
// images without, for the artifact field of the missing policy warning.
//
//nolint:gochecknoglobals // immutable lookup table
var missingPolicyArtifacts = map[types.CheckType]string{
	types.CheckTypeSLSA:         "SLSA provenance attestations",
	types.CheckTypeVEX:          "VEX attestations",
	types.CheckTypeVSA:          "VSA attestations",
	types.CheckTypeNotation:     "Notation signatures",
	types.CheckTypeSBOM:         "SBOM attestations",
	types.CheckTypeSCAI:         "SCAI attestations",
	types.CheckTypeSource:       "source attestations",
	types.CheckTypeBuildEnv:     "build environment attestations",
	types.CheckTypeVulnScan:     "vulnerability scan attestations",
	types.CheckTypeTestResult:   "test result attestations",
	types.CheckTypeRelease:      "release attestations",
	types.CheckTypeRuntimeTrace: "runtime trace attestations",
	types.CheckTypeScorecard:    "OpenSSF Scorecard attestations",
}

// warnPermissiveMissingPolicies warns about attestation sections of an
// enforcing policy whose missingPolicy admits images without the
// attestation. The sections come from the policy section registry, so every
// attestation type is covered.
func warnPermissiveMissingPolicies(ctx context.Context, label string, pol *policy.Policy) {
	for _, section := range policy.AttestationSections() {
		if !pol.HasSection(section.CheckType) &&
			!slices.Contains(alwaysWarnedCheckTypes, section.CheckType) {
			continue
		}

		action := pol.MissingPolicyFor(section.CheckType)
		if action != types.ActionAllow {
			continue
		}

		slog.WarnContext(ctx,
			"enforce mode with default missing_policy=allow allows containers without attestation",
			"check", string(section.CheckType),
			"artifact", missingPolicyArtifacts[section.CheckType],
			"setting", section.Name+".missingPolicy",
			"policy", label,
			string(section.CheckType)+"_missing_policy", action,
		)
	}
}

func warnKeyOnlyWithoutTLog(ctx context.Context, label string, pol *policy.Policy) {
	if pol.Signatures != nil && pol.Signatures.RequireTransparencyLog {
		return
	}

	if pol.Trust == nil || len(pol.Trust.Verifiers) == 0 {
		return
	}

	hasKeyOnly := false

	for idx := range pol.Trust.Verifiers {
		if len(pol.Trust.Verifiers[idx].Keys) > 0 && len(pol.Trust.Issuers) == 0 {
			hasKeyOnly = true

			break
		}
	}

	if !hasKeyOnly {
		return
	}

	slog.WarnContext(ctx,
		"enforce mode with key-only verification and "+
			"requireTransparencyLog=false; operator-configured "+
			"notBefore/notAfter provide basic time-scoping but "+
			"tlog entries give cryptographic proof of signing time",
		"policy", label,
	)
}

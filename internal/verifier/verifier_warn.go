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

//nolint:funlen // one entry per check type
func warnPermissiveMissingPolicies(ctx context.Context, label string, pol *policy.Policy) {
	type checkEntry struct {
		name, artifact, logKey, setting string
		enabled                         bool
		checkType                       types.CheckType
	}

	checks := []checkEntry{
		{
			"SLSA", "SLSA provenance attestations",
			"slsa_missing_policy", "missingPolicy",
			true, types.CheckTypeSLSA,
		},
		{
			"VEX", "VEX attestations",
			"vex_missing_policy", "vex.missingPolicy",
			true, types.CheckTypeVEX,
		},
		{
			"Notation", "Notation signatures",
			"notation_missing_policy", "notation.missingPolicy",
			pol.Notation != nil, types.CheckTypeNotation,
		},
		{
			"SBOM", "SBOM attestations",
			"sbom_missing_policy", "sbom.missingPolicy",
			pol.SBOM != nil, types.CheckTypeSBOM,
		},
		{
			"VSA", "VSA attestations",
			"vsa_missing_policy", "vsa.missingPolicy",
			pol.VSA != nil, types.CheckTypeVSA,
		},
		{
			"SCAI", "SCAI attestations",
			"scai_missing_policy", "scai.missingPolicy",
			pol.SCAI != nil, types.CheckTypeSCAI,
		},
		{
			"Source", "source attestations",
			"source_missing_policy", "source.missingPolicy",
			pol.Source != nil, types.CheckTypeSource,
		},
		{
			"BuildEnv", "build environment attestations",
			"buildenv_missing_policy", "buildEnv.missingPolicy",
			pol.BuildEnv != nil, types.CheckTypeBuildEnv,
		},
		{
			"VulnScan", "vulnerability scan attestations",
			"vulnscan_missing_policy", "vulnScan.missingPolicy",
			pol.VulnScan != nil, types.CheckTypeVulnScan,
		},
		{
			"TestResult", "test result attestations",
			"testresult_missing_policy", "testResult.missingPolicy",
			pol.TestResult != nil, types.CheckTypeTestResult,
		},
		{
			"Release", "release attestations",
			"release_missing_policy", "release.missingPolicy",
			pol.Release != nil, types.CheckTypeRelease,
		},
		{
			"RuntimeTrace", "runtime trace attestations",
			"runtimetrace_missing_policy", "runtimeTrace.missingPolicy",
			pol.RuntimeTrace != nil, types.CheckTypeRuntimeTrace,
		},
	}

	for _, chk := range checks {
		action := pol.MissingPolicyFor(chk.checkType)
		if !chk.enabled || action != types.ActionAllow {
			continue
		}

		slog.WarnContext(ctx,
			"enforce mode with default missing_policy=allow allows containers without attestation",
			"check", chk.name,
			"artifact", chk.artifact,
			"setting", chk.setting,
			"policy", label,
			chk.logKey, action,
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

	for _, v := range pol.Trust.Verifiers {
		if len(v.Keys) > 0 && len(pol.Trust.Issuers) == 0 {
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

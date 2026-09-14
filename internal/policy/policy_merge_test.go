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

package policy_test

import (
	"strings"
	"testing"

	celengine "github.com/saschagrunert/nri-supply-chain/internal/cel"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	testDefaultVerifierID = "default-verifier"
	testDefaultRuleName   = "default-rule"
	testComponentBadPURL  = "pkg:npm/bad@1.0.0"
)

// fieldCheck compares one comparable value extracted from a policy.
type fieldCheck struct {
	name string
	got  func(pol *policy.Policy) any
	want any
}

func assertFields(t *testing.T, pol *policy.Policy, checks []fieldCheck) {
	t.Helper()

	for idx := range checks {
		if got := checks[idx].got(pol); got != checks[idx].want {
			t.Errorf("%s: expected %v, got %v", checks[idx].name, checks[idx].want, got)
		}
	}
}

func joined(values []string) string {
	return strings.Join(values, ",")
}

// fullDefaultPolicy returns a default policy that sets every section.
func fullDefaultPolicy() *policy.Policy {
	wildcard := []string{"*"}

	return &policy.Policy{
		Mode:    config.ModeEnforce,
		Include: []string{testDefaultIncludeGlob},
		Exclude: []string{testDefaultExcludeGlob},
		Trust: &policy.TrustPolicy{
			Builders:  []policy.TrustedBuilder{{ID: testDefaultBuilderID, MaxLevel: 2}},
			Verifiers: []policy.TrustedVerifier{keyVerifier(testDefaultVerifierID, testKeyPath)},
			Issuers:   []string{testDefaultIssuer},
			Sources:   []string{"https://github.com/**"},
		},
		SLSA: &policy.SLSAPolicy{MissingPolicy: types.ActionDeny, RejectUnknownParameters: true},
		VEX: &policy.VEXPolicy{
			MissingPolicy:            types.ActionDeny,
			UnderInvestigationPolicy: types.ActionWarn,
		},
		VSA: &policy.VSAPolicy{
			MissingPolicy: types.ActionDeny, MinimumLevel: 3, Policy: "https://example.com/policy",
		},
		Signatures: &policy.SignaturesPolicy{RequireTransparencyLog: true},
		Notation: &policy.NotationPolicy{
			MissingPolicy:     types.ActionDeny,
			VerificationLevel: testNotationLevelStrict,
			TrustStores: []policy.NotationTrustStore{
				caTrustStore(testNotationStoreName, testNotationCertPath),
			},
			TrustPolicy: []policy.NotationTrustPolicyRule{
				notationTrustRule(
					testDefaultRuleName,
					wildcard,
					[]string{testNotationStoreRef},
					wildcard,
				),
			},
		},
		CEL: &celengine.Policy{
			Rules: []celengine.Rule{{Require: testCELExprTrue, Message: testDefaultLabel}},
		},
		SBOM: &policy.SBOMPolicy{
			MissingPolicy: types.ActionDeny,
			Formats:       []string{testFormatSPDX, testFormatCycloneDX},
			License: &policy.SBOMLicensePolicy{
				Deny: []string{testLicenseAGPL}, Allow: []string{testLicenseMIT},
			},
			Component: &policy.SBOMComponentPolicy{Deny: []string{testComponentBadPURL}},
			CVSS: &policy.SBOMCVSSPolicy{
				MaxScore: new(7.0), IgnoreCVEs: []string{testCVEID},
			},
		},
		SCAI: &policy.SCAIPolicy{
			MissingPolicy:      types.ActionDeny,
			RequiredAttributes: []string{testAttrCodeReview},
			RequireEvidence:    true,
		},
		BuildEnv: &policy.BuildEnvPolicy{
			MissingPolicy:       types.ActionDeny,
			RequiredProperties:  []string{"os"},
			ForbiddenProperties: []string{"debug"},
		},
		VulnScan: &policy.VulnScanPolicy{
			MissingPolicy: types.ActionWarn, MaxScore: new(7.5), IgnoreCVEs: []string{testCVEID},
		},
		TestResult: &policy.TestResultPolicy{
			MissingPolicy: types.ActionDeny, RequiredSuites: []string{"unit", "integration"},
		},
		Release: &policy.ReleasePolicy{
			MissingPolicy:     types.ActionWarn,
			TrustedRegistries: []string{"ghcr.io/myorg/*"},
			RequirePackageID:  true,
		},
		RuntimeTrace: &policy.RuntimeTracePolicy{
			MissingPolicy:         types.ActionDeny,
			TrustedMonitors:       []string{"falco"},
			ForbiddenFilePatterns: []string{"/etc/shadow"},
		},
		Scorecard: &policy.ScorecardPolicy{
			MinScore: new(7.0), Checks: map[string]int{testScorecardCodeReview: 8},
		},
		Rules: []policy.ImageRule{{
			Images: []string{testRuleImagesGlob},
			SLSA:   &policy.SLSAPolicy{MissingPolicy: types.ActionDeny},
		}},
	}
}

func TestMergeWithDefaultInheritsUnsetFields(t *testing.T) {
	t.Parallel()

	merged := policy.MergeWithDefault(&policy.Policy{Inherits: new(true)}, fullDefaultPolicy())

	checks := []fieldCheck{
		{
			name: "inherits is cleared",
			got:  func(p *policy.Policy) any { return p.Inherits == nil },
			want: true,
		},
		{
			name: "default mode",
			got:  func(p *policy.Policy) any { return p.Mode },
			want: config.ModeEnforce,
		},
		{
			name: "default include",
			got:  func(p *policy.Policy) any { return joined(p.Include) },
			want: testDefaultIncludeGlob,
		},
		{
			name: "default exclude",
			got:  func(p *policy.Policy) any { return joined(p.Exclude) },
			want: testDefaultExcludeGlob,
		},
		{
			name: "trust builder",
			got:  func(p *policy.Policy) any { return p.Trust.Builders[0].ID },
			want: testDefaultBuilderID,
		},
		{
			name: "trust verifier",
			got:  func(p *policy.Policy) any { return p.Trust.Verifiers[0].ID },
			want: testDefaultVerifierID,
		},
		{
			name: "trust issuers",
			got:  func(p *policy.Policy) any { return joined(p.Trust.Issuers) },
			want: testDefaultIssuer,
		},
		{
			name: "slsa missing policy",
			got:  func(p *policy.Policy) any { return p.SLSAMissingPolicy() },
			want: types.ActionDeny,
		},
		{
			name: "slsa reject unknown parameters",
			got:  func(p *policy.Policy) any { return p.SLSA.RejectUnknownParameters },
			want: true,
		},
		{
			name: "vex missing policy",
			got:  func(p *policy.Policy) any { return p.VEXMissingPolicy() },
			want: types.ActionDeny,
		},
		{
			name: "vex under investigation policy",
			got:  func(p *policy.Policy) any { return p.VEX.UnderInvestigationPolicy },
			want: types.ActionWarn,
		},
		{
			name: "vsa minimum level",
			got:  func(p *policy.Policy) any { return p.VSA.MinimumLevel },
			want: 3,
		},
		{
			name: "signatures transparency log",
			got:  func(p *policy.Policy) any { return p.Signatures.RequireTransparencyLog },
			want: true,
		},
		{
			name: "notation missing policy",
			got:  func(p *policy.Policy) any { return p.NotationMissingPolicy() },
			want: types.ActionDeny,
		},
		{
			name: "notation verification level",
			got:  func(p *policy.Policy) any { return p.Notation.VerificationLevel },
			want: testNotationLevelStrict,
		},
		{
			name: "notation trust stores",
			got:  func(p *policy.Policy) any { return len(p.Notation.TrustStores) },
			want: 1,
		},
		{
			name: "notation trust store name",
			got:  func(p *policy.Policy) any { return p.Notation.TrustStores[0].Name },
			want: testNotationStoreName,
		},
		{
			name: "notation trust policy",
			got:  func(p *policy.Policy) any { return p.Notation.TrustPolicy[0].Name },
			want: testDefaultRuleName,
		},
		{
			name: "cel rule",
			got:  func(p *policy.Policy) any { return p.CEL.Rules[0].Message },
			want: testDefaultLabel,
		},
		{
			name: "sbom missing policy",
			got:  func(p *policy.Policy) any { return p.SBOMMissingPolicy() },
			want: types.ActionDeny,
		},
		{
			name: "sbom formats",
			got:  func(p *policy.Policy) any { return joined(p.SBOM.Formats) },
			want: testFormatSPDX + "," + testFormatCycloneDX,
		},
		{
			name: "sbom license deny",
			got:  func(p *policy.Policy) any { return joined(p.SBOM.License.Deny) },
			want: testLicenseAGPL,
		},
		{
			name: "sbom license allow",
			got:  func(p *policy.Policy) any { return joined(p.SBOM.License.Allow) },
			want: testLicenseMIT,
		},
		{
			name: "sbom component deny",
			got:  func(p *policy.Policy) any { return joined(p.SBOM.Component.Deny) },
			want: testComponentBadPURL,
		},
		{
			name: "scai missing policy",
			got:  func(p *policy.Policy) any { return p.SCAIMissingPolicy() },
			want: types.ActionDeny,
		},
		{
			name: "scai required attributes",
			got:  func(p *policy.Policy) any { return joined(p.SCAI.RequiredAttributes) },
			want: testAttrCodeReview,
		},
		{
			name: "scai require evidence",
			got:  func(p *policy.Policy) any { return p.SCAI.RequireEvidence },
			want: true,
		},
		{
			name: "buildEnv missing policy",
			got:  func(p *policy.Policy) any { return p.BuildEnv.MissingPolicy },
			want: types.ActionDeny,
		},
		{
			name: "buildEnv properties",
			got: func(p *policy.Policy) any {
				return joined(
					p.BuildEnv.RequiredProperties,
				) + "|" + joined(
					p.BuildEnv.ForbiddenProperties,
				)
			},
			want: "os|debug",
		},
		{
			name: "vulnScan missing policy",
			got:  func(p *policy.Policy) any { return p.VulnScan.MissingPolicy },
			want: types.ActionWarn,
		},
		{
			name: "vulnScan max score",
			got:  func(p *policy.Policy) any { return *p.VulnScan.MaxScore },
			want: 7.5,
		},
		{
			name: "testResult missing policy",
			got:  func(p *policy.Policy) any { return p.TestResult.MissingPolicy },
			want: types.ActionDeny,
		},
		{
			name: "testResult suites",
			got:  func(p *policy.Policy) any { return joined(p.TestResult.RequiredSuites) },
			want: "unit,integration",
		},
		{
			name: "release missing policy",
			got:  func(p *policy.Policy) any { return p.Release.MissingPolicy },
			want: types.ActionWarn,
		},
		{
			name: "release require package ID",
			got:  func(p *policy.Policy) any { return p.Release.RequirePackageID },
			want: true,
		},
		{
			name: "release trusted registries",
			got:  func(p *policy.Policy) any { return len(p.Release.TrustedRegistries) },
			want: 1,
		},
		{
			name: "runtimeTrace missing policy",
			got:  func(p *policy.Policy) any { return p.RuntimeTrace.MissingPolicy },
			want: types.ActionDeny,
		},
		{
			name: "runtimeTrace lists",
			got: func(p *policy.Policy) any {
				return joined(p.RuntimeTrace.TrustedMonitors) + "|" +
					joined(p.RuntimeTrace.ForbiddenFilePatterns)
			},
			want: "falco|/etc/shadow",
		},
		{
			name: "scorecard min score",
			got:  func(p *policy.Policy) any { return *p.Scorecard.MinScore },
			want: 7.0,
		},
		{
			name: "default rules",
			got:  func(p *policy.Policy) any { return p.Rules[0].Images[0] },
			want: testRuleImagesGlob,
		},
	}

	for idx := range checks {
		check := &checks[idx]

		t.Run(check.name, func(t *testing.T) {
			t.Parallel()

			testutil.AssertEqual(t, check.want, check.got(merged))
		})
	}
}

func TestMergeWithDefaultNamespaceOverrides(t *testing.T) {
	t.Parallel()

	//nolint:exhaustruct_v5 // table cases only set the fields they assert
	tests := []struct {
		name string
		// defaults is the default policy; nil uses fullDefaultPolicy.
		defaults  *policy.Policy
		namespace *policy.Policy
		// validate validates the namespace policy before merging.
		validate bool
		checks   []fieldCheck
	}{
		{
			name: "trust",
			namespace: &policy.Policy{Trust: &policy.TrustPolicy{
				Builders: []policy.TrustedBuilder{{ID: testNSBuilderID, MaxLevel: 1}},
			}},
			checks: []fieldCheck{
				{
					name: "builder",
					got:  func(p *policy.Policy) any { return p.Trust.Builders[0].ID },
					want: testNSBuilderID,
				},
				{
					name: "slsa preserved",
					got:  func(p *policy.Policy) any { return p.SLSAMissingPolicy() },
					want: types.ActionDeny,
				},
			},
		},
		{
			name:      "namespace include",
			namespace: &policy.Policy{Include: []string{"ns-include/*"}},
			checks: []fieldCheck{
				{
					name: "include from namespace",
					got:  func(p *policy.Policy) any { return joined(p.Include) },
					want: "ns-include/*",
				},
			},
		},
		{
			name:      "namespace exclude",
			namespace: &policy.Policy{Exclude: []string{"ns-exclude/*"}},
			checks: []fieldCheck{
				{
					name: "exclude from namespace",
					got:  func(p *policy.Policy) any { return joined(p.Exclude) },
					want: "ns-exclude/*",
				},
			},
		},
		{
			name:      "slsa missing policy",
			namespace: &policy.Policy{SLSA: &policy.SLSAPolicy{MissingPolicy: types.ActionAllow}},
			checks: []fieldCheck{
				{
					name: "slsa from namespace",
					got:  func(p *policy.Policy) any { return p.SLSAMissingPolicy() },
					want: types.ActionAllow,
				},
			},
		},
		{
			name:      "vex missing policy",
			namespace: &policy.Policy{VEX: &policy.VEXPolicy{MissingPolicy: types.ActionWarn}},
			checks: []fieldCheck{
				{
					name: "vex from namespace",
					got:  func(p *policy.Policy) any { return p.VEXMissingPolicy() },
					want: types.ActionWarn,
				},
			},
		},
		{
			name:      "vsa minimum level",
			namespace: &policy.Policy{VSA: &policy.VSAPolicy{MinimumLevel: 1}},
			checks: []fieldCheck{
				{
					name: "vsa level",
					got:  func(p *policy.Policy) any { return p.VSA.MinimumLevel },
					want: 1,
				},
			},
		},
		{
			// Policies built in code have no record of explicitly set fields,
			// so a zero value is treated as unset and the default is kept.
			name: "unset signatures field keeps default",
			namespace: &policy.Policy{
				Signatures: &policy.SignaturesPolicy{RequireTransparencyLog: false},
			},
			checks: []fieldCheck{
				{
					name: "transparency log",
					got:  func(p *policy.Policy) any { return p.Signatures.RequireTransparencyLog },
					want: true,
				},
			},
		},
		{
			name: "sbom missing policy and formats",
			namespace: &policy.Policy{SBOM: &policy.SBOMPolicy{
				MissingPolicy: types.ActionWarn,
				Formats:       []string{testFormatCycloneDX},
			}},
			checks: []fieldCheck{
				{
					name: "sbom from namespace",
					got:  func(p *policy.Policy) any { return p.SBOMMissingPolicy() },
					want: types.ActionWarn,
				},
				{
					name: "formats",
					got:  func(p *policy.Policy) any { return joined(p.SBOM.Formats) },
					want: testFormatCycloneDX,
				},
			},
		},
		{
			name: "scai merges field by field",
			namespace: &policy.Policy{SCAI: &policy.SCAIPolicy{
				MissingPolicy:       types.ActionWarn,
				ForbiddenAttributes: []string{testAttrKnownVulnerable},
			}},
			checks: []fieldCheck{
				{
					name: "scai",
					got:  func(p *policy.Policy) any { return p.SCAIMissingPolicy() },
					want: types.ActionWarn,
				},
				{
					name: "forbidden attributes",
					got:  func(p *policy.Policy) any { return joined(p.SCAI.ForbiddenAttributes) },
					want: testAttrKnownVulnerable,
				},
				{
					name: "required attributes inherited",
					got:  func(p *policy.Policy) any { return joined(p.SCAI.RequiredAttributes) },
					want: testAttrCodeReview,
				},
			},
		},
		{
			name: "namespace mode",
			defaults: &policy.Policy{
				Mode: config.ModeWarn,
				SLSA: &policy.SLSAPolicy{MissingPolicy: types.ActionDeny},
			},
			namespace: &policy.Policy{Mode: config.ModeEnforce},
			checks: []fieldCheck{
				{
					name: "mode from namespace",
					got:  func(p *policy.Policy) any { return p.Mode },
					want: config.ModeEnforce,
				},
				{
					name: "slsa inherited",
					got:  func(p *policy.Policy) any { return p.SLSAMissingPolicy() },
					want: types.ActionDeny,
				},
			},
		},
		{
			name: "namespace rules replace default rules",
			namespace: &policy.Policy{Rules: []policy.ImageRule{{
				Images: []string{testDockerGlob},
				VEX:    &policy.VEXPolicy{MissingPolicy: types.ActionWarn},
			}}},
			checks: []fieldCheck{
				{
					name: "one namespace rule",
					got:  func(p *policy.Policy) any { return len(p.Rules) },
					want: 1,
				},
				{
					name: "namespace rule images",
					got:  func(p *policy.Policy) any { return p.Rules[0].Images[0] },
					want: testDockerGlob,
				},
			},
		},
		{
			name:      "empty rules clear inherited rules",
			namespace: &policy.Policy{Rules: []policy.ImageRule{}},
			checks: []fieldCheck{
				{
					name: "no rules",
					got:  func(p *policy.Policy) any { return len(p.Rules) },
					want: 0,
				},
			},
		},
		{
			name: "rules keep compiled CEL",
			defaults: &policy.Policy{
				SLSA: &policy.SLSAPolicy{MissingPolicy: types.ActionAllow},
			},
			namespace: &policy.Policy{Rules: []policy.ImageRule{{
				Images: []string{testRuleImagesGlob},
				CEL: &celengine.Policy{
					Rules: []celengine.Rule{
						{Require: testCELExprSLSAVerified, Message: "rule CEL"},
					},
				},
			}}},
			validate: true,
			checks: []fieldCheck{
				{
					name: "one rule",
					got:  func(p *policy.Policy) any { return len(p.Rules) },
					want: 1,
				},
				{
					name: "rule compiled CEL",
					got:  func(p *policy.Policy) any { return p.Rules[0].CompiledCEL != nil },
					want: true,
				},
			},
		},
		{
			name:      "overriding one section keeps the others",
			namespace: &policy.Policy{SLSA: &policy.SLSAPolicy{MissingPolicy: types.ActionWarn}},
			checks: []fieldCheck{
				{
					name: "slsa overridden",
					got:  func(p *policy.Policy) any { return p.SLSAMissingPolicy() },
					want: types.ActionWarn,
				},
				{
					name: "notation kept",
					got: func(p *policy.Policy) any {
						return string(
							p.NotationMissingPolicy(),
						) + "|" + p.Notation.VerificationLevel +
							"|" + p.Notation.TrustStores[0].Name
					},
					want: string(
						types.ActionDeny,
					) + "|" + testNotationLevelStrict + "|" + testNotationStoreName,
				},
				{
					name: "notation trust policy",
					got:  func(p *policy.Policy) any { return p.Notation.TrustPolicy[0].Name },
					want: testDefaultRuleName,
				},
				{
					name: "sbom kept",
					got: func(p *policy.Policy) any {
						return string(p.SBOMMissingPolicy()) + "|" + joined(p.SBOM.Formats)
					},
					want: string(
						types.ActionDeny,
					) + "|" + testFormatSPDX + "," + testFormatCycloneDX,
				},
				{
					name: "sbom license",
					got: func(p *policy.Policy) any {
						return joined(p.SBOM.License.Deny) + "|" + joined(p.SBOM.License.Allow)
					},
					want: testLicenseAGPL + "|" + testLicenseMIT,
				},
				{
					name: "sbom component deny",
					got:  func(p *policy.Policy) any { return len(p.SBOM.Component.Deny) },
					want: 1,
				},
			},
		},
		{
			name: "all sections",
			defaults: &policy.Policy{
				Include: []string{testDefaultIncludeGlob},
				Exclude: []string{testDefaultExcludeGlob},
				Trust: &policy.TrustPolicy{
					Builders: []policy.TrustedBuilder{{ID: testDefaultBuilderID, MaxLevel: 2}},
					Issuers:  []string{testDefaultIssuer},
				},
				SLSA: &policy.SLSAPolicy{MissingPolicy: types.ActionAllow},
				VEX: &policy.VEXPolicy{
					MissingPolicy:            types.ActionAllow,
					UnderInvestigationPolicy: types.ActionAllow,
				},
				VSA:        &policy.VSAPolicy{MissingPolicy: types.ActionAllow, MinimumLevel: 1},
				Signatures: &policy.SignaturesPolicy{RequireTransparencyLog: false},
				Notation: &policy.NotationPolicy{
					MissingPolicy:     types.ActionAllow,
					VerificationLevel: testNotationPermissive,
				},
				CEL: &celengine.Policy{
					Rules: []celengine.Rule{{Require: testCELExprTrue, Message: testDefaultLabel}},
				},
				SBOM: &policy.SBOMPolicy{
					MissingPolicy: types.ActionAllow,
					Formats:       []string{testFormatSPDX},
				},
			},
			namespace: &policy.Policy{
				Include: []string{"ns-include/**"},
				Exclude: []string{"ns-exclude/**"},
				Trust: &policy.TrustPolicy{
					Builders: []policy.TrustedBuilder{{ID: testNSBuilderID, MaxLevel: 3}},
					Issuers:  []string{"ns-issuer"},
				},
				SLSA: &policy.SLSAPolicy{MissingPolicy: types.ActionDeny},
				VEX: &policy.VEXPolicy{
					MissingPolicy:            types.ActionDeny,
					UnderInvestigationPolicy: types.ActionDeny,
				},
				VSA:        &policy.VSAPolicy{MissingPolicy: types.ActionDeny, MinimumLevel: 3},
				Signatures: &policy.SignaturesPolicy{RequireTransparencyLog: true},
				Notation: &policy.NotationPolicy{
					MissingPolicy:     types.ActionDeny,
					VerificationLevel: testNotationLevelStrict,
				},
				CEL: &celengine.Policy{
					Rules: []celengine.Rule{{Require: testCELExprFalse, Message: "namespace"}},
				},
				SBOM: &policy.SBOMPolicy{
					MissingPolicy: types.ActionDeny,
					Formats:       []string{testFormatCycloneDX},
				},
			},
			checks: []fieldCheck{
				{
					name: "include overridden",
					got:  func(p *policy.Policy) any { return joined(p.Include) },
					want: "ns-include/**",
				},
				{
					name: "exclude overridden",
					got:  func(p *policy.Policy) any { return joined(p.Exclude) },
					want: "ns-exclude/**",
				},
				{
					name: "builder",
					got:  func(p *policy.Policy) any { return p.Trust.Builders[0].ID },
					want: testNSBuilderID,
				},
				{
					name: "issuer",
					got:  func(p *policy.Policy) any { return p.Trust.Issuers[0] },
					want: "ns-issuer",
				},
				{
					name: "namespace slsa",
					got:  func(p *policy.Policy) any { return p.SLSA.MissingPolicy },
					want: types.ActionDeny,
				},
				{
					name: "namespace vex",
					got:  func(p *policy.Policy) any { return p.VEX.MissingPolicy },
					want: types.ActionDeny,
				},
				{
					name: "vex under investigation",
					got:  func(p *policy.Policy) any { return p.VEX.UnderInvestigationPolicy },
					want: types.ActionDeny,
				},
				{
					name: "vsa",
					got:  func(p *policy.Policy) any { return p.VSA.MissingPolicy },
					want: types.ActionDeny,
				},
				{
					name: "vsa level",
					got:  func(p *policy.Policy) any { return p.VSA.MinimumLevel },
					want: 3,
				},
				{
					name: "transparency log",
					got:  func(p *policy.Policy) any { return p.Signatures.RequireTransparencyLog },
					want: true,
				},
				{
					name: "notation",
					got:  func(p *policy.Policy) any { return p.Notation.MissingPolicy },
					want: types.ActionDeny,
				},
				{
					name: "notation level",
					got:  func(p *policy.Policy) any { return p.Notation.VerificationLevel },
					want: testNotationLevelStrict,
				},
				{
					name: "cel",
					got:  func(p *policy.Policy) any { return p.CEL.Rules[0].Message },
					want: "namespace",
				},
				{
					name: "namespace sbom",
					got:  func(p *policy.Policy) any { return p.SBOM.MissingPolicy },
					want: types.ActionDeny,
				},
				{
					name: "sbom formats",
					got:  func(p *policy.Policy) any { return joined(p.SBOM.Formats) },
					want: testFormatCycloneDX,
				},
			},
		},
	}

	for idx := range tests {
		test := &tests[idx]

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			defaults := test.defaults
			if defaults == nil {
				defaults = fullDefaultPolicy()
			}

			if test.validate {
				testutil.AssertNoError(t, test.namespace.Validate())
			}

			assertFields(t, policy.MergeWithDefault(test.namespace, defaults), test.checks)
		})
	}
}

func TestMergeWithDefaultDoesNotAliasDefaults(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(merged *policy.Policy)
		// checks run against the default policy after mutating the merged one.
		checks []fieldCheck
	}{
		{
			name: "verifier keys",
			mutate: func(merged *policy.Policy) {
				merged.Trust.Verifiers[0].Keys[0] = "/mutated.pub"
				merged.Trust.Verifiers[0].Keys = append(merged.Trust.Verifiers[0].Keys, "/c.pub")
			},
			checks: []fieldCheck{
				{
					name: "keys",
					got:  func(p *policy.Policy) any { return joined(p.Trust.Verifiers[0].Keys) },
					want: testKeyPath,
				},
			},
		},
		{
			name: "rule images",
			mutate: func(merged *policy.Policy) {
				merged.Rules[0].Images[0] = testMutatedValue
			},
			checks: []fieldCheck{
				{
					name: "rule images",
					got:  func(p *policy.Policy) any { return p.Rules[0].Images[0] },
					want: testRuleImagesGlob,
				},
			},
		},
		{
			name: "notation trust stores",
			mutate: func(merged *policy.Policy) {
				merged.Notation.TrustStores[0].Name = testMutatedValue
			},
			checks: []fieldCheck{
				{
					name: "trust store",
					got:  func(p *policy.Policy) any { return p.Notation.TrustStores[0].Name },
					want: testNotationStoreName,
				},
			},
		},
		{
			name: "cel rules",
			mutate: func(merged *policy.Policy) {
				merged.CEL.Rules[0].Message = testMutatedValue
			},
			checks: []fieldCheck{
				{
					name: "message",
					got:  func(p *policy.Policy) any { return p.CEL.Rules[0].Message },
					want: testDefaultLabel,
				},
			},
		},
		{
			name: "sbom lists",
			mutate: func(merged *policy.Policy) {
				merged.SBOM.Formats = append(merged.SBOM.Formats, testMutatedValue)
				merged.SBOM.License.Deny[0] = testMutatedValue
				merged.SBOM.License.Allow[0] = testMutatedValue
				merged.SBOM.Component.Deny[0] = "pkg:npm/mutated@1.0.0"
			},
			checks: []fieldCheck{
				{
					name: "formats",
					got:  func(p *policy.Policy) any { return len(p.SBOM.Formats) },
					want: 2,
				},
				{
					name: "license deny",
					got:  func(p *policy.Policy) any { return p.SBOM.License.Deny[0] },
					want: testLicenseAGPL,
				},
				{
					name: "license allow",
					got:  func(p *policy.Policy) any { return p.SBOM.License.Allow[0] },
					want: testLicenseMIT,
				},
				{
					name: "component deny",
					got:  func(p *policy.Policy) any { return p.SBOM.Component.Deny[0] },
					want: testComponentBadPURL,
				},
			},
		},
		{
			name: "sbom cvss",
			mutate: func(merged *policy.Policy) {
				merged.SBOM.CVSS.IgnoreCVEs[0] = "CVE-MUTATED"
				merged.SBOM.CVSS.IgnoreCVEs = append(merged.SBOM.CVSS.IgnoreCVEs, "CVE-EXTRA")
				*merged.SBOM.CVSS.MaxScore = 9.9
			},
			checks: []fieldCheck{
				{
					name: "ignore CVEs",
					got:  func(p *policy.Policy) any { return joined(p.SBOM.CVSS.IgnoreCVEs) },
					want: testCVEID,
				},
				{
					name: "max score",
					got:  func(p *policy.Policy) any { return *p.SBOM.CVSS.MaxScore },
					want: 7.0,
				},
			},
		},
		{
			name: "buildEnv properties",
			mutate: func(merged *policy.Policy) {
				merged.BuildEnv.RequiredProperties[0] = "arch"
			},
			checks: []fieldCheck{
				{
					name: "required properties",
					got:  func(p *policy.Policy) any { return joined(p.BuildEnv.RequiredProperties) },
					want: "os",
				},
			},
		},
		{
			name: "vulnScan max score",
			mutate: func(merged *policy.Policy) {
				*merged.VulnScan.MaxScore = 9.0
			},
			checks: []fieldCheck{
				{
					name: "max score",
					got:  func(p *policy.Policy) any { return *p.VulnScan.MaxScore },
					want: 7.5,
				},
			},
		},
		{
			name: "scorecard",
			mutate: func(merged *policy.Policy) {
				*merged.Scorecard.MinScore = 9.0
				merged.Scorecard.Checks[testScorecardCodeReview] = 10
			},
			checks: []fieldCheck{
				{
					name: "min score",
					got:  func(p *policy.Policy) any { return *p.Scorecard.MinScore },
					want: 7.0,
				},
				{
					name: "checks",
					got:  func(p *policy.Policy) any { return p.Scorecard.Checks[testScorecardCodeReview] },
					want: 8,
				},
			},
		},
	}

	for idx := range tests {
		test := &tests[idx]

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			defaults := fullDefaultPolicy()
			test.mutate(policy.MergeWithDefault(&policy.Policy{}, defaults))
			assertFields(t, defaults, test.checks)
		})
	}
}

func TestApplyRule(t *testing.T) {
	t.Parallel()

	allowSLSA := func() *policy.SLSAPolicy {
		return &policy.SLSAPolicy{MissingPolicy: types.ActionAllow}
	}

	slsaAllowed := fieldCheck{
		name: "base slsa kept",
		got:  func(p *policy.Policy) any { return p.SLSAMissingPolicy() },
		want: types.ActionAllow,
	}

	//nolint:exhaustruct_v5 // table cases only set the fields they assert
	tests := []struct {
		name string
		base *policy.Policy
		rule *policy.ImageRule
		// validate validates the base policy and the rule before applying.
		validate bool
		checks   []fieldCheck
		// verify runs extra assertions after the rule was applied.
		verify func(t *testing.T, base *policy.Policy, rule *policy.ImageRule, resolved *policy.Policy)
	}{
		{
			name: "section override keeps other base sections",
			base: &policy.Policy{
				Trust: &policy.TrustPolicy{
					Builders: []policy.TrustedBuilder{{ID: testBaseBuilderID, MaxLevel: 2}},
				},
				SLSA:  allowSLSA(),
				VEX:   &policy.VEXPolicy{MissingPolicy: types.ActionAllow},
				Rules: []policy.ImageRule{{Images: []string{testRuleImagesGlob}}},
			},
			rule: &policy.ImageRule{
				Images: []string{"ghcr.io/critical/**"},
				SLSA:   &policy.SLSAPolicy{MissingPolicy: types.ActionDeny},
			},
			checks: []fieldCheck{
				{
					name: "slsa from rule",
					got:  func(p *policy.Policy) any { return p.SLSAMissingPolicy() },
					want: types.ActionDeny,
				},
				{
					name: "vex from base",
					got:  func(p *policy.Policy) any { return p.VEXMissingPolicy() },
					want: types.ActionAllow,
				},
				{
					name: "builders from base",
					got:  func(p *policy.Policy) any { return len(p.Builders()) },
					want: 1,
				},
				{
					name: "builder from base",
					got:  func(p *policy.Policy) any { return p.Builders()[0].ID },
					want: testBaseBuilderID,
				},
				{
					name: "rules cleared",
					got:  func(p *policy.Policy) any { return p.Rules == nil },
					want: true,
				},
			},
			verify: func(t *testing.T, base *policy.Policy, _ *policy.ImageRule, _ *policy.Policy) {
				t.Helper()

				testutil.AssertEqual(t, types.ActionAllow, base.SLSAMissingPolicy())
			},
		},
		{
			name: "trust override is deep copied",
			base: &policy.Policy{
				Trust: &policy.TrustPolicy{
					Builders: []policy.TrustedBuilder{{ID: testBaseBuilderID, MaxLevel: 2}},
					Issuers:  []string{"https://base-issuer.example.com"},
				},
				SLSA: allowSLSA(),
			},
			rule: &policy.ImageRule{
				Images: []string{testRuleImagesGlob},
				Trust: &policy.TrustPolicy{
					Builders: []policy.TrustedBuilder{{ID: testRuleBuilderID, MaxLevel: 3}},
					Issuers:  []string{"https://rule-issuer.example.com"},
				},
			},
			checks: []fieldCheck{
				{
					name: "builders",
					got:  func(p *policy.Policy) any { return len(p.Builders()) },
					want: 1,
				},
				{
					name: "builder from rule",
					got:  func(p *policy.Policy) any { return p.Builders()[0].ID },
					want: testRuleBuilderID,
				},
				slsaAllowed,
			},
			verify: func(t *testing.T, base *policy.Policy, rule *policy.ImageRule, resolved *policy.Policy) {
				t.Helper()

				resolved.Trust.Builders[0].ID = testMutatedValue

				testutil.AssertEqual(t, testBaseBuilderID, base.Trust.Builders[0].ID)
				testutil.AssertEqual(t, testRuleBuilderID, rule.Trust.Builders[0].ID)
			},
		},
		{
			name: "trust override preserves all other sections",
			base: &policy.Policy{
				Trust: &policy.TrustPolicy{
					Builders: []policy.TrustedBuilder{{ID: testBaseBuilderID, MaxLevel: 2}},
					Issuers:  []string{"base-issuer"},
					Sources:  []string{"https://github.com/base/**"},
				},
				SLSA:       &policy.SLSAPolicy{MissingPolicy: types.ActionDeny},
				VEX:        &policy.VEXPolicy{MissingPolicy: types.ActionWarn},
				VSA:        &policy.VSAPolicy{MinimumLevel: 2},
				Signatures: &policy.SignaturesPolicy{RequireTransparencyLog: true},
				Notation: &policy.NotationPolicy{
					MissingPolicy:     types.ActionDeny,
					VerificationLevel: testNotationLevelStrict,
				},
				CEL: &celengine.Policy{
					Rules: []celengine.Rule{{Require: testCELExprTrue, Message: testCELMsgBase}},
				},
				SBOM: &policy.SBOMPolicy{
					MissingPolicy: types.ActionDeny,
					Formats:       []string{testFormatSPDX},
				},
			},
			rule: &policy.ImageRule{
				Images: []string{testRuleImagesGlob},
				Trust: &policy.TrustPolicy{
					Builders: []policy.TrustedBuilder{{ID: testRuleBuilderID, MaxLevel: 3}},
					Issuers:  []string{"rule-issuer"},
					Sources:  []string{"https://github.com/rule/**"},
				},
			},
			checks: []fieldCheck{
				{
					name: "builder from rule",
					got:  func(p *policy.Policy) any { return p.Builders()[0].ID },
					want: testRuleBuilderID,
				},
				{
					name: "issuer from rule",
					got:  func(p *policy.Policy) any { return p.Trust.Issuers[0] },
					want: "rule-issuer",
				},
				{
					name: "source from rule",
					got:  func(p *policy.Policy) any { return p.Trust.Sources[0] },
					want: "https://github.com/rule/**",
				},
				{
					name: "slsa from base",
					got:  func(p *policy.Policy) any { return p.SLSA.MissingPolicy },
					want: types.ActionDeny,
				},
				{
					name: "vex from base",
					got:  func(p *policy.Policy) any { return p.VEX.MissingPolicy },
					want: types.ActionWarn,
				},
				{
					name: "vsa from base",
					got:  func(p *policy.Policy) any { return p.VSA.MinimumLevel },
					want: 2,
				},
				{
					name: "signatures from base",
					got:  func(p *policy.Policy) any { return p.Signatures.RequireTransparencyLog },
					want: true,
				},
				{
					name: "notation from base",
					got:  func(p *policy.Policy) any { return p.Notation.VerificationLevel },
					want: testNotationLevelStrict,
				},
				{
					name: "cel from base",
					got:  func(p *policy.Policy) any { return p.CEL.Rules[0].Message },
					want: testCELMsgBase,
				},
				{
					name: "sbom from base",
					got:  func(p *policy.Policy) any { return p.SBOM.MissingPolicy },
					want: types.ActionDeny,
				},
			},
		},
		{
			name: "signatures override",
			base: &policy.Policy{
				Signatures: &policy.SignaturesPolicy{RequireTransparencyLog: false},
				SLSA:       allowSLSA(),
			},
			rule: &policy.ImageRule{
				Images:     []string{testRuleImagesGlob},
				Signatures: &policy.SignaturesPolicy{RequireTransparencyLog: true},
			},
			checks: []fieldCheck{
				{
					name: "transparency log from rule",
					got:  func(p *policy.Policy) any { return p.Signatures.RequireTransparencyLog },
					want: true,
				},
				slsaAllowed,
			},
		},
		{
			name: "sbom override",
			base: &policy.Policy{
				SBOM: &policy.SBOMPolicy{MissingPolicy: types.ActionAllow},
				SLSA: allowSLSA(),
			},
			rule: &policy.ImageRule{
				Images: []string{testRuleImagesGlob},
				SBOM: &policy.SBOMPolicy{
					MissingPolicy: types.ActionDeny,
					Formats:       []string{testFormatSPDX},
					License:       &policy.SBOMLicensePolicy{Deny: []string{testLicenseAGPL}},
				},
			},
			checks: []fieldCheck{
				{
					name: "sbom from rule",
					got:  func(p *policy.Policy) any { return p.SBOMMissingPolicy() },
					want: types.ActionDeny,
				},
				{
					name: "formats from rule",
					got:  func(p *policy.Policy) any { return joined(p.SBOM.Formats) },
					want: testFormatSPDX,
				},
				slsaAllowed,
			},
		},
		{
			name: "notation override",
			base: &policy.Policy{
				Notation: &policy.NotationPolicy{MissingPolicy: types.ActionAllow},
			},
			rule: &policy.ImageRule{
				Images: []string{testRuleImagesGlob},
				Notation: &policy.NotationPolicy{
					MissingPolicy:     types.ActionDeny,
					VerificationLevel: testNotationLevelStrict,
					TrustStores: []policy.NotationTrustStore{
						caTrustStore(testNotationStoreName, testNotationCertPath),
					},
				},
			},
			checks: []fieldCheck{
				{
					name: "notation from rule",
					got:  func(p *policy.Policy) any { return p.NotationMissingPolicy() },
					want: types.ActionDeny,
				},
			},
		},
		{
			name: "cel override",
			base: &policy.Policy{
				CEL: &celengine.Policy{
					Rules: []celengine.Rule{{Require: testCELExprTrue, Message: testCELMsgBase}},
				},
				SLSA: allowSLSA(),
			},
			rule: &policy.ImageRule{
				Images: []string{testRuleImagesGlob},
				CEL: &celengine.Policy{
					Rules: []celengine.Rule{{Require: testCELExprFalse, Message: "override"}},
				},
			},
			checks: []fieldCheck{
				{
					name: "cel from rule",
					got:  func(p *policy.Policy) any { return p.CEL.Rules[0].Message },
					want: "override",
				},
				slsaAllowed,
			},
		},
		{
			name: "rule without CEL keeps compiled base CEL",
			base: &policy.Policy{
				CEL: &celengine.Policy{
					Rules: []celengine.Rule{
						{Require: testCELExprSLSAVerified, Message: "base CEL"},
					},
				},
				SLSA: allowSLSA(),
			},
			rule: &policy.ImageRule{
				Images: []string{testRuleImagesGlob},
				SLSA:   &policy.SLSAPolicy{MissingPolicy: types.ActionDeny},
			},
			validate: true,
			checks: []fieldCheck{
				{
					name: "compiled base CEL kept",
					got:  func(p *policy.Policy) any { return p.CompiledCEL != nil },
					want: true,
				},
				{
					name: "slsa from rule",
					got:  func(p *policy.Policy) any { return p.SLSAMissingPolicy() },
					want: types.ActionDeny,
				},
			},
		},
		{
			name: "rule CEL replaces compiled base CEL",
			base: &policy.Policy{
				CEL: &celengine.Policy{
					Rules: []celengine.Rule{{Require: testCELExprTrue, Message: testCELMsgBase}},
				},
			},
			rule: &policy.ImageRule{
				Images: []string{testRuleImagesGlob},
				CEL: &celengine.Policy{
					Rules: []celengine.Rule{{Require: testCELExprFalse, Message: "rule override"}},
				},
			},
			validate: true,
			checks: []fieldCheck{
				{
					name: "compiled rule CEL",
					got:  func(p *policy.Policy) any { return p.CompiledCEL != nil },
					want: true,
				},
				{
					name: "cel from rule",
					got:  func(p *policy.Policy) any { return p.CEL.Rules[0].Message },
					want: "rule override",
				},
			},
		},
	}

	for idx := range tests {
		test := &tests[idx]

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if test.validate {
				validateBaseAndRule(t, test.base, test.rule)
			}

			resolved := policy.ApplyRule(test.base, test.rule)
			assertFields(t, resolved, test.checks)

			if test.verify != nil {
				test.verify(t, test.base, test.rule, resolved)
			}
		})
	}
}

// validateBaseAndRule compiles CEL for the base policy and the rule and
// asserts that programs were produced where CEL is set.
func validateBaseAndRule(t *testing.T, base *policy.Policy, rule *policy.ImageRule) {
	t.Helper()

	testutil.AssertNoError(t, base.Validate())

	if base.CEL != nil && base.CompiledCEL == nil {
		t.Fatal("expected base CompiledCEL after validation")
	}

	holder := &policy.Policy{Rules: []policy.ImageRule{*rule}}
	testutil.AssertNoError(t, holder.Validate())

	*rule = holder.Rules[0]

	if rule.CEL != nil && rule.CompiledCEL == nil {
		t.Fatal("expected rule CompiledCEL after validation")
	}
}

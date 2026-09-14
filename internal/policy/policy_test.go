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
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	celengine "github.com/saschagrunert/nri-supply-chain/internal/cel"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/fileutil"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	testBuilderID           = "test"
	testInvalidValue        = "invalid"
	testInvalidDuration     = "not-a-duration"
	testNegativeDuration    = "-1h"
	testVerifierID          = "https://example.com/v"
	testIssuerURL           = "https://accounts.google.com"
	testIncludePattern      = "docker.io/myorg/**"
	testKeyPath             = "/etc/keys/verifier.pub"
	testValidKeyPath        = "/valid/key.pub"
	testNonexistentKeyPath  = "/nonexistent/key.pub"
	testRuleImagesGlob      = "ghcr.io/**"
	testGitHubIssuer        = "https://token.actions.githubusercontent.com"
	testGitHubSANPattern    = "https://github.com/saschagrunert/*"
	testNotBefore2024       = "2024-01-01T00:00:00Z"
	testNotAfter2025        = "2025-01-01T00:00:00Z"
	testMidpoint2024        = "2024-06-01T00:00:00Z"
	testBaseBuilderID       = "base-builder"
	testRuleBuilderID       = "rule-builder"
	testMutatedValue        = "mutated"
	testNotationLevelStrict = "strict"
	testNotationLevelSkip   = "skip"
	testNotationPermissive  = "permissive"
	testNotationStoreName   = "myca"
	testNotationStoreRef    = "ca:myca"
	testNotationCertPath    = "/etc/certs/ca.pem"
	testNotationRuleName    = "rule1"
	testDockerGlob          = "docker.io/**"
	testCELExprTrue         = "true"
	testCELExprFalse        = "false"
	testCELExprSLSAVerified = "slsa.verified == true"
	testCELInvalidExpr      = "invalid +++"
	testCELMsgBase          = "base"
	testCVEID               = "CVE-2024-0001"
	testFormatCycloneDX     = "cyclonedx"
	testFormatSPDX          = "spdx"
	testLicenseAGPL         = "AGPL-3.0"
	testLicenseMIT          = "MIT"
	testDefaultBuilderID    = "default-builder"
	testDefaultIssuer       = "default-issuer"
	testNSBuilderID         = "ns-builder"
	testDefaultLabel        = "default"
	testAttrCodeReview      = "PASSED_CODE_REVIEW"
	testAttrKnownVulnerable = "KNOWN_VULNERABLE"
	testAttrFuzzTested      = "FUZZ_TESTED"
	testDefaultIncludeGlob  = "default-include/**"
	testDefaultExcludeGlob  = "default-exclude/**"
	testMaxAge              = "24h"
	testRunnerBuilderID     = "https://github.com/actions/runner"
	testReleaseSAN          = "https://github.com/myorg/app/.github/workflows/release.yml@refs/tags/v1"
	testReleaseSANPattern   = "https://github.com/myorg/app/.github/workflows/release.yml@**"
	testScorecardCodeReview = "Code-Review"
)

// errAnyError marks a table case that expects an error without asserting a
// specific sentinel.
var errAnyError = errors.New("any error")

// assertErr checks err against a table expectation: nil expects success,
// errAnyError expects any error and everything else must match errors.Is.
func assertErr(t *testing.T, err, want error) {
	t.Helper()

	switch {
	case want == nil:
		testutil.AssertNoError(t, err)
	case errors.Is(want, errAnyError):
		testutil.AssertError(t, err)
	default:
		testutil.AssertErrorIs(t, err, want)
	}
}

// assertErrContains checks that err mentions every substring.
func assertErrContains(t *testing.T, err error, substrings []string) {
	t.Helper()

	if len(substrings) == 0 {
		return
	}

	testutil.AssertError(t, err)

	for _, substr := range substrings {
		testutil.AssertContains(t, err.Error(), substr)
	}
}

type validateTest struct {
	name    string
	policy  policy.Policy
	wantErr error
	// check runs additional assertions when validation succeeds.
	check func(t *testing.T, pol *policy.Policy)
}

func runValidateTests(t *testing.T, tests []validateTest) {
	t.Helper()

	for idx := range tests {
		test := &tests[idx]

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := test.policy.Validate()
			assertErr(t, err, test.wantErr)

			if err == nil && test.check != nil {
				test.check(t, &test.policy)
			}
		})
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()

	err := os.WriteFile(path, []byte(content), 0o600)
	if err != nil {
		t.Fatalf("writing file %s: %v", path, err)
	}
}

func trustPolicy(trust *policy.TrustPolicy) policy.Policy {
	return policy.Policy{Trust: trust}
}

func verifierPolicy(issuers []string, verifiers ...policy.TrustedVerifier) policy.Policy {
	return trustPolicy(&policy.TrustPolicy{Issuers: issuers, Verifiers: verifiers})
}

func keyVerifier(id string, keys ...string) policy.TrustedVerifier {
	return policy.TrustedVerifier{ID: id, Keys: keys}
}

func boundedVerifier(notBefore, notAfter string, keys ...string) policy.TrustedVerifier {
	return policy.TrustedVerifier{
		ID: testVerifierID, Keys: keys, NotBefore: notBefore, NotAfter: notAfter,
	}
}

func caTrustStore(name string, certs ...string) policy.NotationTrustStore {
	return policy.NotationTrustStore{Name: name, Type: "ca", Certificates: certs}
}

func notationTrustRule(
	name string,
	scopes, stores, identities []string,
) policy.NotationTrustPolicyRule {
	return policy.NotationTrustPolicyRule{
		Name: name, RegistryScopes: scopes, TrustStores: stores, TrustedIdentities: identities,
	}
}

func notationPolicy(notation *policy.NotationPolicy) policy.Policy {
	return policy.Policy{Notation: notation}
}

func sbomPolicy(sbom *policy.SBOMPolicy) policy.Policy {
	return policy.Policy{SBOM: sbom}
}

func rulesPolicy(rules ...policy.ImageRule) policy.Policy {
	return policy.Policy{Rules: rules}
}

func assertTimeEqual(t *testing.T, want, got time.Time) {
	t.Helper()

	if !got.Equal(want) {
		t.Errorf("expected time %v, got %v", want, got)
	}
}

func TestPolicyValidateTopLevel(t *testing.T) {
	t.Parallel()

	//nolint:exhaustruct_v5 // table cases only set the fields they assert
	runValidateTests(t, []validateTest{
		{
			name: "empty policy is valid",
			check: func(t *testing.T, pol *policy.Policy) {
				t.Helper()

				if pol.CompiledCEL != nil {
					t.Error("expected CompiledCEL to be nil when no CEL section")
				}
			},
		},
		{name: "latest version", policy: policy.Policy{Version: policy.LatestPolicyVersion}},
		{
			name:    "version too new",
			policy:  policy.Policy{Version: policy.LatestPolicyVersion + 1},
			wantErr: policy.ErrPolicyVersionTooNew,
		},
		{
			name:    "negative version",
			policy:  policy.Policy{Version: -1},
			wantErr: policy.ErrPolicyVersionTooNew,
		},
		{name: "warn mode", policy: policy.Policy{Mode: config.ModeWarn}},
		{name: "enforce mode", policy: policy.Policy{Mode: config.ModeEnforce}},
		{name: "disabled mode", policy: policy.Policy{Mode: config.ModeDisabled}},
		{
			name:    "invalid mode",
			policy:  policy.Policy{Mode: testInvalidValue},
			wantErr: policy.ErrInvalidPolicyMode,
		},
		{name: "include single star", policy: policy.Policy{Include: []string{"gcr.io/org/*"}}},
		{
			name:   "include double star",
			policy: policy.Policy{Include: []string{"registry.k8s.io/**"}},
		},
		{name: "exclude single star", policy: policy.Policy{Exclude: []string{"gcr.io/org/*"}}},
		{
			name:   "exclude double star",
			policy: policy.Policy{Exclude: []string{"registry.k8s.io/**"}},
		},
		{
			name: "valid CEL rules are compiled",
			policy: policy.Policy{CEL: &celengine.Policy{Rules: []celengine.Rule{{
				Match:   "image.registry == 'ghcr.io'",
				Require: testCELExprSLSAVerified,
				Message: "GHCR images must have SLSA",
			}}}},
			check: func(t *testing.T, pol *policy.Policy) {
				t.Helper()

				if pol.CompiledCEL == nil {
					t.Error("expected CompiledCEL to be populated after validation")
				}
			},
		},
		{
			name: "CEL syntax error",
			policy: policy.Policy{CEL: &celengine.Policy{
				Rules: []celengine.Rule{{Require: testCELInvalidExpr}},
			}},
			wantErr: policy.ErrCELCompileFailed,
		},
		{
			name:   "CEL section without rules",
			policy: policy.Policy{CEL: &celengine.Policy{Rules: nil}},
			check: func(t *testing.T, pol *policy.Policy) {
				t.Helper()

				if pol.CompiledCEL != nil {
					t.Error("expected CompiledCEL to be nil with empty rules")
				}
			},
		},
	})
}

func TestPolicyValidateTrust(t *testing.T) {
	t.Parallel()

	//nolint:exhaustruct_v5 // table cases only set the fields they assert
	runValidateTests(t, []validateTest{
		{
			name: "valid builder",
			policy: trustPolicy(&policy.TrustPolicy{
				Builders: []policy.TrustedBuilder{{ID: testRunnerBuilderID, MaxLevel: 3}},
			}),
		},
		{
			name: "builder without ID",
			policy: trustPolicy(&policy.TrustPolicy{
				Builders: []policy.TrustedBuilder{{ID: "", MaxLevel: 2}},
			}),
			wantErr: policy.ErrBuilderIDRequired,
		},
		{
			name: "builder with invalid max level",
			policy: trustPolicy(&policy.TrustPolicy{
				Builders: []policy.TrustedBuilder{{ID: testBuilderID, MaxLevel: 5}},
			}),
			wantErr: policy.ErrBuilderMaxLevel,
		},
		{
			name: "duplicate builder ID",
			policy: trustPolicy(&policy.TrustPolicy{
				Builders: []policy.TrustedBuilder{
					{ID: "https://builder.example.com", MaxLevel: 2},
					{ID: "https://builder.example.com", MaxLevel: 3},
				},
			}),
			wantErr: policy.ErrDuplicateBuilderID,
		},
		{
			name: "builder identity without SAN pattern",
			policy: trustPolicy(&policy.TrustPolicy{
				Issuers: []string{testGitHubIssuer},
				Builders: []policy.TrustedBuilder{{
					ID:         testBuilderID,
					Identities: []policy.TrustedIdentity{{Issuer: testGitHubIssuer}},
				}},
			}),
			wantErr: policy.ErrIdentitySANPatternRequired,
		},
		{
			name: "relative builder key",
			policy: trustPolicy(&policy.TrustPolicy{
				Builders: []policy.TrustedBuilder{
					{ID: testBuilderID, Keys: []string{"keys/builder.pub"}},
				},
			}),
			wantErr: policy.ErrBuilderKeyNotAbsolute,
		},
		{
			name: "duplicate builder key",
			policy: trustPolicy(&policy.TrustPolicy{
				Builders: []policy.TrustedBuilder{
					{ID: testBuilderID, Keys: []string{testKeyPath, testKeyPath}},
				},
			}),
			wantErr: policy.ErrDuplicateBuilderKey,
		},
		{
			name: "key shared by builder and verifier",
			policy: trustPolicy(&policy.TrustPolicy{
				Builders: []policy.TrustedBuilder{
					{ID: testBuilderID, Keys: []string{testKeyPath}},
				},
				Verifiers: []policy.TrustedVerifier{keyVerifier(testVerifierID, testKeyPath)},
			}),
			wantErr: policy.ErrDuplicateKeyAcrossVerifiers,
		},
		{
			name: "key shared by two builders",
			policy: trustPolicy(&policy.TrustPolicy{
				Builders: []policy.TrustedBuilder{
					{ID: testBuilderID, Keys: []string{testKeyPath}},
					{ID: "https://example.com/other-builder", Keys: []string{testKeyPath}},
				},
			}),
		},
		{
			name:    "keyless verifier without issuers",
			policy:  verifierPolicy(nil, keyVerifier(testBuilderID)),
			wantErr: policy.ErrKeylessVerifierRequiresIssuers,
		},
		{
			name:   "keyless verifier with issuers",
			policy: verifierPolicy([]string{testGitHubIssuer}, keyVerifier(testBuilderID)),
		},
		{
			name:    "verifier without ID",
			policy:  verifierPolicy(nil, keyVerifier("", testKeyPath)),
			wantErr: policy.ErrVerifierIDRequired,
		},
		{
			name:   "verifier with single key",
			policy: verifierPolicy(nil, keyVerifier(testBuilderID, testKeyPath)),
		},
		{
			name:   "verifier with multiple keys",
			policy: verifierPolicy(nil, keyVerifier(testBuilderID, "/path/a.pub", "/path/b.pub")),
		},
		{
			name:    "verifier with relative key path",
			policy:  verifierPolicy(nil, keyVerifier(testBuilderID, "relative/path.pub")),
			wantErr: policy.ErrVerifierKeyNotAbsolute,
		},
		{
			name: "verifier with keys containing relative path",
			policy: verifierPolicy(nil,
				keyVerifier(testBuilderID, "/abs/good.pub", "relative/bad.pub"),
			),
			wantErr: policy.ErrVerifierKeyNotAbsolute,
		},
		{
			name:    "verifier with empty string in keys",
			policy:  verifierPolicy(nil, keyVerifier(testBuilderID, testValidKeyPath, "")),
			wantErr: policy.ErrEmptyValue,
		},
		{
			name: "verifier with duplicate keys",
			policy: verifierPolicy(nil,
				keyVerifier(testBuilderID, testValidKeyPath, testValidKeyPath),
			),
			wantErr: policy.ErrDuplicateVerifierKey,
		},
		{
			name: "duplicate verifier ID",
			policy: verifierPolicy([]string{testIssuerURL},
				keyVerifier("https://verifier.example.com"),
				keyVerifier("https://verifier.example.com"),
			),
			wantErr: policy.ErrDuplicateVerifierID,
		},
		{
			name: "same key in two verifiers",
			policy: verifierPolicy(nil,
				policy.TrustedVerifier{
					ID:        "verifier-a",
					Keys:      []string{testKeyPath},
					NotBefore: testNotBefore2024,
					NotAfter:  testNotAfter2025,
				},
				keyVerifier("verifier-b", testKeyPath),
			),
			wantErr: policy.ErrDuplicateKeyAcrossVerifiers,
		},
		{
			name: "different keys in two verifiers",
			policy: verifierPolicy(nil,
				keyVerifier("verifier-a", "/key/a.pub"),
				keyVerifier("verifier-b", "/key/b.pub"),
			),
		},
		{
			name: "valid verifier identity",
			policy: verifierPolicy([]string{testGitHubIssuer}, policy.TrustedVerifier{
				ID: testVerifierID,
				Identities: []policy.TrustedIdentity{
					{Issuer: testGitHubIssuer, SANPattern: testReleaseSANPattern},
				},
			}),
		},
		{
			name: "verifier identity without issuer",
			policy: verifierPolicy([]string{testGitHubIssuer}, policy.TrustedVerifier{
				ID:         testVerifierID,
				Identities: []policy.TrustedIdentity{{SANPattern: testReleaseSANPattern}},
			}),
			wantErr: policy.ErrIdentityIssuerRequired,
		},
		{
			name: "notBefore and notAfter are resolved",
			policy: verifierPolicy(nil,
				boundedVerifier(testNotBefore2024, testNotAfter2025, testKeyPath),
			),
			check: func(t *testing.T, pol *policy.Policy) {
				t.Helper()

				verif := pol.Trust.Verifiers[0]
				assertTimeEqual(t, time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), verif.NotBeforeTime)
				assertTimeEqual(t, time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), verif.NotAfterTime)
			},
		},
		{
			name:   "notBefore only",
			policy: verifierPolicy(nil, boundedVerifier("2024-06-15T12:00:00Z", "", testKeyPath)),
			check: func(t *testing.T, pol *policy.Policy) {
				t.Helper()

				testutil.AssertEqual(t, false, pol.Trust.Verifiers[0].NotBeforeTime.IsZero())
				testutil.AssertEqual(t, true, pol.Trust.Verifiers[0].NotAfterTime.IsZero())
			},
		},
		{
			name:   "notAfter only",
			policy: verifierPolicy(nil, boundedVerifier("", "2025-12-31T23:59:59Z", testKeyPath)),
			check: func(t *testing.T, pol *policy.Policy) {
				t.Helper()

				testutil.AssertEqual(t, true, pol.Trust.Verifiers[0].NotBeforeTime.IsZero())
				testutil.AssertEqual(t, false, pol.Trust.Verifiers[0].NotAfterTime.IsZero())
			},
		},
		{
			name:    "invalid notBefore format",
			policy:  verifierPolicy(nil, boundedVerifier("not-a-date", "", testKeyPath)),
			wantErr: policy.ErrInvalidNotBefore,
		},
		{
			name:    "invalid notAfter format",
			policy:  verifierPolicy(nil, boundedVerifier("", "2024/01/01", testKeyPath)),
			wantErr: policy.ErrInvalidNotAfter,
		},
		{
			name: "notAfter before notBefore",
			policy: verifierPolicy(nil,
				boundedVerifier(testNotAfter2025, testNotBefore2024, testKeyPath),
			),
			wantErr: policy.ErrNotAfterBeforeNotBefore,
		},
		{
			name: "notAfter equals notBefore",
			policy: verifierPolicy(nil,
				boundedVerifier(testMidpoint2024, testMidpoint2024, testKeyPath),
			),
			wantErr: policy.ErrNotAfterBeforeNotBefore,
		},
		{
			name: "notBefore without keys",
			policy: verifierPolicy(
				[]string{testIssuerURL},
				boundedVerifier(testNotBefore2024, ""),
			),
			wantErr: policy.ErrTimeBoundsWithoutKeys,
		},
		{
			name:    "notAfter without keys",
			policy:  verifierPolicy([]string{testIssuerURL}, boundedVerifier("", testNotAfter2025)),
			wantErr: policy.ErrTimeBoundsWithoutKeys,
		},
		{
			name: "notBefore and notAfter without keys",
			policy: verifierPolicy([]string{testIssuerURL},
				boundedVerifier(testNotBefore2024, testNotAfter2025),
			),
			wantErr: policy.ErrTimeBoundsWithoutKeys,
		},
	})
}

// maxAgeTests generates the shared maxAge validation cases for a section.
func maxAgeTests(
	section string, notPositive error,
	withMaxAge func(maxAge string) policy.Policy,
	duration func(pol *policy.Policy) time.Duration,
) []validateTest {
	expectDuration := func(want time.Duration) func(*testing.T, *policy.Policy) {
		return func(t *testing.T, pol *policy.Policy) {
			t.Helper()

			testutil.AssertEqual(t, want, duration(pol))
		}
	}

	//nolint:exhaustruct_v5 // table cases only set the fields they assert
	return []validateTest{
		{
			name:   section + " maxAge is resolved",
			policy: withMaxAge(testMaxAge),
			check:  expectDuration(24 * time.Hour),
		},
		{
			name:   section + " without maxAge skips resolve",
			policy: withMaxAge(""),
			check:  expectDuration(0),
		},
		{
			name:    section + " negative maxAge",
			policy:  withMaxAge(testNegativeDuration),
			wantErr: notPositive,
		},
		{name: section + " zero maxAge", policy: withMaxAge("0s"), wantErr: notPositive},
		{
			name:    section + " invalid maxAge format",
			policy:  withMaxAge(testInvalidDuration),
			wantErr: errAnyError,
		},
	}
}

func TestPolicyValidateSectionMaxAge(t *testing.T) {
	t.Parallel()

	var tests []validateTest

	tests = append(tests, maxAgeTests("slsa", policy.ErrSLSAMaxAgeNotPositive,
		func(maxAge string) policy.Policy {
			return policy.Policy{SLSA: &policy.SLSAPolicy{MaxAge: maxAge}}
		},
		func(pol *policy.Policy) time.Duration { return pol.SLSA.MaxAgeDuration },
	)...)
	tests = append(tests, maxAgeTests("vsa", policy.ErrVSAMaxAgeNotPositive,
		func(maxAge string) policy.Policy {
			return policy.Policy{VSA: &policy.VSAPolicy{MaxAge: maxAge}}
		},
		func(pol *policy.Policy) time.Duration { return pol.VSA.MaxAgeDuration },
	)...)
	tests = append(tests, maxAgeTests("source", policy.ErrSourceMaxAgeNotPositive,
		func(maxAge string) policy.Policy {
			return policy.Policy{Source: &policy.SourcePolicy{MaxAge: maxAge}}
		},
		func(pol *policy.Policy) time.Duration { return pol.Source.MaxAgeDuration },
	)...)
	tests = append(tests, maxAgeTests("vulnScan", policy.ErrVulnScanMaxAgeNotPositive,
		func(maxAge string) policy.Policy {
			return policy.Policy{VulnScan: &policy.VulnScanPolicy{MaxAge: maxAge}}
		},
		func(pol *policy.Policy) time.Duration { return pol.VulnScan.MaxAgeDuration },
	)...)
	tests = append(tests, maxAgeTests("testResult", policy.ErrTestResultMaxAgeNotPositive,
		func(maxAge string) policy.Policy {
			return policy.Policy{TestResult: &policy.TestResultPolicy{MaxAge: maxAge}}
		},
		func(pol *policy.Policy) time.Duration { return pol.TestResult.MaxAgeDuration },
	)...)
	tests = append(tests, maxAgeTests("runtimeTrace", policy.ErrRuntimeTraceMaxAgeNotPositive,
		func(maxAge string) policy.Policy {
			return policy.Policy{RuntimeTrace: &policy.RuntimeTracePolicy{MaxAge: maxAge}}
		},
		func(pol *policy.Policy) time.Duration { return pol.RuntimeTrace.MaxAgeDuration },
	)...)

	runValidateTests(t, tests)
}

func TestPolicyValidateSections(t *testing.T) {
	t.Parallel()

	//nolint:exhaustruct_v5 // table cases only set the fields they assert
	runValidateTests(t, []validateTest{
		{
			name:    "slsa invalid missing policy",
			policy:  policy.Policy{SLSA: &policy.SLSAPolicy{MissingPolicy: testInvalidValue}},
			wantErr: types.ErrInvalidAction,
		},
		{
			name: "vex valid",
			policy: policy.Policy{VEX: &policy.VEXPolicy{
				MissingPolicy:            types.ActionWarn,
				UnderInvestigationPolicy: types.ActionAllow,
			}},
		},
		{
			name:    "vex invalid missing policy",
			policy:  policy.Policy{VEX: &policy.VEXPolicy{MissingPolicy: testInvalidValue}},
			wantErr: types.ErrInvalidAction,
		},
		{
			name: "vex invalid under investigation policy",
			policy: policy.Policy{VEX: &policy.VEXPolicy{
				UnderInvestigationPolicy: testInvalidValue,
			}},
			wantErr: types.ErrInvalidAction,
		},
		{
			name: "vsa valid",
			policy: policy.Policy{VSA: &policy.VSAPolicy{
				MinimumLevel: 2, MaxAge: "168h", Policy: "https://example.com/policy",
			}},
		},
		{
			name:    "vsa invalid minimum level",
			policy:  policy.Policy{VSA: &policy.VSAPolicy{MinimumLevel: 5}},
			wantErr: policy.ErrVSAMinimumLevel,
		},
		{
			name:    "vsa invalid missing policy",
			policy:  policy.Policy{VSA: &policy.VSAPolicy{MissingPolicy: testInvalidValue}},
			wantErr: types.ErrInvalidAction,
		},
		{
			name:    "vulnScan maxScore out of range",
			policy:  policy.Policy{VulnScan: &policy.VulnScanPolicy{MaxScore: new(11.0)}},
			wantErr: policy.ErrVulnScanMaxScoreRange,
		},
		{
			name:    "vulnScan invalid minSeverity",
			policy:  policy.Policy{VulnScan: &policy.VulnScanPolicy{MinSeverity: "moderate"}},
			wantErr: policy.ErrVulnScanMinSeverityInvalid,
		},
		{
			name: "vulnScan valid",
			policy: policy.Policy{VulnScan: &policy.VulnScanPolicy{
				MaxScore: new(7.0), MinSeverity: "high", MaxAge: testMaxAge,
			}},
		},
		{
			name:    "scorecard minScore below range",
			policy:  policy.Policy{Scorecard: &policy.ScorecardPolicy{MinScore: new(-0.1)}},
			wantErr: policy.ErrScorecardMinScoreRange,
		},
		{
			name:    "scorecard minScore above range",
			policy:  policy.Policy{Scorecard: &policy.ScorecardPolicy{MinScore: new(10.1)}},
			wantErr: policy.ErrScorecardMinScoreRange,
		},
		{
			name: "scorecard check score below range",
			policy: policy.Policy{Scorecard: &policy.ScorecardPolicy{
				Checks: map[string]int{testScorecardCodeReview: -1},
			}},
			wantErr: policy.ErrScorecardCheckScoreRange,
		},
		{
			name: "scorecard check score above range",
			policy: policy.Policy{Scorecard: &policy.ScorecardPolicy{
				Checks: map[string]int{testScorecardCodeReview: 11},
			}},
			wantErr: policy.ErrScorecardCheckScoreRange,
		},
		{
			name: "scorecard empty check name",
			policy: policy.Policy{
				Scorecard: &policy.ScorecardPolicy{Checks: map[string]int{"": 7}},
			},
			wantErr: policy.ErrEmptyValue,
		},
		{
			name: "scorecard valid",
			policy: policy.Policy{Scorecard: &policy.ScorecardPolicy{
				MinScore: new(7.0),
				Checks:   map[string]int{testScorecardCodeReview: 8, "Branch-Protection": 9},
			}},
		},
		{
			name:    "source invalid level",
			policy:  policy.Policy{Source: &policy.SourcePolicy{MinimumLevel: 4}},
			wantErr: policy.ErrInvalidSourceLevel,
		},
		{
			name:   "source valid",
			policy: policy.Policy{Source: &policy.SourcePolicy{MinimumLevel: 2, MaxAge: "12h"}},
		},
		{
			name: "buildEnv overlapping required and forbidden properties",
			policy: policy.Policy{BuildEnv: &policy.BuildEnvPolicy{
				RequiredProperties:  []string{"OS"},
				ForbiddenProperties: []string{"os"},
			}},
			wantErr: policy.ErrBuildEnvOverlappingProperties,
		},
		{
			name: "buildEnv valid",
			policy: policy.Policy{BuildEnv: &policy.BuildEnvPolicy{
				RequiredProperties:  []string{"OS", "ARCH"},
				ForbiddenProperties: []string{"DEBUG_MODE"},
			}},
		},
		{
			name: "testResult valid",
			policy: policy.Policy{TestResult: &policy.TestResultPolicy{
				RequiredSuites: []string{"unit", "integration"}, MaxAge: "6h",
			}},
		},
		{
			name: "scai overlapping required and forbidden attributes",
			policy: policy.Policy{SCAI: &policy.SCAIPolicy{
				RequiredAttributes:  []string{testAttrCodeReview, testAttrFuzzTested},
				ForbiddenAttributes: []string{testAttrCodeReview},
			}},
			wantErr: policy.ErrSCAIOverlappingAttributes,
		},
		{
			name: "scai overlapping attributes is case-insensitive",
			policy: policy.Policy{SCAI: &policy.SCAIPolicy{
				RequiredAttributes:  []string{"Passed_Code_Review"},
				ForbiddenAttributes: []string{"passed_code_review"},
			}},
			wantErr: policy.ErrSCAIOverlappingAttributes,
		},
		{
			name: "scai without overlap",
			policy: policy.Policy{SCAI: &policy.SCAIPolicy{
				RequiredAttributes:  []string{testAttrCodeReview},
				ForbiddenAttributes: []string{testAttrKnownVulnerable},
			}},
		},
		{
			name:   "vsa missing policy deny",
			policy: policy.Policy{VSA: &policy.VSAPolicy{MissingPolicy: types.ActionDeny}},
		},
		{
			name:   "vsa missing policy warn",
			policy: policy.Policy{VSA: &policy.VSAPolicy{MissingPolicy: types.ActionWarn}},
		},
		{
			name:   "vsa missing policy allow",
			policy: policy.Policy{VSA: &policy.VSAPolicy{MissingPolicy: types.ActionAllow}},
		},
	})
}

func TestPolicyValidateSBOM(t *testing.T) {
	t.Parallel()

	//nolint:exhaustruct_v5 // table cases only set the fields they assert
	runValidateTests(t, []validateTest{
		{
			name: "valid SBOM config",
			policy: sbomPolicy(&policy.SBOMPolicy{
				MissingPolicy: types.ActionWarn,
				Formats:       []string{testFormatSPDX, testFormatCycloneDX},
				License:       &policy.SBOMLicensePolicy{Deny: []string{testLicenseAGPL}},
				Component: &policy.SBOMComponentPolicy{
					Deny: []string{"pkg:npm/bad-package@1.0.0"},
				},
			}),
		},
		{
			name:    "invalid SBOM missing policy",
			policy:  sbomPolicy(&policy.SBOMPolicy{MissingPolicy: testInvalidValue}),
			wantErr: types.ErrInvalidAction,
		},
		{
			name:    "invalid SBOM format",
			policy:  sbomPolicy(&policy.SBOMPolicy{Formats: []string{"unknown"}}),
			wantErr: policy.ErrInvalidSBOMFormat,
		},
		{
			name: "empty license in deny list",
			policy: sbomPolicy(&policy.SBOMPolicy{
				License: &policy.SBOMLicensePolicy{Deny: []string{testLicenseMIT, ""}},
			}),
			wantErr: policy.ErrEmptyValue,
		},
		{
			name: "empty license in allow list",
			policy: sbomPolicy(&policy.SBOMPolicy{
				License: &policy.SBOMLicensePolicy{Allow: []string{testLicenseMIT, ""}},
			}),
			wantErr: policy.ErrEmptyValue,
		},
		{
			name: "invalid component deny list entry",
			policy: sbomPolicy(&policy.SBOMPolicy{
				Component: &policy.SBOMComponentPolicy{Deny: []string{"not-a-purl"}},
			}),
			wantErr: policy.ErrInvalidComponentPURL,
		},
		{
			name: "empty component deny list entry",
			policy: sbomPolicy(&policy.SBOMPolicy{
				Component: &policy.SBOMComponentPolicy{Deny: []string{""}},
			}),
			wantErr: policy.ErrEmptyValue,
		},
		{
			name: "invalid component allow list entry",
			policy: sbomPolicy(&policy.SBOMPolicy{
				Component: &policy.SBOMComponentPolicy{Allow: []string{"not-a-purl"}},
			}),
			wantErr: policy.ErrInvalidComponentPURL,
		},
		{
			name: "bare pkg: scheme without type/name rejected",
			policy: sbomPolicy(&policy.SBOMPolicy{
				Component: &policy.SBOMComponentPolicy{Deny: []string{"pkg:"}},
			}),
			wantErr: policy.ErrInvalidComponentPURL,
		},
		{
			name: "pkg:type without name rejected",
			policy: sbomPolicy(&policy.SBOMPolicy{
				Component: &policy.SBOMComponentPolicy{Deny: []string{"pkg:npm"}},
			}),
			wantErr: policy.ErrInvalidComponentPURL,
		},
		{
			name: "valid allow lists",
			policy: sbomPolicy(&policy.SBOMPolicy{
				License:   &policy.SBOMLicensePolicy{Allow: []string{testLicenseMIT, "Apache-2.0"}},
				Component: &policy.SBOMComponentPolicy{Allow: []string{"pkg:npm/trusted@1.0.0"}},
			}),
		},
		{
			name: "valid CVSS policy",
			policy: sbomPolicy(&policy.SBOMPolicy{CVSS: &policy.SBOMCVSSPolicy{
				MaxScore: new(7.0), MinSeverity: "high", IgnoreCVEs: []string{testCVEID},
			}}),
		},
		{
			name: "CVSS maxScore too high",
			policy: sbomPolicy(
				&policy.SBOMPolicy{CVSS: &policy.SBOMCVSSPolicy{MaxScore: new(11.0)}},
			),
			wantErr: policy.ErrCVSSMaxScoreRange,
		},
		{
			name: "CVSS maxScore negative",
			policy: sbomPolicy(
				&policy.SBOMPolicy{CVSS: &policy.SBOMCVSSPolicy{MaxScore: new(-1.0)}},
			),
			wantErr: policy.ErrCVSSMaxScoreRange,
		},
		{
			name: "CVSS invalid minSeverity",
			policy: sbomPolicy(&policy.SBOMPolicy{
				CVSS: &policy.SBOMCVSSPolicy{MinSeverity: "extreme"},
			}),
			wantErr: policy.ErrCVSSMinSeverityInvalid,
		},
		{
			name: "CVSS empty ignoreCVEs entry",
			policy: sbomPolicy(&policy.SBOMPolicy{
				CVSS: &policy.SBOMCVSSPolicy{IgnoreCVEs: []string{testCVEID, ""}},
			}),
			wantErr: policy.ErrEmptyValue,
		},
		{
			name: "valid drift policy",
			policy: sbomPolicy(&policy.SBOMPolicy{Drift: &policy.SBOMDriftPolicy{
				MaxAdded: new(5), MaxRemoved: new(3), MaxModified: new(2), MaxScore: new(1.5),
			}}),
		},
		{
			name: "drift maxAdded negative",
			policy: sbomPolicy(
				&policy.SBOMPolicy{Drift: &policy.SBOMDriftPolicy{MaxAdded: new(-1)}},
			),
			wantErr: policy.ErrDriftThresholdNegative,
		},
		{
			name: "drift maxScore negative",
			policy: sbomPolicy(
				&policy.SBOMPolicy{Drift: &policy.SBOMDriftPolicy{MaxScore: new(-0.5)}},
			),
			wantErr: policy.ErrDriftThresholdNegative,
		},
	})
}

func TestPolicyValidateNotation(t *testing.T) {
	t.Parallel()

	store := caTrustStore(testNotationStoreName, testNotationCertPath)
	wildcard := []string{"*"}
	storeRefs := []string{testNotationStoreRef}

	//nolint:exhaustruct_v5 // table cases only set the fields they assert
	tests := []validateTest{
		{
			name: "valid notation config",
			policy: notationPolicy(&policy.NotationPolicy{
				MissingPolicy:     types.ActionDeny,
				VerificationLevel: testNotationLevelStrict,
				TrustStores:       []policy.NotationTrustStore{store},
				TrustPolicy: []policy.NotationTrustPolicyRule{
					notationTrustRule(testDefaultLabel, wildcard, storeRefs, wildcard),
				},
			}),
		},
		{
			name: "valid permissive verification level",
			policy: notationPolicy(&policy.NotationPolicy{
				VerificationLevel: testNotationPermissive,
				TrustStores:       []policy.NotationTrustStore{store},
			}),
		},
		{
			name:    "invalid missing policy",
			policy:  notationPolicy(&policy.NotationPolicy{MissingPolicy: testInvalidValue}),
			wantErr: types.ErrInvalidAction,
		},
		{
			name: "invalid verification level",
			policy: notationPolicy(&policy.NotationPolicy{
				MissingPolicy:     types.ActionDeny,
				VerificationLevel: testInvalidValue,
				TrustStores:       []policy.NotationTrustStore{store},
			}),
			wantErr: policy.ErrNotationVerificationLevelInvalid,
		},
		{
			name: "trust store missing name",
			policy: notationPolicy(&policy.NotationPolicy{
				TrustStores: []policy.NotationTrustStore{caTrustStore("", testNotationCertPath)},
			}),
			wantErr: policy.ErrNotationTrustStoreNameRequired,
		},
		{
			name: "trust store invalid type",
			policy: notationPolicy(&policy.NotationPolicy{
				TrustStores: []policy.NotationTrustStore{{
					Name: testNotationStoreName, Type: testInvalidValue,
					Certificates: []string{testNotationCertPath},
				}},
			}),
			wantErr: policy.ErrNotationTrustStoreTypeInvalid,
		},
		{
			name: "trust store without certificates",
			policy: notationPolicy(&policy.NotationPolicy{
				TrustStores: []policy.NotationTrustStore{caTrustStore(testNotationStoreName)},
			}),
			wantErr: policy.ErrNotationTrustStoreCertsRequired,
		},
		{
			name: "trust store relative certificate path",
			policy: notationPolicy(&policy.NotationPolicy{
				TrustStores: []policy.NotationTrustStore{
					caTrustStore(testNotationStoreName, "relative/path.pem"),
				},
			}),
			wantErr: policy.ErrNotationCertNotAbsolute,
		},
		{
			name: "duplicate trust store name",
			policy: notationPolicy(&policy.NotationPolicy{
				TrustStores: []policy.NotationTrustStore{
					store, caTrustStore(testNotationStoreName, "/etc/certs/ca2.pem"),
				},
			}),
			wantErr: policy.ErrDuplicateNotationTrustStoreName,
		},
		{
			name: "trust policy missing name",
			policy: notationPolicy(&policy.NotationPolicy{
				TrustPolicy: []policy.NotationTrustPolicyRule{
					notationTrustRule("", wildcard, storeRefs, wildcard),
				},
			}),
			wantErr: policy.ErrNotationTrustPolicyNameRequired,
		},
		{
			name: "trust policy missing registry scopes",
			policy: notationPolicy(&policy.NotationPolicy{
				TrustPolicy: []policy.NotationTrustPolicyRule{
					notationTrustRule(testNotationRuleName, nil, storeRefs, wildcard),
				},
			}),
			wantErr: policy.ErrNotationTrustPolicyScopesRequired,
		},
		{
			name: "trust policy missing trust stores",
			policy: notationPolicy(&policy.NotationPolicy{
				TrustPolicy: []policy.NotationTrustPolicyRule{
					notationTrustRule(testNotationRuleName, wildcard, nil, wildcard),
				},
			}),
			wantErr: policy.ErrNotationTrustPolicyStoresRequired,
		},
		{
			name: "trust policy missing trusted identities",
			policy: notationPolicy(&policy.NotationPolicy{
				TrustPolicy: []policy.NotationTrustPolicyRule{
					notationTrustRule(testNotationRuleName, wildcard, storeRefs, nil),
				},
			}),
			wantErr: policy.ErrNotationTrustPolicyIdentitiesRequired,
		},
		{
			name: "duplicate trust policy name",
			policy: notationPolicy(&policy.NotationPolicy{
				TrustPolicy: []policy.NotationTrustPolicyRule{
					notationTrustRule(testNotationRuleName, wildcard, storeRefs, wildcard),
					notationTrustRule(
						testNotationRuleName,
						[]string{testDockerGlob},
						storeRefs,
						wildcard,
					),
				},
			}),
			wantErr: policy.ErrDuplicateNotationTrustPolicyName,
		},
		{
			name:    "invalid revocation mode",
			policy:  notationPolicy(&policy.NotationPolicy{RevocationMode: testInvalidValue}),
			wantErr: policy.ErrNotationRevocationModeInvalid,
		},
	}

	for _, mode := range []string{testNotationLevelStrict, "soft", testNotationLevelSkip, ""} {
		//nolint:exhaustruct_v5 // table cases only set the fields they assert
		tests = append(tests, validateTest{
			name: "revocation mode " + mode + " is valid",
			policy: notationPolicy(&policy.NotationPolicy{
				RevocationMode: mode,
				TrustStores:    []policy.NotationTrustStore{store},
			}),
		})

		if mode == "" {
			continue
		}

		//nolint:exhaustruct_v5 // table cases only set the fields they assert
		tests = append(tests, validateTest{
			name: "revocation mode " + mode + " rejected with verification level skip",
			policy: notationPolicy(&policy.NotationPolicy{
				VerificationLevel: testNotationLevelSkip,
				RevocationMode:    mode,
			}),
			wantErr: policy.ErrNotationRevocationWithSkipLevel,
		})
	}

	runValidateTests(t, tests)
}

func TestPolicyValidateRules(t *testing.T) {
	t.Parallel()

	//nolint:exhaustruct_v5 // table cases only set the fields they assert
	runValidateTests(t, []validateTest{
		{
			name: "valid rule",
			policy: rulesPolicy(policy.ImageRule{
				Images: []string{"ghcr.io/myorg/**"},
				SLSA:   &policy.SLSAPolicy{MissingPolicy: types.ActionDeny},
			}),
		},
		{
			name: "valid glob patterns",
			policy: rulesPolicy(policy.ImageRule{
				Images: []string{"ghcr.io/myorg/**", "docker.io/library/*"},
			}),
		},
		{
			name:    "empty images",
			policy:  rulesPolicy(policy.ImageRule{Images: nil}),
			wantErr: policy.ErrRuleImagesRequired,
		},
		{
			name:    "empty string in images",
			policy:  rulesPolicy(policy.ImageRule{Images: []string{""}}),
			wantErr: policy.ErrEmptyValue,
		},
		{
			name: "invalid trust",
			policy: rulesPolicy(policy.ImageRule{
				Images: []string{testRuleImagesGlob},
				Trust: &policy.TrustPolicy{
					Builders: []policy.TrustedBuilder{{ID: "", MaxLevel: 0}},
				},
			}),
			wantErr: policy.ErrBuilderIDRequired,
		},
		{
			name: "keyless verifier uses base issuers",
			policy: policy.Policy{
				Trust: &policy.TrustPolicy{Issuers: []string{testGitHubIssuer}},
				Rules: []policy.ImageRule{{
					Images: []string{testRuleImagesGlob},
					Trust: &policy.TrustPolicy{
						Verifiers: []policy.TrustedVerifier{keyVerifier(testVerifierID)},
					},
				}},
			},
		},
		{
			name: "keyless verifier without effective issuers",
			policy: policy.Policy{
				Trust: &policy.TrustPolicy{
					Issuers:   []string{testGitHubIssuer},
					Verifiers: []policy.TrustedVerifier{keyVerifier(testVerifierID)},
				},
				Rules: []policy.ImageRule{{
					Images: []string{testRuleImagesGlob},
					Trust:  &policy.TrustPolicy{Issuers: []string{}},
				}},
			},
			wantErr: policy.ErrKeylessVerifierRequiresIssuers,
		},
		{
			name: "CEL syntax error",
			policy: rulesPolicy(policy.ImageRule{
				Images: []string{testRuleImagesGlob},
				CEL: &celengine.Policy{
					Rules: []celengine.Rule{{Require: testCELInvalidExpr}},
				},
			}),
			wantErr: policy.ErrCELCompileFailed,
		},
		{
			name: "overlapping SCAI attributes",
			policy: rulesPolicy(policy.ImageRule{
				Images: []string{testRuleImagesGlob},
				SCAI: &policy.SCAIPolicy{
					RequiredAttributes:  []string{testAttrFuzzTested},
					ForbiddenAttributes: []string{testAttrFuzzTested},
				},
			}),
			wantErr: policy.ErrSCAIOverlappingAttributes,
		},
		{
			name: "VSA maxAge is resolved",
			policy: rulesPolicy(policy.ImageRule{
				Images: []string{testRuleImagesGlob},
				VSA:    &policy.VSAPolicy{MissingPolicy: types.ActionDeny, MaxAge: testMaxAge},
			}),
			check: func(t *testing.T, pol *policy.Policy) {
				t.Helper()

				testutil.AssertEqual(t, 24*time.Hour, pol.Rules[0].VSA.MaxAgeDuration)
			},
		},
		{
			name: "SLSA maxAge is resolved",
			policy: rulesPolicy(policy.ImageRule{
				Images: []string{testRuleImagesGlob},
				SLSA:   &policy.SLSAPolicy{MaxAge: testMaxAge},
			}),
			check: func(t *testing.T, pol *policy.Policy) {
				t.Helper()

				testutil.AssertEqual(t, 24*time.Hour, pol.Rules[0].SLSA.MaxAgeDuration)
			},
		},
	})
}

func TestPolicyValidateCollectsMultipleErrors(t *testing.T) {
	t.Parallel()

	//nolint:exhaustruct_v5 // table cases only set the fields they assert
	tests := []struct {
		name         string
		policy       *policy.Policy
		wantErrs     []error
		wantContains []string
	}{
		{
			name: "builders and VSA",
			policy: &policy.Policy{
				Trust: &policy.TrustPolicy{
					Builders: []policy.TrustedBuilder{{ID: ""}, {ID: "b1", MaxLevel: 99}},
				},
				VSA: &policy.VSAPolicy{MinimumLevel: -1},
			},
			wantErrs: []error{
				policy.ErrBuilderIDRequired, policy.ErrBuilderMaxLevel, policy.ErrVSAMinimumLevel,
			},
		},
		{
			name: "verifiers",
			policy: &policy.Policy{
				Trust: &policy.TrustPolicy{
					Verifiers: []policy.TrustedVerifier{
						{ID: ""}, keyVerifier("v1", "relative/path"),
					},
				},
			},
			wantErrs: []error{policy.ErrVerifierIDRequired, policy.ErrVerifierKeyNotAbsolute},
		},
		{
			name: "trust string fields",
			policy: &policy.Policy{
				Trust: &policy.TrustPolicy{
					Issuers:     []string{"valid", ""},
					Sources:     []string{"", "["},
					BuildTypes:  []string{""},
					SANPatterns: []string{"", "["},
				},
			},
			wantErrs: []error{policy.ErrEmptyValue},
			wantContains: []string{
				"trust.issuers", "trust.sources", "trust.buildTypes", "trust.sanPatterns",
			},
		},
		{
			name: "rule sub-policy references the rule index",
			policy: &policy.Policy{Rules: []policy.ImageRule{{
				Images: []string{testRuleImagesGlob},
				SLSA:   &policy.SLSAPolicy{MissingPolicy: testInvalidValue},
			}}},
			wantContains: []string{"rules[0]"},
		},
		{
			name: "multiple rules",
			policy: &policy.Policy{Rules: []policy.ImageRule{
				{Images: nil},
				{
					Images: []string{testRuleImagesGlob},
					VEX:    &policy.VEXPolicy{MissingPolicy: testInvalidValue},
				},
			}},
			wantErrs:     []error{policy.ErrRuleImagesRequired},
			wantContains: []string{"rules[1]"},
		},
	}

	for idx := range tests {
		test := &tests[idx]

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := test.policy.Validate()
			testutil.AssertError(t, err)

			for _, want := range test.wantErrs {
				testutil.AssertErrorIs(t, err, want)
			}

			assertErrContains(t, err, test.wantContains)
		})
	}
}

func TestValidateEnforce(t *testing.T) {
	t.Parallel()

	auditNotation := &policy.NotationPolicy{VerificationLevel: "audit"}

	//nolint:exhaustruct_v5 // table cases only set the fields they assert
	tests := []struct {
		name    string
		policy  *policy.Policy
		wantErr error
	}{
		{
			name: "issuers require SAN patterns",
			policy: &policy.Policy{
				Trust: &policy.TrustPolicy{Issuers: []string{testIssuerURL}},
			},
			wantErr: policy.ErrSANPatternsRequired,
		},
		{
			name: "issuers with SAN patterns",
			policy: &policy.Policy{Trust: &policy.TrustPolicy{
				Issuers:     []string{testIssuerURL},
				SANPatterns: []string{"build@example.com"},
			}},
		},
		{name: "trust without issuers", policy: &policy.Policy{Trust: &policy.TrustPolicy{}}},
		{name: "nil trust", policy: &policy.Policy{}},
		{
			name: "rule issuers require SAN patterns",
			policy: &policy.Policy{Rules: []policy.ImageRule{{
				Images: []string{testRuleImagesGlob},
				Trust:  &policy.TrustPolicy{Issuers: []string{testIssuerURL}},
			}}},
			wantErr: policy.ErrSANPatternsRequired,
		},
		{
			name: "rule issuers with SAN patterns",
			policy: &policy.Policy{Rules: []policy.ImageRule{{
				Images: []string{testRuleImagesGlob},
				Trust: &policy.TrustPolicy{
					Issuers:     []string{testIssuerURL},
					SANPatterns: []string{"https://github.com/**"},
				},
			}}},
		},
		{
			name: "rule clearing SAN patterns under base issuers is rejected",
			policy: &policy.Policy{
				Trust: &policy.TrustPolicy{
					Issuers:     []string{testIssuerURL},
					SANPatterns: []string{testReleaseSANPattern},
				},
				Rules: []policy.ImageRule{{
					Images: []string{testRuleImagesGlob},
					Trust:  &policy.TrustPolicy{SANPatterns: []string{}},
				}},
			},
			wantErr: policy.ErrSANPatternsRequired,
		},
		{
			name: "rule issuers inherit base SAN patterns",
			policy: &policy.Policy{
				Trust: &policy.TrustPolicy{SANPatterns: []string{testReleaseSANPattern}},
				Rules: []policy.ImageRule{{
					Images: []string{testRuleImagesGlob},
					Trust:  &policy.TrustPolicy{Issuers: []string{testIssuerURL}},
				}},
			},
		},
		{
			name: "notation skip is rejected",
			policy: &policy.Policy{
				Notation: &policy.NotationPolicy{VerificationLevel: testNotationLevelSkip},
			},
			wantErr: policy.ErrNotationSkipInEnforceMode,
		},
		{
			name: "notation strict is allowed",
			policy: &policy.Policy{
				Notation: &policy.NotationPolicy{VerificationLevel: testNotationLevelStrict},
			},
		},
		{
			name: "notation permissive is allowed",
			policy: &policy.Policy{
				Notation: &policy.NotationPolicy{VerificationLevel: testNotationPermissive},
			},
		},
		{
			name:    "notation audit is rejected",
			policy:  &policy.Policy{Notation: auditNotation},
			wantErr: policy.ErrNotationAuditInEnforceMode,
		},
		{
			name: "rule notation audit is rejected",
			policy: &policy.Policy{Rules: []policy.ImageRule{{
				Images:   []string{testRuleImagesGlob},
				Notation: auditNotation,
			}}},
			wantErr: policy.ErrNotationAuditInEnforceMode,
		},
	}

	for idx := range tests {
		test := &tests[idx]

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			assertErr(t, test.policy.ValidateEnforce(), test.wantErr)
		})
	}
}

func TestValidateRuntime(t *testing.T) {
	t.Parallel()

	//nolint:exhaustruct_v5 // table cases only set the fields they assert
	tests := []struct {
		name string
		// policy builds the policy under test; dir is a fresh temporary directory.
		policy       func(t *testing.T, dir string) *policy.Policy
		wantErr      error
		wantContains []string
	}{
		{
			name: "empty policy passes",
			policy: func(*testing.T, string) *policy.Policy {
				return &policy.Policy{}
			},
		},
		{
			name: "valid key file exists",
			policy: func(t *testing.T, dir string) *policy.Policy {
				t.Helper()

				keyPath := filepath.Join(dir, "verifier.pub")
				writeFile(t, keyPath, "public-key-data")

				pol := verifierPolicy(nil, keyVerifier(testVerifierID, keyPath))

				return &pol
			},
		},
		{
			name: "valid key files exist",
			policy: func(t *testing.T, dir string) *policy.Policy {
				t.Helper()

				key1 := filepath.Join(dir, "old.pub")
				key2 := filepath.Join(dir, "new.pub")

				writeFile(t, key1, "old-key-data")
				writeFile(t, key2, "new-key-data")

				pol := verifierPolicy(nil, keyVerifier(testVerifierID, key1, key2))

				return &pol
			},
		},
		{
			name: "key file projected by a Secret volume symlink passes",
			// Mimic a Kubernetes Secret volume: key.pub -> ..data/key.pub.
			policy: func(t *testing.T, dir string) *policy.Policy {
				t.Helper()

				dataDir := filepath.Join(dir, "..2026_01_01")
				testutil.AssertNoError(t, os.Mkdir(dataDir, 0o700))
				writeFile(t, filepath.Join(dataDir, "key.pub"), "public-key-data")
				testutil.AssertNoError(t, os.Symlink("..2026_01_01", filepath.Join(dir, "..data")))

				keyPath := filepath.Join(dir, "key.pub")
				testutil.AssertNoError(t, os.Symlink(filepath.Join("..data", "key.pub"), keyPath))

				pol := verifierPolicy(nil, keyVerifier(testVerifierID, keyPath))

				return &pol
			},
		},
		{
			name: "key file symlink escaping its directory fails",
			policy: func(t *testing.T, dir string) *policy.Policy {
				t.Helper()

				outside := filepath.Join(t.TempDir(), "evil.pub")
				writeFile(t, outside, "public-key-data")

				keyPath := filepath.Join(dir, "key.pub")
				testutil.AssertNoError(t, os.Symlink(outside, keyPath))

				pol := verifierPolicy(nil, keyVerifier(testVerifierID, keyPath))

				return &pol
			},
			wantErr: fileutil.ErrSymlink,
		},
		{
			name: "nonexistent key path fails",
			policy: func(*testing.T, string) *policy.Policy {
				pol := verifierPolicy(nil, keyVerifier(testVerifierID, testNonexistentKeyPath))

				return &pol
			},
			wantErr: errAnyError,
		},
		{
			name: "key path is directory fails",
			policy: func(_ *testing.T, dir string) *policy.Policy {
				pol := verifierPolicy(nil, keyVerifier(testVerifierID, dir))

				return &pol
			},
			wantErr: policy.ErrNotRegularFile,
		},
		{
			name: "keys with mix of valid and invalid paths",
			policy: func(t *testing.T, dir string) *policy.Policy {
				t.Helper()

				existingKey := filepath.Join(dir, "existing.pub")
				writeFile(t, existingKey, "key-data")

				pol := verifierPolicy(nil,
					keyVerifier(testVerifierID, existingKey, "/nonexistent/rotation.pub"),
				)

				return &pol
			},
			wantErr: errAnyError,
		},
		{
			name: "collects errors for every verifier",
			policy: func(*testing.T, string) *policy.Policy {
				pol := verifierPolicy(nil,
					keyVerifier("v1", "/nonexistent/key1.pub"),
					keyVerifier("v2", "/nonexistent/key2.pub"),
				)

				return &pol
			},
			wantErr:      errAnyError,
			wantContains: []string{"key1.pub", "key2.pub"},
		},
		{
			name: "rule keys are checked",
			policy: func(*testing.T, string) *policy.Policy {
				pol := rulesPolicy(policy.ImageRule{
					Images: []string{testRuleImagesGlob},
					Trust: &policy.TrustPolicy{
						Verifiers: []policy.TrustedVerifier{
							keyVerifier(testVerifierID, testNonexistentKeyPath),
						},
						Issuers: []string{testIssuerURL},
					},
				})

				return &pol
			},
			wantErr:      errAnyError,
			wantContains: []string{"rules[0]"},
		},
		{
			name: "missing builder key file",
			policy: func(_ *testing.T, dir string) *policy.Policy {
				pol := trustPolicy(&policy.TrustPolicy{
					Builders: []policy.TrustedBuilder{{
						ID: testBuilderID, Keys: []string{filepath.Join(dir, "missing.pub")},
					}},
				})

				return &pol
			},
			wantErr: os.ErrNotExist,
		},
		{
			name: "valid notation certificate file",
			policy: func(t *testing.T, dir string) *policy.Policy {
				t.Helper()

				certPath := filepath.Join(dir, "ca.pem")
				writeFile(t, certPath, "PEM DATA")

				pol := notationPolicy(&policy.NotationPolicy{
					TrustStores: []policy.NotationTrustStore{
						caTrustStore(testNotationStoreName, certPath),
					},
				})

				return &pol
			},
		},
		{
			name: "missing notation certificate file",
			policy: func(*testing.T, string) *policy.Policy {
				pol := notationPolicy(&policy.NotationPolicy{
					TrustStores: []policy.NotationTrustStore{
						caTrustStore(testNotationStoreName, "/nonexistent/cert.pem"),
					},
				})

				return &pol
			},
			wantErr: os.ErrNotExist,
		},
	}

	for idx := range tests {
		test := &tests[idx]

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := test.policy(t, t.TempDir()).ValidateRuntime()
			assertErr(t, err, test.wantErr)
			assertErrContains(t, err, test.wantContains)
		})
	}
}

func TestMissingPolicyAccessors(t *testing.T) {
	t.Parallel()

	accessors := []struct {
		section string
		get     func(*policy.Policy) types.Action
		with    func(missing types.Action) *policy.Policy
	}{
		{
			section: "slsa",
			get:     (*policy.Policy).SLSAMissingPolicy,
			with: func(missing types.Action) *policy.Policy {
				return &policy.Policy{SLSA: &policy.SLSAPolicy{MissingPolicy: missing}}
			},
		},
		{
			section: "vex",
			get:     (*policy.Policy).VEXMissingPolicy,
			with: func(missing types.Action) *policy.Policy {
				return &policy.Policy{VEX: &policy.VEXPolicy{MissingPolicy: missing}}
			},
		},
		{
			section: "vsa",
			get:     (*policy.Policy).VSAMissingPolicy,
			with: func(missing types.Action) *policy.Policy {
				return &policy.Policy{VSA: &policy.VSAPolicy{MissingPolicy: missing}}
			},
		},
		{
			section: "notation",
			get:     (*policy.Policy).NotationMissingPolicy,
			with: func(missing types.Action) *policy.Policy {
				return &policy.Policy{Notation: &policy.NotationPolicy{MissingPolicy: missing}}
			},
		},
		{
			section: "sbom",
			get:     (*policy.Policy).SBOMMissingPolicy,
			with: func(missing types.Action) *policy.Policy {
				return &policy.Policy{SBOM: &policy.SBOMPolicy{MissingPolicy: missing}}
			},
		},
		{
			section: "scai",
			get:     (*policy.Policy).SCAIMissingPolicy,
			with: func(missing types.Action) *policy.Policy {
				return &policy.Policy{SCAI: &policy.SCAIPolicy{MissingPolicy: missing}}
			},
		},
		{
			section: "source",
			get:     (*policy.Policy).SourceMissingPolicy,
			with: func(missing types.Action) *policy.Policy {
				return &policy.Policy{Source: &policy.SourcePolicy{MissingPolicy: missing}}
			},
		},
		{
			section: "buildEnv",
			get:     (*policy.Policy).BuildEnvMissingPolicy,
			with: func(missing types.Action) *policy.Policy {
				return &policy.Policy{BuildEnv: &policy.BuildEnvPolicy{MissingPolicy: missing}}
			},
		},
		{
			section: "vulnScan",
			get:     (*policy.Policy).VulnScanMissingPolicy,
			with: func(missing types.Action) *policy.Policy {
				return &policy.Policy{VulnScan: &policy.VulnScanPolicy{MissingPolicy: missing}}
			},
		},
		{
			section: "testResult",
			get:     (*policy.Policy).TestResultMissingPolicy,
			with: func(missing types.Action) *policy.Policy {
				return &policy.Policy{TestResult: &policy.TestResultPolicy{MissingPolicy: missing}}
			},
		},
		{
			section: "release",
			get:     (*policy.Policy).ReleaseMissingPolicy,
			with: func(missing types.Action) *policy.Policy {
				return &policy.Policy{Release: &policy.ReleasePolicy{MissingPolicy: missing}}
			},
		},
		{
			section: "runtimeTrace",
			get:     (*policy.Policy).RuntimeTraceMissingPolicy,
			with: func(missing types.Action) *policy.Policy {
				return &policy.Policy{
					RuntimeTrace: &policy.RuntimeTracePolicy{MissingPolicy: missing},
				}
			},
		},
		{
			section: "scorecard",
			get:     (*policy.Policy).ScorecardMissingPolicy,
			with: func(missing types.Action) *policy.Policy {
				return &policy.Policy{Scorecard: &policy.ScorecardPolicy{MissingPolicy: missing}}
			},
		},
	}

	for idx := range accessors {
		accessor := &accessors[idx]

		t.Run(accessor.section, func(t *testing.T) {
			t.Parallel()

			tests := []struct {
				name   string
				policy *policy.Policy
				want   types.Action
			}{
				{
					name:   "nil section defaults to allow",
					policy: &policy.Policy{},
					want:   types.ActionAllow,
				},
				{
					name:   "empty missing policy defaults to allow",
					policy: accessor.with(""),
					want:   types.ActionAllow,
				},
				{
					name:   "explicit deny",
					policy: accessor.with(types.ActionDeny),
					want:   types.ActionDeny,
				},
				{
					name:   "explicit warn",
					policy: accessor.with(types.ActionWarn),
					want:   types.ActionWarn,
				},
				{
					name:   "explicit allow",
					policy: accessor.with(types.ActionAllow),
					want:   types.ActionAllow,
				},
			}

			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					t.Parallel()

					testutil.AssertEqual(t, test.want, accessor.get(test.policy))
				})
			}
		})
	}
}

func TestBuildersNilTrust(t *testing.T) {
	t.Parallel()

	pol := policy.Policy{}

	if builders := pol.Builders(); builders != nil {
		t.Errorf("expected nil builders, got %v", builders)
	}
}

func TestTrustedVerifierMatchesSigner(t *testing.T) {
	t.Parallel()

	verifier := &policy.TrustedVerifier{
		ID:   testVerifierID,
		Keys: []string{"/etc/keys/vsa.pub"},
		Identities: []policy.TrustedIdentity{
			{Issuer: testGitHubIssuer, SANPattern: testReleaseSANPattern},
		},
	}

	type signer struct {
		keyPath, issuer, san string
	}

	tests := []struct {
		name   string
		signer signer
		want   bool
	}{
		{name: "matching key", signer: signer{"/etc/keys/vsa.pub", "", ""}, want: true},
		{
			name:   "matching key unclean path",
			signer: signer{"/etc/keys/../keys/vsa.pub", "", ""},
			want:   true,
		},
		{name: "other key", signer: signer{"/etc/keys/other.pub", "", ""}, want: false},
		{
			name:   "matching identity",
			signer: signer{"", testGitHubIssuer, testReleaseSAN},
			want:   true,
		},
		{
			name: "other workflow",
			signer: signer{
				"", testGitHubIssuer,
				"https://github.com/myorg/app/.github/workflows/ci.yml@refs/heads/main",
			},
			want: false,
		},
		{
			name:   "other issuer",
			signer: signer{"", testIssuerURL, testReleaseSAN},
			want:   false,
		},
		{name: "no signer", signer: signer{"", "", ""}, want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			testutil.AssertEqual(t, test.want, verifier.MatchesSigner(
				test.signer.keyPath, test.signer.issuer, test.signer.san,
			))
		})
	}

	unbound := &policy.TrustedVerifier{ID: testVerifierID}
	testutil.AssertEqual(t, false, unbound.Bound())
	testutil.AssertEqual(t, false, unbound.MatchesSigner("", testGitHubIssuer, testReleaseSAN))
}

func TestTrustedBuilderMatchesSigner(t *testing.T) {
	t.Parallel()

	builder := &policy.TrustedBuilder{
		ID: testRunnerBuilderID,
		Identities: []policy.TrustedIdentity{
			{Issuer: testGitHubIssuer, SANPattern: testReleaseSANPattern},
		},
	}

	testutil.AssertEqual(t, true, builder.Bound())
	testutil.AssertEqual(t, true, builder.MatchesSigner("", testGitHubIssuer, testReleaseSAN))
	testutil.AssertEqual(t, false, builder.MatchesSigner("/etc/keys/a.pub", "", ""))

	unbound := &policy.TrustedBuilder{ID: testRunnerBuilderID}
	testutil.AssertEqual(t, false, unbound.Bound())
	testutil.AssertEqual(t, false, unbound.MatchesSigner("", testGitHubIssuer, testReleaseSAN))
}

func TestSectionRegistryComplete(t *testing.T) {
	t.Parallel()

	testutil.AssertNoError(t, policy.CheckSectionRegistryForTest())
}

func TestEffectiveMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		policyMode config.VerificationMode
		globalMode config.VerificationMode
		expected   config.VerificationMode
	}{
		{
			name:       "empty mode uses global",
			policyMode: "",
			globalMode: config.ModeWarn,
			expected:   config.ModeWarn,
		},
		{
			name:       "per-namespace enforce overrides global warn",
			policyMode: config.ModeEnforce,
			globalMode: config.ModeWarn,
			expected:   config.ModeEnforce,
		},
		{
			name:       "per-namespace warn with global warn",
			policyMode: config.ModeWarn,
			globalMode: config.ModeWarn,
			expected:   config.ModeWarn,
		},
		{
			name:       "per-namespace enforce with global enforce",
			policyMode: config.ModeEnforce,
			globalMode: config.ModeEnforce,
			expected:   config.ModeEnforce,
		},
		{
			name:       "per-namespace disabled with global disabled",
			policyMode: config.ModeDisabled,
			globalMode: config.ModeDisabled,
			expected:   config.ModeDisabled,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			pol := &policy.Policy{Mode: test.policyMode}
			testutil.AssertEqual(t, test.expected, pol.EffectiveMode(test.globalMode))
		})
	}
}

func TestValidateModeStrictness(t *testing.T) {
	t.Parallel()

	//nolint:exhaustruct_v5 // table cases only set the fields they assert
	tests := []struct {
		name       string
		policyMode config.VerificationMode
		globalMode config.VerificationMode
		wantErr    bool
	}{
		{name: "empty mode always valid", policyMode: "", globalMode: config.ModeEnforce},
		{
			name:       "enforce >= enforce is valid",
			policyMode: config.ModeEnforce,
			globalMode: config.ModeEnforce,
		},
		{
			name:       "enforce > warn is valid",
			policyMode: config.ModeEnforce,
			globalMode: config.ModeWarn,
		},
		{
			name:       "enforce > disabled is valid",
			policyMode: config.ModeEnforce,
			globalMode: config.ModeDisabled,
		},
		{name: "warn >= warn is valid", policyMode: config.ModeWarn, globalMode: config.ModeWarn},
		{
			name:       "warn > disabled is valid",
			policyMode: config.ModeWarn,
			globalMode: config.ModeDisabled,
		},
		{
			name:       "warn < enforce is rejected",
			policyMode: config.ModeWarn,
			globalMode: config.ModeEnforce,
			wantErr:    true,
		},
		{
			name:       "disabled < warn is rejected",
			policyMode: config.ModeDisabled,
			globalMode: config.ModeWarn,
			wantErr:    true,
		},
		{
			name:       "disabled < enforce is rejected",
			policyMode: config.ModeDisabled,
			globalMode: config.ModeEnforce,
			wantErr:    true,
		},
		{
			name:       "disabled >= disabled is valid",
			policyMode: config.ModeDisabled,
			globalMode: config.ModeDisabled,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			pol := &policy.Policy{Mode: test.policyMode}

			var wantErr error
			if test.wantErr {
				wantErr = policy.ErrModeNotStricter
			}

			assertErr(t, pol.ValidateModeStrictness(test.globalMode), wantErr)
		})
	}
}

func TestHash(t *testing.T) {
	t.Parallel()

	hash := func(t *testing.T, pol *policy.Policy) string {
		t.Helper()

		sum, err := pol.Hash()
		testutil.AssertNoError(t, err)

		return sum
	}

	denySLSA := func() *policy.Policy {
		return &policy.Policy{SLSA: &policy.SLSAPolicy{MissingPolicy: types.ActionDeny}}
	}

	t.Run("identical policies produce same hash", func(t *testing.T) {
		t.Parallel()

		testutil.AssertEqual(t, hash(t, denySLSA()), hash(t, denySLSA()))
	})

	t.Run("different policies produce different hashes", func(t *testing.T) {
		t.Parallel()

		allowSLSA := &policy.Policy{SLSA: &policy.SLSAPolicy{MissingPolicy: types.ActionAllow}}

		if hash(t, denySLSA()) == hash(t, allowSLSA) {
			t.Error("different policies should produce different hashes")
		}
	})

	t.Run("hash is deterministic", func(t *testing.T) {
		t.Parallel()

		pol := &policy.Policy{
			Trust: &policy.TrustPolicy{
				Builders: []policy.TrustedBuilder{{ID: "https://example.com/builder", MaxLevel: 3}},
			},
			SLSA: &policy.SLSAPolicy{MissingPolicy: types.ActionWarn},
		}

		testutil.AssertEqual(t, hash(t, pol), hash(t, pol))
	})

	t.Run("empty policy hashes without error", func(t *testing.T) {
		t.Parallel()

		if hash(t, &policy.Policy{}) == "" {
			t.Error("expected non-empty hash for empty policy")
		}
	})

	t.Run("explicit zero value in a rule changes the hash", func(t *testing.T) {
		t.Parallel()

		load := func(t *testing.T, ruleSignatures string) *policy.Policy {
			t.Helper()

			dir := t.TempDir()
			testutil.WritePolicy(t, dir, testDefaultJSON, `{
				"signatures": {"requireTransparencyLog": true},
				"rules": [{"images": ["ghcr.io/**"], "signatures": `+ruleSignatures+`}]
			}`)

			pol, err := policy.Load(filepath.Join(dir, testDefaultJSON))
			testutil.AssertNoError(t, err)

			return pol
		}

		// Both policies marshal identically, but only the explicit false
		// disables the base transparency log requirement for the rule.
		explicit := load(t, `{"requireTransparencyLog": false}`)
		omitted := load(t, `{}`)

		testutil.AssertEqual(t, false,
			policy.ApplyRule(explicit, &explicit.Rules[0]).Signatures.RequireTransparencyLog)
		testutil.AssertEqual(t, true,
			policy.ApplyRule(omitted, &omitted.Rules[0]).Signatures.RequireTransparencyLog)

		if hash(t, explicit) == hash(t, omitted) {
			t.Error("removing an explicit field should change the hash")
		}
	})
}

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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	celengine "github.com/saschagrunert/nri-supply-chain/internal/cel"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	testBuilderID              = "test"
	testInvalidValue           = "invalid"
	testVerifierID             = "https://example.com/v"
	testIssuerURL              = "https://accounts.google.com"
	testIncludePattern         = "docker.io/myorg/**"
	testKeyPath                = "/etc/keys/verifier.pub"
	testValidKeyPath           = "/valid/key.pub"
	testEmptyMissingPolicyName = "empty missing policy defaults to allow"
	testExplicitDenyName       = "explicit deny"
	testNonexistentKeyPath     = "/nonexistent/key.pub"
	testRuleImagesGlob         = "ghcr.io/**"
	testBaseBuilderID          = "base-builder"
	testRuleBuilderID          = "rule-builder"
	testMutatedValue           = "mutated"
	testNotationLevelStrict    = "strict"
	testNotationStoreName      = "myca"
	testNotationStoreRef       = "ca:myca"
	testNotationCertPath       = "/etc/certs/ca.pem"
	testNotationRuleName       = "rule1"
	testDockerGlob             = "docker.io/**"
	testCELExprTrue            = "true"
	testCELExprSLSAVerified    = "slsa.verified == true"
	testFormatCycloneDX        = "cyclonedx"
	testFormatSPDX             = "spdx"
	testLicenseAGPL            = "AGPL-3.0"
	testLicenseMIT             = "MIT"
)

type validateTest struct {
	name        string
	policy      policy.Policy
	wantErr     bool
	expectedErr error
}

func runValidateTests(t *testing.T, tests []validateTest) {
	t.Helper()

	for idx := range tests {
		t.Run(tests[idx].name, func(t *testing.T) {
			t.Parallel()

			err := tests[idx].policy.Validate()
			if tests[idx].wantErr && err == nil {
				t.Error("expected error, got nil")
			}

			if !tests[idx].wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if tests[idx].expectedErr != nil && !errors.Is(err, tests[idx].expectedErr) {
				t.Errorf("expected error %v, got %v", tests[idx].expectedErr, err)
			}
		})
	}
}

func emptyPolicy() policy.Policy {
	return policy.Policy{
		Exclude: nil,
		Sections: policy.Sections{
			Trust: nil, SLSA: nil,
			VEX: nil, VSA: nil, Signatures: nil,
		},
	}
}

func TestPolicyValidateEmpty(t *testing.T) {
	t.Parallel()

	runValidateTests(t, []validateTest{
		{
			name:        "empty policy is valid",
			policy:      emptyPolicy(),
			wantErr:     false,
			expectedErr: nil,
		},
	})
}

func TestPolicyValidateBuilders(t *testing.T) {
	t.Parallel()

	runValidateTests(t, []validateTest{
		{
			name: "valid trust with builders",
			policy: policy.Policy{
				Exclude: nil,
				Sections: policy.Sections{
					Trust: &policy.TrustPolicy{
						Builders: []policy.TrustedBuilder{
							{ID: "https://github.com/actions/runner", MaxLevel: 3},
						},
						Verifiers: nil, Issuers: nil, Sources: nil, BuildTypes: nil,
					},
					SLSA: nil, VEX: nil, VSA: nil, Signatures: nil,
				},
			},
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name: "builder without ID",
			policy: policy.Policy{
				Exclude: nil,
				Sections: policy.Sections{
					Trust: &policy.TrustPolicy{
						Builders:  []policy.TrustedBuilder{{ID: "", MaxLevel: 2}},
						Verifiers: nil, Issuers: nil, Sources: nil, BuildTypes: nil,
					},
					SLSA: nil, VEX: nil, VSA: nil, Signatures: nil,
				},
			},
			wantErr:     true,
			expectedErr: policy.ErrBuilderIDRequired,
		},
		{
			name: "builder with invalid max level",
			policy: policy.Policy{
				Exclude: nil,
				Sections: policy.Sections{
					Trust: &policy.TrustPolicy{
						Builders: []policy.TrustedBuilder{
							{ID: testBuilderID, MaxLevel: 5},
						},
						Verifiers: nil, Issuers: nil, Sources: nil, BuildTypes: nil,
					},
					SLSA: nil, VEX: nil, VSA: nil, Signatures: nil,
				},
			},
			wantErr:     true,
			expectedErr: policy.ErrBuilderMaxLevel,
		},
	})
}

func TestPolicyValidateVerifiers(t *testing.T) {
	t.Parallel()

	runValidateTests(t, []validateTest{
		{
			name: "keyless verifier without issuers",
			policy: policy.Policy{
				Exclude: nil,
				Sections: policy.Sections{
					Trust: &policy.TrustPolicy{
						Builders: nil,
						Verifiers: []policy.TrustedVerifier{
							{ID: testBuilderID},
						},
						Issuers: nil, Sources: nil, BuildTypes: nil,
					},
					SLSA: nil, VEX: nil, VSA: nil, Signatures: nil,
				},
			},
			wantErr:     true,
			expectedErr: policy.ErrKeylessVerifierRequiresIssuers,
		},
		{
			name: "keyless verifier with issuers",
			policy: policy.Policy{
				Exclude: nil,
				Sections: policy.Sections{
					Trust: &policy.TrustPolicy{
						Builders: nil,
						Verifiers: []policy.TrustedVerifier{
							{ID: testBuilderID},
						},
						Issuers: []string{"https://token.actions.githubusercontent.com"},
						Sources: nil, BuildTypes: nil,
					},
					SLSA: nil, VEX: nil, VSA: nil, Signatures: nil,
				},
			},
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name: "verifier with relative key path in keys",
			policy: policy.Policy{
				Exclude: nil,
				Sections: policy.Sections{
					Trust: &policy.TrustPolicy{
						Builders: nil,
						Verifiers: []policy.TrustedVerifier{
							{ID: testBuilderID, Keys: []string{"relative/path.pub"}},
						},
						Issuers: nil, Sources: nil, BuildTypes: nil,
					},
					SLSA: nil, VEX: nil, VSA: nil, Signatures: nil,
				},
			},
			wantErr:     true,
			expectedErr: policy.ErrVerifierKeyNotAbsolute,
		},
		{
			name: "valid verifier with single key",
			policy: policy.Policy{
				Exclude: nil,
				Sections: policy.Sections{
					Trust: &policy.TrustPolicy{
						Builders: nil,
						Verifiers: []policy.TrustedVerifier{
							{ID: testBuilderID, Keys: []string{testKeyPath}},
						},
						Issuers: nil, Sources: nil, BuildTypes: nil,
					},
					SLSA: nil, VEX: nil, VSA: nil, Signatures: nil,
				},
			},
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name: "valid verifier with multiple keys",
			policy: policy.Policy{
				Sections: policy.Sections{
					Trust: &policy.TrustPolicy{
						Verifiers: []policy.TrustedVerifier{
							{
								ID:   testBuilderID,
								Keys: []string{"/path/a.pub", "/path/b.pub"},
							},
						},
					},
				},
			},
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name: "verifier with keys containing relative path",
			policy: policy.Policy{
				Sections: policy.Sections{
					Trust: &policy.TrustPolicy{
						Verifiers: []policy.TrustedVerifier{
							{
								ID:   testBuilderID,
								Keys: []string{"/abs/good.pub", "relative/bad.pub"},
							},
						},
					},
				},
			},
			wantErr:     true,
			expectedErr: policy.ErrVerifierKeyNotAbsolute,
		},
		{
			name: "verifier with keys only is not keyless",
			policy: policy.Policy{
				Sections: policy.Sections{
					Trust: &policy.TrustPolicy{
						Verifiers: []policy.TrustedVerifier{
							{
								ID:   testBuilderID,
								Keys: []string{testKeyPath},
							},
						},
					},
				},
			},
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name: "verifier with no keys and no issuers",
			policy: policy.Policy{
				Sections: policy.Sections{
					Trust: &policy.TrustPolicy{
						Verifiers: []policy.TrustedVerifier{
							{ID: testBuilderID},
						},
					},
				},
			},
			wantErr:     true,
			expectedErr: policy.ErrKeylessVerifierRequiresIssuers,
		},
		{
			name: "verifier with empty string in keys",
			policy: policy.Policy{
				Sections: policy.Sections{
					Trust: &policy.TrustPolicy{
						Verifiers: []policy.TrustedVerifier{
							{
								ID:   testBuilderID,
								Keys: []string{testValidKeyPath, ""},
							},
						},
					},
				},
			},
			wantErr:     true,
			expectedErr: policy.ErrEmptyValue,
		},
		{
			name: "verifier with duplicate keys",
			policy: policy.Policy{
				Sections: policy.Sections{
					Trust: &policy.TrustPolicy{
						Verifiers: []policy.TrustedVerifier{
							{
								ID:   testBuilderID,
								Keys: []string{testValidKeyPath, testValidKeyPath},
							},
						},
					},
				},
			},
			wantErr:     true,
			expectedErr: policy.ErrDuplicateVerifierKey,
		},
	})
}

func TestPolicyValidateInclude(t *testing.T) {
	t.Parallel()

	runValidateTests(t, []validateTest{
		{
			name: "valid include pattern single star",
			policy: policy.Policy{
				Include: []string{"gcr.io/org/*"}, Exclude: nil,
				Sections: policy.Sections{
					Trust: nil, SLSA: nil, VEX: nil, VSA: nil, Signatures: nil,
				},
			},
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name: "valid include pattern double star",
			policy: policy.Policy{
				Include: []string{"registry.k8s.io/**"}, Exclude: nil,
				Sections: policy.Sections{
					Trust: nil, SLSA: nil, VEX: nil, VSA: nil, Signatures: nil,
				},
			},
			wantErr:     false,
			expectedErr: nil,
		},
	})
}

func TestPolicyValidateExclude(t *testing.T) {
	t.Parallel()

	runValidateTests(t, []validateTest{
		{
			name: "valid exclude pattern single star",
			policy: policy.Policy{
				Exclude: []string{"gcr.io/org/*"},
				Sections: policy.Sections{
					Trust: nil, SLSA: nil, VEX: nil, VSA: nil, Signatures: nil,
				},
			},
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name: "valid exclude pattern double star",
			policy: policy.Policy{
				Exclude: []string{"registry.k8s.io/**"},
				Sections: policy.Sections{
					Trust: nil, SLSA: nil, VEX: nil, VSA: nil, Signatures: nil,
				},
			},
			wantErr:     false,
			expectedErr: nil,
		},
	})
}

func TestPolicyValidateSLSA(t *testing.T) {
	t.Parallel()

	runValidateTests(t, []validateTest{
		{
			name: "invalid slsa missing policy",
			policy: policy.Policy{
				Exclude: nil,
				Sections: policy.Sections{
					Trust: nil,
					SLSA: &policy.SLSAPolicy{
						MissingPolicy: testInvalidValue, RejectUnknownParameters: false,
					},
					VEX: nil, VSA: nil, Signatures: nil,
				},
			},
			wantErr:     true,
			expectedErr: types.ErrInvalidAction,
		},
	})
}

func TestPolicyValidateVEX(t *testing.T) {
	t.Parallel()

	runValidateTests(t, []validateTest{
		{
			name: "valid VEX config",
			policy: policy.Policy{
				Exclude: nil,
				Sections: policy.Sections{
					Trust: nil, SLSA: nil,
					VEX: &policy.VEXPolicy{
						MissingPolicy:            types.ActionWarn,
						UnderInvestigationPolicy: types.ActionAllow,
					},
					VSA: nil, Signatures: nil,
				},
			},
			wantErr:     false,
			expectedErr: nil,
		},
	})
}

func TestPolicyValidateVSA(t *testing.T) {
	t.Parallel()

	runValidateTests(t, []validateTest{
		{
			name: "invalid VSA minimum level",
			policy: policy.Policy{
				Exclude: nil,
				Sections: policy.Sections{
					Trust: nil, SLSA: nil, VEX: nil,
					VSA:        &policy.VSAPolicy{MinimumLevel: 5, MaxAge: "", Policy: ""},
					Signatures: nil,
				},
			},
			wantErr:     true,
			expectedErr: policy.ErrVSAMinimumLevel,
		},
		{
			name: "invalid VSA max age",
			policy: policy.Policy{
				Exclude: nil,
				Sections: policy.Sections{
					Trust: nil, SLSA: nil, VEX: nil,
					VSA: &policy.VSAPolicy{
						MinimumLevel: 0, MaxAge: "not-a-duration", Policy: "",
					},
					Signatures: nil,
				},
			},
			wantErr:     true,
			expectedErr: nil,
		},
	})
}

func TestSLSAMissingPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		policy   policy.Policy
		expected types.Action
	}{
		{
			name:     "nil slsa defaults to allow",
			policy:   emptyPolicy(),
			expected: types.ActionAllow,
		},
		{
			name: testEmptyMissingPolicyName,
			policy: policy.Policy{
				Exclude: nil,
				Sections: policy.Sections{
					Trust: nil,
					SLSA: &policy.SLSAPolicy{
						MissingPolicy: "", RejectUnknownParameters: false,
					},
					VEX: nil, VSA: nil, Signatures: nil,
				},
			},
			expected: types.ActionAllow,
		},
		{
			name: testExplicitDenyName,
			policy: policy.Policy{
				Exclude: nil,
				Sections: policy.Sections{
					Trust: nil,
					SLSA: &policy.SLSAPolicy{
						MissingPolicy: types.ActionDeny, RejectUnknownParameters: false,
					},
					VEX: nil, VSA: nil, Signatures: nil,
				},
			},
			expected: types.ActionDeny,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := test.policy.SLSAMissingPolicy(); got != test.expected {
				t.Errorf("expected %q, got %q", test.expected, got)
			}
		})
	}
}

func TestVEXMissingPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		policy   policy.Policy
		expected types.Action
	}{
		{
			name:     "nil vex defaults to allow",
			policy:   emptyPolicy(),
			expected: types.ActionAllow,
		},
		{
			name: testEmptyMissingPolicyName,
			policy: policy.Policy{
				Exclude: nil,
				Sections: policy.Sections{
					Trust: nil, SLSA: nil,
					VEX: &policy.VEXPolicy{
						MissingPolicy:            "",
						UnderInvestigationPolicy: "",
					},
					VSA: nil, Signatures: nil,
				},
			},
			expected: types.ActionAllow,
		},
		{
			name: testExplicitDenyName,
			policy: policy.Policy{
				Exclude: nil,
				Sections: policy.Sections{
					Trust: nil, SLSA: nil,
					VEX: &policy.VEXPolicy{
						MissingPolicy:            types.ActionDeny,
						UnderInvestigationPolicy: "",
					},
					VSA: nil, Signatures: nil,
				},
			},
			expected: types.ActionDeny,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := test.policy.VEXMissingPolicy(); got != test.expected {
				t.Errorf("expected %q, got %q", test.expected, got)
			}
		})
	}
}

func TestVSAMissingPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		policy   policy.Policy
		expected types.Action
	}{
		{
			name:     "nil vsa defaults to allow",
			policy:   emptyPolicy(),
			expected: types.ActionAllow,
		},
		{
			name: testEmptyMissingPolicyName,
			policy: policy.Policy{
				Exclude: nil,
				Sections: policy.Sections{
					Trust: nil, SLSA: nil, VEX: nil,
					VSA:        &policy.VSAPolicy{MissingPolicy: ""},
					Signatures: nil,
				},
			},
			expected: types.ActionAllow,
		},
		{
			name: testExplicitDenyName,
			policy: policy.Policy{
				Exclude: nil,
				Sections: policy.Sections{
					Trust: nil, SLSA: nil, VEX: nil,
					VSA:        &policy.VSAPolicy{MissingPolicy: types.ActionDeny},
					Signatures: nil,
				},
			},
			expected: types.ActionDeny,
		},
		{
			name: "explicit warn",
			policy: policy.Policy{
				Exclude: nil,
				Sections: policy.Sections{
					Trust: nil, SLSA: nil, VEX: nil,
					VSA:        &policy.VSAPolicy{MissingPolicy: types.ActionWarn},
					Signatures: nil,
				},
			},
			expected: types.ActionWarn,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := test.policy.VSAMissingPolicy(); got != test.expected {
				t.Errorf("expected %q, got %q", test.expected, got)
			}
		})
	}
}

func TestLoadPolicyValid(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	policyPath := filepath.Join(dir, "test.json")

	content := `{
		"trust": {
			"builders": [{"id": "https://example.com/builder", "maxLevel": 2}]
		},
		"slsa": {"missingPolicy": "warn"}
	}`
	writeFile(t, policyPath, content)

	pol, err := policy.Load(policyPath)
	testutil.AssertNoError(t, err)

	if len(pol.Builders()) != 1 {
		t.Fatalf("expected 1 builder, got %d", len(pol.Builders()))
	}

	if pol.Builders()[0].ID != "https://example.com/builder" {
		t.Errorf("unexpected builder ID: %s", pol.Builders()[0].ID)
	}

	if pol.SLSAMissingPolicy() != types.ActionWarn {
		t.Errorf("expected warn, got %s", pol.SLSAMissingPolicy())
	}
}

func TestLoadPolicyErrors(t *testing.T) {
	t.Parallel()

	t.Run("unknown fields rejected", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		policyPath := filepath.Join(dir, "test.json")

		writeFile(t, policyPath, `{"unknownField": true}`)

		_, err := policy.Load(policyPath)
		testutil.AssertError(t, err)
	})

	t.Run("trailing content rejected", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		policyPath := filepath.Join(dir, "test.json")

		writeFile(t, policyPath, `{}{}`)

		_, err := policy.Load(policyPath)
		testutil.AssertError(t, err)

		if !errors.Is(err, policy.ErrTrailingContent) {
			t.Errorf("expected error %v, got %v", policy.ErrTrailingContent, err)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		t.Parallel()

		_, err := policy.Load("/nonexistent/policy.json")
		testutil.AssertError(t, err)
	})
}

func TestLoadAllNamespaces(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "default.json"),
		`{"slsa":{"missingPolicy":"allow"}}`)
	writeFile(t, filepath.Join(dir, "production.json"),
		`{"slsa":{"missingPolicy":"deny"}}`)

	policies, err := policy.LoadAll(dir)
	testutil.AssertNoError(t, err)

	if len(policies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(policies))
	}

	defaultPolicy, found := policies[""]
	if !found {
		t.Fatal("expected default policy")
	}

	if defaultPolicy.SLSAMissingPolicy() != types.ActionAllow {
		t.Errorf(
			"expected allow, got %s", defaultPolicy.SLSAMissingPolicy(),
		)
	}

	prodPolicy, found := policies["production"]
	if !found {
		t.Fatal("expected production policy")
	}

	if prodPolicy.SLSAMissingPolicy() != types.ActionDeny {
		t.Errorf(
			"expected deny, got %s", prodPolicy.SLSAMissingPolicy(),
		)
	}
}

func TestBuildersNilTrust(t *testing.T) {
	t.Parallel()

	pol := emptyPolicy()

	if builders := pol.Builders(); builders != nil {
		t.Errorf("expected nil builders, got %v", builders)
	}
}

func TestPolicyValidateVerifierWithoutID(t *testing.T) {
	t.Parallel()

	runValidateTests(t, []validateTest{
		{
			name: "verifier without ID",
			policy: policy.Policy{
				Exclude: nil,
				Sections: policy.Sections{
					Trust: &policy.TrustPolicy{
						Builders: nil,
						Verifiers: []policy.TrustedVerifier{
							{ID: "", Keys: []string{testKeyPath}},
						},
						Issuers: nil, Sources: nil, BuildTypes: nil,
					},
					SLSA: nil, VEX: nil, VSA: nil, Signatures: nil,
				},
			},
			wantErr:     true,
			expectedErr: policy.ErrVerifierIDRequired,
		},
	})
}

func TestPolicyValidateVEXPolicies(t *testing.T) {
	t.Parallel()

	runValidateTests(t, []validateTest{
		{
			name: "invalid VEX missing policy",
			policy: policy.Policy{
				Exclude: nil,
				Sections: policy.Sections{
					Trust: nil, SLSA: nil,
					VEX: &policy.VEXPolicy{
						MissingPolicy:            testInvalidValue,
						UnderInvestigationPolicy: "",
					},
					VSA: nil, Signatures: nil,
				},
			},
			wantErr:     true,
			expectedErr: types.ErrInvalidAction,
		},
		{
			name: "invalid VEX under investigation policy",
			policy: policy.Policy{
				Exclude: nil,
				Sections: policy.Sections{
					Trust: nil, SLSA: nil,
					VEX: &policy.VEXPolicy{
						MissingPolicy:            "",
						UnderInvestigationPolicy: testInvalidValue,
					},
					VSA: nil, Signatures: nil,
				},
			},
			wantErr:     true,
			expectedErr: types.ErrInvalidAction,
		},
	})
}

func TestPolicyValidateVSAMissingPolicy(t *testing.T) {
	t.Parallel()

	runValidateTests(t, []validateTest{
		{
			name: "valid VSA missing policy deny",
			policy: policy.Policy{
				Exclude: nil,
				Sections: policy.Sections{
					Trust: nil, SLSA: nil, VEX: nil,
					VSA:        &policy.VSAPolicy{MissingPolicy: types.ActionDeny},
					Signatures: nil,
				},
			},
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name: "valid VSA missing policy warn",
			policy: policy.Policy{
				Exclude: nil,
				Sections: policy.Sections{
					Trust: nil, SLSA: nil, VEX: nil,
					VSA:        &policy.VSAPolicy{MissingPolicy: types.ActionWarn},
					Signatures: nil,
				},
			},
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name: "valid VSA missing policy allow",
			policy: policy.Policy{
				Exclude: nil,
				Sections: policy.Sections{
					Trust: nil, SLSA: nil, VEX: nil,
					VSA:        &policy.VSAPolicy{MissingPolicy: types.ActionAllow},
					Signatures: nil,
				},
			},
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name: "invalid VSA missing policy",
			policy: policy.Policy{
				Exclude: nil,
				Sections: policy.Sections{
					Trust: nil, SLSA: nil, VEX: nil,
					VSA:        &policy.VSAPolicy{MissingPolicy: testInvalidValue},
					Signatures: nil,
				},
			},
			wantErr:     true,
			expectedErr: types.ErrInvalidAction,
		},
	})
}

func TestPolicyValidateVSAValid(t *testing.T) {
	t.Parallel()

	runValidateTests(t, []validateTest{
		{
			name: "valid VSA",
			policy: policy.Policy{
				Exclude: nil,
				Sections: policy.Sections{
					Trust: nil, SLSA: nil, VEX: nil,
					VSA: &policy.VSAPolicy{
						MinimumLevel: 2, MaxAge: "168h", Policy: "https://example.com/policy",
					},
					Signatures: nil,
				},
			},
			wantErr:     false,
			expectedErr: nil,
		},
	})
}

func TestLoadAllSkipsNonJSON(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "default.json"), `{}`)
	writeFile(t, filepath.Join(dir, "readme.txt"), `not a policy`)

	subDir := filepath.Join(dir, "subdir")
	testutil.AssertNoError(t, os.MkdirAll(subDir, 0o750))

	policies, err := policy.LoadAll(dir)
	testutil.AssertNoError(t, err)

	if len(policies) != 1 {
		t.Errorf("expected 1 policy, got %d", len(policies))
	}
}

func TestLoadAllInvalidPolicy(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "bad.json"), `{invalid json}`)

	_, err := policy.LoadAll(dir)
	testutil.AssertError(t, err)
}

func TestLoadPolicyValidationError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	policyPath := filepath.Join(dir, "test.json")

	writeFile(t, policyPath, `{"trust":{"builders":[{"id":"","maxLevel":0}]}}`)

	_, err := policy.Load(policyPath)
	testutil.AssertError(t, err)

	if !errors.Is(err, policy.ErrBuilderIDRequired) {
		t.Errorf("expected error %v, got %v", policy.ErrBuilderIDRequired, err)
	}
}

func TestLoadAllEmpty(t *testing.T) {
	t.Parallel()

	t.Run("empty directory", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()

		policies, err := policy.LoadAll(dir)
		testutil.AssertNoError(t, err)

		if len(policies) != 0 {
			t.Errorf("expected 0 policies, got %d", len(policies))
		}
	})

	t.Run("nonexistent directory returns empty", func(t *testing.T) {
		t.Parallel()

		policies, err := policy.LoadAll("/nonexistent/dir")
		testutil.AssertNoError(t, err)

		if len(policies) != 0 {
			t.Errorf("expected 0 policies, got %d", len(policies))
		}
	})

	t.Run("empty string returns empty", func(t *testing.T) {
		t.Parallel()

		policies, err := policy.LoadAll("")
		testutil.AssertNoError(t, err)

		if len(policies) != 0 {
			t.Errorf("expected 0 policies, got %d", len(policies))
		}
	})
}

func defaultTestPolicy() *policy.Policy {
	return &policy.Policy{
		Inherits: nil,
		Include:  []string{testIncludePattern},
		Exclude:  []string{"gcr.io/default/*"},
		Sections: policy.Sections{
			Trust: &policy.TrustPolicy{
				Builders: []policy.TrustedBuilder{
					{ID: "default-builder", MaxLevel: 3},
				},
				Verifiers:   nil,
				Issuers:     []string{"default-issuer"},
				SANPatterns: nil,
				Sources:     nil,
				BuildTypes:  nil,
			},
			SLSA: &policy.SLSAPolicy{
				MissingPolicy:           types.ActionDeny,
				RejectUnknownParameters: false,
				KnownParameters:         nil,
			},
			VEX: &policy.VEXPolicy{
				MissingPolicy:            types.ActionWarn,
				UnderInvestigationPolicy: "",
			},
			VSA: &policy.VSAPolicy{
				MissingPolicy:  "",
				MinimumLevel:   2,
				MaxAge:         "",
				MaxAgeDuration: 0,
				Policy:         "",
			},
			Signatures: &policy.SignaturesPolicy{
				RequireTransparencyLog: true,
			},
		},
	}
}

func mergedEmptyNamespace() *policy.Policy {
	nsPol := &policy.Policy{
		Inherits: nil, Include: nil, Exclude: nil,
		Sections: policy.Sections{
			Trust: nil, SLSA: nil, VEX: nil, VSA: nil, Signatures: nil,
		},
	}

	return policy.MergeWithDefault(nsPol, defaultTestPolicy())
}

func TestMergeWithDefaultInheritsCleared(t *testing.T) {
	t.Parallel()

	if mergedEmptyNamespace().Inherits != nil {
		t.Error("expected Inherits to be nil")
	}
}

func TestMergeWithDefaultInheritsTrust(t *testing.T) {
	t.Parallel()

	merged := mergedEmptyNamespace()
	if merged.Trust == nil ||
		merged.Trust.Builders[0].ID != "default-builder" {
		t.Error("expected default Trust to be inherited")
	}
}

func TestMergeWithDefaultInheritsInclude(t *testing.T) {
	t.Parallel()

	merged := mergedEmptyNamespace()
	if len(merged.Include) != 1 ||
		merged.Include[0] != testIncludePattern {
		t.Error("expected default Include to be inherited")
	}
}

func TestMergeWithDefaultInheritsExclude(t *testing.T) {
	t.Parallel()

	merged := mergedEmptyNamespace()
	if len(merged.Exclude) != 1 ||
		merged.Exclude[0] != "gcr.io/default/*" {
		t.Error("expected default Exclude to be inherited")
	}
}

func TestMergeWithDefaultInheritsSLSA(t *testing.T) {
	t.Parallel()

	merged := mergedEmptyNamespace()
	if merged.SLSA == nil ||
		merged.SLSA.MissingPolicy != types.ActionDeny {
		t.Error("expected default SLSA to be inherited")
	}
}

func TestMergeWithDefaultInheritsVEX(t *testing.T) {
	t.Parallel()

	merged := mergedEmptyNamespace()
	if merged.VEX == nil ||
		merged.VEX.MissingPolicy != types.ActionWarn {
		t.Error("expected default VEX to be inherited")
	}
}

func TestMergeWithDefaultInheritsVSA(t *testing.T) {
	t.Parallel()

	merged := mergedEmptyNamespace()
	if merged.VSA == nil || merged.VSA.MinimumLevel != 2 {
		t.Error("expected default VSA to be inherited")
	}
}

func TestMergeWithDefaultInheritsSignatures(t *testing.T) {
	t.Parallel()

	merged := mergedEmptyNamespace()
	if merged.Signatures == nil ||
		!merged.Signatures.RequireTransparencyLog {
		t.Error("expected default Signatures to be inherited")
	}
}

func TestMergeWithDefaultTrustOverride(t *testing.T) {
	t.Parallel()

	nsTrust := &policy.TrustPolicy{
		Builders: []policy.TrustedBuilder{
			{ID: "ns-builder", MaxLevel: 1},
		},
		Verifiers:   nil,
		Issuers:     nil,
		SANPatterns: nil,
		Sources:     nil,
		BuildTypes:  nil,
	}
	nsPol := &policy.Policy{
		Inherits: nil, Exclude: nil,
		Sections: policy.Sections{
			Trust: nsTrust, SLSA: nil, VEX: nil, VSA: nil, Signatures: nil,
		},
	}

	merged := policy.MergeWithDefault(nsPol, defaultTestPolicy())

	if merged.Trust.Builders[0].ID != "ns-builder" {
		t.Errorf("expected ns-builder, got %s",
			merged.Trust.Builders[0].ID)
	}

	if merged.SLSA.MissingPolicy != types.ActionDeny {
		t.Error("expected default SLSA to be preserved")
	}
}

func TestMergeWithDefaultIncludeOverride(t *testing.T) {
	t.Parallel()

	nsPol := &policy.Policy{
		Inherits: nil,
		Include:  []string{"ns-include/*"},
		Exclude:  nil,
		Sections: policy.Sections{
			Trust: nil, SLSA: nil, VEX: nil, VSA: nil, Signatures: nil,
		},
	}

	merged := policy.MergeWithDefault(nsPol, defaultTestPolicy())

	if len(merged.Include) != 1 ||
		merged.Include[0] != "ns-include/*" {
		t.Error("expected namespace Include to override default")
	}
}

func TestMergeWithDefaultExcludeOverride(t *testing.T) {
	t.Parallel()

	nsPol := &policy.Policy{
		Inherits: nil,
		Exclude:  []string{"ns-exclude/*"},
		Sections: policy.Sections{
			Trust: nil, SLSA: nil, VEX: nil, VSA: nil, Signatures: nil,
		},
	}

	merged := policy.MergeWithDefault(nsPol, defaultTestPolicy())

	if len(merged.Exclude) != 1 ||
		merged.Exclude[0] != "ns-exclude/*" {
		t.Error("expected namespace Exclude to override default")
	}
}

func TestMergeWithDefaultSLSAOverride(t *testing.T) {
	t.Parallel()

	nsPol := &policy.Policy{
		Inherits: nil, Exclude: nil,
		Sections: policy.Sections{
			Trust: nil,
			SLSA: &policy.SLSAPolicy{
				MissingPolicy:           types.ActionAllow,
				RejectUnknownParameters: false,
				KnownParameters:         nil,
			},
			VEX: nil, VSA: nil, Signatures: nil,
		},
	}

	merged := policy.MergeWithDefault(nsPol, defaultTestPolicy())

	if merged.SLSA.MissingPolicy != types.ActionAllow {
		t.Error("expected namespace SLSA to override default")
	}
}

func TestMergeWithDefaultVEXOverride(t *testing.T) {
	t.Parallel()

	nsPol := &policy.Policy{
		Inherits: nil, Exclude: nil,
		Sections: policy.Sections{
			Trust: nil, SLSA: nil,
			VEX: &policy.VEXPolicy{
				MissingPolicy:            types.ActionDeny,
				UnderInvestigationPolicy: "",
			},
			VSA: nil, Signatures: nil,
		},
	}

	merged := policy.MergeWithDefault(nsPol, defaultTestPolicy())

	if merged.VEX.MissingPolicy != types.ActionDeny {
		t.Error("expected namespace VEX to override default")
	}
}

func TestMergeWithDefaultVSAOverride(t *testing.T) {
	t.Parallel()

	nsPol := &policy.Policy{
		Inherits: nil, Exclude: nil,
		Sections: policy.Sections{
			Trust: nil, SLSA: nil, VEX: nil,
			VSA: &policy.VSAPolicy{
				MinimumLevel:   1,
				MaxAge:         "",
				MaxAgeDuration: 0,
				Policy:         "",
			},
			Signatures: nil,
		},
	}

	merged := policy.MergeWithDefault(nsPol, defaultTestPolicy())

	if merged.VSA.MinimumLevel != 1 {
		t.Errorf("expected MinimumLevel 1, got %d",
			merged.VSA.MinimumLevel)
	}
}

func TestMergeWithDefaultSignaturesOverride(t *testing.T) {
	t.Parallel()

	nsPol := &policy.Policy{
		Inherits: nil, Exclude: nil,
		Sections: policy.Sections{
			Trust: nil, SLSA: nil, VEX: nil, VSA: nil,
			Signatures: &policy.SignaturesPolicy{RequireTransparencyLog: false},
		},
	}

	merged := policy.MergeWithDefault(nsPol, defaultTestPolicy())

	if merged.Signatures.RequireTransparencyLog {
		t.Error("expected namespace Signatures to override default")
	}
}

func TestLoadAllInheritsMergesWithDefault(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "default.json"), `{
		"slsa": {"missingPolicy": "deny"},
		"exclude": ["default-exclude/*"]
	}`)
	writeFile(t, filepath.Join(dir, "staging.json"), `{
		"inherits": true,
		"slsa": {"missingPolicy": "allow"}
	}`)

	policies, err := policy.LoadAll(dir)
	testutil.AssertNoError(t, err)

	staging := policies["staging"]
	if staging.SLSAMissingPolicy() != types.ActionAllow {
		t.Errorf("expected allow (overridden), got %s",
			staging.SLSAMissingPolicy())
	}

	if len(staging.Exclude) != 1 ||
		staging.Exclude[0] != "default-exclude/*" {
		t.Error("expected Exclude to be inherited from default")
	}
}

func TestLoadAllInheritsInclude(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "default.json"), `{
		"include": ["docker.io/myorg/**"],
		"slsa": {"missingPolicy": "deny"}
	}`)
	writeFile(t, filepath.Join(dir, "staging.json"), `{
		"inherits": true,
		"slsa": {"missingPolicy": "allow"}
	}`)

	policies, err := policy.LoadAll(dir)
	testutil.AssertNoError(t, err)

	staging := policies["staging"]
	if len(staging.Include) != 1 ||
		staging.Include[0] != testIncludePattern {
		t.Error("expected Include to be inherited from default")
	}
}

func TestLoadAllInheritsFalseNoMerge(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "default.json"), `{
		"exclude": ["default-exclude/*"]
	}`)
	writeFile(t, filepath.Join(dir, "staging.json"), `{
		"inherits": false
	}`)

	policies, err := policy.LoadAll(dir)
	testutil.AssertNoError(t, err)

	staging := policies["staging"]
	if staging.Exclude != nil {
		t.Error("expected nil Exclude when inherits=false")
	}
}

func TestLoadAllInheritsNilNoMerge(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "default.json"), `{
		"exclude": ["default-exclude/*"]
	}`)
	writeFile(t, filepath.Join(dir, "staging.json"), `{}`)

	policies, err := policy.LoadAll(dir)
	testutil.AssertNoError(t, err)

	staging := policies["staging"]
	if staging.Exclude != nil {
		t.Error("expected nil Exclude when inherits not set")
	}
}

func TestLoadAllDefaultCannotInherit(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "default.json"), `{
		"inherits": true
	}`)

	_, err := policy.LoadAll(dir)
	if err == nil {
		t.Fatal("expected error when default has inherits=true")
	}

	if !errors.Is(err, policy.ErrDefaultCannotInherit) {
		t.Errorf("expected ErrDefaultCannotInherit, got %v", err)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()

	err := os.WriteFile(path, []byte(content), 0o600)
	if err != nil {
		t.Fatalf("writing file %s: %v", path, err)
	}
}

func TestValidateEnforceRequiresSANPatterns(t *testing.T) {
	t.Parallel()

	pol := &policy.Policy{
		Sections: policy.Sections{
			Trust: &policy.TrustPolicy{
				Issuers: []string{testIssuerURL},
			},
		},
	}

	err := pol.ValidateEnforce()
	if !errors.Is(err, policy.ErrSANPatternsRequired) {
		t.Errorf("expected ErrSANPatternsRequired, got %v", err)
	}
}

func TestValidateEnforcePassesWithSANPatterns(t *testing.T) {
	t.Parallel()

	pol := &policy.Policy{
		Sections: policy.Sections{
			Trust: &policy.TrustPolicy{
				Issuers:     []string{testIssuerURL},
				SANPatterns: []string{"build@example.com"},
			},
		},
	}

	err := pol.ValidateEnforce()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateEnforcePassesWithoutIssuers(t *testing.T) {
	t.Parallel()

	pol := &policy.Policy{
		Sections: policy.Sections{
			Trust: &policy.TrustPolicy{},
		},
	}

	err := pol.ValidateEnforce()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateEnforcePassesNilTrust(t *testing.T) {
	t.Parallel()

	pol := &policy.Policy{}

	err := pol.ValidateEnforce()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateRuntime(t *testing.T) {
	t.Parallel()

	t.Run("empty policy passes", func(t *testing.T) {
		t.Parallel()

		pol := emptyPolicy()
		err := pol.ValidateRuntime()
		testutil.AssertNoError(t, err)
	})

	t.Run("nil trust passes", func(t *testing.T) {
		t.Parallel()

		pol := &policy.Policy{}
		err := pol.ValidateRuntime()
		testutil.AssertNoError(t, err)
	})

	t.Run("valid key file exists", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		keyPath := filepath.Join(dir, "verifier.pub")
		writeFile(t, keyPath, "public-key-data")

		pol := &policy.Policy{
			Sections: policy.Sections{
				Trust: &policy.TrustPolicy{
					Verifiers: []policy.TrustedVerifier{
						{ID: testVerifierID, Keys: []string{keyPath}},
					},
				},
			},
		}

		err := pol.ValidateRuntime()
		testutil.AssertNoError(t, err)
	})

	t.Run("nonexistent key path fails", func(t *testing.T) {
		t.Parallel()

		pol := &policy.Policy{
			Sections: policy.Sections{
				Trust: &policy.TrustPolicy{
					Verifiers: []policy.TrustedVerifier{
						{ID: testVerifierID, Keys: []string{testNonexistentKeyPath}},
					},
				},
			},
		}

		err := pol.ValidateRuntime()
		testutil.AssertError(t, err)
	})

	t.Run("key path is directory fails", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()

		pol := &policy.Policy{
			Sections: policy.Sections{
				Trust: &policy.TrustPolicy{
					Verifiers: []policy.TrustedVerifier{
						{ID: testVerifierID, Keys: []string{dir}},
					},
				},
			},
		}

		err := pol.ValidateRuntime()
		testutil.AssertError(t, err)

		if !errors.Is(err, policy.ErrNotRegularFile) {
			t.Errorf("expected ErrNotRegularFile, got %v", err)
		}
	})

	t.Run("valid keys files exist", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()

		key1 := filepath.Join(dir, "old.pub")
		key2 := filepath.Join(dir, "new.pub")

		writeFile(t, key1, "old-key-data")
		writeFile(t, key2, "new-key-data")

		pol := &policy.Policy{
			Sections: policy.Sections{
				Trust: &policy.TrustPolicy{
					Verifiers: []policy.TrustedVerifier{
						{ID: testVerifierID, Keys: []string{key1, key2}},
					},
				},
			},
		}

		err := pol.ValidateRuntime()
		testutil.AssertNoError(t, err)
	})

	t.Run("nonexistent keys path fails", func(t *testing.T) {
		t.Parallel()

		pol := &policy.Policy{
			Sections: policy.Sections{
				Trust: &policy.TrustPolicy{
					Verifiers: []policy.TrustedVerifier{
						{ID: testVerifierID, Keys: []string{testNonexistentKeyPath}},
					},
				},
			},
		}

		err := pol.ValidateRuntime()
		testutil.AssertError(t, err)
	})

	t.Run("keys with mix of valid and invalid paths", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		existingKey := filepath.Join(dir, "existing.pub")
		writeFile(t, existingKey, "key-data")

		pol := &policy.Policy{
			Sections: policy.Sections{
				Trust: &policy.TrustPolicy{
					Verifiers: []policy.TrustedVerifier{
						{
							ID:   testVerifierID,
							Keys: []string{existingKey, "/nonexistent/rotation.pub"},
						},
					},
				},
			},
		}

		err := pol.ValidateRuntime()
		testutil.AssertError(t, err)
	})
}

func TestHash(t *testing.T) {
	t.Parallel()

	t.Run("identical policies produce same hash", func(t *testing.T) {
		t.Parallel()

		pol1 := &policy.Policy{
			Sections: policy.Sections{
				SLSA: &policy.SLSAPolicy{
					MissingPolicy: types.ActionDeny,
				},
			},
		}
		pol2 := &policy.Policy{
			Sections: policy.Sections{
				SLSA: &policy.SLSAPolicy{
					MissingPolicy: types.ActionDeny,
				},
			},
		}

		hash1, err := pol1.Hash()
		testutil.AssertNoError(t, err)

		hash2, err := pol2.Hash()
		testutil.AssertNoError(t, err)

		if hash1 != hash2 {
			t.Errorf("identical policies should produce same hash: %q vs %q",
				hash1, hash2)
		}
	})

	t.Run("different policies produce different hashes", func(t *testing.T) {
		t.Parallel()

		pol1 := &policy.Policy{
			Sections: policy.Sections{
				SLSA: &policy.SLSAPolicy{
					MissingPolicy: types.ActionDeny,
				},
			},
		}
		pol2 := &policy.Policy{
			Sections: policy.Sections{
				SLSA: &policy.SLSAPolicy{
					MissingPolicy: types.ActionAllow,
				},
			},
		}

		hash1, err := pol1.Hash()
		testutil.AssertNoError(t, err)

		hash2, err := pol2.Hash()
		testutil.AssertNoError(t, err)

		if hash1 == hash2 {
			t.Error("different policies should produce different hashes")
		}
	})

	t.Run("hash is deterministic", func(t *testing.T) {
		t.Parallel()

		pol := &policy.Policy{
			Sections: policy.Sections{
				Trust: &policy.TrustPolicy{
					Builders: []policy.TrustedBuilder{
						{ID: "https://example.com/builder", MaxLevel: 3},
					},
				},
				SLSA: &policy.SLSAPolicy{
					MissingPolicy: types.ActionWarn,
				},
			},
		}

		hash1, err := pol.Hash()
		testutil.AssertNoError(t, err)

		hash2, err := pol.Hash()
		testutil.AssertNoError(t, err)

		if hash1 != hash2 {
			t.Errorf("hash should be deterministic: %q vs %q",
				hash1, hash2)
		}
	})

	t.Run("empty policy hashes without error", func(t *testing.T) {
		t.Parallel()

		pol := emptyPolicy()
		hash, err := pol.Hash()
		testutil.AssertNoError(t, err)

		if hash == "" {
			t.Error("expected non-empty hash for empty policy")
		}
	})
}

func TestValidateDuplicateBuilderID(t *testing.T) {
	t.Parallel()

	pol := policy.Policy{
		Sections: policy.Sections{
			Trust: &policy.TrustPolicy{
				Builders: []policy.TrustedBuilder{
					{ID: "https://builder.example.com", MaxLevel: 2},
					{ID: "https://builder.example.com", MaxLevel: 3},
				},
			},
		},
	}

	err := pol.Validate()
	if !errors.Is(err, policy.ErrDuplicateBuilderID) {
		t.Errorf("expected ErrDuplicateBuilderID, got %v", err)
	}
}

func TestValidateDuplicateVerifierID(t *testing.T) {
	t.Parallel()

	pol := policy.Policy{
		Sections: policy.Sections{
			Trust: &policy.TrustPolicy{
				Issuers: []string{testIssuerURL},
				Verifiers: []policy.TrustedVerifier{
					{ID: "https://verifier.example.com"},
					{ID: "https://verifier.example.com"},
				},
			},
		},
	}

	err := pol.Validate()
	if !errors.Is(err, policy.ErrDuplicateVerifierID) {
		t.Errorf("expected ErrDuplicateVerifierID, got %v", err)
	}
}

func TestValidateVSAMaxAgeNegative(t *testing.T) {
	t.Parallel()

	pol := policy.Policy{
		Sections: policy.Sections{
			VSA: &policy.VSAPolicy{MaxAge: "-1h"},
		},
	}

	err := pol.Validate()
	if !errors.Is(err, policy.ErrVSAMaxAgeNotPositive) {
		t.Errorf("expected ErrVSAMaxAgeNotPositive, got %v", err)
	}
}

func TestValidateVSAMaxAgeZero(t *testing.T) {
	t.Parallel()

	pol := policy.Policy{
		Sections: policy.Sections{
			VSA: &policy.VSAPolicy{MaxAge: "0s"},
		},
	}

	err := pol.Validate()
	if !errors.Is(err, policy.ErrVSAMaxAgeNotPositive) {
		t.Errorf("expected ErrVSAMaxAgeNotPositive, got %v", err)
	}
}

func TestValidateVSAMaxAgeResolved(t *testing.T) {
	t.Parallel()

	pol := policy.Policy{
		Sections: policy.Sections{
			VSA: &policy.VSAPolicy{MaxAge: "24h"},
		},
	}

	testutil.AssertNoError(t, pol.Validate())
	testutil.AssertEqual(t, 24*time.Hour, pol.VSA.MaxAgeDuration)
}

func TestValidateVSANoMaxAgeSkipsResolve(t *testing.T) {
	t.Parallel()

	pol := policy.Policy{
		Sections: policy.Sections{
			VSA: &policy.VSAPolicy{},
		},
	}

	testutil.AssertNoError(t, pol.Validate())
	testutil.AssertEqual(t, time.Duration(0), pol.VSA.MaxAgeDuration)
}

func TestTooManyPolicyFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	for i := range 1001 {
		testutil.WritePolicy(t, dir, fmt.Sprintf("policy-%04d.json", i), "{}")
	}

	_, err := policy.LoadAll(dir)
	if !errors.Is(err, policy.ErrTooManyPolicyFiles) {
		t.Errorf("expected ErrTooManyPolicyFiles, got %v", err)
	}
}

func TestPolicyValidateCollectsMultipleErrors(t *testing.T) {
	t.Parallel()

	pol := &policy.Policy{
		Sections: policy.Sections{
			Trust: &policy.TrustPolicy{
				Builders: []policy.TrustedBuilder{
					{ID: ""},
					{ID: "b1", MaxLevel: 99},
				},
			},
			VSA: &policy.VSAPolicy{
				MinimumLevel: -1,
			},
		},
	}

	err := pol.Validate()
	testutil.AssertError(t, err)

	if !errors.Is(err, policy.ErrBuilderIDRequired) {
		t.Errorf("expected ErrBuilderIDRequired, got %v", err)
	}

	if !errors.Is(err, policy.ErrBuilderMaxLevel) {
		t.Errorf("expected ErrBuilderMaxLevel, got %v", err)
	}

	if !errors.Is(err, policy.ErrVSAMinimumLevel) {
		t.Errorf("expected ErrVSAMinimumLevel, got %v", err)
	}
}

func TestPolicyValidateVerifiersCollectsMultipleErrors(t *testing.T) {
	t.Parallel()

	pol := &policy.Policy{
		Sections: policy.Sections{
			Trust: &policy.TrustPolicy{
				Verifiers: []policy.TrustedVerifier{
					{ID: ""},
					{ID: "v1", Keys: []string{"relative/path"}},
				},
			},
		},
	}

	err := pol.Validate()
	testutil.AssertError(t, err)

	if !errors.Is(err, policy.ErrVerifierIDRequired) {
		t.Errorf("expected ErrVerifierIDRequired, got %v", err)
	}

	if !errors.Is(err, policy.ErrVerifierKeyNotAbsolute) {
		t.Errorf("expected ErrVerifierKeyNotAbsolute, got %v", err)
	}
}

func TestLoadAllCollectsMultiplePolicyErrors(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	testutil.WritePolicy(t, dir, "a.json", `{"trust":{"builders":[{"id":""}]}}`)
	testutil.WritePolicy(t, dir, "b.json", `{"trust":{"builders":[{"id":""}]}}`)

	_, err := policy.LoadAll(dir)
	testutil.AssertError(t, err)

	errMsg := err.Error()
	if !strings.Contains(errMsg, "a.json") {
		t.Errorf("expected error to mention a.json, got %v", err)
	}

	if !strings.Contains(errMsg, "b.json") {
		t.Errorf("expected error to mention b.json, got %v", err)
	}
}

func TestPolicyValidateTrustStringFieldsCollectsMultipleErrors(t *testing.T) {
	t.Parallel()

	pol := &policy.Policy{
		Sections: policy.Sections{
			Trust: &policy.TrustPolicy{
				Issuers:     []string{"valid", ""},
				Sources:     []string{"", "["},
				BuildTypes:  []string{""},
				SANPatterns: []string{"", "["},
			},
		},
	}

	err := pol.Validate()
	testutil.AssertError(t, err)

	if !errors.Is(err, policy.ErrEmptyValue) {
		t.Errorf("expected ErrEmptyValue, got %v", err)
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "trust.issuers") {
		t.Errorf("expected error to mention trust.issuers, got %v", err)
	}

	if !strings.Contains(errMsg, "trust.sources") {
		t.Errorf("expected error to mention trust.sources, got %v", err)
	}

	if !strings.Contains(errMsg, "trust.buildTypes") {
		t.Errorf("expected error to mention trust.buildTypes, got %v", err)
	}

	if !strings.Contains(errMsg, "trust.sanPatterns") {
		t.Errorf("expected error to mention trust.sanPatterns, got %v", err)
	}
}

func TestPolicyValidateRuntimeCollectsMultipleErrors(t *testing.T) {
	t.Parallel()

	pol := &policy.Policy{
		Sections: policy.Sections{
			Trust: &policy.TrustPolicy{
				Verifiers: []policy.TrustedVerifier{
					{ID: "v1", Keys: []string{"/nonexistent/key1.pub"}},
					{ID: "v2", Keys: []string{"/nonexistent/key2.pub"}},
				},
			},
		},
	}

	err := pol.ValidateRuntime()
	testutil.AssertError(t, err)

	errMsg := err.Error()
	if !strings.Contains(errMsg, "key1.pub") {
		t.Errorf("expected error to mention key1.pub, got %v", err)
	}

	if !strings.Contains(errMsg, "key2.pub") {
		t.Errorf("expected error to mention key2.pub, got %v", err)
	}
}

func TestCloneIsolatesVerifierKeys(t *testing.T) {
	t.Parallel()

	original := &policy.Policy{
		Sections: policy.Sections{
			Trust: &policy.TrustPolicy{
				Verifiers: []policy.TrustedVerifier{
					{ID: "v1", Keys: []string{"/a.pub", "/b.pub"}},
				},
			},
		},
	}

	clone := policy.MergeWithDefault(&policy.Policy{}, original)

	clone.Trust.Verifiers[0].Keys[0] = "/mutated.pub"
	clone.Trust.Verifiers[0].Keys = append(clone.Trust.Verifiers[0].Keys, "/c.pub")

	if original.Trust.Verifiers[0].Keys[0] != "/a.pub" {
		t.Errorf("expected original keys[0] to be /a.pub, got %s",
			original.Trust.Verifiers[0].Keys[0])
	}

	if len(original.Trust.Verifiers[0].Keys) != 2 {
		t.Errorf("expected original to have 2 keys, got %d",
			len(original.Trust.Verifiers[0].Keys))
	}
}

func TestPolicyValidateMode(t *testing.T) {
	t.Parallel()

	runValidateTests(t, []validateTest{
		{
			name: "empty mode is valid",
			policy: policy.Policy{
				Mode: "",
			},
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name: "warn mode is valid",
			policy: policy.Policy{
				Mode: config.ModeWarn,
			},
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name: "enforce mode is valid",
			policy: policy.Policy{
				Mode: config.ModeEnforce,
			},
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name: "disabled mode is valid",
			policy: policy.Policy{
				Mode: config.ModeDisabled,
			},
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name: "invalid mode is rejected",
			policy: policy.Policy{
				Mode: testInvalidValue,
			},
			wantErr:     true,
			expectedErr: policy.ErrInvalidPolicyMode,
		},
	})
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
			got := pol.EffectiveMode(test.globalMode)

			if got != test.expected {
				t.Errorf("expected %q, got %q", test.expected, got)
			}
		})
	}
}

func TestValidateModeStrictness(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		policyMode config.VerificationMode
		globalMode config.VerificationMode
		wantErr    bool
	}{
		{
			name:       "empty mode always valid",
			policyMode: "",
			globalMode: config.ModeEnforce,
			wantErr:    false,
		},
		{
			name:       "enforce >= enforce is valid",
			policyMode: config.ModeEnforce,
			globalMode: config.ModeEnforce,
			wantErr:    false,
		},
		{
			name:       "enforce > warn is valid",
			policyMode: config.ModeEnforce,
			globalMode: config.ModeWarn,
			wantErr:    false,
		},
		{
			name:       "enforce > disabled is valid",
			policyMode: config.ModeEnforce,
			globalMode: config.ModeDisabled,
			wantErr:    false,
		},
		{
			name:       "warn >= warn is valid",
			policyMode: config.ModeWarn,
			globalMode: config.ModeWarn,
			wantErr:    false,
		},
		{
			name:       "warn > disabled is valid",
			policyMode: config.ModeWarn,
			globalMode: config.ModeDisabled,
			wantErr:    false,
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
			wantErr:    false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			pol := &policy.Policy{Mode: test.policyMode}
			err := pol.ValidateModeStrictness(test.globalMode)

			if test.wantErr && err == nil {
				t.Error("expected error, got nil")
			}

			if !test.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if test.wantErr && !errors.Is(err, policy.ErrModeNotStricter) {
				t.Errorf("expected ErrModeNotStricter, got %v", err)
			}
		})
	}
}

func TestMergeWithDefaultModeOverride(t *testing.T) {
	t.Parallel()

	t.Run("namespace mode overrides default", func(t *testing.T) {
		t.Parallel()

		defaultPol := &policy.Policy{
			Mode: config.ModeWarn,
			Sections: policy.Sections{
				SLSA: &policy.SLSAPolicy{MissingPolicy: types.ActionDeny},
			},
		}
		nsPol := &policy.Policy{
			Mode: config.ModeEnforce,
		}

		merged := policy.MergeWithDefault(nsPol, defaultPol)

		if merged.Mode != config.ModeEnforce {
			t.Errorf("expected mode %q, got %q", config.ModeEnforce, merged.Mode)
		}

		if merged.SLSA == nil || merged.SLSA.MissingPolicy != types.ActionDeny {
			t.Error("expected SLSA to be inherited from default")
		}
	})

	t.Run("empty namespace mode inherits default", func(t *testing.T) {
		t.Parallel()

		defaultPol := &policy.Policy{
			Mode: config.ModeEnforce,
		}
		nsPol := &policy.Policy{}

		merged := policy.MergeWithDefault(nsPol, defaultPol)

		if merged.Mode != config.ModeEnforce {
			t.Errorf("expected mode %q, got %q", config.ModeEnforce, merged.Mode)
		}
	})
}

func TestLoadPolicyWithMode(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	policyPath := filepath.Join(dir, "test.json")

	writeFile(t, policyPath, `{
		"mode": "enforce",
		"slsa": {"missingPolicy": "deny"}
	}`)

	pol, err := policy.Load(policyPath)
	testutil.AssertNoError(t, err)

	if pol.Mode != config.ModeEnforce {
		t.Errorf("expected mode %q, got %q", config.ModeEnforce, pol.Mode)
	}
}

func TestLoadPolicyInvalidMode(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	policyPath := filepath.Join(dir, "test.json")

	writeFile(t, policyPath, `{
		"mode": "invalid"
	}`)

	_, err := policy.Load(policyPath)
	testutil.AssertError(t, err)

	if !errors.Is(err, policy.ErrInvalidPolicyMode) {
		t.Errorf("expected ErrInvalidPolicyMode, got %v", err)
	}
}

func TestLoadAllModeStrictnessValidation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "default.json"), `{
		"slsa": {"missingPolicy": "allow"}
	}`)
	writeFile(t, filepath.Join(dir, "production.json"), `{
		"mode": "enforce",
		"slsa": {"missingPolicy": "deny"}
	}`)

	policies, err := policy.LoadAll(dir)
	testutil.AssertNoError(t, err)

	if len(policies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(policies))
	}

	prod := policies["production"]
	if prod.Mode != config.ModeEnforce {
		t.Errorf("expected mode %q, got %q", config.ModeEnforce, prod.Mode)
	}
}

func TestLoadAllInheritsMergesModeFromNamespace(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "default.json"), `{
		"slsa": {"missingPolicy": "allow"}
	}`)
	writeFile(t, filepath.Join(dir, "staging.json"), `{
		"inherits": true,
		"mode": "enforce"
	}`)

	policies, err := policy.LoadAll(dir)
	testutil.AssertNoError(t, err)

	staging := policies["staging"]

	if staging.Mode != config.ModeEnforce {
		t.Errorf("expected mode %q, got %q", config.ModeEnforce, staging.Mode)
	}

	if staging.SLSAMissingPolicy() != types.ActionAllow {
		t.Errorf("expected inherited SLSA missing policy %q, got %q",
			types.ActionAllow, staging.SLSAMissingPolicy())
	}
}

func TestPolicyValidateRulesValid(t *testing.T) {
	t.Parallel()

	pol := &policy.Policy{
		Rules: []policy.ImageRule{
			{
				Images: []string{"ghcr.io/myorg/**"},
				Sections: policy.Sections{
					SLSA: &policy.SLSAPolicy{MissingPolicy: types.ActionDeny},
				},
			},
		},
	}

	testutil.AssertNoError(t, pol.Validate())
}

func TestPolicyValidateRulesEmptySlice(t *testing.T) {
	t.Parallel()

	pol := &policy.Policy{}
	testutil.AssertNoError(t, pol.Validate())
}

func TestPolicyValidateRulesEmptyImages(t *testing.T) {
	t.Parallel()

	pol := &policy.Policy{
		Rules: []policy.ImageRule{
			{Images: nil},
		},
	}

	err := pol.Validate()
	if !errors.Is(err, policy.ErrRuleImagesRequired) {
		t.Errorf("expected ErrRuleImagesRequired, got %v", err)
	}
}

func TestPolicyValidateRulesEmptyStringInImages(t *testing.T) {
	t.Parallel()

	pol := &policy.Policy{
		Rules: []policy.ImageRule{
			{Images: []string{""}},
		},
	}

	err := pol.Validate()
	if !errors.Is(err, policy.ErrEmptyValue) {
		t.Errorf("expected ErrEmptyValue, got %v", err)
	}
}

func TestPolicyValidateRulesValidGlob(t *testing.T) {
	t.Parallel()

	pol := &policy.Policy{
		Rules: []policy.ImageRule{
			{Images: []string{"ghcr.io/myorg/**", "docker.io/library/*"}},
		},
	}

	testutil.AssertNoError(t, pol.Validate())
}

func TestPolicyValidateRulesInvalidSubPolicy(t *testing.T) {
	t.Parallel()

	pol := &policy.Policy{
		Rules: []policy.ImageRule{
			{
				Images: []string{testRuleImagesGlob},
				Sections: policy.Sections{
					SLSA: &policy.SLSAPolicy{MissingPolicy: testInvalidValue},
				},
			},
		},
	}

	err := pol.Validate()
	testutil.AssertError(t, err)

	if !strings.Contains(err.Error(), "rules[0]") {
		t.Errorf("expected error to reference rules[0], got %v", err)
	}
}

func TestPolicyValidateRulesMultipleErrors(t *testing.T) {
	t.Parallel()

	pol := &policy.Policy{
		Rules: []policy.ImageRule{
			{Images: nil},
			{
				Images: []string{testRuleImagesGlob},
				Sections: policy.Sections{
					VEX: &policy.VEXPolicy{MissingPolicy: testInvalidValue},
				},
			},
		},
	}

	err := pol.Validate()
	testutil.AssertError(t, err)

	if !errors.Is(err, policy.ErrRuleImagesRequired) {
		t.Errorf("expected ErrRuleImagesRequired, got %v", err)
	}

	if !strings.Contains(err.Error(), "rules[1]") {
		t.Errorf("expected error to reference rules[1], got %v", err)
	}
}

func TestPolicyValidateRulesInvalidTrust(t *testing.T) {
	t.Parallel()

	pol := &policy.Policy{
		Rules: []policy.ImageRule{
			{
				Images: []string{testRuleImagesGlob},
				Sections: policy.Sections{
					Trust: &policy.TrustPolicy{
						Builders: []policy.TrustedBuilder{
							{ID: "", MaxLevel: 0},
						},
					},
				},
			},
		},
	}

	err := pol.Validate()
	if !errors.Is(err, policy.ErrBuilderIDRequired) {
		t.Errorf("expected ErrBuilderIDRequired, got %v", err)
	}
}

func TestPolicyValidateRulesVSADurationResolved(t *testing.T) {
	t.Parallel()

	pol := &policy.Policy{
		Rules: []policy.ImageRule{
			{
				Images: []string{testRuleImagesGlob},
				Sections: policy.Sections{
					VSA: &policy.VSAPolicy{
						MissingPolicy: types.ActionDeny,
						MaxAge:        "24h",
					},
				},
			},
		},
	}

	testutil.AssertNoError(t, pol.Validate())

	if pol.Rules[0].VSA.MaxAgeDuration != 24*time.Hour {
		t.Errorf("expected MaxAgeDuration 24h, got %v",
			pol.Rules[0].VSA.MaxAgeDuration)
	}
}

func TestValidateEnforceWithRules(t *testing.T) {
	t.Parallel()

	pol := &policy.Policy{
		Rules: []policy.ImageRule{
			{
				Images: []string{testRuleImagesGlob},
				Sections: policy.Sections{
					Trust: &policy.TrustPolicy{
						Issuers: []string{testIssuerURL},
					},
				},
			},
		},
	}

	err := pol.ValidateEnforce()
	if !errors.Is(err, policy.ErrSANPatternsRequired) {
		t.Errorf("expected ErrSANPatternsRequired, got %v", err)
	}
}

func TestValidateEnforceWithRulesValid(t *testing.T) {
	t.Parallel()

	pol := &policy.Policy{
		Rules: []policy.ImageRule{
			{
				Images: []string{testRuleImagesGlob},
				Sections: policy.Sections{
					Trust: &policy.TrustPolicy{
						Issuers:     []string{testIssuerURL},
						SANPatterns: []string{"https://github.com/**"},
					},
				},
			},
		},
	}

	testutil.AssertNoError(t, pol.ValidateEnforce())
}

func TestValidateEnforceRejectsNotationSkip(t *testing.T) {
	t.Parallel()

	pol := &policy.Policy{
		Sections: policy.Sections{
			Notation: &policy.NotationPolicy{
				VerificationLevel: "skip",
			},
		},
	}

	err := pol.ValidateEnforce()
	if !errors.Is(err, policy.ErrNotationSkipInEnforceMode) {
		t.Errorf("expected ErrNotationSkipInEnforceMode, got %v", err)
	}
}

func TestValidateEnforceAllowsNotationStrict(t *testing.T) {
	t.Parallel()

	pol := &policy.Policy{
		Sections: policy.Sections{
			Notation: &policy.NotationPolicy{
				VerificationLevel: testNotationLevelStrict,
			},
		},
	}

	testutil.AssertNoError(t, pol.ValidateEnforce())
}

func TestValidateRuntimeWithRules(t *testing.T) {
	t.Parallel()

	pol := &policy.Policy{
		Rules: []policy.ImageRule{
			{
				Images: []string{testRuleImagesGlob},
				Sections: policy.Sections{
					Trust: &policy.TrustPolicy{
						Verifiers: []policy.TrustedVerifier{
							{
								ID:   testVerifierID,
								Keys: []string{testNonexistentKeyPath},
							},
						},
						Issuers: []string{testIssuerURL},
					},
				},
			},
		},
	}

	err := pol.ValidateRuntime()
	testutil.AssertError(t, err)

	if !strings.Contains(err.Error(), "rules[0]") {
		t.Errorf("expected error to reference rules[0], got %v", err)
	}
}

func TestApplyRuleOverrides(t *testing.T) {
	t.Parallel()

	base := &policy.Policy{
		Sections: policy.Sections{
			Trust: &policy.TrustPolicy{
				Builders: []policy.TrustedBuilder{{ID: testBaseBuilderID, MaxLevel: 2}},
			},
			SLSA: &policy.SLSAPolicy{MissingPolicy: types.ActionAllow},
			VEX:  &policy.VEXPolicy{MissingPolicy: types.ActionAllow},
		},
		Rules: []policy.ImageRule{
			{Images: []string{testRuleImagesGlob}},
		},
	}

	rule := &policy.ImageRule{
		Images: []string{"ghcr.io/critical/**"},
		Sections: policy.Sections{
			SLSA: &policy.SLSAPolicy{MissingPolicy: types.ActionDeny},
		},
	}

	resolved := policy.ApplyRule(base, rule)

	if resolved.SLSAMissingPolicy() != types.ActionDeny {
		t.Errorf("expected SLSA deny from rule, got %v", resolved.SLSAMissingPolicy())
	}

	if resolved.VEXMissingPolicy() != types.ActionAllow {
		t.Errorf("expected VEX allow from base, got %v", resolved.VEXMissingPolicy())
	}

	if len(resolved.Builders()) != 1 || resolved.Builders()[0].ID != testBaseBuilderID {
		t.Errorf("expected trust inherited from base, got %v", resolved.Builders())
	}

	if resolved.Rules != nil {
		t.Error("expected resolved policy to have nil Rules")
	}
}

func TestApplyRuleDeepCopyIsolation(t *testing.T) {
	t.Parallel()

	base := &policy.Policy{
		Sections: policy.Sections{
			SLSA: &policy.SLSAPolicy{MissingPolicy: types.ActionAllow},
		},
	}

	rule := &policy.ImageRule{
		Images: []string{testRuleImagesGlob},
		Sections: policy.Sections{
			SLSA: &policy.SLSAPolicy{MissingPolicy: types.ActionDeny},
		},
	}

	resolved := policy.ApplyRule(base, rule)

	if base.SLSAMissingPolicy() != types.ActionAllow {
		t.Error("base policy was mutated by ApplyRule")
	}

	if resolved.SLSAMissingPolicy() != types.ActionDeny {
		t.Error("resolved policy should have rule's SLSA setting")
	}
}

func TestMergeWithDefaultIncludesRules(t *testing.T) {
	t.Parallel()

	t.Run("nil rules inherits default", func(t *testing.T) {
		t.Parallel()

		defaultPol := &policy.Policy{
			Rules: []policy.ImageRule{
				{
					Images: []string{testRuleImagesGlob},
					Sections: policy.Sections{
						SLSA: &policy.SLSAPolicy{MissingPolicy: types.ActionDeny},
					},
				},
			},
		}

		nsPol := &policy.Policy{}
		merged := policy.MergeWithDefault(nsPol, defaultPol)

		if len(merged.Rules) != 1 {
			t.Fatalf("expected 1 inherited rule, got %d", len(merged.Rules))
		}

		if merged.Rules[0].Images[0] != testRuleImagesGlob {
			t.Errorf("expected inherited rule images, got %v", merged.Rules[0].Images)
		}
	})

	t.Run("non-nil rules overrides default", func(t *testing.T) {
		t.Parallel()

		defaultPol := &policy.Policy{
			Rules: []policy.ImageRule{
				{
					Images: []string{testRuleImagesGlob},
					Sections: policy.Sections{
						SLSA: &policy.SLSAPolicy{MissingPolicy: types.ActionDeny},
					},
				},
			},
		}

		nsPol := &policy.Policy{
			Rules: []policy.ImageRule{
				{
					Images: []string{testDockerGlob},
					Sections: policy.Sections{
						VEX: &policy.VEXPolicy{MissingPolicy: types.ActionWarn},
					},
				},
			},
		}

		merged := policy.MergeWithDefault(nsPol, defaultPol)

		if len(merged.Rules) != 1 {
			t.Fatalf("expected 1 overridden rule, got %d", len(merged.Rules))
		}

		if merged.Rules[0].Images[0] != testDockerGlob {
			t.Errorf("expected namespace rule images, got %v", merged.Rules[0].Images)
		}
	})
}

func TestCloneIsolatesRules(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "default.json"), `{
		"rules": [
			{
				"images": ["ghcr.io/**"],
				"slsa": {"missingPolicy": "deny"}
			}
		]
	}`)

	policies, err := policy.LoadAll(dir)
	testutil.AssertNoError(t, err)

	original := policies[""]
	if len(original.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(original.Rules))
	}

	original.Rules[0].Images[0] = testMutatedValue

	reloaded, err := policy.LoadAll(dir)
	testutil.AssertNoError(t, err)

	if reloaded[""].Rules[0].Images[0] == testMutatedValue {
		t.Error("clone did not isolate rules")
	}
}

func TestLoadPolicyWithRules(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "default.json"), `{
		"slsa": {"missingPolicy": "warn"},
		"rules": [
			{
				"images": ["ghcr.io/myorg/critical-*"],
				"slsa": {"missingPolicy": "deny"},
				"vex": {"missingPolicy": "deny"}
			},
			{
				"images": ["ghcr.io/myorg/experimental-*"],
				"slsa": {"missingPolicy": "allow"}
			}
		]
	}`)

	policies, err := policy.LoadAll(dir)
	testutil.AssertNoError(t, err)

	pol := policies[""]
	if len(pol.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(pol.Rules))
	}

	if pol.Rules[0].Images[0] != "ghcr.io/myorg/critical-*" {
		t.Errorf("expected first rule images, got %v", pol.Rules[0].Images)
	}

	if pol.Rules[0].SLSA.MissingPolicy != types.ActionDeny {
		t.Errorf("expected first rule SLSA deny, got %v", pol.Rules[0].SLSA.MissingPolicy)
	}

	if pol.Rules[1].SLSA.MissingPolicy != types.ActionAllow {
		t.Errorf("expected second rule SLSA allow, got %v", pol.Rules[1].SLSA.MissingPolicy)
	}
}

func TestLoadPolicyWithRulesUnknownField(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "default.json"), `{
		"rules": [
			{
				"images": ["ghcr.io/**"],
				"mode": "enforce"
			}
		]
	}`)

	_, err := policy.LoadAll(dir)
	testutil.AssertError(t, err)
}

func TestLoadAllInheritsRules(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "default.json"), `{
		"slsa": {"missingPolicy": "warn"},
		"rules": [
			{
				"images": ["ghcr.io/myorg/**"],
				"slsa": {"missingPolicy": "deny"}
			}
		]
	}`)
	writeFile(t, filepath.Join(dir, "staging.json"), `{
		"inherits": true
	}`)

	policies, err := policy.LoadAll(dir)
	testutil.AssertNoError(t, err)

	staging := policies["staging"]
	if len(staging.Rules) != 1 {
		t.Fatalf("expected 1 inherited rule, got %d", len(staging.Rules))
	}

	if staging.Rules[0].SLSA.MissingPolicy != types.ActionDeny {
		t.Errorf("expected inherited rule SLSA deny, got %v",
			staging.Rules[0].SLSA.MissingPolicy)
	}
}

func TestMergeWithDefaultEmptyRulesClearsInherited(t *testing.T) {
	t.Parallel()

	defaultPol := &policy.Policy{
		Rules: []policy.ImageRule{
			{
				Images: []string{testRuleImagesGlob},
				Sections: policy.Sections{
					SLSA: &policy.SLSAPolicy{MissingPolicy: types.ActionDeny},
				},
			},
		},
	}

	nsPol := &policy.Policy{
		Rules: []policy.ImageRule{},
	}

	merged := policy.MergeWithDefault(nsPol, defaultPol)

	if len(merged.Rules) != 0 {
		t.Errorf("expected empty rules to clear inherited rules, got %d", len(merged.Rules))
	}
}

func TestApplyRuleTrustOverride(t *testing.T) {
	t.Parallel()

	base := &policy.Policy{
		Sections: policy.Sections{
			Trust: &policy.TrustPolicy{
				Builders: []policy.TrustedBuilder{{ID: testBaseBuilderID, MaxLevel: 2}},
				Issuers:  []string{"https://base-issuer.example.com"},
			},
			SLSA: &policy.SLSAPolicy{MissingPolicy: types.ActionAllow},
		},
	}

	rule := &policy.ImageRule{
		Images: []string{testRuleImagesGlob},
		Sections: policy.Sections{
			Trust: &policy.TrustPolicy{
				Builders: []policy.TrustedBuilder{{ID: testRuleBuilderID, MaxLevel: 3}},
				Issuers:  []string{"https://rule-issuer.example.com"},
			},
		},
	}

	resolved := policy.ApplyRule(base, rule)

	if len(resolved.Builders()) != 1 || resolved.Builders()[0].ID != testRuleBuilderID {
		t.Errorf("expected rule builder, got %v", resolved.Builders())
	}

	if resolved.SLSAMissingPolicy() != types.ActionAllow {
		t.Errorf("expected base SLSA allow, got %v", resolved.SLSAMissingPolicy())
	}

	// Verify deep-copy isolation.
	resolved.Trust.Builders[0].ID = testMutatedValue

	if base.Trust.Builders[0].ID != testBaseBuilderID {
		t.Error("base trust was mutated by ApplyRule")
	}

	if rule.Trust.Builders[0].ID != testRuleBuilderID {
		t.Error("rule trust was mutated by ApplyRule")
	}
}

func TestApplyRuleSignaturesOverride(t *testing.T) {
	t.Parallel()

	base := &policy.Policy{
		Sections: policy.Sections{
			Signatures: &policy.SignaturesPolicy{RequireTransparencyLog: false},
			SLSA:       &policy.SLSAPolicy{MissingPolicy: types.ActionAllow},
		},
	}

	rule := &policy.ImageRule{
		Images: []string{testRuleImagesGlob},
		Sections: policy.Sections{
			Signatures: &policy.SignaturesPolicy{RequireTransparencyLog: true},
		},
	}

	resolved := policy.ApplyRule(base, rule)

	if !resolved.Signatures.RequireTransparencyLog {
		t.Error("expected rule to override signatures RequireTransparencyLog to true")
	}

	if resolved.SLSAMissingPolicy() != types.ActionAllow {
		t.Errorf("expected base SLSA allow, got %v", resolved.SLSAMissingPolicy())
	}
}

func TestSBOMMissingPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		policy   policy.Policy
		expected types.Action
	}{
		{
			name:     "nil sbom defaults to allow",
			policy:   emptyPolicy(),
			expected: types.ActionAllow,
		},
		{
			name: testEmptyMissingPolicyName,
			policy: policy.Policy{
				Sections: policy.Sections{
					SBOM: &policy.SBOMPolicy{
						MissingPolicy: "",
					},
				},
			},
			expected: types.ActionAllow,
		},
		{
			name: testExplicitDenyName,
			policy: policy.Policy{
				Sections: policy.Sections{
					SBOM: &policy.SBOMPolicy{
						MissingPolicy: types.ActionDeny,
					},
				},
			},
			expected: types.ActionDeny,
		},
		{
			name: "explicit warn",
			policy: policy.Policy{
				Sections: policy.Sections{
					SBOM: &policy.SBOMPolicy{
						MissingPolicy: types.ActionWarn,
					},
				},
			},
			expected: types.ActionWarn,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := test.policy.SBOMMissingPolicy(); got != test.expected {
				t.Errorf("expected %q, got %q", test.expected, got)
			}
		})
	}
}

func TestPolicyValidateSBOM(t *testing.T) {
	t.Parallel()

	runValidateTests(t, []validateTest{
		{
			name: "valid SBOM config",
			policy: policy.Policy{
				Sections: policy.Sections{
					SBOM: &policy.SBOMPolicy{
						MissingPolicy: types.ActionWarn,
						Formats:       []string{testFormatSPDX, testFormatCycloneDX},
						License: &policy.SBOMLicensePolicy{
							Deny: []string{testLicenseAGPL},
						},
						Component: &policy.SBOMComponentPolicy{
							Deny: []string{
								"pkg:npm/bad-package@1.0.0",
							},
						},
					},
				},
			},
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name: "invalid SBOM missing policy",
			policy: policy.Policy{
				Sections: policy.Sections{
					SBOM: &policy.SBOMPolicy{
						MissingPolicy: testInvalidValue,
					},
				},
			},
			wantErr:     true,
			expectedErr: types.ErrInvalidAction,
		},
		{
			name: "invalid SBOM format",
			policy: policy.Policy{
				Sections: policy.Sections{
					SBOM: &policy.SBOMPolicy{
						Formats: []string{"unknown"},
					},
				},
			},
			wantErr:     true,
			expectedErr: policy.ErrInvalidSBOMFormat,
		},
		{
			name: "empty license in deny list",
			policy: policy.Policy{
				Sections: policy.Sections{
					SBOM: &policy.SBOMPolicy{
						License: &policy.SBOMLicensePolicy{
							Deny: []string{testLicenseMIT, ""},
						},
					},
				},
			},
			wantErr:     true,
			expectedErr: policy.ErrEmptyValue,
		},
		{
			name: "invalid component deny list entry",
			policy: policy.Policy{
				Sections: policy.Sections{
					SBOM: &policy.SBOMPolicy{
						Component: &policy.SBOMComponentPolicy{
							Deny: []string{"not-a-purl"},
						},
					},
				},
			},
			wantErr:     true,
			expectedErr: policy.ErrInvalidComponentPURL,
		},
		{
			name: "empty component deny list entry",
			policy: policy.Policy{
				Sections: policy.Sections{
					SBOM: &policy.SBOMPolicy{
						Component: &policy.SBOMComponentPolicy{
							Deny: []string{""},
						},
					},
				},
			},
			wantErr:     true,
			expectedErr: policy.ErrEmptyValue,
		},
		{
			name: "empty license in allow list",
			policy: policy.Policy{
				Sections: policy.Sections{
					SBOM: &policy.SBOMPolicy{
						License: &policy.SBOMLicensePolicy{
							Allow: []string{testLicenseMIT, ""},
						},
					},
				},
			},
			wantErr:     true,
			expectedErr: policy.ErrEmptyValue,
		},
		{
			name: "invalid component allow list entry",
			policy: policy.Policy{
				Sections: policy.Sections{
					SBOM: &policy.SBOMPolicy{
						Component: &policy.SBOMComponentPolicy{
							Allow: []string{"not-a-purl"},
						},
					},
				},
			},
			wantErr:     true,
			expectedErr: policy.ErrInvalidComponentPURL,
		},
		{
			name: "bare pkg: scheme without type/name rejected",
			policy: policy.Policy{
				Sections: policy.Sections{
					SBOM: &policy.SBOMPolicy{
						Component: &policy.SBOMComponentPolicy{
							Deny: []string{"pkg:"},
						},
					},
				},
			},
			wantErr:     true,
			expectedErr: policy.ErrInvalidComponentPURL,
		},
		{
			name: "pkg:type without name rejected",
			policy: policy.Policy{
				Sections: policy.Sections{
					SBOM: &policy.SBOMPolicy{
						Component: &policy.SBOMComponentPolicy{
							Deny: []string{"pkg:npm"},
						},
					},
				},
			},
			wantErr:     true,
			expectedErr: policy.ErrInvalidComponentPURL,
		},
		{
			name: "valid allow lists",
			policy: policy.Policy{
				Sections: policy.Sections{
					SBOM: &policy.SBOMPolicy{
						License: &policy.SBOMLicensePolicy{
							Allow: []string{testLicenseMIT, "Apache-2.0"},
						},
						Component: &policy.SBOMComponentPolicy{
							Allow: []string{"pkg:npm/trusted@1.0.0"},
						},
					},
				},
			},
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name: "nil SBOM is valid",
			policy: policy.Policy{
				Sections: policy.Sections{
					SBOM: nil,
				},
			},
			wantErr:     false,
			expectedErr: nil,
		},
	})
}

func TestApplyRuleSBOMOverride(t *testing.T) {
	t.Parallel()

	base := &policy.Policy{
		Sections: policy.Sections{
			SBOM: &policy.SBOMPolicy{
				MissingPolicy: types.ActionAllow,
			},
			SLSA: &policy.SLSAPolicy{MissingPolicy: types.ActionAllow},
		},
	}

	rule := &policy.ImageRule{
		Images: []string{testRuleImagesGlob},
		Sections: policy.Sections{
			SBOM: &policy.SBOMPolicy{
				MissingPolicy: types.ActionDeny,
				Formats:       []string{testFormatSPDX},
				License: &policy.SBOMLicensePolicy{
					Deny: []string{testLicenseAGPL},
				},
			},
		},
	}

	resolved := policy.ApplyRule(base, rule)

	if resolved.SBOMMissingPolicy() != types.ActionDeny {
		t.Errorf(
			"expected rule SBOM deny, got %v",
			resolved.SBOMMissingPolicy(),
		)
	}

	if resolved.SLSAMissingPolicy() != types.ActionAllow {
		t.Errorf("expected base SLSA allow, got %v", resolved.SLSAMissingPolicy())
	}

	if len(resolved.SBOM.Formats) != 1 || resolved.SBOM.Formats[0] != testFormatSPDX {
		t.Errorf("expected rule SBOM formats, got %v", resolved.SBOM.Formats)
	}
}

func TestMergeWithDefaultInheritsSBOM(t *testing.T) {
	t.Parallel()

	defaultPol := &policy.Policy{
		Sections: policy.Sections{
			SBOM: &policy.SBOMPolicy{
				MissingPolicy: types.ActionDeny,
				Formats:       []string{testFormatSPDX},
				License: &policy.SBOMLicensePolicy{
					Deny: []string{testLicenseAGPL},
				},
			},
		},
	}

	nsPol := &policy.Policy{}
	merged := policy.MergeWithDefault(nsPol, defaultPol)

	if merged.SBOM == nil {
		t.Fatal("expected SBOM to be inherited")
	}

	if merged.SBOMMissingPolicy() != types.ActionDeny {
		t.Errorf("expected inherited SBOM deny, got %v", merged.SBOMMissingPolicy())
	}

	if len(merged.SBOM.Formats) != 1 || merged.SBOM.Formats[0] != testFormatSPDX {
		t.Errorf("expected inherited SBOM formats, got %v", merged.SBOM.Formats)
	}
}

func TestMergeWithDefaultSBOMOverride(t *testing.T) {
	t.Parallel()

	defaultPol := &policy.Policy{
		Sections: policy.Sections{
			SBOM: &policy.SBOMPolicy{
				MissingPolicy: types.ActionAllow,
				Formats:       []string{testFormatSPDX, testFormatCycloneDX},
			},
		},
	}

	nsPol := &policy.Policy{
		Sections: policy.Sections{
			SBOM: &policy.SBOMPolicy{
				MissingPolicy: types.ActionDeny,
				Formats:       []string{testFormatCycloneDX},
			},
		},
	}

	merged := policy.MergeWithDefault(nsPol, defaultPol)

	if merged.SBOMMissingPolicy() != types.ActionDeny {
		t.Errorf("expected overridden SBOM deny, got %v", merged.SBOMMissingPolicy())
	}

	if len(merged.SBOM.Formats) != 1 || merged.SBOM.Formats[0] != testFormatCycloneDX {
		t.Errorf("expected overridden SBOM formats, got %v", merged.SBOM.Formats)
	}
}

func TestCloneIsolatesSBOM(t *testing.T) {
	t.Parallel()

	original := &policy.Policy{
		Sections: policy.Sections{
			SBOM: &policy.SBOMPolicy{
				MissingPolicy: types.ActionDeny,
				Formats:       []string{testFormatSPDX},
				License: &policy.SBOMLicensePolicy{
					Deny: []string{testLicenseMIT},
				},
				Component: &policy.SBOMComponentPolicy{
					Deny:  []string{"pkg:npm/bad@1.0.0"},
					Allow: []string{"pkg:npm/good@1.0.0"},
				},
			},
		},
	}

	clone := policy.MergeWithDefault(&policy.Policy{}, original)

	clone.SBOM.Formats = append(clone.SBOM.Formats, testFormatCycloneDX)
	clone.SBOM.License.Deny[0] = testLicenseAGPL
	clone.SBOM.Component.Allow[0] = "pkg:npm/mutated@1.0.0"

	if len(original.SBOM.Formats) != 1 {
		t.Errorf("expected original to have 1 format, got %d",
			len(original.SBOM.Formats))
	}

	if original.SBOM.License.Deny[0] != "MIT" {
		t.Errorf("expected original license deny list unchanged, got %s",
			original.SBOM.License.Deny[0])
	}

	if original.SBOM.Component.Allow[0] != "pkg:npm/good@1.0.0" {
		t.Errorf("expected original component allow list unchanged, got %s",
			original.SBOM.Component.Allow[0])
	}
}

func TestNotationMissingPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		policy   policy.Policy
		expected types.Action
	}{
		{
			name:     "nil notation defaults to allow",
			policy:   emptyPolicy(),
			expected: types.ActionAllow,
		},
		{
			name: testEmptyMissingPolicyName,
			policy: policy.Policy{
				Sections: policy.Sections{
					Notation: &policy.NotationPolicy{
						MissingPolicy: "",
					},
				},
			},
			expected: types.ActionAllow,
		},
		{
			name: testExplicitDenyName,
			policy: policy.Policy{
				Sections: policy.Sections{
					Notation: &policy.NotationPolicy{
						MissingPolicy: types.ActionDeny,
					},
				},
			},
			expected: types.ActionDeny,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := test.policy.NotationMissingPolicy(); got != test.expected {
				t.Errorf("expected %q, got %q", test.expected, got)
			}
		})
	}
}

func validNotationPolicy() *policy.NotationPolicy {
	return &policy.NotationPolicy{
		MissingPolicy:     types.ActionDeny,
		VerificationLevel: "strict",
		TrustStores: []policy.NotationTrustStore{
			{
				Name:         testNotationStoreName,
				Type:         "ca",
				Certificates: []string{testNotationCertPath},
			},
		},
		TrustPolicy: []policy.NotationTrustPolicyRule{
			{
				Name:              "default",
				RegistryScopes:    []string{"*"},
				TrustStores:       []string{testNotationStoreRef},
				TrustedIdentities: []string{"*"},
			},
		},
	}
}

func TestPolicyValidateNotation(t *testing.T) {
	t.Parallel()

	runValidateTests(t, []validateTest{
		{
			name: "valid notation config",
			policy: policy.Policy{
				Sections: policy.Sections{
					Notation: validNotationPolicy(),
				},
			},
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name: "invalid verification level",
			policy: policy.Policy{
				Sections: policy.Sections{
					Notation: &policy.NotationPolicy{
						MissingPolicy:     types.ActionDeny,
						VerificationLevel: "invalid",
						TrustStores: []policy.NotationTrustStore{
							{
								Name:         testNotationStoreName,
								Type:         "ca",
								Certificates: []string{testNotationCertPath},
							},
						},
					},
				},
			},
			wantErr:     true,
			expectedErr: policy.ErrNotationVerificationLevelInvalid,
		},
		{
			name: "trust store missing name",
			policy: policy.Policy{
				Sections: policy.Sections{
					Notation: &policy.NotationPolicy{
						TrustStores: []policy.NotationTrustStore{
							{
								Name:         "",
								Type:         "ca",
								Certificates: []string{testNotationCertPath},
							},
						},
					},
				},
			},
			wantErr:     true,
			expectedErr: policy.ErrNotationTrustStoreNameRequired,
		},
		{
			name: "trust store invalid type",
			policy: policy.Policy{
				Sections: policy.Sections{
					Notation: &policy.NotationPolicy{
						TrustStores: []policy.NotationTrustStore{
							{
								Name:         testNotationStoreName,
								Type:         "invalid",
								Certificates: []string{testNotationCertPath},
							},
						},
					},
				},
			},
			wantErr:     true,
			expectedErr: policy.ErrNotationTrustStoreTypeInvalid,
		},
		{
			name: "trust store no certificates",
			policy: policy.Policy{
				Sections: policy.Sections{
					Notation: &policy.NotationPolicy{
						TrustStores: []policy.NotationTrustStore{
							{
								Name:         testNotationStoreName,
								Type:         "ca",
								Certificates: nil,
							},
						},
					},
				},
			},
			wantErr:     true,
			expectedErr: policy.ErrNotationTrustStoreCertsRequired,
		},
		{
			name: "trust store relative certificate path",
			policy: policy.Policy{
				Sections: policy.Sections{
					Notation: &policy.NotationPolicy{
						TrustStores: []policy.NotationTrustStore{
							{
								Name:         testNotationStoreName,
								Type:         "ca",
								Certificates: []string{"relative/path.pem"},
							},
						},
					},
				},
			},
			wantErr:     true,
			expectedErr: policy.ErrNotationCertNotAbsolute,
		},
		{
			name: "duplicate trust store name",
			policy: policy.Policy{
				Sections: policy.Sections{
					Notation: &policy.NotationPolicy{
						TrustStores: []policy.NotationTrustStore{
							{
								Name:         testNotationStoreName,
								Type:         "ca",
								Certificates: []string{testNotationCertPath},
							},
							{
								Name:         testNotationStoreName,
								Type:         "ca",
								Certificates: []string{"/etc/certs/ca2.pem"},
							},
						},
					},
				},
			},
			wantErr:     true,
			expectedErr: policy.ErrDuplicateNotationTrustStoreName,
		},
		{
			name: "trust policy missing name",
			policy: policy.Policy{
				Sections: policy.Sections{
					Notation: &policy.NotationPolicy{
						TrustPolicy: []policy.NotationTrustPolicyRule{
							{
								Name:              "",
								RegistryScopes:    []string{"*"},
								TrustStores:       []string{testNotationStoreRef},
								TrustedIdentities: []string{"*"},
							},
						},
					},
				},
			},
			wantErr:     true,
			expectedErr: policy.ErrNotationTrustPolicyNameRequired,
		},
		{
			name: "trust policy missing registry scopes",
			policy: policy.Policy{
				Sections: policy.Sections{
					Notation: &policy.NotationPolicy{
						TrustPolicy: []policy.NotationTrustPolicyRule{
							{
								Name:              testNotationRuleName,
								RegistryScopes:    nil,
								TrustStores:       []string{testNotationStoreRef},
								TrustedIdentities: []string{"*"},
							},
						},
					},
				},
			},
			wantErr:     true,
			expectedErr: policy.ErrNotationTrustPolicyScopesRequired,
		},
		{
			name: "trust policy missing trust stores",
			policy: policy.Policy{
				Sections: policy.Sections{
					Notation: &policy.NotationPolicy{
						TrustPolicy: []policy.NotationTrustPolicyRule{
							{
								Name:              testNotationRuleName,
								RegistryScopes:    []string{"*"},
								TrustStores:       nil,
								TrustedIdentities: []string{"*"},
							},
						},
					},
				},
			},
			wantErr:     true,
			expectedErr: policy.ErrNotationTrustPolicyStoresRequired,
		},
		{
			name: "trust policy missing trusted identities",
			policy: policy.Policy{
				Sections: policy.Sections{
					Notation: &policy.NotationPolicy{
						TrustPolicy: []policy.NotationTrustPolicyRule{
							{
								Name:              testNotationRuleName,
								RegistryScopes:    []string{"*"},
								TrustStores:       []string{testNotationStoreRef},
								TrustedIdentities: nil,
							},
						},
					},
				},
			},
			wantErr:     true,
			expectedErr: policy.ErrNotationTrustPolicyIdentitiesRequired,
		},
		{
			name: "duplicate trust policy name",
			policy: policy.Policy{
				Sections: policy.Sections{
					Notation: &policy.NotationPolicy{
						TrustPolicy: []policy.NotationTrustPolicyRule{
							{
								Name:              testNotationRuleName,
								RegistryScopes:    []string{"*"},
								TrustStores:       []string{testNotationStoreRef},
								TrustedIdentities: []string{"*"},
							},
							{
								Name:              testNotationRuleName,
								RegistryScopes:    []string{testDockerGlob},
								TrustStores:       []string{testNotationStoreRef},
								TrustedIdentities: []string{"*"},
							},
						},
					},
				},
			},
			wantErr:     true,
			expectedErr: policy.ErrDuplicateNotationTrustPolicyName,
		},
		{
			name: "valid permissive verification level",
			policy: policy.Policy{
				Sections: policy.Sections{
					Notation: &policy.NotationPolicy{
						VerificationLevel: "permissive",
						TrustStores: []policy.NotationTrustStore{
							{
								Name:         testNotationStoreName,
								Type:         "ca",
								Certificates: []string{testNotationCertPath},
							},
						},
					},
				},
			},
			wantErr:     false,
			expectedErr: nil,
		},
	})
}

func TestPolicyValidateNotationMissingPolicy(t *testing.T) {
	t.Parallel()

	runValidateTests(t, []validateTest{
		{
			name: "notation invalid missing policy",
			policy: policy.Policy{
				Sections: policy.Sections{
					Notation: &policy.NotationPolicy{
						MissingPolicy: testInvalidValue,
					},
				},
			},
			wantErr:     true,
			expectedErr: types.ErrInvalidAction,
		},
	})
}

func TestPolicyValidateNotationRuntime(t *testing.T) {
	t.Parallel()

	t.Run("valid cert file", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		certPath := filepath.Join(dir, "ca.pem")

		err := os.WriteFile(certPath, []byte("PEM DATA"), 0o600)
		if err != nil {
			t.Fatalf("writing cert: %v", err)
		}

		pol := &policy.Policy{
			Sections: policy.Sections{
				Notation: &policy.NotationPolicy{
					TrustStores: []policy.NotationTrustStore{
						{
							Name:         testNotationStoreName,
							Type:         "ca",
							Certificates: []string{certPath},
						},
					},
				},
			},
		}

		err = pol.ValidateRuntime()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("missing cert file", func(t *testing.T) {
		t.Parallel()

		pol := &policy.Policy{
			Sections: policy.Sections{
				Notation: &policy.NotationPolicy{
					TrustStores: []policy.NotationTrustStore{
						{
							Name:         testNotationStoreName,
							Type:         "ca",
							Certificates: []string{"/nonexistent/cert.pem"},
						},
					},
				},
			},
		}

		err := pol.ValidateRuntime()
		if err == nil {
			t.Fatal("expected error, got nil")
		}

		if !errors.Is(err, os.ErrNotExist) {
			t.Errorf("expected os.ErrNotExist, got: %v", err)
		}
	})
}

func TestApplyRuleNotation(t *testing.T) {
	t.Parallel()

	base := &policy.Policy{
		Sections: policy.Sections{
			Notation: &policy.NotationPolicy{
				MissingPolicy: types.ActionAllow,
			},
		},
	}

	rule := &policy.ImageRule{
		Images: []string{testRuleImagesGlob},
		Sections: policy.Sections{
			Notation: &policy.NotationPolicy{
				MissingPolicy:     types.ActionDeny,
				VerificationLevel: testNotationLevelStrict,
				TrustStores: []policy.NotationTrustStore{
					{
						Name:         testNotationStoreName,
						Type:         "ca",
						Certificates: []string{testNotationCertPath},
					},
				},
			},
		},
	}

	resolved := policy.ApplyRule(base, rule)

	if resolved.NotationMissingPolicy() != types.ActionDeny {
		t.Errorf(
			"expected rule Notation deny, got %v",
			resolved.NotationMissingPolicy(),
		)
	}
}

func TestPolicyValidateCELValid(t *testing.T) {
	t.Parallel()

	pol := &policy.Policy{
		Sections: policy.Sections{
			CEL: &celengine.Policy{
				Rules: []celengine.Rule{
					{
						Match:   "image.registry == 'ghcr.io'",
						Require: testCELExprSLSAVerified,
						Message: "GHCR images must have SLSA",
					},
				},
			},
		},
	}

	testutil.AssertNoError(t, pol.Validate())

	if pol.CompiledCEL == nil {
		t.Error("expected CompiledCEL to be populated after validation")
	}
}

func TestPolicyValidateCELSyntaxError(t *testing.T) {
	t.Parallel()

	pol := &policy.Policy{
		Sections: policy.Sections{
			CEL: &celengine.Policy{
				Rules: []celengine.Rule{
					{Require: "invalid +++"},
				},
			},
		},
	}

	err := pol.Validate()
	if !errors.Is(err, policy.ErrCELCompileFailed) {
		t.Errorf("expected ErrCELCompileFailed, got %v", err)
	}
}

func TestPolicyValidateCELNilSection(t *testing.T) {
	t.Parallel()

	pol := &policy.Policy{}

	testutil.AssertNoError(t, pol.Validate())

	if pol.CompiledCEL != nil {
		t.Error("expected CompiledCEL to be nil when no CEL section")
	}
}

func TestPolicyValidateCELEmptyRules(t *testing.T) {
	t.Parallel()

	pol := &policy.Policy{
		Sections: policy.Sections{
			CEL: &celengine.Policy{
				Rules: nil,
			},
		},
	}

	testutil.AssertNoError(t, pol.Validate())

	if pol.CompiledCEL != nil {
		t.Error("expected CompiledCEL to be nil with empty rules")
	}
}

func TestCloneSectionsCEL(t *testing.T) {
	t.Parallel()

	original := &policy.Policy{
		Sections: policy.Sections{
			CEL: &celengine.Policy{
				Rules: []celengine.Rule{
					{Require: testCELExprTrue, Message: "original"},
				},
			},
		},
	}

	clone := policy.MergeWithDefault(&policy.Policy{}, original)

	if clone.CEL == nil {
		t.Fatal("expected CEL to be cloned")
	}

	if len(clone.CEL.Rules) != 1 {
		t.Fatalf("expected 1 cloned rule, got %d", len(clone.CEL.Rules))
	}

	// Mutate clone and verify original is unaffected.
	clone.CEL.Rules[0].Message = "mutated"

	if original.CEL.Rules[0].Message != "original" {
		t.Error("clone mutation affected original CEL rules")
	}
}

func TestApplySectionsCELOverride(t *testing.T) {
	t.Parallel()

	base := &policy.Policy{
		Sections: policy.Sections{
			CEL: &celengine.Policy{
				Rules: []celengine.Rule{
					{Require: testCELExprTrue, Message: "base"},
				},
			},
			SLSA: &policy.SLSAPolicy{MissingPolicy: types.ActionAllow},
		},
	}

	rule := &policy.ImageRule{
		Images: []string{testRuleImagesGlob},
		Sections: policy.Sections{
			CEL: &celengine.Policy{
				Rules: []celengine.Rule{
					{Require: "false", Message: "override"},
				},
			},
		},
	}

	resolved := policy.ApplyRule(base, rule)

	if resolved.CEL == nil {
		t.Fatal("expected CEL section on resolved policy")
	}

	if resolved.CEL.Rules[0].Message != "override" {
		t.Errorf("expected override CEL rule, got %s", resolved.CEL.Rules[0].Message)
	}

	if resolved.SLSAMissingPolicy() != types.ActionAllow {
		t.Errorf("expected base SLSA to be preserved, got %v", resolved.SLSAMissingPolicy())
	}
}

func TestLoadPolicyWithCEL(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "default.json"), `{
		"cel": {
			"rules": [
				{
					"match": "image.registry == 'ghcr.io'",
					"require": "slsa.verified == true",
					"message": "GHCR images must have SLSA provenance"
				}
			]
		}
	}`)

	policies, err := policy.LoadAll(dir)
	testutil.AssertNoError(t, err)

	pol := policies[""]
	if pol.CEL == nil {
		t.Fatal("expected CEL section to be loaded")
	}

	if len(pol.CEL.Rules) != 1 {
		t.Fatalf("expected 1 CEL rule, got %d", len(pol.CEL.Rules))
	}

	if pol.CompiledCEL == nil {
		t.Error("expected CEL rules to be compiled during validation")
	}
}

func TestLoadPolicyWithCELInheritance(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "default.json"), `{
		"cel": {
			"rules": [
				{
					"require": "slsa.verified == true",
					"message": "default CEL rule"
				}
			]
		}
	}`)
	writeFile(t, filepath.Join(dir, "staging.json"), `{
		"inherits": true
	}`)

	policies, err := policy.LoadAll(dir)
	testutil.AssertNoError(t, err)

	staging := policies["staging"]
	if staging.CEL == nil {
		t.Fatal("expected CEL to be inherited")
	}

	if staging.CEL.Rules[0].Message != "default CEL rule" {
		t.Errorf("expected inherited CEL rule message, got %s", staging.CEL.Rules[0].Message)
	}

	if staging.CompiledCEL == nil {
		t.Error("expected CompiledCEL to be inherited from default")
	}
}

func TestApplyRulePreservesCompiledCEL(t *testing.T) {
	t.Parallel()

	base := &policy.Policy{
		Sections: policy.Sections{
			CEL: &celengine.Policy{
				Rules: []celengine.Rule{
					{Require: testCELExprSLSAVerified, Message: "base CEL"},
				},
			},
			SLSA: &policy.SLSAPolicy{MissingPolicy: types.ActionAllow},
		},
	}

	testutil.AssertNoError(t, base.Validate())

	if base.CompiledCEL == nil {
		t.Fatal("expected base CompiledCEL after validation")
	}

	// Rule without CEL should inherit base's CompiledCEL.
	rule := &policy.ImageRule{
		Images: []string{testRuleImagesGlob},
		Sections: policy.Sections{
			SLSA: &policy.SLSAPolicy{MissingPolicy: types.ActionDeny},
		},
	}

	resolved := policy.ApplyRule(base, rule)

	if resolved.CompiledCEL == nil {
		t.Error("expected CompiledCEL to be preserved from base when rule has no CEL")
	}

	if resolved.SLSAMissingPolicy() != types.ActionDeny {
		t.Errorf("expected SLSA deny from rule, got %v", resolved.SLSAMissingPolicy())
	}
}

func TestApplyRuleCELOverrideCompiledCEL(t *testing.T) {
	t.Parallel()

	base := &policy.Policy{
		Sections: policy.Sections{
			CEL: &celengine.Policy{
				Rules: []celengine.Rule{
					{Require: testCELExprTrue, Message: "base"},
				},
			},
		},
	}

	testutil.AssertNoError(t, base.Validate())

	// Rule with its own CEL should use its CompiledCEL.
	rulePol := &policy.Policy{
		Rules: []policy.ImageRule{
			{
				Images: []string{testRuleImagesGlob},
				Sections: policy.Sections{
					CEL: &celengine.Policy{
						Rules: []celengine.Rule{
							{Require: "false", Message: "rule override"},
						},
					},
				},
			},
		},
	}

	testutil.AssertNoError(t, rulePol.Validate())

	if rulePol.Rules[0].CompiledCEL == nil {
		t.Fatal("expected rule CompiledCEL after validation")
	}

	resolved := policy.ApplyRule(base, &rulePol.Rules[0])

	if resolved.CompiledCEL == nil {
		t.Fatal("expected CompiledCEL on resolved policy")
	}

	if resolved.CEL.Rules[0].Message != "rule override" {
		t.Errorf("expected rule CEL, got %s", resolved.CEL.Rules[0].Message)
	}
}

func TestPolicyValidateRuleCELSyntaxError(t *testing.T) {
	t.Parallel()

	pol := &policy.Policy{
		Rules: []policy.ImageRule{
			{
				Images: []string{testRuleImagesGlob},
				Sections: policy.Sections{
					CEL: &celengine.Policy{
						Rules: []celengine.Rule{
							{Require: "invalid +++"},
						},
					},
				},
			},
		},
	}

	err := pol.Validate()
	if !errors.Is(err, policy.ErrCELCompileFailed) {
		t.Errorf("expected ErrCELCompileFailed for rule CEL, got %v", err)
	}
}

func TestLoadPolicyWithCELOverride(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "default.json"), `{
		"cel": {
			"rules": [
				{
					"require": "true",
					"message": "default"
				}
			]
		}
	}`)
	writeFile(t, filepath.Join(dir, "production.json"), `{
		"inherits": true,
		"cel": {
			"rules": [
				{
					"require": "slsa.verified == true && vex.verified == true",
					"message": "production requires all checks"
				}
			]
		}
	}`)

	policies, err := policy.LoadAll(dir)
	testutil.AssertNoError(t, err)

	prod := policies["production"]
	if prod.CEL == nil {
		t.Fatal("expected CEL section on production policy")
	}

	if len(prod.CEL.Rules) != 1 {
		t.Fatalf("expected 1 CEL rule, got %d", len(prod.CEL.Rules))
	}

	if prod.CEL.Rules[0].Message != "production requires all checks" {
		t.Errorf("expected production CEL rule, got %s", prod.CEL.Rules[0].Message)
	}

	if prod.CompiledCEL == nil {
		t.Error("expected CompiledCEL to be set after CEL override")
	}
}

func TestCloneRulesPreservesCompiledCEL(t *testing.T) {
	t.Parallel()

	pol := &policy.Policy{
		Rules: []policy.ImageRule{
			{
				Images: []string{testRuleImagesGlob},
				Sections: policy.Sections{
					CEL: &celengine.Policy{
						Rules: []celengine.Rule{
							{Require: testCELExprSLSAVerified, Message: "rule CEL"},
						},
					},
				},
			},
		},
	}

	testutil.AssertNoError(t, pol.Validate())

	if pol.Rules[0].CompiledCEL == nil {
		t.Fatal("expected CompiledCEL on rule after validation")
	}

	// MergeWithDefault clones rules via cloneRules. The cloned rules
	// must preserve CompiledCEL so that per-rule CEL is not silently lost.
	defaultPol := &policy.Policy{
		Sections: policy.Sections{
			SLSA: &policy.SLSAPolicy{MissingPolicy: types.ActionAllow},
		},
	}

	nsPol := &policy.Policy{
		Rules: pol.Rules,
	}

	merged := policy.MergeWithDefault(nsPol, defaultPol)

	if len(merged.Rules) != 1 {
		t.Fatalf("expected 1 merged rule, got %d", len(merged.Rules))
	}

	if merged.Rules[0].CompiledCEL == nil {
		t.Error("expected CompiledCEL to be preserved after cloneRules")
	}
}

func TestInheritedRulesPreserveCompiledCEL(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "default.json"), `{
		"rules": [
			{
				"images": ["ghcr.io/**"],
				"cel": {
					"rules": [
						{
							"require": "slsa.verified == true",
							"message": "inherited rule CEL"
						}
					]
				}
			}
		]
	}`)
	writeFile(t, filepath.Join(dir, "staging.json"), `{
		"inherits": true
	}`)

	policies, err := policy.LoadAll(dir)
	testutil.AssertNoError(t, err)

	staging := policies["staging"]
	if len(staging.Rules) != 1 {
		t.Fatalf("expected 1 inherited rule, got %d", len(staging.Rules))
	}

	if staging.Rules[0].CompiledCEL == nil {
		t.Error("expected CompiledCEL to be preserved on inherited rule")
	}
}

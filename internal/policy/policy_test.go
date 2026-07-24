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

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	testBuilderID    = "test"
	testInvalidValue = "invalid"
	testVerifierID   = "https://example.com/v"
)

type validateTest struct {
	name        string
	policy      policy.Policy
	wantErr     bool
	expectedErr error
}

func runValidateTests(t *testing.T, tests []validateTest) {
	t.Helper()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := test.policy.Validate()
			if test.wantErr && err == nil {
				t.Error("expected error, got nil")
			}

			if !test.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if test.expectedErr != nil && !errors.Is(err, test.expectedErr) {
				t.Errorf("expected error %v, got %v", test.expectedErr, err)
			}
		})
	}
}

func emptyPolicy() policy.Policy {
	return policy.Policy{
		Trust: nil, Exclude: nil, SLSA: nil,
		VEX: nil, VSA: nil, Signatures: nil,
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
				Trust: &policy.TrustPolicy{
					Builders: []policy.TrustedBuilder{
						{ID: "https://github.com/actions/runner", MaxLevel: 3},
					},
					Verifiers: nil, Issuers: nil, Sources: nil, BuildTypes: nil,
				},
				Exclude: nil, SLSA: nil, VEX: nil, VSA: nil, Signatures: nil,
			},
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name: "builder without ID",
			policy: policy.Policy{
				Trust: &policy.TrustPolicy{
					Builders:  []policy.TrustedBuilder{{ID: "", MaxLevel: 2}},
					Verifiers: nil, Issuers: nil, Sources: nil, BuildTypes: nil,
				},
				Exclude: nil, SLSA: nil, VEX: nil, VSA: nil, Signatures: nil,
			},
			wantErr:     true,
			expectedErr: policy.ErrBuilderIDRequired,
		},
		{
			name: "builder with invalid max level",
			policy: policy.Policy{
				Trust: &policy.TrustPolicy{
					Builders: []policy.TrustedBuilder{
						{ID: testBuilderID, MaxLevel: 5},
					},
					Verifiers: nil, Issuers: nil, Sources: nil, BuildTypes: nil,
				},
				Exclude: nil, SLSA: nil, VEX: nil, VSA: nil, Signatures: nil,
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
				Trust: &policy.TrustPolicy{
					Builders: nil,
					Verifiers: []policy.TrustedVerifier{
						{ID: testBuilderID, Key: ""},
					},
					Issuers: nil, Sources: nil, BuildTypes: nil,
				},
				Exclude: nil, SLSA: nil, VEX: nil, VSA: nil, Signatures: nil,
			},
			wantErr:     true,
			expectedErr: policy.ErrKeylessVerifierRequiresIssuers,
		},
		{
			name: "keyless verifier with issuers",
			policy: policy.Policy{
				Trust: &policy.TrustPolicy{
					Builders: nil,
					Verifiers: []policy.TrustedVerifier{
						{ID: testBuilderID},
					},
					Issuers: []string{"https://token.actions.githubusercontent.com"},
					Sources: nil, BuildTypes: nil,
				},
				Exclude: nil, SLSA: nil, VEX: nil, VSA: nil, Signatures: nil,
			},
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name: "verifier with relative key path",
			policy: policy.Policy{
				Trust: &policy.TrustPolicy{
					Builders: nil,
					Verifiers: []policy.TrustedVerifier{
						{ID: testBuilderID, Key: "relative/path.pub"},
					},
					Issuers: nil, Sources: nil, BuildTypes: nil,
				},
				Exclude: nil, SLSA: nil, VEX: nil, VSA: nil, Signatures: nil,
			},
			wantErr:     true,
			expectedErr: policy.ErrVerifierKeyNotAbsolute,
		},
		{
			name: "valid verifier with key",
			policy: policy.Policy{
				Trust: &policy.TrustPolicy{
					Builders: nil,
					Verifiers: []policy.TrustedVerifier{
						{ID: testBuilderID, Key: "/etc/keys/verifier.pub"},
					},
					Issuers: nil, Sources: nil, BuildTypes: nil,
				},
				Exclude: nil, SLSA: nil, VEX: nil, VSA: nil, Signatures: nil,
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
				Trust: nil, Exclude: []string{"gcr.io/org/*"}, SLSA: nil,
				VEX: nil, VSA: nil, Signatures: nil,
			},
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name: "valid exclude pattern double star",
			policy: policy.Policy{
				Trust: nil, Exclude: []string{"registry.k8s.io/**"}, SLSA: nil,
				VEX: nil, VSA: nil, Signatures: nil,
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
				Trust: nil, Exclude: nil,
				SLSA: &policy.SLSAPolicy{
					MissingPolicy: testInvalidValue, RejectUnknownParameters: false,
				},
				VEX: nil, VSA: nil, Signatures: nil,
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
				Trust: nil, Exclude: nil, SLSA: nil,
				VEX: &policy.VEXPolicy{
					MissingPolicy:            types.ActionWarn,
					UnderInvestigationPolicy: types.ActionAllow,
				},
				VSA: nil, Signatures: nil,
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
				Trust: nil, Exclude: nil, SLSA: nil, VEX: nil,
				VSA:        &policy.VSAPolicy{MinimumLevel: 5, MaxAge: "", Policy: ""},
				Signatures: nil,
			},
			wantErr:     true,
			expectedErr: policy.ErrVSAMinimumLevel,
		},
		{
			name: "invalid VSA max age",
			policy: policy.Policy{
				Trust: nil, Exclude: nil, SLSA: nil, VEX: nil,
				VSA: &policy.VSAPolicy{
					MinimumLevel: 0, MaxAge: "not-a-duration", Policy: "",
				},
				Signatures: nil,
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
			name: "empty missing policy defaults to allow",
			policy: policy.Policy{
				Trust: nil, Exclude: nil,
				SLSA: &policy.SLSAPolicy{
					MissingPolicy: "", RejectUnknownParameters: false,
				},
				VEX: nil, VSA: nil, Signatures: nil,
			},
			expected: types.ActionAllow,
		},
		{
			name: "explicit deny",
			policy: policy.Policy{
				Trust: nil, Exclude: nil,
				SLSA: &policy.SLSAPolicy{
					MissingPolicy: types.ActionDeny, RejectUnknownParameters: false,
				},
				VEX: nil, VSA: nil, Signatures: nil,
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
			name: "empty missing policy defaults to allow",
			policy: policy.Policy{
				Trust: nil, Exclude: nil, SLSA: nil,
				VEX: &policy.VEXPolicy{
					MissingPolicy:            "",
					UnderInvestigationPolicy: "",
				},
				VSA: nil, Signatures: nil,
			},
			expected: types.ActionAllow,
		},
		{
			name: "explicit deny",
			policy: policy.Policy{
				Trust: nil, Exclude: nil, SLSA: nil,
				VEX: &policy.VEXPolicy{
					MissingPolicy:            types.ActionDeny,
					UnderInvestigationPolicy: "",
				},
				VSA: nil, Signatures: nil,
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
				Trust: &policy.TrustPolicy{
					Builders: nil,
					Verifiers: []policy.TrustedVerifier{
						{ID: "", Key: "/etc/keys/verifier.pub"},
					},
					Issuers: nil, Sources: nil, BuildTypes: nil,
				},
				Exclude: nil, SLSA: nil, VEX: nil, VSA: nil, Signatures: nil,
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
				Trust: nil, Exclude: nil, SLSA: nil,
				VEX: &policy.VEXPolicy{
					MissingPolicy:            testInvalidValue,
					UnderInvestigationPolicy: "",
				},
				VSA: nil, Signatures: nil,
			},
			wantErr:     true,
			expectedErr: types.ErrInvalidAction,
		},
		{
			name: "invalid VEX under investigation policy",
			policy: policy.Policy{
				Trust: nil, Exclude: nil, SLSA: nil,
				VEX: &policy.VEXPolicy{
					MissingPolicy:            "",
					UnderInvestigationPolicy: testInvalidValue,
				},
				VSA: nil, Signatures: nil,
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
				Trust: nil, Exclude: nil, SLSA: nil, VEX: nil,
				VSA: &policy.VSAPolicy{
					MinimumLevel: 2, MaxAge: "168h", Policy: "https://example.com/policy",
				},
				Signatures: nil,
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
		Exclude: []string{"gcr.io/default/*"},
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
			MinimumLevel:   2,
			MaxAge:         "",
			MaxAgeDuration: 0,
			Policy:         "",
		},
		Signatures: &policy.SignaturesPolicy{
			RequireTransparencyLog: true,
		},
	}
}

func mergedEmptyNamespace() *policy.Policy {
	nsPol := &policy.Policy{
		Inherits: nil, Trust: nil, Exclude: nil, SLSA: nil,
		VEX: nil, VSA: nil, Signatures: nil,
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
		Inherits: nil, Trust: nsTrust, Exclude: nil,
		SLSA: nil, VEX: nil, VSA: nil, Signatures: nil,
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

func TestMergeWithDefaultExcludeOverride(t *testing.T) {
	t.Parallel()

	nsPol := &policy.Policy{
		Inherits: nil, Trust: nil,
		Exclude: []string{"ns-exclude/*"},
		SLSA:    nil, VEX: nil, VSA: nil, Signatures: nil,
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
		Inherits: nil, Trust: nil, Exclude: nil,
		SLSA: &policy.SLSAPolicy{
			MissingPolicy:           types.ActionAllow,
			RejectUnknownParameters: false,
			KnownParameters:         nil,
		},
		VEX: nil, VSA: nil, Signatures: nil,
	}

	merged := policy.MergeWithDefault(nsPol, defaultTestPolicy())

	if merged.SLSA.MissingPolicy != types.ActionAllow {
		t.Error("expected namespace SLSA to override default")
	}
}

func TestMergeWithDefaultVEXOverride(t *testing.T) {
	t.Parallel()

	nsPol := &policy.Policy{
		Inherits: nil, Trust: nil, Exclude: nil, SLSA: nil,
		VEX: &policy.VEXPolicy{
			MissingPolicy:            types.ActionDeny,
			UnderInvestigationPolicy: "",
		},
		VSA: nil, Signatures: nil,
	}

	merged := policy.MergeWithDefault(nsPol, defaultTestPolicy())

	if merged.VEX.MissingPolicy != types.ActionDeny {
		t.Error("expected namespace VEX to override default")
	}
}

func TestMergeWithDefaultVSAOverride(t *testing.T) {
	t.Parallel()

	nsPol := &policy.Policy{
		Inherits: nil, Trust: nil, Exclude: nil, SLSA: nil,
		VEX: nil,
		VSA: &policy.VSAPolicy{
			MinimumLevel:   1,
			MaxAge:         "",
			MaxAgeDuration: 0,
			Policy:         "",
		},
		Signatures: nil,
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
		Inherits: nil, Trust: nil, Exclude: nil, SLSA: nil,
		VEX:        nil,
		VSA:        nil,
		Signatures: &policy.SignaturesPolicy{RequireTransparencyLog: false},
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
		Trust: &policy.TrustPolicy{
			Issuers: []string{"https://accounts.google.com"},
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
		Trust: &policy.TrustPolicy{
			Issuers:     []string{"https://accounts.google.com"},
			SANPatterns: []string{"build@example.com"},
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
		Trust: &policy.TrustPolicy{},
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
			Trust: &policy.TrustPolicy{
				Verifiers: []policy.TrustedVerifier{
					{ID: testVerifierID, Key: keyPath},
				},
			},
		}

		err := pol.ValidateRuntime()
		testutil.AssertNoError(t, err)
	})

	t.Run("nonexistent key path fails", func(t *testing.T) {
		t.Parallel()

		pol := &policy.Policy{
			Trust: &policy.TrustPolicy{
				Verifiers: []policy.TrustedVerifier{
					{ID: testVerifierID, Key: "/nonexistent/key.pub"},
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
			Trust: &policy.TrustPolicy{
				Verifiers: []policy.TrustedVerifier{
					{ID: testVerifierID, Key: dir},
				},
			},
		}

		err := pol.ValidateRuntime()
		testutil.AssertError(t, err)

		if !errors.Is(err, policy.ErrNotRegularFile) {
			t.Errorf("expected ErrNotRegularFile, got %v", err)
		}
	})
}

func TestHash(t *testing.T) {
	t.Parallel()

	t.Run("identical policies produce same hash", func(t *testing.T) {
		t.Parallel()

		pol1 := &policy.Policy{
			SLSA: &policy.SLSAPolicy{
				MissingPolicy: types.ActionDeny,
			},
		}
		pol2 := &policy.Policy{
			SLSA: &policy.SLSAPolicy{
				MissingPolicy: types.ActionDeny,
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
			SLSA: &policy.SLSAPolicy{
				MissingPolicy: types.ActionDeny,
			},
		}
		pol2 := &policy.Policy{
			SLSA: &policy.SLSAPolicy{
				MissingPolicy: types.ActionAllow,
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
			Trust: &policy.TrustPolicy{
				Builders: []policy.TrustedBuilder{
					{ID: "https://example.com/builder", MaxLevel: 3},
				},
			},
			SLSA: &policy.SLSAPolicy{
				MissingPolicy: types.ActionWarn,
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

func TestInitDerivedInvalidMaxAge(t *testing.T) {
	t.Parallel()

	pol := &policy.Policy{
		VSA: &policy.VSAPolicy{
			MaxAge: "not-a-duration",
		},
	}

	pol.ExportInitDerived()

	if pol.VSA.MaxAgeDuration != 0 {
		t.Errorf("expected MaxAgeDuration=0 for invalid MaxAge, got %v", pol.VSA.MaxAgeDuration)
	}
}

func TestInitDerivedValidMaxAge(t *testing.T) {
	t.Parallel()

	pol := &policy.Policy{
		VSA: &policy.VSAPolicy{
			MaxAge: "24h",
		},
	}

	pol.ExportInitDerived()

	if pol.VSA.MaxAgeDuration != 24*time.Hour {
		t.Errorf("expected MaxAgeDuration=24h, got %v", pol.VSA.MaxAgeDuration)
	}
}

func TestInitDerivedOverwritesPrevious(t *testing.T) {
	t.Parallel()

	pol := &policy.Policy{
		VSA: &policy.VSAPolicy{
			MaxAge:         "1h",
			MaxAgeDuration: 48 * time.Hour,
		},
	}

	pol.ExportInitDerived()

	if pol.VSA.MaxAgeDuration != time.Hour {
		t.Errorf("expected MaxAgeDuration=1h (from MaxAge), got %v", pol.VSA.MaxAgeDuration)
	}
}

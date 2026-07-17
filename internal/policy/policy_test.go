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

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
)

const (
	testBuilderID    = "test"
	testInvalidValue = "invalid"
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
		Trust: nil, Exclude: nil, Provenance: nil,
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
				Exclude: nil, Provenance: nil, VEX: nil, VSA: nil, Signatures: nil,
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
				Exclude: nil, Provenance: nil, VEX: nil, VSA: nil, Signatures: nil,
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
				Exclude: nil, Provenance: nil, VEX: nil, VSA: nil, Signatures: nil,
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
			name: "verifier without key",
			policy: policy.Policy{
				Trust: &policy.TrustPolicy{
					Builders: nil,
					Verifiers: []policy.TrustedVerifier{
						{ID: testBuilderID, Key: ""},
					},
					Issuers: nil, Sources: nil, BuildTypes: nil,
				},
				Exclude: nil, Provenance: nil, VEX: nil, VSA: nil, Signatures: nil,
			},
			wantErr:     true,
			expectedErr: policy.ErrVerifierKeyRequired,
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
				Exclude: nil, Provenance: nil, VEX: nil, VSA: nil, Signatures: nil,
			},
			wantErr:     true,
			expectedErr: policy.ErrVerifierKeyNotAbsolute,
		},
		{
			name: "valid verifier",
			policy: policy.Policy{
				Trust: &policy.TrustPolicy{
					Builders: nil,
					Verifiers: []policy.TrustedVerifier{
						{ID: testBuilderID, Key: "/etc/keys/verifier.pub"},
					},
					Issuers: nil, Sources: nil, BuildTypes: nil,
				},
				Exclude: nil, Provenance: nil, VEX: nil, VSA: nil, Signatures: nil,
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
			name: "invalid exclude pattern",
			policy: policy.Policy{
				Trust: nil, Exclude: []string{"[invalid"}, Provenance: nil,
				VEX: nil, VSA: nil, Signatures: nil,
			},
			wantErr:     true,
			expectedErr: nil,
		},
		{
			name: "valid exclude pattern",
			policy: policy.Policy{
				Trust: nil, Exclude: []string{"gcr.io/org/*"}, Provenance: nil,
				VEX: nil, VSA: nil, Signatures: nil,
			},
			wantErr:     false,
			expectedErr: nil,
		},
	})
}

func TestPolicyValidateProvenance(t *testing.T) {
	t.Parallel()

	runValidateTests(t, []validateTest{
		{
			name: "invalid provenance missing policy",
			policy: policy.Policy{
				Trust: nil, Exclude: nil,
				Provenance: &policy.ProvenancePolicy{
					MissingPolicy: testInvalidValue, RejectUnknownParameters: false,
				},
				VEX: nil, VSA: nil, Signatures: nil,
			},
			wantErr:     true,
			expectedErr: policy.ErrInvalidAction,
		},
	})
}

func TestPolicyValidateVEX(t *testing.T) {
	t.Parallel()

	runValidateTests(t, []validateTest{
		{
			name: "valid VEX config",
			policy: policy.Policy{
				Trust: nil, Exclude: nil, Provenance: nil,
				VEX: &policy.VEXPolicy{
					MissingPolicy:            policy.ActionWarn,
					UnderInvestigationPolicy: policy.ActionAllow,
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
				Trust: nil, Exclude: nil, Provenance: nil, VEX: nil,
				VSA:        &policy.VSAPolicy{MinimumLevel: 5, MaxAge: "", Policy: ""},
				Signatures: nil,
			},
			wantErr:     true,
			expectedErr: policy.ErrVSAMinimumLevel,
		},
		{
			name: "invalid VSA max age",
			policy: policy.Policy{
				Trust: nil, Exclude: nil, Provenance: nil, VEX: nil,
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

func TestProvenanceMissingPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		policy   policy.Policy
		expected string
	}{
		{
			name:     "nil provenance defaults to allow",
			policy:   emptyPolicy(),
			expected: policy.ActionAllow,
		},
		{
			name: "empty missing policy defaults to allow",
			policy: policy.Policy{
				Trust: nil, Exclude: nil,
				Provenance: &policy.ProvenancePolicy{
					MissingPolicy: "", RejectUnknownParameters: false,
				},
				VEX: nil, VSA: nil, Signatures: nil,
			},
			expected: policy.ActionAllow,
		},
		{
			name: "explicit deny",
			policy: policy.Policy{
				Trust: nil, Exclude: nil,
				Provenance: &policy.ProvenancePolicy{
					MissingPolicy: policy.ActionDeny, RejectUnknownParameters: false,
				},
				VEX: nil, VSA: nil, Signatures: nil,
			},
			expected: policy.ActionDeny,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := test.policy.ProvenanceMissingPolicy(); got != test.expected {
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
		"provenance": {"missingPolicy": "warn"}
	}`
	writeFile(t, policyPath, content)

	pol, err := policy.Load(policyPath)
	assertNoError(t, err)

	if len(pol.Builders()) != 1 {
		t.Fatalf("expected 1 builder, got %d", len(pol.Builders()))
	}

	if pol.Builders()[0].ID != "https://example.com/builder" {
		t.Errorf("unexpected builder ID: %s", pol.Builders()[0].ID)
	}

	if pol.ProvenanceMissingPolicy() != policy.ActionWarn {
		t.Errorf("expected warn, got %s", pol.ProvenanceMissingPolicy())
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
		assertError(t, err)
	})

	t.Run("trailing content rejected", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		policyPath := filepath.Join(dir, "test.json")

		writeFile(t, policyPath, `{}{}`)

		_, err := policy.Load(policyPath)
		assertError(t, err)

		if !errors.Is(err, policy.ErrTrailingContent) {
			t.Errorf("expected error %v, got %v", policy.ErrTrailingContent, err)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		t.Parallel()

		_, err := policy.Load("/nonexistent/policy.json")
		assertError(t, err)
	})
}

func TestLoadAllNamespaces(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "default.json"),
		`{"provenance":{"missingPolicy":"allow"}}`)
	writeFile(t, filepath.Join(dir, "production.json"),
		`{"provenance":{"missingPolicy":"deny"}}`)

	policies, err := policy.LoadAll(dir)
	assertNoError(t, err)

	if len(policies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(policies))
	}

	defaultPolicy, found := policies[""]
	if !found {
		t.Fatal("expected default policy")
	}

	if defaultPolicy.ProvenanceMissingPolicy() != policy.ActionAllow {
		t.Errorf(
			"expected allow, got %s", defaultPolicy.ProvenanceMissingPolicy(),
		)
	}

	prodPolicy, found := policies["production"]
	if !found {
		t.Fatal("expected production policy")
	}

	if prodPolicy.ProvenanceMissingPolicy() != policy.ActionDeny {
		t.Errorf(
			"expected deny, got %s", prodPolicy.ProvenanceMissingPolicy(),
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
				Exclude: nil, Provenance: nil, VEX: nil, VSA: nil, Signatures: nil,
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
				Trust: nil, Exclude: nil, Provenance: nil,
				VEX: &policy.VEXPolicy{
					MissingPolicy:            testInvalidValue,
					UnderInvestigationPolicy: "",
				},
				VSA: nil, Signatures: nil,
			},
			wantErr:     true,
			expectedErr: policy.ErrInvalidAction,
		},
		{
			name: "invalid VEX under investigation policy",
			policy: policy.Policy{
				Trust: nil, Exclude: nil, Provenance: nil,
				VEX: &policy.VEXPolicy{
					MissingPolicy:            "",
					UnderInvestigationPolicy: testInvalidValue,
				},
				VSA: nil, Signatures: nil,
			},
			wantErr:     true,
			expectedErr: policy.ErrInvalidAction,
		},
	})
}

func TestPolicyValidateVSAValid(t *testing.T) {
	t.Parallel()

	runValidateTests(t, []validateTest{
		{
			name: "valid VSA",
			policy: policy.Policy{
				Trust: nil, Exclude: nil, Provenance: nil, VEX: nil,
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
	assertNoError(t, os.MkdirAll(subDir, 0o750))

	policies, err := policy.LoadAll(dir)
	assertNoError(t, err)

	if len(policies) != 1 {
		t.Errorf("expected 1 policy, got %d", len(policies))
	}
}

func TestLoadAllInvalidPolicy(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "bad.json"), `{invalid json}`)

	_, err := policy.LoadAll(dir)
	assertError(t, err)
}

func TestLoadPolicyValidationError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	policyPath := filepath.Join(dir, "test.json")

	writeFile(t, policyPath, `{"trust":{"builders":[{"id":"","maxLevel":0}]}}`)

	_, err := policy.Load(policyPath)
	assertError(t, err)

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
		assertNoError(t, err)

		if len(policies) != 0 {
			t.Errorf("expected 0 policies, got %d", len(policies))
		}
	})

	t.Run("nonexistent directory returns empty", func(t *testing.T) {
		t.Parallel()

		policies, err := policy.LoadAll("/nonexistent/dir")
		assertNoError(t, err)

		if len(policies) != 0 {
			t.Errorf("expected 0 policies, got %d", len(policies))
		}
	})

	t.Run("empty string returns empty", func(t *testing.T) {
		t.Parallel()

		policies, err := policy.LoadAll("")
		assertNoError(t, err)

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
		Provenance: &policy.ProvenancePolicy{
			MissingPolicy:           policy.ActionDeny,
			RejectUnknownParameters: false,
			KnownParameters:         nil,
		},
		VEX: &policy.VEXPolicy{
			MissingPolicy:            policy.ActionWarn,
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
		Inherits: nil, Trust: nil, Exclude: nil, Provenance: nil,
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

func TestMergeWithDefaultInheritsProvenance(t *testing.T) {
	t.Parallel()

	merged := mergedEmptyNamespace()
	if merged.Provenance == nil ||
		merged.Provenance.MissingPolicy != policy.ActionDeny {
		t.Error("expected default Provenance to be inherited")
	}
}

func TestMergeWithDefaultInheritsVEX(t *testing.T) {
	t.Parallel()

	merged := mergedEmptyNamespace()
	if merged.VEX == nil ||
		merged.VEX.MissingPolicy != policy.ActionWarn {
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
		Provenance: nil, VEX: nil, VSA: nil, Signatures: nil,
	}

	merged := policy.MergeWithDefault(nsPol, defaultTestPolicy())

	if merged.Trust.Builders[0].ID != "ns-builder" {
		t.Errorf("expected ns-builder, got %s",
			merged.Trust.Builders[0].ID)
	}

	if merged.Provenance.MissingPolicy != policy.ActionDeny {
		t.Error("expected default Provenance to be preserved")
	}
}

func TestMergeWithDefaultExcludeOverride(t *testing.T) {
	t.Parallel()

	nsPol := &policy.Policy{
		Inherits: nil, Trust: nil,
		Exclude:    []string{"ns-exclude/*"},
		Provenance: nil, VEX: nil, VSA: nil, Signatures: nil,
	}

	merged := policy.MergeWithDefault(nsPol, defaultTestPolicy())

	if len(merged.Exclude) != 1 ||
		merged.Exclude[0] != "ns-exclude/*" {
		t.Error("expected namespace Exclude to override default")
	}
}

func TestMergeWithDefaultProvenanceOverride(t *testing.T) {
	t.Parallel()

	nsPol := &policy.Policy{
		Inherits: nil, Trust: nil, Exclude: nil,
		Provenance: &policy.ProvenancePolicy{
			MissingPolicy:           policy.ActionAllow,
			RejectUnknownParameters: false,
			KnownParameters:         nil,
		},
		VEX: nil, VSA: nil, Signatures: nil,
	}

	merged := policy.MergeWithDefault(nsPol, defaultTestPolicy())

	if merged.Provenance.MissingPolicy != policy.ActionAllow {
		t.Error("expected namespace Provenance to override default")
	}
}

func TestMergeWithDefaultVEXOverride(t *testing.T) {
	t.Parallel()

	nsPol := &policy.Policy{
		Inherits: nil, Trust: nil, Exclude: nil, Provenance: nil,
		VEX: &policy.VEXPolicy{
			MissingPolicy:            policy.ActionDeny,
			UnderInvestigationPolicy: "",
		},
		VSA: nil, Signatures: nil,
	}

	merged := policy.MergeWithDefault(nsPol, defaultTestPolicy())

	if merged.VEX.MissingPolicy != policy.ActionDeny {
		t.Error("expected namespace VEX to override default")
	}
}

func TestMergeWithDefaultVSAOverride(t *testing.T) {
	t.Parallel()

	nsPol := &policy.Policy{
		Inherits: nil, Trust: nil, Exclude: nil, Provenance: nil,
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
		Inherits: nil, Trust: nil, Exclude: nil, Provenance: nil,
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
		"provenance": {"missingPolicy": "deny"},
		"exclude": ["default-exclude/*"]
	}`)
	writeFile(t, filepath.Join(dir, "staging.json"), `{
		"inherits": true,
		"provenance": {"missingPolicy": "allow"}
	}`)

	policies, err := policy.LoadAll(dir)
	assertNoError(t, err)

	staging := policies["staging"]
	if staging.ProvenanceMissingPolicy() != policy.ActionAllow {
		t.Errorf("expected allow (overridden), got %s",
			staging.ProvenanceMissingPolicy())
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
	assertNoError(t, err)

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
	assertNoError(t, err)

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

func assertNoError(t *testing.T, err error) {
	t.Helper()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func assertError(t *testing.T, err error) {
	t.Helper()

	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

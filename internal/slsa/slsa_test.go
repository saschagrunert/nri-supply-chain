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

package slsa_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/slsa"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
	"github.com/saschagrunert/nri-supply-chain/policy"
)

const (
	testDigest      = "sha256:abc123def456"
	testDigestHash  = "abc123def456"
	testDigestAlgo  = "sha256"
	testBuilderID   = "https://github.com/actions/runner"
	testBuildType   = "https://actions.github.io/buildtypes/workflow/v1"
	testSource      = "github.com/example/repo"
	testWorkflow    = ".github/workflows/release.yml"
	testSourceGlob  = "github.com/example/*"
	testKeySource   = "source"
	testKeyWorkflow = "workflow"
	testPlaceholder = "test"
)

func validStatement() slsa.Statement {
	return slsa.Statement{
		Type: "https://in-toto.io/Statement/v1",
		Subject: []slsa.Subject{
			{
				Name:   "nginx",
				Digest: map[string]string{testDigestAlgo: testDigestHash},
			},
		},
		PredicateType: attestation.PredicateSLSAProvenanceV1,
		Predicate: slsa.ProvenancePredicate{
			BuildDefinition: slsa.BuildDefinition{
				BuildType: testBuildType,
				ExternalParameters: map[string]any{
					testKeySource:   testSource,
					testKeyWorkflow: testWorkflow,
				},
				InternalParameters: map[string]any{},
			},
			RunDetails: slsa.RunDetails{
				Builder: slsa.Builder{
					ID: testBuilderID,
				},
				Metadata: slsa.Metadata{
					InvocationID: "run-123",
				},
			},
		},
	}
}

func mustMarshal(t *testing.T, val any) []byte {
	t.Helper()

	data, err := json.Marshal(val)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}

	return data
}

func assertNoError(t *testing.T, err error) {
	t.Helper()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerify(t *testing.T) { //nolint:funlen,maintidx // Table-driven test.
	t.Parallel()

	tests := []struct {
		name       string
		data       func(t *testing.T) []byte
		policy     *policy.Policy
		digest     string
		wantErr    error
		wantPass   bool
		wantType   string
		wantStatus string
	}{
		{
			name: "valid statement",
			data: func(t *testing.T) []byte {
				t.Helper()

				return mustMarshal(t, validStatement())
			},
			policy: &policy.Policy{
				Trust: &policy.TrustPolicy{
					Builders: []policy.TrustedBuilder{
						{ID: testBuilderID, MaxLevel: 2},
					},
				},
			},
			digest:     testDigest,
			wantErr:    nil,
			wantPass:   true,
			wantType:   "slsa_provenance",
			wantStatus: types.StatusPass,
		},
		{
			name: "v0.2 predicate rejected",
			data: func(t *testing.T) []byte {
				t.Helper()

				stmt := validStatement()
				stmt.PredicateType = "https://slsa.dev/provenance/v0.2"

				return mustMarshal(t, stmt)
			},
			policy: &policy.Policy{
				Trust: &policy.TrustPolicy{
					Builders: []policy.TrustedBuilder{
						{ID: testBuilderID, MaxLevel: 2},
					},
				},
			},
			digest:     testDigest,
			wantErr:    slsa.ErrInvalidProvenance,
			wantPass:   false,
			wantType:   "",
			wantStatus: "",
		},
		{
			name: "invalid JSON",
			data: func(_ *testing.T) []byte {
				return []byte("not json")
			},
			policy:     &policy.Policy{},
			digest:     testDigest,
			wantErr:    slsa.ErrInvalidProvenance,
			wantPass:   false,
			wantType:   "",
			wantStatus: "",
		},
		{
			name: "invalid predicate type",
			data: func(t *testing.T) []byte {
				t.Helper()

				stmt := validStatement()
				stmt.PredicateType = "https://example.com/other"

				return mustMarshal(t, stmt)
			},
			policy:     &policy.Policy{},
			digest:     testDigest,
			wantErr:    slsa.ErrInvalidProvenance,
			wantPass:   false,
			wantType:   "",
			wantStatus: "",
		},
		{
			name: "subject digest mismatch",
			data: func(t *testing.T) []byte {
				t.Helper()

				return mustMarshal(t, validStatement())
			},
			policy:     &policy.Policy{},
			digest:     "sha256:different",
			wantErr:    nil,
			wantPass:   false,
			wantType:   "",
			wantStatus: types.StatusFail,
		},
		{
			name: "invalid digest format",
			data: func(t *testing.T) []byte {
				t.Helper()

				return mustMarshal(t, validStatement())
			},
			policy:     &policy.Policy{},
			digest:     "nocolon",
			wantErr:    nil,
			wantPass:   false,
			wantType:   "",
			wantStatus: types.StatusFail,
		},
		{
			name: "untrusted builder",
			data: func(t *testing.T) []byte {
				t.Helper()

				return mustMarshal(t, validStatement())
			},
			policy: &policy.Policy{
				Trust: &policy.TrustPolicy{
					Builders: []policy.TrustedBuilder{
						{ID: "https://other-builder.example.com", MaxLevel: 3},
					},
				},
			},
			digest:     testDigest,
			wantErr:    nil,
			wantPass:   false,
			wantType:   "",
			wantStatus: types.StatusFail,
		},
		{
			name: "no builders configured",
			data: func(t *testing.T) []byte {
				t.Helper()

				return mustMarshal(t, validStatement())
			},
			policy:     &policy.Policy{},
			digest:     testDigest,
			wantErr:    nil,
			wantPass:   true,
			wantType:   "",
			wantStatus: types.StatusPass,
		},
		{
			name: "untrusted build type",
			data: func(t *testing.T) []byte {
				t.Helper()

				return mustMarshal(t, validStatement())
			},
			policy: &policy.Policy{
				Trust: &policy.TrustPolicy{
					Builders: []policy.TrustedBuilder{
						{ID: testBuilderID, MaxLevel: 2},
					},
					BuildTypes: []string{"https://other.example.com/build/v1"},
				},
			},
			digest:     testDigest,
			wantErr:    nil,
			wantPass:   false,
			wantType:   "",
			wantStatus: types.StatusFail,
		},
		{
			name: "allowed build type",
			data: func(t *testing.T) []byte {
				t.Helper()

				return mustMarshal(t, validStatement())
			},
			policy: &policy.Policy{
				Trust: &policy.TrustPolicy{
					Builders: []policy.TrustedBuilder{
						{ID: testBuilderID, MaxLevel: 2},
					},
					BuildTypes: []string{
						"https://actions.github.io/buildtypes/workflow/v1",
					},
				},
			},
			digest:     testDigest,
			wantErr:    nil,
			wantPass:   true,
			wantType:   "",
			wantStatus: types.StatusPass,
		},
		{
			name: "untrusted source",
			data: func(t *testing.T) []byte {
				t.Helper()

				return mustMarshal(t, validStatement())
			},
			policy: &policy.Policy{
				Trust: &policy.TrustPolicy{
					Builders: []policy.TrustedBuilder{
						{ID: testBuilderID, MaxLevel: 2},
					},
					Sources: []string{"github.com/other-org/*"},
				},
			},
			digest:     testDigest,
			wantErr:    nil,
			wantPass:   false,
			wantType:   "",
			wantStatus: types.StatusFail,
		},
		{
			name: "allowed source",
			data: func(t *testing.T) []byte {
				t.Helper()

				return mustMarshal(t, validStatement())
			},
			policy: &policy.Policy{
				Trust: &policy.TrustPolicy{
					Builders: []policy.TrustedBuilder{
						{ID: testBuilderID, MaxLevel: 2},
					},
					Sources: []string{testSourceGlob},
				},
			},
			digest:     testDigest,
			wantErr:    nil,
			wantPass:   true,
			wantType:   "",
			wantStatus: types.StatusPass,
		},
		{
			name: "source parameter missing",
			data: func(t *testing.T) []byte {
				t.Helper()

				stmt := validStatement()
				stmt.Predicate.BuildDefinition.ExternalParameters = map[string]any{
					testKeyWorkflow: testPlaceholder,
				}

				return mustMarshal(t, stmt)
			},
			policy: &policy.Policy{
				Trust: &policy.TrustPolicy{
					Builders: []policy.TrustedBuilder{
						{ID: testBuilderID, MaxLevel: 2},
					},
					Sources: []string{testSourceGlob},
				},
			},
			digest:     testDigest,
			wantErr:    nil,
			wantPass:   false,
			wantType:   "",
			wantStatus: types.StatusFail,
		},
		{
			name: "source parameter not a string",
			data: func(t *testing.T) []byte {
				t.Helper()

				stmt := validStatement()
				stmt.Predicate.BuildDefinition.ExternalParameters = map[string]any{
					testKeySource: 123,
				}

				return mustMarshal(t, stmt)
			},
			policy: &policy.Policy{
				Trust: &policy.TrustPolicy{
					Builders: []policy.TrustedBuilder{
						{ID: testBuilderID, MaxLevel: 2},
					},
					Sources: []string{testSourceGlob},
				},
			},
			digest:     testDigest,
			wantErr:    nil,
			wantPass:   false,
			wantType:   "",
			wantStatus: types.StatusFail,
		},
		{
			name: "reject unknown parameters",
			data: func(t *testing.T) []byte {
				t.Helper()

				stmt := validStatement()
				stmt.Predicate.BuildDefinition.ExternalParameters["customKey"] = "value"

				return mustMarshal(t, stmt)
			},
			policy: &policy.Policy{
				Trust: &policy.TrustPolicy{
					Builders: []policy.TrustedBuilder{
						{ID: testBuilderID, MaxLevel: 2},
					},
				},
				Provenance: &policy.ProvenancePolicy{
					RejectUnknownParameters: true,
				},
			},
			digest:     testDigest,
			wantErr:    nil,
			wantPass:   false,
			wantType:   "",
			wantStatus: types.StatusFail,
		},
		{
			name: "allow unknown parameters",
			data: func(t *testing.T) []byte {
				t.Helper()

				stmt := validStatement()
				stmt.Predicate.BuildDefinition.ExternalParameters["customKey"] = "value"

				return mustMarshal(t, stmt)
			},
			policy: &policy.Policy{
				Trust: &policy.TrustPolicy{
					Builders: []policy.TrustedBuilder{
						{ID: testBuilderID, MaxLevel: 2},
					},
				},
				Provenance: &policy.ProvenancePolicy{
					RejectUnknownParameters: false,
				},
			},
			digest:     testDigest,
			wantErr:    nil,
			wantPass:   true,
			wantType:   "",
			wantStatus: types.StatusPass,
		},
		{
			name: "all known parameters",
			data: func(t *testing.T) []byte {
				t.Helper()

				stmt := validStatement()
				stmt.Predicate.BuildDefinition.ExternalParameters = map[string]any{
					testKeySource:   testPlaceholder,
					"repository":    testPlaceholder,
					"ref":           "main",
					testKeyWorkflow: ".github/workflows/ci.yml",
					"buildType":     "release",
				}

				return mustMarshal(t, stmt)
			},
			policy: &policy.Policy{
				Trust: &policy.TrustPolicy{
					Builders: []policy.TrustedBuilder{
						{ID: testBuilderID, MaxLevel: 2},
					},
				},
				Provenance: &policy.ProvenancePolicy{
					RejectUnknownParameters: true,
				},
			},
			digest:     testDigest,
			wantErr:    nil,
			wantPass:   true,
			wantType:   "",
			wantStatus: types.StatusPass,
		},
		{
			name: "multiple subjects with match",
			data: func(t *testing.T) []byte {
				t.Helper()

				stmt := validStatement()
				stmt.Subject = []slsa.Subject{
					{
						Name:   "other-image",
						Digest: map[string]string{"sha256": "other"},
					},
					{
						Name:   "nginx",
						Digest: map[string]string{"sha256": "abc123def456"},
					},
				}

				return mustMarshal(t, stmt)
			},
			policy:     &policy.Policy{},
			digest:     testDigest,
			wantErr:    nil,
			wantPass:   true,
			wantType:   "",
			wantStatus: types.StatusPass,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			result, err := slsa.Verify(test.data(t), test.policy, test.digest)

			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) {
					t.Fatalf("expected %v, got %v", test.wantErr, err)
				}

				return
			}

			assertNoError(t, err)

			if result.Passed != test.wantPass {
				t.Errorf("expected Passed=%v, got Passed=%v (detail: %s)",
					test.wantPass, result.Passed, result.Detail)
			}

			if test.wantType != "" && result.Type != test.wantType {
				t.Errorf("expected type %q, got %q", test.wantType, result.Type)
			}

			if test.wantStatus != "" && result.Status != test.wantStatus {
				t.Errorf("expected status %q, got %q", test.wantStatus, result.Status)
			}
		})
	}
}

func TestVerifyMultiple(t *testing.T) { //nolint:funlen // Table-driven test.
	t.Parallel()

	tests := []struct {
		name               string
		attestations       func(t *testing.T) []attestation.VerifiedAttestation
		policy             *policy.Policy
		wantPass           bool
		wantDetailContains string
	}{
		{
			name: "any attestation passes",
			attestations: func(t *testing.T) []attestation.VerifiedAttestation {
				t.Helper()

				goodStmt := validStatement()
				badStmt := validStatement()
				badStmt.Predicate.RunDetails.Builder.ID = "https://untrusted.example.com"

				return []attestation.VerifiedAttestation{
					{
						PredicateType: attestation.PredicateSLSAProvenanceV1,
						Payload:       mustMarshal(t, badStmt),
						Digest:        testDigest,
					},
					{
						PredicateType: attestation.PredicateSLSAProvenanceV1,
						Payload:       mustMarshal(t, goodStmt),
						Digest:        testDigest,
					},
				}
			},
			policy: &policy.Policy{
				Trust: &policy.TrustPolicy{
					Builders: []policy.TrustedBuilder{
						{ID: testBuilderID, MaxLevel: 2},
					},
				},
			},
			wantPass:           true,
			wantDetailContains: "",
		},
		{
			name: "all attestations fail",
			attestations: func(t *testing.T) []attestation.VerifiedAttestation {
				t.Helper()

				badStmt := validStatement()
				badStmt.Predicate.RunDetails.Builder.ID = "https://untrusted.example.com"

				return []attestation.VerifiedAttestation{
					{
						PredicateType: attestation.PredicateSLSAProvenanceV1,
						Payload:       mustMarshal(t, badStmt),
						Digest:        testDigest,
					},
				}
			},
			policy: &policy.Policy{
				Trust: &policy.TrustPolicy{
					Builders: []policy.TrustedBuilder{
						{ID: testBuilderID, MaxLevel: 2},
					},
				},
			},
			wantPass:           false,
			wantDetailContains: "",
		},
		{
			name: "empty attestations",
			attestations: func(_ *testing.T) []attestation.VerifiedAttestation {
				return []attestation.VerifiedAttestation{}
			},
			policy:             &policy.Policy{},
			wantPass:           false,
			wantDetailContains: "",
		},
		{
			name: "skips invalid attestation",
			attestations: func(t *testing.T) []attestation.VerifiedAttestation {
				t.Helper()

				goodStmt := validStatement()

				return []attestation.VerifiedAttestation{
					{
						PredicateType: attestation.PredicateSLSAProvenanceV1,
						Payload:       []byte("invalid json"),
						Digest:        testDigest,
					},
					{
						PredicateType: attestation.PredicateSLSAProvenanceV1,
						Payload:       mustMarshal(t, goodStmt),
						Digest:        testDigest,
					},
				}
			},
			policy: &policy.Policy{
				Trust: &policy.TrustPolicy{
					Builders: []policy.TrustedBuilder{
						{ID: testBuilderID, MaxLevel: 2},
					},
				},
			},
			wantPass:           true,
			wantDetailContains: "",
		},
		{
			name: "all attestations fail to parse",
			attestations: func(_ *testing.T) []attestation.VerifiedAttestation {
				return []attestation.VerifiedAttestation{
					{
						PredicateType: attestation.PredicateSLSAProvenanceV1,
						Payload:       []byte("{invalid}"),
						Digest:        testDigest,
					},
					{
						PredicateType: attestation.PredicateSLSAProvenanceV1,
						Payload:       []byte("not json at all"),
						Digest:        testDigest,
					},
				}
			},
			policy:             &policy.Policy{},
			wantPass:           false,
			wantDetailContains: "no valid provenance:",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			result, err := slsa.VerifyMultiple(
				test.attestations(t), test.policy, testDigest,
			)
			assertNoError(t, err)

			if result.Passed != test.wantPass {
				t.Errorf("expected Passed=%v, got Passed=%v (detail: %s)",
					test.wantPass, result.Passed, result.Detail)
			}

			if test.wantDetailContains != "" &&
				!strings.Contains(result.Detail, test.wantDetailContains) {
				t.Errorf("expected detail to contain %q, got %q",
					test.wantDetailContains, result.Detail)
			}
		})
	}
}

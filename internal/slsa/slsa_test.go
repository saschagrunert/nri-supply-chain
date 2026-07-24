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
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/slsa"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	testDigest           = "sha256:abc123def456"
	testDigestHash       = "abc123def456"
	testDigestAlgo       = "sha256"
	testBuilderID        = "https://github.com/actions/runner"
	testUntrustedBuilder = "https://untrusted.example.com"
	testBuildType        = "https://actions.github.io/buildtypes/workflow/v1"
	testSource           = "github.com/example/repo"
	testWorkflow         = ".github/workflows/release.yml"
	testSourceGlob       = "github.com/example/*"
	testKeySource        = "source"
	testKeyWorkflow      = "workflow"
	testPlaceholder      = "test"
	testCustomParamKey   = "custom-param"
	testValue            = "value"
	testSubjectName      = "nginx"
)

func validStatement() slsa.Statement {
	return slsa.Statement{
		Type: "https://in-toto.io/Statement/v1",
		Subject: []slsa.Subject{
			{
				Name:   testSubjectName,
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

func TestVerify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		data       func(t *testing.T) []byte
		policy     *policy.Policy
		digest     string
		wantErr    error
		wantPass   bool
		wantType   types.CheckType
		wantStatus types.CheckStatus
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
			wantType:   types.CheckTypeSLSA,
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
			wantType:   types.CheckTypeSLSA,
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
			wantType:   types.CheckTypeSLSA,
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
			wantType:   types.CheckTypeSLSA,
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
			wantType:   types.CheckTypeSLSA,
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
			wantType:   types.CheckTypeSLSA,
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
			wantType:   types.CheckTypeSLSA,
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
			wantType:   types.CheckTypeSLSA,
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
			wantType:   types.CheckTypeSLSA,
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
			wantType:   types.CheckTypeSLSA,
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
			wantType:   types.CheckTypeSLSA,
			wantStatus: types.StatusFail,
		},
		{
			name: "reject unknown parameters",
			data: func(t *testing.T) []byte {
				t.Helper()

				stmt := validStatement()
				stmt.Predicate.BuildDefinition.ExternalParameters["customKey"] = testValue

				return mustMarshal(t, stmt)
			},
			policy: &policy.Policy{
				Trust: &policy.TrustPolicy{
					Builders: []policy.TrustedBuilder{
						{ID: testBuilderID, MaxLevel: 2},
					},
				},
				SLSA: &policy.SLSAPolicy{
					RejectUnknownParameters: true,
				},
			},
			digest:     testDigest,
			wantErr:    nil,
			wantPass:   false,
			wantType:   types.CheckTypeSLSA,
			wantStatus: types.StatusFail,
		},
		{
			name: "allow unknown parameters",
			data: func(t *testing.T) []byte {
				t.Helper()

				stmt := validStatement()
				stmt.Predicate.BuildDefinition.ExternalParameters["customKey"] = testValue

				return mustMarshal(t, stmt)
			},
			policy: &policy.Policy{
				Trust: &policy.TrustPolicy{
					Builders: []policy.TrustedBuilder{
						{ID: testBuilderID, MaxLevel: 2},
					},
				},
				SLSA: &policy.SLSAPolicy{
					RejectUnknownParameters: false,
				},
			},
			digest:     testDigest,
			wantErr:    nil,
			wantPass:   true,
			wantType:   types.CheckTypeSLSA,
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
				SLSA: &policy.SLSAPolicy{
					RejectUnknownParameters: true,
				},
			},
			digest:     testDigest,
			wantErr:    nil,
			wantPass:   true,
			wantType:   types.CheckTypeSLSA,
			wantStatus: types.StatusPass,
		},
		{
			name: "custom known parameters accepted",
			data: func(t *testing.T) []byte {
				t.Helper()

				stmt := validStatement()
				stmt.Predicate.BuildDefinition.ExternalParameters = map[string]any{
					testCustomParamKey: testValue,
				}

				return mustMarshal(t, stmt)
			},
			policy: &policy.Policy{
				Trust: &policy.TrustPolicy{
					Builders: []policy.TrustedBuilder{
						{ID: testBuilderID, MaxLevel: 2},
					},
				},
				SLSA: &policy.SLSAPolicy{
					RejectUnknownParameters: true,
					KnownParameters:         []string{testCustomParamKey},
				},
			},
			digest:     testDigest,
			wantErr:    nil,
			wantPass:   true,
			wantType:   types.CheckTypeSLSA,
			wantStatus: types.StatusPass,
		},
		{
			name: "custom known parameters rejected",
			data: func(t *testing.T) []byte {
				t.Helper()

				stmt := validStatement()
				stmt.Predicate.BuildDefinition.ExternalParameters = map[string]any{
					testCustomParamKey: testValue,
					"unknown":          "bad",
				}

				return mustMarshal(t, stmt)
			},
			policy: &policy.Policy{
				Trust: &policy.TrustPolicy{
					Builders: []policy.TrustedBuilder{
						{ID: testBuilderID, MaxLevel: 2},
					},
				},
				SLSA: &policy.SLSAPolicy{
					RejectUnknownParameters: true,
					KnownParameters:         []string{testCustomParamKey},
				},
			},
			digest:     testDigest,
			wantErr:    nil,
			wantPass:   false,
			wantType:   types.CheckTypeSLSA,
			wantStatus: types.StatusFail,
		},
		{
			name: "multiple subjects with match",
			data: func(t *testing.T) []byte {
				t.Helper()

				stmt := validStatement()
				stmt.Subject = []slsa.Subject{
					{
						Name:   "other-image",
						Digest: map[string]string{testDigestAlgo: "other"},
					},
					{
						Name:   testSubjectName,
						Digest: map[string]string{testDigestAlgo: testDigestHash},
					},
				}

				return mustMarshal(t, stmt)
			},
			policy:     &policy.Policy{},
			digest:     testDigest,
			wantErr:    nil,
			wantPass:   true,
			wantType:   types.CheckTypeSLSA,
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

			testutil.AssertNoError(t, err)

			if result.Passed != test.wantPass {
				t.Errorf("expected Passed=%v, got Passed=%v (detail: %s)",
					test.wantPass, result.Passed, result.Detail)
			}

			if result.Type != test.wantType {
				t.Errorf("expected type %q, got %q", test.wantType, result.Type)
			}

			if result.Status != test.wantStatus {
				t.Errorf("expected status %q, got %q", test.wantStatus, result.Status)
			}
		})
	}
}

func TestVerifyEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("empty payload", func(t *testing.T) {
		t.Parallel()

		_, err := slsa.Verify([]byte{}, &policy.Policy{}, testDigest)
		testutil.AssertError(t, err)

		if !errors.Is(err, slsa.ErrInvalidProvenance) {
			t.Errorf("expected ErrInvalidProvenance, got %v", err)
		}
	})

	t.Run("nil policy trust section", func(t *testing.T) {
		t.Parallel()

		result, err := slsa.Verify(
			mustMarshal(t, validStatement()),
			&policy.Policy{},
			testDigest,
		)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, true, result.Passed)
	})

	t.Run("empty JSON object", func(t *testing.T) {
		t.Parallel()

		_, err := slsa.Verify([]byte("{}"), &policy.Policy{}, testDigest)

		if !errors.Is(err, slsa.ErrInvalidProvenance) {
			t.Errorf("expected ErrInvalidProvenance for empty JSON object, got %v", err)
		}
	})

	t.Run("empty subjects list", func(t *testing.T) {
		t.Parallel()

		stmt := validStatement()
		stmt.Subject = []slsa.Subject{}

		result, err := slsa.Verify(mustMarshal(t, stmt), &policy.Policy{}, testDigest)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, false, result.Passed)
		testutil.AssertEqual(t, types.StatusFail, result.Status)
	})

	t.Run("subject with wrong algorithm", func(t *testing.T) {
		t.Parallel()

		stmt := validStatement()
		stmt.Subject = []slsa.Subject{
			{
				Name:   testSubjectName,
				Digest: map[string]string{"sha512": testDigestHash},
			},
		}

		result, err := slsa.Verify(mustMarshal(t, stmt), &policy.Policy{}, testDigest)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, false, result.Passed)
	})

	t.Run("subject with empty digest map", func(t *testing.T) {
		t.Parallel()

		stmt := validStatement()
		stmt.Subject = []slsa.Subject{
			{
				Name:   testSubjectName,
				Digest: map[string]string{},
			},
		}

		result, err := slsa.Verify(mustMarshal(t, stmt), &policy.Policy{}, testDigest)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, false, result.Passed)
	})

	t.Run("empty digest string", func(t *testing.T) {
		t.Parallel()

		result, err := slsa.Verify(mustMarshal(t, validStatement()), &policy.Policy{}, "")
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, false, result.Passed)
	})

	t.Run("digest with empty hash", func(t *testing.T) {
		t.Parallel()

		result, err := slsa.Verify(mustMarshal(t, validStatement()), &policy.Policy{}, "sha256:")
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, false, result.Passed)
	})

	t.Run("digest with empty algorithm", func(t *testing.T) {
		t.Parallel()

		result, err := slsa.Verify(mustMarshal(t, validStatement()), &policy.Policy{}, ":abc123")
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, false, result.Passed)
	})

	t.Run("empty external parameters with reject unknown", func(t *testing.T) {
		t.Parallel()

		stmt := validStatement()
		stmt.Predicate.BuildDefinition.ExternalParameters = map[string]any{}

		result, err := slsa.Verify(mustMarshal(t, stmt), &policy.Policy{
			SLSA: &policy.SLSAPolicy{
				RejectUnknownParameters: true,
			},
		}, testDigest)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, true, result.Passed)
	})

	t.Run("nil slsa policy allows unknown parameters", func(t *testing.T) {
		t.Parallel()

		stmt := validStatement()
		stmt.Predicate.BuildDefinition.ExternalParameters["extra"] = "data"

		result, err := slsa.Verify(mustMarshal(t, stmt), &policy.Policy{}, testDigest)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, true, result.Passed)
	})

	t.Run("multiple builders with one matching", func(t *testing.T) {
		t.Parallel()

		result, err := slsa.Verify(
			mustMarshal(t, validStatement()),
			&policy.Policy{
				Trust: &policy.TrustPolicy{
					Builders: []policy.TrustedBuilder{
						{ID: "https://other-builder.example.com", MaxLevel: 3},
						{ID: testBuilderID, MaxLevel: 2},
						{ID: "https://yet-another.example.com", MaxLevel: 1},
					},
				},
			},
			testDigest,
		)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, true, result.Passed)
	})

	t.Run("empty builder ID in statement", func(t *testing.T) {
		t.Parallel()

		stmt := validStatement()
		stmt.Predicate.RunDetails.Builder.ID = ""

		result, err := slsa.Verify(
			mustMarshal(t, stmt),
			&policy.Policy{
				Trust: &policy.TrustPolicy{
					Builders: []policy.TrustedBuilder{
						{ID: testBuilderID, MaxLevel: 2},
					},
				},
			},
			testDigest,
		)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, false, result.Passed)
	})

	t.Run("multiple source patterns with later match", func(t *testing.T) {
		t.Parallel()

		result, err := slsa.Verify(
			mustMarshal(t, validStatement()),
			&policy.Policy{
				Trust: &policy.TrustPolicy{
					Sources: []string{
						"github.com/other/*",
						"github.com/another/*",
						testSourceGlob,
					},
				},
			},
			testDigest,
		)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, true, result.Passed)
	})

	t.Run("source glob does not match nested paths", func(t *testing.T) {
		t.Parallel()

		stmt := validStatement()
		stmt.Predicate.BuildDefinition.ExternalParameters[testKeySource] = "github.com/example/repo/subdir"

		result, err := slsa.Verify(
			mustMarshal(t, stmt),
			&policy.Policy{
				Trust: &policy.TrustPolicy{
					Sources: []string{testSourceGlob},
				},
			},
			testDigest,
		)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, false, result.Passed)
	})

	t.Run("no build types configured allows any", func(t *testing.T) {
		t.Parallel()

		result, err := slsa.Verify(
			mustMarshal(t, validStatement()),
			&policy.Policy{
				Trust: &policy.TrustPolicy{},
			},
			testDigest,
		)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, true, result.Passed)
	})

	t.Run("multiple build types with match", func(t *testing.T) {
		t.Parallel()

		result, err := slsa.Verify(
			mustMarshal(t, validStatement()),
			&policy.Policy{
				Trust: &policy.TrustPolicy{
					BuildTypes: []string{
						"https://other.example.com/build/v1",
						testBuildType,
					},
				},
			},
			testDigest,
		)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, true, result.Passed)
	})

	t.Run("truncated JSON", func(t *testing.T) {
		t.Parallel()

		_, err := slsa.Verify([]byte(`{"_type":"https://in-toto`), &policy.Policy{}, testDigest)

		if !errors.Is(err, slsa.ErrInvalidProvenance) {
			t.Errorf("expected ErrInvalidProvenance, got %v", err)
		}
	})

	t.Run("multiple subjects none matching", func(t *testing.T) {
		t.Parallel()

		stmt := validStatement()
		stmt.Subject = []slsa.Subject{
			{
				Name:   "image-a",
				Digest: map[string]string{testDigestAlgo: "aaa111"},
			},
			{
				Name:   "image-b",
				Digest: map[string]string{testDigestAlgo: "bbb222"},
			},
			{
				Name:   "image-c",
				Digest: map[string]string{testDigestAlgo: "ccc333"},
			},
		}

		result, err := slsa.Verify(mustMarshal(t, stmt), &policy.Policy{}, testDigest)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, false, result.Passed)
	})

	t.Run("source with exact match no glob", func(t *testing.T) {
		t.Parallel()

		result, err := slsa.Verify(
			mustMarshal(t, validStatement()),
			&policy.Policy{
				Trust: &policy.TrustPolicy{
					Sources: []string{testSource},
				},
			},
			testDigest,
		)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, true, result.Passed)
	})

	t.Run("empty source string in params", func(t *testing.T) {
		t.Parallel()

		stmt := validStatement()
		stmt.Predicate.BuildDefinition.ExternalParameters[testKeySource] = ""

		result, err := slsa.Verify(
			mustMarshal(t, stmt),
			&policy.Policy{
				Trust: &policy.TrustPolicy{
					Sources: []string{testSourceGlob},
				},
			},
			testDigest,
		)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, false, result.Passed)
	})
}

func TestVerifyMultiple(t *testing.T) {
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
				badStmt.Predicate.RunDetails.Builder.ID = testUntrustedBuilder

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
				badStmt.Predicate.RunDetails.Builder.ID = testUntrustedBuilder

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
			testutil.AssertNoError(t, err)

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

func TestVerifyMultipleEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("nil attestation slice", func(t *testing.T) {
		t.Parallel()

		result, err := slsa.VerifyMultiple(nil, &policy.Policy{}, testDigest)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, false, result.Passed)

		if !strings.Contains(result.Detail, "no valid provenance") {
			t.Errorf("expected detail about no valid provenance, got %q", result.Detail)
		}
	})

	t.Run("mix of parse errors and verification failures", func(t *testing.T) {
		t.Parallel()

		badStmt := validStatement()
		badStmt.Predicate.RunDetails.Builder.ID = testUntrustedBuilder

		atts := []attestation.VerifiedAttestation{
			{
				PredicateType: attestation.PredicateSLSAProvenanceV1,
				Payload:       mustMarshal(t, badStmt),
				Digest:        testDigest,
			},
			{
				PredicateType: attestation.PredicateSLSAProvenanceV1,
				Payload:       []byte("not json"),
				Digest:        testDigest,
			},
		}

		result, err := slsa.VerifyMultiple(atts, &policy.Policy{
			Trust: &policy.TrustPolicy{
				Builders: []policy.TrustedBuilder{
					{ID: testBuilderID, MaxLevel: 2},
				},
			},
		}, testDigest)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, false, result.Passed)

		if !strings.Contains(result.Detail, "also failed to parse") {
			t.Errorf("expected detail mentioning parse failures, got %q", result.Detail)
		}
	})

	t.Run("first attestation passes stops early", func(t *testing.T) {
		t.Parallel()

		goodStmt := validStatement()

		atts := []attestation.VerifiedAttestation{
			{
				PredicateType: attestation.PredicateSLSAProvenanceV1,
				Payload:       mustMarshal(t, goodStmt),
				Digest:        testDigest,
			},
			{
				PredicateType: attestation.PredicateSLSAProvenanceV1,
				Payload:       []byte("should not matter"),
				Digest:        testDigest,
			},
		}

		result, err := slsa.VerifyMultiple(atts, &policy.Policy{}, testDigest)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, true, result.Passed)
	})

	t.Run("single valid attestation passes", func(t *testing.T) {
		t.Parallel()

		goodStmt := validStatement()

		atts := []attestation.VerifiedAttestation{
			{
				PredicateType: attestation.PredicateSLSAProvenanceV1,
				Payload:       mustMarshal(t, goodStmt),
				Digest:        testDigest,
			},
		}

		result, err := slsa.VerifyMultiple(atts, &policy.Policy{}, testDigest)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, true, result.Passed)
	})

	t.Run("multiple failures aggregated", func(t *testing.T) {
		t.Parallel()

		badStmt1 := validStatement()
		badStmt1.Predicate.RunDetails.Builder.ID = "https://untrusted-a.example.com"

		badStmt2 := validStatement()
		badStmt2.Predicate.RunDetails.Builder.ID = "https://untrusted-b.example.com"

		atts := []attestation.VerifiedAttestation{
			{
				PredicateType: attestation.PredicateSLSAProvenanceV1,
				Payload:       mustMarshal(t, badStmt1),
				Digest:        testDigest,
			},
			{
				PredicateType: attestation.PredicateSLSAProvenanceV1,
				Payload:       mustMarshal(t, badStmt2),
				Digest:        testDigest,
			},
		}

		result, err := slsa.VerifyMultiple(atts, &policy.Policy{
			Trust: &policy.TrustPolicy{
				Builders: []policy.TrustedBuilder{
					{ID: testBuilderID, MaxLevel: 2},
				},
			},
		}, testDigest)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, false, result.Passed)

		if !strings.Contains(result.Detail, "untrusted-a") ||
			!strings.Contains(result.Detail, "untrusted-b") {
			t.Errorf("expected both failure reasons in detail, got %q", result.Detail)
		}
	})
}

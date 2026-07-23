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

package vsa_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
	"github.com/saschagrunert/nri-supply-chain/internal/vsa"
)

const (
	testImageRef      = "docker.io/library/nginx@sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1"
	testVerifierID    = "https://example.com/verifier"
	testVerifierKey   = "/etc/keys/verifier.pub"
	testPolicyURI     = "https://example.com/policy"
	testBuildLevel3   = "SLSA_BUILD_LEVEL_3"
	testBuildLevel2   = "SLSA_BUILD_LEVEL_2"
	testBuildLevel1   = "SLSA_BUILD_LEVEL_1"
	testBuildLevelPfx = "SLSA_BUILD_LEVEL_"
)

func validVSAStatement() vsa.Statement {
	return vsa.Statement{
		Type:          "https://in-toto.io/Statement/v1",
		PredicateType: "https://slsa.dev/verification_summary/v1",
		Predicate: vsa.Predicate{
			Verifier: vsa.Verifier{
				ID: testVerifierID,
			},
			TimeVerified:       time.Now().UTC().Format(time.RFC3339),
			ResourceURI:        testImageRef,
			Policy:             vsa.Policy{URI: testPolicyURI},
			VerificationResult: vsa.ResultPassed,
			VerifiedLevels:     []string{testBuildLevel3},
			SLSAVersion:        "1.0",
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

func trustedPolicy() *policy.Policy {
	return &policy.Policy{
		Trust: &policy.TrustPolicy{
			Verifiers: []policy.TrustedVerifier{
				{ID: testVerifierID, Key: testVerifierKey},
			},
		},
		VSA: &policy.VSAPolicy{
			MinimumLevel:   2,
			MaxAge:         "24h",
			MaxAgeDuration: 24 * time.Hour,
			Policy:         testPolicyURI,
		},
	}
}

func TestVerify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		modify     func(*vsa.Statement)
		pol        *policy.Policy
		wantPassed bool
		wantReject bool
		wantStatus types.CheckStatus
		wantErr    error
	}{
		{
			name:       "passed",
			modify:     nil,
			pol:        trustedPolicy(),
			wantPassed: true,
			wantReject: false,
			wantStatus: types.StatusPass,
			wantErr:    nil,
		},
		{
			name: "failed hard reject",
			modify: func(s *vsa.Statement) {
				s.Predicate.VerificationResult = vsa.ResultFailed
			},
			pol:        trustedPolicy(),
			wantPassed: false,
			wantReject: true,
			wantStatus: types.StatusFail,
			wantErr:    nil,
		},
		{
			name: "untrusted verifier",
			modify: func(s *vsa.Statement) {
				s.Predicate.Verifier.ID = "https://unknown.example.com"
			},
			pol:        trustedPolicy(),
			wantPassed: false,
			wantReject: false,
			wantStatus: types.StatusWarn,
			wantErr:    nil,
		},
		{
			name:       "no verifiers configured",
			modify:     nil,
			pol:        &policy.Policy{},
			wantPassed: false,
			wantReject: false,
			wantStatus: types.StatusWarn,
			wantErr:    nil,
		},
		{
			name: "insufficient level",
			modify: func(s *vsa.Statement) {
				s.Predicate.VerifiedLevels = []string{testBuildLevel1}
			},
			pol:        trustedPolicy(),
			wantPassed: false,
			wantReject: false,
			wantStatus: types.StatusFail,
			wantErr:    nil,
		},
		{
			name: "meets exact level",
			modify: func(s *vsa.Statement) {
				s.Predicate.VerifiedLevels = []string{testBuildLevel2}
			},
			pol:        trustedPolicy(),
			wantPassed: true,
			wantReject: false,
			wantStatus: types.StatusPass,
			wantErr:    nil,
		},
		{
			name: "no minimum level required",
			modify: func(s *vsa.Statement) {
				s.Predicate.VerifiedLevels = []string{testBuildLevel1}
			},
			pol: &policy.Policy{
				Trust: &policy.TrustPolicy{
					Verifiers: []policy.TrustedVerifier{
						{ID: testVerifierID, Key: testVerifierKey},
					},
				},
			},
			wantPassed: true,
			wantReject: false,
			wantStatus: types.StatusPass,
			wantErr:    nil,
		},
		{
			name: "resource URI mismatch",
			modify: func(s *vsa.Statement) {
				s.Predicate.ResourceURI = "docker.io/library/other@sha256:xyz"
			},
			pol:        trustedPolicy(),
			wantPassed: false,
			wantReject: false,
			wantStatus: types.StatusFail,
			wantErr:    nil,
		},
		{
			name: "empty resource URI",
			modify: func(s *vsa.Statement) {
				s.Predicate.ResourceURI = ""
			},
			pol:        trustedPolicy(),
			wantPassed: false,
			wantReject: false,
			wantStatus: types.StatusFail,
			wantErr:    nil,
		},
		{
			name: "SLSA version too old",
			modify: func(s *vsa.Statement) {
				s.Predicate.SLSAVersion = "0.9"
			},
			pol:        trustedPolicy(),
			wantPassed: false,
			wantReject: false,
			wantStatus: types.StatusFail,
			wantErr:    nil,
		},
		{
			name: "empty SLSA version",
			modify: func(s *vsa.Statement) {
				s.Predicate.SLSAVersion = ""
			},
			pol:        trustedPolicy(),
			wantPassed: false,
			wantReject: false,
			wantStatus: types.StatusFail,
			wantErr:    nil,
		},
		{
			name: "SLSA version 2.0",
			modify: func(s *vsa.Statement) {
				s.Predicate.SLSAVersion = "2.0"
			},
			pol:        trustedPolicy(),
			wantPassed: true,
			wantReject: false,
			wantStatus: types.StatusPass,
			wantErr:    nil,
		},
		{
			name: "SLSA version 1.1",
			modify: func(s *vsa.Statement) {
				s.Predicate.SLSAVersion = "1.1"
			},
			pol:        trustedPolicy(),
			wantPassed: true,
			wantReject: false,
			wantStatus: types.StatusPass,
			wantErr:    nil,
		},
		{
			name: "policy mismatch",
			modify: func(s *vsa.Statement) {
				s.Predicate.Policy = vsa.Policy{URI: "https://other.example.com/policy"}
			},
			pol:        trustedPolicy(),
			wantPassed: false,
			wantReject: false,
			wantStatus: types.StatusFail,
			wantErr:    nil,
		},
		{
			name: "no policy required",
			modify: func(s *vsa.Statement) {
				s.Predicate.Policy = vsa.Policy{URI: "any-policy"}
			},
			pol: &policy.Policy{
				Trust: &policy.TrustPolicy{
					Verifiers: []policy.TrustedVerifier{
						{ID: testVerifierID, Key: testVerifierKey},
					},
				},
			},
			wantPassed: true,
			wantReject: false,
			wantStatus: types.StatusPass,
			wantErr:    nil,
		},
		{
			name: "stale VSA",
			modify: func(s *vsa.Statement) {
				s.Predicate.TimeVerified = time.Now().
					Add(-48 * time.Hour).
					UTC().
					Format(time.RFC3339)
			},
			pol:        trustedPolicy(),
			wantPassed: false,
			wantReject: false,
			wantStatus: types.StatusWarn,
			wantErr:    nil,
		},
		{
			name: "future timeVerified rejected",
			modify: func(s *vsa.Statement) {
				s.Predicate.TimeVerified = time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
			},
			pol:        trustedPolicy(),
			wantPassed: false,
			wantReject: false,
			wantStatus: types.StatusWarn,
			wantErr:    nil,
		},
		{
			name: "minor clock skew tolerated",
			modify: func(s *vsa.Statement) {
				s.Predicate.TimeVerified = time.Now().
					Add(30 * time.Second).
					UTC().
					Format(time.RFC3339)
			},
			pol:        trustedPolicy(),
			wantPassed: true,
			wantReject: false,
			wantStatus: types.StatusPass,
			wantErr:    nil,
		},
		{
			name: "future timestamp within tolerance treated as fresh",
			modify: func(s *vsa.Statement) {
				s.Predicate.TimeVerified = time.Now().
					Add(30 * time.Second).
					UTC().
					Format(time.RFC3339)
			},
			pol: &policy.Policy{
				Trust: &policy.TrustPolicy{
					Verifiers: []policy.TrustedVerifier{
						{ID: testVerifierID, Key: testVerifierKey},
					},
				},
				VSA: &policy.VSAPolicy{
					MinimumLevel:   2,
					MaxAge:         "1s",
					MaxAgeDuration: 1 * time.Second,
					Policy:         testPolicyURI,
				},
			},
			wantPassed: true,
			wantReject: false,
			wantStatus: types.StatusPass,
			wantErr:    nil,
		},
		{
			name: "no max age configured",
			modify: func(s *vsa.Statement) {
				s.Predicate.TimeVerified = time.Now().
					Add(-720 * time.Hour).
					UTC().
					Format(time.RFC3339)
			},
			pol: &policy.Policy{
				Trust: &policy.TrustPolicy{
					Verifiers: []policy.TrustedVerifier{
						{ID: testVerifierID, Key: testVerifierKey},
					},
				},
			},
			wantPassed: true,
			wantReject: false,
			wantStatus: types.StatusPass,
			wantErr:    nil,
		},
		{
			name: "unexpected verification result",
			modify: func(s *vsa.Statement) {
				s.Predicate.VerificationResult = "UNKNOWN"
			},
			pol:        trustedPolicy(),
			wantPassed: false,
			wantReject: false,
			wantStatus: types.StatusWarn,
			wantErr:    nil,
		},
		{
			name: "sub-second timestamp accepted",
			modify: func(s *vsa.Statement) {
				s.Predicate.TimeVerified = time.Now().UTC().Format(time.RFC3339Nano)
			},
			pol:        trustedPolicy(),
			wantPassed: true,
			wantReject: false,
			wantStatus: types.StatusPass,
			wantErr:    nil,
		},
		{
			name: "invalid timestamp format",
			modify: func(s *vsa.Statement) {
				s.Predicate.TimeVerified = "not-a-timestamp"
			},
			pol:        trustedPolicy(),
			wantPassed: false,
			wantReject: false,
			wantStatus: types.StatusWarn,
			wantErr:    nil,
		},
		{
			name:   "invalid max age duration",
			modify: nil,
			pol: &policy.Policy{
				Trust: &policy.TrustPolicy{
					Verifiers: []policy.TrustedVerifier{
						{ID: testVerifierID, Key: testVerifierKey},
					},
				},
				VSA: &policy.VSAPolicy{MaxAge: "not-a-duration"},
			},
			wantPassed: false,
			wantReject: false,
			wantStatus: types.StatusWarn,
			wantErr:    nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			stmt := validVSAStatement()
			if test.modify != nil {
				test.modify(&stmt)
			}

			result, err := vsa.Verify(mustMarshal(t, stmt), test.pol, testImageRef)
			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) {
					t.Fatalf("expected error %v, got %v", test.wantErr, err)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Check.Passed != test.wantPassed {
				t.Errorf("expected passed=%v, got passed=%v (detail: %s)",
					test.wantPassed, result.Check.Passed, result.Check.Detail)
			}

			if result.HardReject != test.wantReject {
				t.Errorf("expected hardReject=%v, got %v", test.wantReject, result.HardReject)
			}

			if result.Check.Status != test.wantStatus {
				t.Errorf("expected status %q, got %q", test.wantStatus, result.Check.Status)
			}
		})
	}
}

func TestVerifyMalformedPayloads(t *testing.T) {
	t.Parallel()

	t.Run("empty payload", func(t *testing.T) {
		t.Parallel()

		_, err := vsa.Verify([]byte{}, trustedPolicy(), testImageRef)

		if !errors.Is(err, vsa.ErrInvalidVSA) {
			t.Errorf("expected ErrInvalidVSA, got %v", err)
		}
	})

	t.Run("nil payload", func(t *testing.T) {
		t.Parallel()

		_, err := vsa.Verify(nil, trustedPolicy(), testImageRef)

		if !errors.Is(err, vsa.ErrInvalidVSA) {
			t.Errorf("expected ErrInvalidVSA, got %v", err)
		}
	})

	t.Run("empty JSON object", func(t *testing.T) {
		t.Parallel()

		result, err := vsa.Verify([]byte("{}"), trustedPolicy(), testImageRef)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Check.Passed {
			t.Error("expected fail for empty JSON object")
		}
	})

	t.Run("truncated JSON", func(t *testing.T) {
		t.Parallel()

		_, err := vsa.Verify([]byte(`{"predicate":{`), trustedPolicy(), testImageRef)

		if !errors.Is(err, vsa.ErrInvalidVSA) {
			t.Errorf("expected ErrInvalidVSA, got %v", err)
		}
	})
}

func TestVerifyVerifierEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("empty verifier ID in statement", func(t *testing.T) {
		t.Parallel()

		stmt := validVSAStatement()
		stmt.Predicate.Verifier.ID = ""

		result, err := vsa.Verify(mustMarshal(t, stmt), trustedPolicy(), testImageRef)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Check.Passed {
			t.Error("expected fail for empty verifier ID")
		}

		if result.Check.Status != types.StatusWarn {
			t.Errorf("expected warn status, got %q", result.Check.Status)
		}
	})

	t.Run("multiple verifiers with one match", func(t *testing.T) {
		t.Parallel()

		stmt := validVSAStatement()

		pol := &policy.Policy{
			Trust: &policy.TrustPolicy{
				Verifiers: []policy.TrustedVerifier{
					{ID: "https://other.example.com", Key: "/etc/keys/other.pub"},
					{ID: testVerifierID, Key: testVerifierKey},
				},
			},
		}

		result, err := vsa.Verify(mustMarshal(t, stmt), pol, testImageRef)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !result.Check.Passed {
			t.Errorf("expected pass with matching verifier, got: %s", result.Check.Detail)
		}
	})

	t.Run("empty verification result string", func(t *testing.T) {
		t.Parallel()

		stmt := validVSAStatement()
		stmt.Predicate.VerificationResult = ""

		result, err := vsa.Verify(mustMarshal(t, stmt), trustedPolicy(), testImageRef)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Check.Passed {
			t.Error("expected fail for empty verification result")
		}
	})

	t.Run("case sensitive verification result", func(t *testing.T) {
		t.Parallel()

		stmt := validVSAStatement()
		stmt.Predicate.VerificationResult = "passed"

		result, err := vsa.Verify(mustMarshal(t, stmt), trustedPolicy(), testImageRef)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Check.Passed {
			t.Error("expected fail for lowercase 'passed'")
		}
	})

	t.Run("hard reject does not pass", func(t *testing.T) {
		t.Parallel()

		stmt := validVSAStatement()
		stmt.Predicate.VerificationResult = vsa.ResultFailed

		result, err := vsa.Verify(mustMarshal(t, stmt), trustedPolicy(), testImageRef)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Check.Passed {
			t.Error("expected fail for FAILED result")
		}

		if !result.HardReject {
			t.Error("expected hard reject for FAILED result")
		}

		if result.Check.Status != types.StatusFail {
			t.Errorf("expected fail status, got %q", result.Check.Status)
		}
	})
}

func TestVerifyLevelEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("empty verified levels with minimum required", func(t *testing.T) {
		t.Parallel()

		stmt := validVSAStatement()
		stmt.Predicate.VerifiedLevels = []string{}

		result, err := vsa.Verify(mustMarshal(t, stmt), trustedPolicy(), testImageRef)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Check.Passed {
			t.Error("expected fail for empty verified levels with minimum required")
		}
	})

	t.Run("nil verified levels with minimum required", func(t *testing.T) {
		t.Parallel()

		stmt := validVSAStatement()
		stmt.Predicate.VerifiedLevels = nil

		result, err := vsa.Verify(mustMarshal(t, stmt), trustedPolicy(), testImageRef)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Check.Passed {
			t.Error("expected fail for nil verified levels with minimum required")
		}
	})

	t.Run("malformed level string", func(t *testing.T) {
		t.Parallel()

		stmt := validVSAStatement()
		stmt.Predicate.VerifiedLevels = []string{"NOT_A_LEVEL"}

		result, err := vsa.Verify(mustMarshal(t, stmt), trustedPolicy(), testImageRef)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Check.Passed {
			t.Error("expected fail for malformed level string")
		}
	})

	t.Run("level with non-numeric suffix", func(t *testing.T) {
		t.Parallel()

		stmt := validVSAStatement()
		stmt.Predicate.VerifiedLevels = []string{testBuildLevelPfx + "abc"}

		result, err := vsa.Verify(mustMarshal(t, stmt), trustedPolicy(), testImageRef)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Check.Passed {
			t.Error("expected fail for non-numeric level suffix")
		}
	})

	t.Run("multiple levels with one sufficient", func(t *testing.T) {
		t.Parallel()

		stmt := validVSAStatement()
		stmt.Predicate.VerifiedLevels = []string{
			testBuildLevel1,
			testBuildLevel3,
		}

		result, err := vsa.Verify(mustMarshal(t, stmt), trustedPolicy(), testImageRef)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !result.Check.Passed {
			t.Errorf("expected pass when one level is sufficient, got: %s", result.Check.Detail)
		}
	})
}

func TestVerifyVersionEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("SLSA version with v prefix", func(t *testing.T) {
		t.Parallel()

		stmt := validVSAStatement()
		stmt.Predicate.SLSAVersion = "v1.0"

		result, err := vsa.Verify(mustMarshal(t, stmt), trustedPolicy(), testImageRef)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !result.Check.Passed {
			t.Errorf("expected pass for v-prefixed version, got: %s", result.Check.Detail)
		}
	})

	t.Run("SLSA version non-numeric", func(t *testing.T) {
		t.Parallel()

		stmt := validVSAStatement()
		stmt.Predicate.SLSAVersion = "abc"

		result, err := vsa.Verify(mustMarshal(t, stmt), trustedPolicy(), testImageRef)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Check.Passed {
			t.Error("expected fail for non-numeric SLSA version")
		}
	})

	t.Run("policy URI empty in policy allows any", func(t *testing.T) {
		t.Parallel()

		stmt := validVSAStatement()
		stmt.Predicate.Policy = vsa.Policy{URI: "https://arbitrary.example.com/pol"}

		pol := &policy.Policy{
			Trust: &policy.TrustPolicy{
				Verifiers: []policy.TrustedVerifier{
					{ID: testVerifierID, Key: testVerifierKey},
				},
			},
			VSA: &policy.VSAPolicy{MinimumLevel: 2},
		}

		result, err := vsa.Verify(mustMarshal(t, stmt), pol, testImageRef)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !result.Check.Passed {
			t.Errorf("expected pass when no policy URI required, got: %s", result.Check.Detail)
		}
	})

	t.Run("invalid resource URI format", func(t *testing.T) {
		t.Parallel()

		stmt := validVSAStatement()
		stmt.Predicate.ResourceURI = ":::not-a-valid-ref:::"

		result, err := vsa.Verify(mustMarshal(t, stmt), trustedPolicy(), testImageRef)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Check.Passed {
			t.Error("expected fail for invalid resource URI")
		}
	})
}

func TestVerifyFreshnessEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("timestamp at exact clock skew boundary", func(t *testing.T) {
		t.Parallel()

		stmt := validVSAStatement()
		stmt.Predicate.TimeVerified = time.Now().
			Add(59 * time.Second).
			UTC().
			Format(time.RFC3339)

		result, err := vsa.Verify(mustMarshal(t, stmt), trustedPolicy(), testImageRef)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !result.Check.Passed {
			t.Errorf("expected pass within clock skew tolerance, got: %s", result.Check.Detail)
		}
	})

	t.Run("timestamp well beyond clock skew", func(t *testing.T) {
		t.Parallel()

		stmt := validVSAStatement()
		stmt.Predicate.TimeVerified = time.Now().
			Add(5 * time.Minute).
			UTC().
			Format(time.RFC3339)

		result, err := vsa.Verify(mustMarshal(t, stmt), trustedPolicy(), testImageRef)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Check.Passed {
			t.Error("expected fail for future timestamp beyond tolerance")
		}
	})

	t.Run("stale VSA beyond max age", func(t *testing.T) {
		t.Parallel()

		stmt := validVSAStatement()
		stmt.Predicate.TimeVerified = time.Now().
			Add(-25 * time.Hour).
			UTC().
			Format(time.RFC3339)

		result, err := vsa.Verify(mustMarshal(t, stmt), trustedPolicy(), testImageRef)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Check.Passed {
			t.Error("expected stale result for VSA older than max age")
		}

		if result.Check.Status != types.StatusWarn {
			t.Errorf("expected warn status for stale, got %q", result.Check.Status)
		}
	})

	t.Run("fresh VSA within max age", func(t *testing.T) {
		t.Parallel()

		stmt := validVSAStatement()
		stmt.Predicate.TimeVerified = time.Now().
			Add(-1 * time.Hour).
			UTC().
			Format(time.RFC3339)

		result, err := vsa.Verify(mustMarshal(t, stmt), trustedPolicy(), testImageRef)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !result.Check.Passed {
			t.Errorf("expected pass for VSA within max age, got: %s", result.Check.Detail)
		}
	})
}

func TestVerifyInvalidJSON(t *testing.T) {
	t.Parallel()

	_, err := vsa.Verify([]byte("not json"), trustedPolicy(), testImageRef)
	if !errors.Is(err, vsa.ErrInvalidVSA) {
		t.Errorf("expected ErrInvalidVSA, got %v", err)
	}
}

func TestVerifyResourceURIExactMatch(t *testing.T) {
	t.Parallel()

	stmt := validVSAStatement()
	stmt.Predicate.ResourceURI = testImageRef

	result, err := vsa.Verify(
		mustMarshal(t, stmt), trustedPolicy(), testImageRef,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Check.Passed {
		t.Errorf("expected pass for exact match, got: %s", result.Check.Detail)
	}
}

func TestVerifyResourceURINormalized(t *testing.T) {
	t.Parallel()

	pol := &policy.Policy{
		Trust: &policy.TrustPolicy{
			Verifiers: []policy.TrustedVerifier{
				{ID: testVerifierID, Key: testVerifierKey},
			},
		},
	}

	t.Run("tag normalization matches", func(t *testing.T) {
		t.Parallel()

		stmt := validVSAStatement()
		stmt.Predicate.ResourceURI = "docker.io/library/nginx:latest"

		result, err := vsa.Verify(mustMarshal(t, stmt), pol, "nginx:latest")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !result.Check.Passed {
			t.Errorf("expected pass for normalized tag match, got: %s", result.Check.Detail)
		}
	})

	t.Run("digest preserved in normalization", func(t *testing.T) {
		t.Parallel()

		stmt := validVSAStatement()
		stmt.Predicate.ResourceURI = testImageRef

		result, err := vsa.Verify(mustMarshal(t, stmt), pol, testImageRef)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !result.Check.Passed {
			t.Errorf("expected pass for digest match, got: %s", result.Check.Detail)
		}
	})

	t.Run("different digest rejected", func(t *testing.T) {
		t.Parallel()

		stmt := validVSAStatement()
		otherDigest := "sha256:" + strings.Repeat("0", 64)
		stmt.Predicate.ResourceURI = "docker.io/library/nginx@" + otherDigest

		result, err := vsa.Verify(mustMarshal(t, stmt), pol, testImageRef)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Check.Passed {
			t.Error("expected failure for different digest, got pass")
		}
	})
}

func TestVerifyCheckType(t *testing.T) {
	t.Parallel()

	stmt := validVSAStatement()

	result, err := vsa.Verify(mustMarshal(t, stmt), trustedPolicy(), testImageRef)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Check.Type != "vsa" {
		t.Errorf("expected type vsa, got %q", result.Check.Type)
	}
}

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

//nolint:testpackage // testing unexported functions
package notation

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/notaryproject/notation-core-go/signature"
	notationlib "github.com/notaryproject/notation-go"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	testImageDigest       = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	testImageRef          = "example.com/img@sha256:" + testImageDigest
	testDigest            = "sha256:" + testImageDigest
	testRuleName          = "rule1"
	testStoreName         = "mystore"
	testStoreRef          = "ca:mystore"
	testNotationMediaType = "application/cose"
	testCertPlaceholder   = "/tmp/cert.pem"
	testDocVersion        = "1.0"
	testLevelStrict       = "strict"
	testStoreRefAlt       = "ca:store1"
)

func validNotationPolicy(t *testing.T) *policy.NotationPolicy {
	t.Helper()

	certPath := writeTempCert(t)

	return &policy.NotationPolicy{
		TrustStores: []policy.NotationTrustStore{
			{
				Name:         testStoreName,
				Type:         "ca",
				Certificates: []string{certPath},
			},
		},
		TrustPolicy: []policy.NotationTrustPolicyRule{
			{
				Name:              "default-rule",
				RegistryScopes:    []string{"*"},
				TrustStores:       []string{testStoreRef},
				TrustedIdentities: []string{"*"},
			},
		},
	}
}

func TestBuildTrustPolicyDocument(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		np                *policy.NotationPolicy
		wantVersion       string
		wantLevel         string
		wantPoliciesCount int
	}{
		{
			name: "default verification level is strict",
			np: &policy.NotationPolicy{
				TrustPolicy: []policy.NotationTrustPolicyRule{
					{
						Name:              testRuleName,
						RegistryScopes:    []string{"*"},
						TrustStores:       []string{testStoreRefAlt},
						TrustedIdentities: []string{"*"},
					},
				},
			},
			wantVersion:       testDocVersion,
			wantLevel:         testLevelStrict,
			wantPoliciesCount: 1,
		},
		{
			name: "custom verification level permissive",
			np: &policy.NotationPolicy{
				VerificationLevel: "permissive",
				TrustPolicy: []policy.NotationTrustPolicyRule{
					{
						Name:              testRuleName,
						RegistryScopes:    []string{"*"},
						TrustStores:       []string{testStoreRefAlt},
						TrustedIdentities: []string{"*"},
					},
				},
			},
			wantVersion:       testDocVersion,
			wantLevel:         "permissive",
			wantPoliciesCount: 1,
		},
		{
			name: "custom verification level audit",
			np: &policy.NotationPolicy{
				VerificationLevel: "audit",
				TrustPolicy: []policy.NotationTrustPolicyRule{
					{
						Name:              testRuleName,
						RegistryScopes:    []string{"*"},
						TrustStores:       []string{testStoreRefAlt},
						TrustedIdentities: []string{"*"},
					},
				},
			},
			wantVersion:       testDocVersion,
			wantLevel:         "audit",
			wantPoliciesCount: 1,
		},
		{
			name: "custom verification level skip",
			np: &policy.NotationPolicy{
				VerificationLevel: "skip",
				TrustPolicy: []policy.NotationTrustPolicyRule{
					{
						Name:              testRuleName,
						RegistryScopes:    []string{"*"},
						TrustStores:       []string{testStoreRefAlt},
						TrustedIdentities: []string{"*"},
					},
				},
			},
			wantVersion:       testDocVersion,
			wantLevel:         "skip",
			wantPoliciesCount: 1,
		},
		{
			name: "multiple trust policy rules",
			np: &policy.NotationPolicy{
				TrustPolicy: []policy.NotationTrustPolicyRule{
					{
						Name:              testRuleName,
						RegistryScopes:    []string{"registry.example.com/*"},
						TrustStores:       []string{testStoreRefAlt},
						TrustedIdentities: []string{"*"},
					},
					{
						Name:              "rule2",
						RegistryScopes:    []string{"other.registry.io/*"},
						TrustStores:       []string{"signingAuthority:store2"},
						TrustedIdentities: []string{"x509.subject: CN=test"},
					},
				},
			},
			wantVersion:       testDocVersion,
			wantLevel:         testLevelStrict,
			wantPoliciesCount: 2,
		},
		{
			name: "empty trust policy results in empty policies",
			np: &policy.NotationPolicy{
				TrustPolicy: nil,
			},
			wantVersion:       testDocVersion,
			wantLevel:         testLevelStrict,
			wantPoliciesCount: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			doc := buildTrustPolicyDocument(tc.np)

			if doc.Version != tc.wantVersion {
				t.Errorf("version = %q, want %q", doc.Version, tc.wantVersion)
			}

			if len(doc.TrustPolicies) != tc.wantPoliciesCount {
				t.Fatalf("trust policies count = %d, want %d",
					len(doc.TrustPolicies), tc.wantPoliciesCount)
			}

			for _, tp := range doc.TrustPolicies {
				if tp.SignatureVerification.VerificationLevel != tc.wantLevel {
					t.Errorf("verification level = %q, want %q",
						tp.SignatureVerification.VerificationLevel, tc.wantLevel)
				}
			}
		})
	}
}

func TestBuildTrustPolicyDocumentFieldMapping(t *testing.T) {
	t.Parallel()

	np := &policy.NotationPolicy{
		TrustPolicy: []policy.NotationTrustPolicyRule{
			{
				Name:              "test-rule",
				RegistryScopes:    []string{"scope1", "scope2"},
				TrustStores:       []string{testStoreRefAlt, "signingAuthority:store2"},
				TrustedIdentities: []string{"id1", "id2"},
			},
		},
	}

	doc := buildTrustPolicyDocument(np)

	if len(doc.TrustPolicies) != 1 {
		t.Fatalf("expected 1 trust policy, got %d", len(doc.TrustPolicies))
	}

	tp := doc.TrustPolicies[0]

	if tp.Name != "test-rule" {
		t.Errorf("name = %q, want %q", tp.Name, "test-rule")
	}

	if len(tp.RegistryScopes) != 2 {
		t.Fatalf("registry scopes count = %d, want 2", len(tp.RegistryScopes))
	}

	if tp.RegistryScopes[0] != "scope1" || tp.RegistryScopes[1] != "scope2" {
		t.Errorf("registry scopes = %v, want [scope1 scope2]", tp.RegistryScopes)
	}

	if len(tp.TrustStores) != 2 {
		t.Fatalf("trust stores count = %d, want 2", len(tp.TrustStores))
	}

	if len(tp.TrustedIdentities) != 2 {
		t.Fatalf("trusted identities count = %d, want 2", len(tp.TrustedIdentities))
	}
}

func TestVerify(t *testing.T) {
	t.Parallel()

	testSig := &attestation.VerifiedAttestation{
		PredicateType:     attestation.NotationSignatureMediaType,
		Payload:           []byte("invalid-envelope"),
		Digest:            testDigest,
		SignatureType:     attestation.SignatureTypeNotation,
		NotationMediaType: testNotationMediaType,
	}

	tests := []struct {
		name     string
		pol      func(t *testing.T) *policy.Policy
		wantErr  error
		wantNil  bool
		wantPass bool
	}{
		{
			name: "nil notation policy returns ErrNotationNotConfigured",
			pol: func(t *testing.T) *policy.Policy {
				t.Helper()

				return &policy.Policy{}
			},
			wantErr:  ErrNotationNotConfigured,
			wantNil:  true,
			wantPass: false,
		},
		{
			name: "empty trust stores returns ErrNoTrustStores",
			pol: func(t *testing.T) *policy.Policy {
				t.Helper()

				return &policy.Policy{
					Sections: policy.Sections{
						Notation: &policy.NotationPolicy{
							TrustStores: nil,
							TrustPolicy: []policy.NotationTrustPolicyRule{
								{
									Name:              "rule",
									RegistryScopes:    []string{"*"},
									TrustStores:       []string{"ca:store"},
									TrustedIdentities: []string{"*"},
								},
							},
						},
					},
				}
			},
			wantErr:  ErrNoTrustStores,
			wantNil:  true,
			wantPass: false,
		},
		{
			name: "empty trust policy returns ErrNoTrustPolicy",
			pol: func(t *testing.T) *policy.Policy {
				t.Helper()

				return &policy.Policy{
					Sections: policy.Sections{
						Notation: &policy.NotationPolicy{
							TrustStores: []policy.NotationTrustStore{
								{
									Name:         "store",
									Type:         "ca",
									Certificates: []string{testCertPlaceholder},
								},
							},
							TrustPolicy: nil,
						},
					},
				}
			},
			wantErr:  ErrNoTrustPolicy,
			wantNil:  true,
			wantPass: false,
		},
		{
			name: "invalid envelope fails crypto verification",
			pol: func(t *testing.T) *policy.Policy {
				t.Helper()

				return &policy.Policy{
					Sections: policy.Sections{
						Notation: validNotationPolicy(t),
					},
				}
			},
			wantErr:  nil,
			wantNil:  false,
			wantPass: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			pol := tc.pol(t)

			result, err := Verify(ctx, testSig, testImageRef, testDigest, pol)

			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Errorf("error = %v, want %v", err, tc.wantErr)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tc.wantNil && result != nil {
				t.Errorf("expected nil result, got %+v", result)
			}

			if !tc.wantNil {
				if result == nil {
					t.Fatal("expected non-nil result, got nil")
				}

				if result.Passed != tc.wantPass {
					t.Errorf("passed = %v, want %v (detail: %s)",
						result.Passed, tc.wantPass, result.Detail)
				}
			}
		})
	}
}

func TestVerifyMultiple(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		signatures []attestation.VerifiedAttestation
		pol        func(t *testing.T) *policy.Policy
		wantErr    error
		wantNil    bool
		wantPass   bool
		wantDetail string
	}{
		{
			name:       "nil notation policy returns ErrNotationNotConfigured",
			signatures: nil,
			pol: func(t *testing.T) *policy.Policy {
				t.Helper()

				return &policy.Policy{}
			},
			wantErr:    ErrNotationNotConfigured,
			wantNil:    true,
			wantPass:   false,
			wantDetail: "",
		},
		{
			name:       "empty trust stores returns ErrNoTrustStores",
			signatures: nil,
			pol: func(t *testing.T) *policy.Policy {
				t.Helper()

				return &policy.Policy{
					Sections: policy.Sections{
						Notation: &policy.NotationPolicy{
							TrustStores: nil,
							TrustPolicy: []policy.NotationTrustPolicyRule{
								{
									Name:              "rule",
									RegistryScopes:    []string{"*"},
									TrustStores:       []string{"ca:store"},
									TrustedIdentities: []string{"*"},
								},
							},
						},
					},
				}
			},
			wantErr:    ErrNoTrustStores,
			wantNil:    true,
			wantPass:   false,
			wantDetail: "",
		},
		{
			name:       "empty trust policy returns ErrNoTrustPolicy",
			signatures: nil,
			pol: func(t *testing.T) *policy.Policy {
				t.Helper()

				return &policy.Policy{
					Sections: policy.Sections{
						Notation: &policy.NotationPolicy{
							TrustStores: []policy.NotationTrustStore{
								{
									Name:         "store",
									Type:         "ca",
									Certificates: []string{testCertPlaceholder},
								},
							},
							TrustPolicy: nil,
						},
					},
				}
			},
			wantErr:    ErrNoTrustPolicy,
			wantNil:    true,
			wantPass:   false,
			wantDetail: "",
		},
		{
			name:       "empty signatures returns fail result",
			signatures: []attestation.VerifiedAttestation{},
			pol: func(t *testing.T) *policy.Policy {
				t.Helper()

				return &policy.Policy{
					Sections: policy.Sections{
						Notation: validNotationPolicy(t),
					},
				}
			},
			wantErr:    nil,
			wantNil:    false,
			wantPass:   false,
			wantDetail: "no notation signatures found",
		},
		{
			name: "invalid signature envelope fails crypto verification",
			signatures: []attestation.VerifiedAttestation{
				{
					PredicateType:     attestation.NotationSignatureMediaType,
					Payload:           []byte("invalid-envelope"),
					Digest:            testDigest,
					SignatureType:     attestation.SignatureTypeNotation,
					NotationMediaType: testNotationMediaType,
				},
			},
			pol: func(t *testing.T) *policy.Policy {
				t.Helper()

				return &policy.Policy{
					Sections: policy.Sections{
						Notation: validNotationPolicy(t),
					},
				}
			},
			wantErr:    nil,
			wantNil:    false,
			wantPass:   false,
			wantDetail: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			pol := tc.pol(t)

			result, err := VerifyMultiple(ctx, tc.signatures, testImageRef, testDigest, pol)

			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Errorf("error = %v, want %v", err, tc.wantErr)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tc.wantNil && result != nil {
				t.Errorf("expected nil result, got %+v", result)
			}

			if !tc.wantNil {
				if result == nil {
					t.Fatal("expected non-nil result, got nil")
				}

				if result.Passed != tc.wantPass {
					t.Errorf("passed = %v, want %v (detail: %s)",
						result.Passed, tc.wantPass, result.Detail)
				}

				if tc.wantDetail != "" && result.Detail != tc.wantDetail {
					t.Errorf("detail = %q, want %q", result.Detail, tc.wantDetail)
				}
			}
		})
	}
}

func TestVerifySubjectDigestCrossCheck(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		sig           *attestation.VerifiedAttestation
		wantPass      bool
		wantDetailSub string
	}{
		{
			name: "empty subject digest returns no subject binding",
			sig: &attestation.VerifiedAttestation{
				PredicateType:         attestation.NotationSignatureMediaType,
				Payload:               []byte("invalid-envelope"),
				Digest:                testDigest,
				SignatureType:         attestation.SignatureTypeNotation,
				NotationMediaType:     testNotationMediaType,
				NotationSubjectDigest: "",
			},
			wantPass:      false,
			wantDetailSub: "signature has no subject binding",
		},
		{
			name: "mismatched subject digest returns does not match",
			sig: &attestation.VerifiedAttestation{
				PredicateType:         attestation.NotationSignatureMediaType,
				Payload:               []byte("invalid-envelope"),
				Digest:                testDigest,
				SignatureType:         attestation.SignatureTypeNotation,
				NotationMediaType:     testNotationMediaType,
				NotationSubjectDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			},
			wantPass:      false,
			wantDetailSub: "does not match",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			pol := &policy.Policy{
				Sections: policy.Sections{
					Notation: validNotationPolicy(t),
				},
			}

			result, err := Verify(ctx, tc.sig, testImageRef, testDigest, pol)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result == nil {
				t.Fatal("expected non-nil result, got nil")
			}

			if result.Passed != tc.wantPass {
				t.Errorf("passed = %v, want %v (detail: %s)",
					result.Passed, tc.wantPass, result.Detail)
			}

			if tc.wantDetailSub != "" && !strings.Contains(result.Detail, tc.wantDetailSub) {
				t.Errorf("detail = %q, want substring %q", result.Detail, tc.wantDetailSub)
			}
		})
	}
}

func TestPassResult(t *testing.T) {
	t.Parallel()

	result := passResult()

	if result.Type != types.CheckTypeNotation {
		t.Errorf("type = %q, want %q", result.Type, types.CheckTypeNotation)
	}

	if !result.Passed {
		t.Error("expected result to be passed")
	}

	if result.Status != types.StatusPass {
		t.Errorf("status = %q, want %q", result.Status, types.StatusPass)
	}

	const wantDetail = "Notation signature cryptographically verified"

	if result.Detail != wantDetail {
		t.Errorf("detail = %q, want %q", result.Detail, wantDetail)
	}
}

func TestFailResult(t *testing.T) {
	t.Parallel()

	detail := "signature mismatch"
	result := failResult(detail)

	if result.Type != types.CheckTypeNotation {
		t.Errorf("type = %q, want %q", result.Type, types.CheckTypeNotation)
	}

	if result.Passed {
		t.Error("expected result to not be passed")
	}

	if result.Status != types.StatusFail {
		t.Errorf("status = %q, want %q", result.Status, types.StatusFail)
	}

	if result.Detail != detail {
		t.Errorf("detail = %q, want %q", result.Detail, detail)
	}
}

func TestExtractSignerDN(t *testing.T) {
	t.Parallel()

	t.Run("nil outcome returns empty", func(t *testing.T) {
		t.Parallel()

		dn := extractSignerDN(nil)
		if dn != "" {
			t.Errorf("expected empty, got %q", dn)
		}
	})

	t.Run("nil envelope content returns empty", func(t *testing.T) {
		t.Parallel()

		outcome := &notationlib.VerificationOutcome{
			RawSignature:        nil,
			EnvelopeContent:     nil,
			VerificationLevel:   nil,
			VerificationResults: nil,
			Error:               nil,
		}
		dn := extractSignerDN(outcome)

		if dn != "" {
			t.Errorf("expected empty, got %q", dn)
		}
	})

	t.Run("empty certificate chain returns empty", func(t *testing.T) {
		t.Parallel()

		outcome := &notationlib.VerificationOutcome{
			RawSignature: nil,
			EnvelopeContent: &signature.EnvelopeContent{
				SignerInfo: signature.SignerInfo{
					SignedAttributes: signature.SignedAttributes{
						SigningScheme:      "",
						SigningTime:        time.Time{},
						Expiry:             time.Time{},
						ExtendedAttributes: nil,
					},
					UnsignedAttributes: signature.UnsignedAttributes{
						TimestampSignature: nil,
						SigningAgent:       "",
					},
					SignatureAlgorithm: 0,
					CertificateChain:   nil,
					Signature:          nil,
				},
				Payload: signature.Payload{
					ContentType: "",
					Content:     nil,
				},
			},
			VerificationLevel:   nil,
			VerificationResults: nil,
			Error:               nil,
		}
		dn := extractSignerDN(outcome)

		if dn != "" {
			t.Errorf("expected empty, got %q", dn)
		}
	})

	t.Run("certificate chain returns subject DN", func(t *testing.T) {
		t.Parallel()

		_, certPath := generateTestCert(t)

		certData, readErr := os.ReadFile(certPath) //nolint:gosec // test helper reads test cert
		if readErr != nil {
			t.Fatalf("reading cert: %v", readErr)
		}

		block, _ := pem.Decode(certData)

		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			t.Fatalf("parsing cert: %v", parseErr)
		}

		outcome := &notationlib.VerificationOutcome{
			RawSignature: nil,
			EnvelopeContent: &signature.EnvelopeContent{
				SignerInfo: signature.SignerInfo{
					SignedAttributes: signature.SignedAttributes{
						SigningScheme:      "",
						SigningTime:        time.Time{},
						Expiry:             time.Time{},
						ExtendedAttributes: nil,
					},
					UnsignedAttributes: signature.UnsignedAttributes{
						TimestampSignature: nil,
						SigningAgent:       "",
					},
					SignatureAlgorithm: 0,
					CertificateChain:   []*x509.Certificate{cert},
					Signature:          nil,
				},
				Payload: signature.Payload{
					ContentType: "",
					Content:     nil,
				},
			},
			VerificationLevel:   nil,
			VerificationResults: nil,
			Error:               nil,
		}
		dn := extractSignerDN(outcome)

		if !strings.Contains(dn, "CN=test-cert") {
			t.Errorf("expected DN containing CN=test-cert, got %q", dn)
		}
	})
}

func TestBuildVerifierForImageReturnsTrustPolicyName(t *testing.T) {
	t.Parallel()

	notationPolicy := validNotationPolicy(t)

	_, trustPolicyName, err := buildVerifierForImage(notationPolicy, testImageRef)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if trustPolicyName != "default-rule" {
		t.Errorf("trust policy name = %q, want %q", trustPolicyName, "default-rule")
	}
}

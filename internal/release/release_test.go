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

package release_test

import (
	"context"
	"errors"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/intoto"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/release"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	testDigest          = "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	testPredicateType   = "https://in-toto.io/attestation/release/v0.1"
	testPURL            = "pkg:oci/myimage@sha256:abc123?repository_url=ghcr.io/example"
	testPackageID       = "example-package-id"
	testTrustedRegistry = "pkg:oci/**"
)

type relPredicate struct {
	PURL      string `json:"purl"`
	PackageID string `json:"packageId,omitempty"` //nolint:tagliatelle // matches spec
}

func validPredicate() relPredicate {
	return relPredicate{
		PURL:      testPURL,
		PackageID: testPackageID,
	}
}

func TestVerify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		doc        relPredicate
		pol        *policy.Policy
		wantPassed bool
		wantStatus types.CheckStatus
	}{
		{
			name:       "valid release with no policy passes",
			doc:        validPredicate(),
			pol:        &policy.Policy{},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name: "trusted registry pattern passes",
			doc:  validPredicate(),
			pol: &policy.Policy{
				Release: &policy.ReleasePolicy{
					TrustedRegistries: []string{testTrustedRegistry},
				},
			},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name: "untrusted registry pattern fails",
			doc:  validPredicate(),
			pol: &policy.Policy{
				Release: &policy.ReleasePolicy{
					TrustedRegistries: []string{"pkg:npm/*"},
				},
			},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name: "requirePackageId passes when present",
			doc:  validPredicate(),
			pol: &policy.Policy{
				Release: &policy.ReleasePolicy{
					RequirePackageID: true,
				},
			},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name: "requirePackageId fails when missing",
			doc: relPredicate{ //nolint:exhaustruct_v5 // test omits PackageID
				PURL: testPURL,
			},
			pol: &policy.Policy{
				Release: &policy.ReleasePolicy{
					RequirePackageID: true,
				},
			},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			att := testutil.WrapInToto(t, test.doc, testDigest, testPredicateType)

			result, err := release.Verify(context.Background(), att, test.pol, testDigest)
			testutil.AssertNoError(t, err)

			testutil.AssertEqual(t, test.wantPassed, result.Passed)
			testutil.AssertEqual(t, test.wantStatus, result.Status)
		})
	}
}

func TestVerifyCheckType(t *testing.T) {
	t.Parallel()

	att := testutil.WrapInToto(t, validPredicate(), testDigest, testPredicateType)

	result, err := release.Verify(context.Background(), att, &policy.Policy{}, testDigest)
	testutil.AssertNoError(t, err)

	testutil.AssertEqual(t, types.CheckType("release"), result.Type)
}

func TestVerifyMetadata(t *testing.T) {
	t.Parallel()

	att := testutil.WrapInToto(t, validPredicate(), testDigest, testPredicateType)

	result, err := release.Verify(context.Background(), att, &policy.Policy{}, testDigest)
	testutil.AssertNoError(t, err)

	if result.Metadata == nil {
		t.Fatal("expected metadata on release result")
	}

	purl, ok := result.Metadata["purl"].(string)
	if !ok || purl != testPURL {
		t.Errorf("purl = %v, want %s", result.Metadata["purl"], testPURL)
	}

	packageID, ok := result.Metadata["packageId"].(string)
	if !ok || packageID != testPackageID {
		t.Errorf("packageId = %v, want %s", result.Metadata["packageId"], testPackageID)
	}
}

func TestVerifyMalformedPayloads(t *testing.T) {
	t.Parallel()

	t.Run("empty payload", func(t *testing.T) {
		t.Parallel()

		_, err := release.Verify(context.Background(), []byte{}, &policy.Policy{}, testDigest)
		if !errors.Is(err, release.ErrInvalidRelease) {
			t.Errorf("expected ErrInvalidRelease, got %v", err)
		}
	})

	t.Run("nil payload", func(t *testing.T) {
		t.Parallel()

		_, err := release.Verify(context.Background(), nil, &policy.Policy{}, testDigest)
		if !errors.Is(err, release.ErrInvalidRelease) {
			t.Errorf("expected ErrInvalidRelease, got %v", err)
		}
	})

	t.Run("truncated JSON", func(t *testing.T) {
		t.Parallel()

		_, err := release.Verify(
			context.Background(), []byte(`{"subject":[`), &policy.Policy{}, testDigest,
		)
		if !errors.Is(err, release.ErrInvalidRelease) {
			t.Errorf("expected ErrInvalidRelease, got %v", err)
		}
	})
}

func TestVerifySubjectEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("subject with mismatched digest", func(t *testing.T) {
		t.Parallel()

		att := testutil.WrapInToto(t, validPredicate(), testDigest, testPredicateType)

		_, err := release.Verify(context.Background(),
			att, &policy.Policy{},
			"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		)
		if !errors.Is(err, intoto.ErrSubjectMismatch) {
			t.Errorf("expected ErrSubjectMismatch, got %v", err)
		}
	})

	t.Run("empty digest with subjects rejects for binding", func(t *testing.T) {
		t.Parallel()

		att := testutil.WrapInToto(t, validPredicate(), testDigest, testPredicateType)

		_, err := release.Verify(context.Background(), att, &policy.Policy{}, "")
		if !errors.Is(err, intoto.ErrNoDigestBinding) {
			t.Errorf("expected ErrNoDigestBinding, got %v", err)
		}
	})
}

func TestVerifyMultiple(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		docs       []relPredicate
		pol        *policy.Policy
		wantPassed bool
		wantStatus types.CheckStatus
	}{
		{
			name:       "single valid passes",
			docs:       []relPredicate{validPredicate()},
			pol:        &policy.Policy{},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name: "any valid passing attestation passes",
			docs: []relPredicate{
				validPredicate(),
				{ //nolint:exhaustruct_v5 // test omits PackageID
					PURL: "pkg:npm/untrusted@1.0",
				},
			},
			pol: &policy.Policy{
				Release: &policy.ReleasePolicy{
					TrustedRegistries: []string{testTrustedRegistry},
				},
			},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name: "all failing fails",
			docs: []relPredicate{
				{ //nolint:exhaustruct_v5 // test omits PackageID
					PURL: "pkg:npm/untrusted@1.0",
				},
			},
			pol: &policy.Policy{
				Release: &policy.ReleasePolicy{
					TrustedRegistries: []string{testTrustedRegistry},
				},
			},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name:       "empty attestation list fails",
			docs:       []relPredicate{},
			pol:        &policy.Policy{},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			attestations := make([][]byte, len(test.docs))
			for idx := range test.docs {
				attestations[idx] = testutil.WrapInToto(
					t, test.docs[idx], testDigest, testPredicateType,
				)
			}

			result, err := release.VerifyMultiple(
				context.Background(),
				attestations,
				test.pol,
				testDigest,
			)
			testutil.AssertNoError(t, err)

			testutil.AssertEqual(t, test.wantPassed, result.Passed)
			testutil.AssertEqual(t, test.wantStatus, result.Status)
		})
	}
}

func TestVerifyMultipleEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("nil attestation slice fails", func(t *testing.T) {
		t.Parallel()

		result, err := release.VerifyMultiple(
			context.Background(),
			nil,
			&policy.Policy{},
			testDigest,
		)
		testutil.AssertNoError(t, err)

		if result.Passed {
			t.Errorf("expected fail for nil attestation slice, got: %s", result.Detail)
		}

		testutil.AssertEqual(t, types.StatusFail, result.Status)
	})

	t.Run("all invalid returns fail with parse errors", func(t *testing.T) {
		t.Parallel()

		attestations := [][]byte{
			[]byte("bad json 1"),
			[]byte("bad json 2"),
		}

		result, err := release.VerifyMultiple(
			context.Background(),
			attestations,
			&policy.Policy{},
			testDigest,
		)
		testutil.AssertNoError(t, err)

		if result.Passed {
			t.Error("expected fail when all documents are invalid")
		}

		testutil.AssertEqual(t, types.StatusFail, result.Status)
	})

	t.Run("mix of valid and invalid with valid passing", func(t *testing.T) {
		t.Parallel()

		attestations := [][]byte{
			[]byte("invalid json"),
			testutil.WrapInToto(t, validPredicate(), testDigest, testPredicateType),
		}

		result, err := release.VerifyMultiple(
			context.Background(),
			attestations,
			&policy.Policy{},
			testDigest,
		)
		testutil.AssertNoError(t, err)

		if !result.Passed {
			t.Errorf("expected pass with valid doc, got: %s", result.Detail)
		}
	})
}

func TestVerifyEmptyPURL(t *testing.T) {
	t.Parallel()

	doc := relPredicate{ //nolint:exhaustruct_v5 // test omits PackageID
		PURL: "",
	}
	att := testutil.WrapInToto(t, doc, testDigest, testPredicateType)

	t.Run("empty purl with no policy passes", func(t *testing.T) {
		t.Parallel()

		result, err := release.Verify(context.Background(), att, &policy.Policy{}, testDigest)
		testutil.AssertNoError(t, err)

		if !result.Passed {
			t.Errorf("expected pass for empty purl with no policy, got: %s", result.Detail)
		}
	})

	t.Run("empty purl with trusted registries fails", func(t *testing.T) {
		t.Parallel()

		result, err := release.Verify(context.Background(), att, &policy.Policy{
			Release: &policy.ReleasePolicy{
				TrustedRegistries: []string{testTrustedRegistry},
			},
		}, testDigest)
		testutil.AssertNoError(t, err)

		if result.Passed {
			t.Error("expected fail for empty purl with trusted registries")
		}
	})
}

func TestVerifyUntrustedRegistryDetailMessage(t *testing.T) {
	t.Parallel()

	att := testutil.WrapInToto(t, validPredicate(), testDigest, testPredicateType)

	result, err := release.Verify(context.Background(), att, &policy.Policy{
		Release: &policy.ReleasePolicy{
			TrustedRegistries: []string{"pkg:npm/*"},
		},
	}, testDigest)
	testutil.AssertNoError(t, err)

	if result.Passed {
		t.Fatal("expected fail")
	}

	if result.Metadata == nil {
		t.Fatal("expected metadata on failed result")
	}

	purl, ok := result.Metadata["purl"].(string)
	if !ok || purl != testPURL {
		t.Errorf("purl metadata = %v, want %s", result.Metadata["purl"], testPURL)
	}
}

func TestVerifyCancelledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := release.Verify(ctx, nil, nil, "")
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}

	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

func TestVerifyMultipleCancelledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := release.VerifyMultiple(ctx, [][]byte{[]byte("a")}, nil, "")
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}

	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

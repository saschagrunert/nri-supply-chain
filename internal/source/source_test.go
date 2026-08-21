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

package source_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/intoto"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/source"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	testDigest         = "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	testDigestAlgo     = "sha256"
	testInTotoType     = "https://in-toto.io/Statement/v1"
	testSubjectName    = "test-image"
	testPredicateType  = "https://slsa.dev/source/v1"
	testSourceURI      = "https://github.com/example/repo"
	testSourceBranch   = "main"
	testTrustedPattern = "https://github.com/example/*"
)

type inTotoWrapper struct {
	Type          string          `json:"_type"` //nolint:tagliatelle // In-toto spec field name.
	Subject       []inTotoSubj    `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

type inTotoSubj struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type srcPredicate struct {
	SourceLocations []srcLocation `json:"sourceLocations"`
	SourceMetadata  *srcMetadata  `json:"sourceMetadata,omitempty"`
}

type srcLocation struct {
	URI    string            `json:"uri"`
	Digest map[string]string `json:"digest,omitempty"`
	Branch string            `json:"branch,omitempty"`
}

type srcMetadata struct {
	SourceLevel int        `json:"sourceLevel,omitempty"`
	VerifiedOn  *time.Time `json:"verifiedOn,omitempty"`
}

func validPredicate() srcPredicate {
	return srcPredicate{
		SourceLocations: []srcLocation{
			{ //nolint:exhaustruct_v5 // test only needs URI+Branch
				URI:    testSourceURI,
				Branch: testSourceBranch,
			},
		},
		SourceMetadata: &srcMetadata{ //nolint:exhaustruct_v5 // test only needs SourceLevel
			SourceLevel: 2,
		},
	}
}

func wrapInToto(t *testing.T, doc any, digest string) []byte {
	t.Helper()

	predBytes := testutil.MustMarshal(t, doc)

	wrapper := inTotoWrapper{
		Type: testInTotoType,
		Subject: []inTotoSubj{
			{
				Name:   testSubjectName,
				Digest: map[string]string{testDigestAlgo: digest[len(testDigestAlgo)+1:]},
			},
		},
		PredicateType: testPredicateType,
		Predicate:     predBytes,
	}

	return testutil.MustMarshal(t, wrapper)
}

func TestVerify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		doc        srcPredicate
		pol        *policy.Policy
		wantPassed bool
		wantStatus types.CheckStatus
	}{
		{
			name:       "valid source with no policy passes",
			doc:        validPredicate(),
			pol:        &policy.Policy{},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name: "trusted source pattern passes",
			doc:  validPredicate(),
			pol: &policy.Policy{
				Trust: &policy.TrustPolicy{
					Sources: []string{testTrustedPattern},
				},
			},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name: "untrusted source pattern fails",
			doc:  validPredicate(),
			pol: &policy.Policy{
				Trust: &policy.TrustPolicy{
					Sources: []string{"https://github.com/other/*"},
				},
			},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name: "source level meets minimum passes",
			doc:  validPredicate(),
			pol: &policy.Policy{
				Source: &policy.SourcePolicy{
					MinimumLevel: 2,
				},
			},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name: "source level below minimum fails",
			doc:  validPredicate(),
			pol: &policy.Policy{
				Source: &policy.SourcePolicy{
					MinimumLevel: 3,
				},
			},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name: "no source metadata defaults level to zero",
			doc: srcPredicate{ //nolint:exhaustruct_v5 // test omits SourceMetadata
				SourceLocations: []srcLocation{
					{ //nolint:exhaustruct_v5 // test only needs URI+Branch
						URI:    testSourceURI,
						Branch: testSourceBranch,
					},
				},
			},
			pol: &policy.Policy{
				Source: &policy.SourcePolicy{
					MinimumLevel: 1,
				},
			},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name: "empty source locations with trust policy and no URI fails",
			doc: srcPredicate{ //nolint:exhaustruct_v5 // test omits SourceMetadata
				SourceLocations: []srcLocation{},
			},
			pol: &policy.Policy{
				Trust: &policy.TrustPolicy{
					Sources: []string{testTrustedPattern},
				},
			},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			att := wrapInToto(t, test.doc, testDigest)

			result, err := source.Verify(context.Background(), att, test.pol, testDigest)
			testutil.AssertNoError(t, err)

			testutil.AssertEqual(t, test.wantPassed, result.Passed)
			testutil.AssertEqual(t, test.wantStatus, result.Status)
		})
	}
}

func TestVerifyCheckType(t *testing.T) {
	t.Parallel()

	att := wrapInToto(t, validPredicate(), testDigest)

	result, err := source.Verify(context.Background(), att, &policy.Policy{}, testDigest)
	testutil.AssertNoError(t, err)

	testutil.AssertEqual(t, types.CheckType("source"), result.Type)
}

func TestVerifyMetadata(t *testing.T) {
	t.Parallel()

	att := wrapInToto(t, validPredicate(), testDigest)

	result, err := source.Verify(context.Background(), att, &policy.Policy{}, testDigest)
	testutil.AssertNoError(t, err)

	if result.Metadata == nil {
		t.Fatal("expected metadata on source result")
	}

	srcURI, ok := result.Metadata["source"].(string)
	if !ok || srcURI != testSourceURI {
		t.Errorf("source = %v, want %s", result.Metadata["source"], testSourceURI)
	}

	branch, ok := result.Metadata["branch"].(string)
	if !ok || branch != testSourceBranch {
		t.Errorf("branch = %v, want %s", result.Metadata["branch"], testSourceBranch)
	}

	level, ok := result.Metadata["level"].(int64)
	if !ok || level != 2 {
		t.Errorf("level = %v, want 2", result.Metadata["level"])
	}
}

func TestVerifyMalformedPayloads(t *testing.T) {
	t.Parallel()

	t.Run("empty payload", func(t *testing.T) {
		t.Parallel()

		_, err := source.Verify(context.Background(), []byte{}, &policy.Policy{}, testDigest)
		if !errors.Is(err, source.ErrInvalidSource) {
			t.Errorf("expected ErrInvalidSource, got %v", err)
		}
	})

	t.Run("nil payload", func(t *testing.T) {
		t.Parallel()

		_, err := source.Verify(context.Background(), nil, &policy.Policy{}, testDigest)
		if !errors.Is(err, source.ErrInvalidSource) {
			t.Errorf("expected ErrInvalidSource, got %v", err)
		}
	})

	t.Run("truncated JSON", func(t *testing.T) {
		t.Parallel()

		_, err := source.Verify(
			context.Background(), []byte(`{"subject":[`), &policy.Policy{}, testDigest,
		)
		if !errors.Is(err, source.ErrInvalidSource) {
			t.Errorf("expected ErrInvalidSource, got %v", err)
		}
	})
}

func TestVerifySubjectEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("subject with mismatched digest", func(t *testing.T) {
		t.Parallel()

		att := wrapInToto(t, validPredicate(), testDigest)

		_, err := source.Verify(context.Background(),
			att, &policy.Policy{},
			"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		)
		if !errors.Is(err, intoto.ErrSubjectMismatch) {
			t.Errorf("expected ErrSubjectMismatch, got %v", err)
		}
	})

	t.Run("empty digest with subjects rejects for binding", func(t *testing.T) {
		t.Parallel()

		att := wrapInToto(t, validPredicate(), testDigest)

		_, err := source.Verify(context.Background(), att, &policy.Policy{}, "")
		if !errors.Is(err, intoto.ErrNoDigestBinding) {
			t.Errorf("expected ErrNoDigestBinding, got %v", err)
		}
	})
}

func TestVerifyUntrustedSourceDetailMessage(t *testing.T) {
	t.Parallel()

	att := wrapInToto(t, validPredicate(), testDigest)

	result, err := source.Verify(context.Background(), att, &policy.Policy{
		Trust: &policy.TrustPolicy{
			Sources: []string{"https://github.com/other/*"},
		},
	}, testDigest)
	testutil.AssertNoError(t, err)

	if result.Passed {
		t.Fatal("expected fail")
	}

	if !strings.Contains(result.Detail, "untrusted") {
		t.Errorf("expected detail to mention untrusted, got %q", result.Detail)
	}

	if !strings.Contains(result.Detail, testSourceURI) {
		t.Errorf("expected detail to contain source URI, got %q", result.Detail)
	}
}

func TestVerifyLevelDetailMessage(t *testing.T) {
	t.Parallel()

	att := wrapInToto(t, validPredicate(), testDigest)

	result, err := source.Verify(context.Background(), att, &policy.Policy{
		Source: &policy.SourcePolicy{
			MinimumLevel: 3,
		},
	}, testDigest)
	testutil.AssertNoError(t, err)

	if result.Passed {
		t.Fatal("expected fail")
	}

	if !strings.Contains(result.Detail, "below minimum") {
		t.Errorf("expected detail to mention level, got %q", result.Detail)
	}
}

func TestVerifyMultiple(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		docs       []srcPredicate
		pol        *policy.Policy
		wantPassed bool
		wantStatus types.CheckStatus
	}{
		{
			name:       "single valid passes",
			docs:       []srcPredicate{validPredicate()},
			pol:        &policy.Policy{},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name: "any valid passing attestation passes",
			docs: []srcPredicate{
				validPredicate(),
				{ //nolint:exhaustruct_v5 // test omits SourceMetadata
					SourceLocations: []srcLocation{
						{ //nolint:exhaustruct_v5 // test only needs URI
							URI: "https://github.com/untrusted/repo",
						},
					},
				},
			},
			pol: &policy.Policy{
				Trust: &policy.TrustPolicy{
					Sources: []string{testTrustedPattern},
				},
			},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name: "all failing fails",
			docs: []srcPredicate{
				{ //nolint:exhaustruct_v5 // test omits SourceMetadata
					SourceLocations: []srcLocation{
						{ //nolint:exhaustruct_v5 // test only needs URI
							URI: "https://github.com/untrusted/repo",
						},
					},
				},
			},
			pol: &policy.Policy{
				Trust: &policy.TrustPolicy{
					Sources: []string{testTrustedPattern},
				},
			},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name:       "empty attestation list fails",
			docs:       []srcPredicate{},
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
				attestations[idx] = wrapInToto(t, test.docs[idx], testDigest)
			}

			result, err := source.VerifyMultiple(
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

		result, err := source.VerifyMultiple(
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

		result, err := source.VerifyMultiple(
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
			wrapInToto(t, validPredicate(), testDigest),
		}

		result, err := source.VerifyMultiple(
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

func TestVerifyEmptySourceLocations(t *testing.T) {
	t.Parallel()

	doc := srcPredicate{ //nolint:exhaustruct_v5 // test omits SourceMetadata
		SourceLocations: []srcLocation{},
	}
	att := wrapInToto(t, doc, testDigest)

	t.Run("empty locations with no policy passes", func(t *testing.T) {
		t.Parallel()

		result, err := source.Verify(context.Background(), att, &policy.Policy{}, testDigest)
		testutil.AssertNoError(t, err)

		if !result.Passed {
			t.Errorf("expected pass for empty locations, got: %s", result.Detail)
		}

		srcURI, ok := result.Metadata["source"].(string)
		if !ok || srcURI != "" {
			t.Errorf("source = %v, want empty string", result.Metadata["source"])
		}
	})

	t.Run("empty locations with level requirement fails", func(t *testing.T) {
		t.Parallel()

		result, err := source.Verify(context.Background(), att, &policy.Policy{
			Source: &policy.SourcePolicy{
				MinimumLevel: 1,
			},
		}, testDigest)
		testutil.AssertNoError(t, err)

		if result.Passed {
			t.Error("expected fail for empty locations with level requirement")
		}
	})
}

func TestVerifyFreshness(t *testing.T) {
	t.Parallel()

	staleTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	freshTime := time.Now().Add(-10 * time.Minute).UTC()

	tests := []struct {
		name       string
		doc        srcPredicate
		pol        *policy.Policy
		wantPassed bool
		wantSubstr string
	}{
		{
			name: "stale source fails",
			doc: srcPredicate{
				SourceLocations: []srcLocation{
					{ //nolint:exhaustruct_v5 // test omits Digest
						URI:    testSourceURI,
						Branch: testSourceBranch,
					},
				},
				SourceMetadata: &srcMetadata{
					SourceLevel: 2,
					VerifiedOn:  &staleTime,
				},
			},
			pol: &policy.Policy{
				Source: &policy.SourcePolicy{
					MaxAge:         "1h",
					MaxAgeDuration: time.Hour,
				},
			},
			wantPassed: false,
			wantSubstr: "stale",
		},
		{
			name: "fresh source passes",
			doc: srcPredicate{
				SourceLocations: []srcLocation{
					{ //nolint:exhaustruct_v5 // test omits Digest
						URI:    testSourceURI,
						Branch: testSourceBranch,
					},
				},
				SourceMetadata: &srcMetadata{
					SourceLevel: 2,
					VerifiedOn:  &freshTime,
				},
			},
			pol: &policy.Policy{
				Source: &policy.SourcePolicy{
					MaxAge:         "1h",
					MaxAgeDuration: time.Hour,
				},
			},
			wantPassed: true,
			wantSubstr: "",
		},
		{
			name: "no timestamp with maxAge fails",
			doc:  validPredicate(),
			pol: &policy.Policy{
				Source: &policy.SourcePolicy{
					MaxAge:         "1h",
					MaxAgeDuration: time.Hour,
				},
			},
			wantPassed: false,
			wantSubstr: "no verified timestamp",
		},
		{
			name:       "no timestamp without maxAge passes",
			doc:        validPredicate(),
			pol:        &policy.Policy{},
			wantPassed: true,
			wantSubstr: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			att := wrapInToto(t, test.doc, testDigest)

			result, err := source.Verify(context.Background(), att, test.pol, testDigest)
			testutil.AssertNoError(t, err)

			testutil.AssertEqual(t, test.wantPassed, result.Passed)

			if test.wantSubstr != "" && !strings.Contains(result.Detail, test.wantSubstr) {
				t.Errorf("expected detail to contain %q, got %q", test.wantSubstr, result.Detail)
			}
		})
	}
}

func TestVerifyCancelledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := source.Verify(ctx, nil, nil, "")
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

	_, err := source.VerifyMultiple(ctx, [][]byte{[]byte("a")}, nil, "")
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}

	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

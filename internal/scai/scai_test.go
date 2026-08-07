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

package scai_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/intoto"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/scai"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	testDigest              = "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	testDigestAlgo          = "sha256"
	testInTotoType          = "https://in-toto.io/Statement/v1"
	testSubjectName         = "test-image"
	testPredicateType       = "https://in-toto.io/attestation/scai/v0.3"
	testAttrCodeReview      = "PASSED_CODE_REVIEW"
	testAttrPassedTests     = "PASSED_TESTS"
	testAttrFuzzTested      = "FUZZ_TESTED"
	testAttrKnownVulnerable = "KNOWN_VULNERABLE"
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

type scaiReport struct {
	Attributes []scaiAttribute `json:"attributes"`
}

type scaiAttribute struct {
	Attribute string          `json:"attribute"`
	Evidence  json.RawMessage `json:"evidence,omitempty"`
}

func validReport() scaiReport {
	return scaiReport{
		Attributes: []scaiAttribute{
			{
				Attribute: testAttrCodeReview,
				Evidence:  json.RawMessage(`{"url":"https://review.example.com/123"}`),
			},
			{
				Attribute: testAttrPassedTests,
				Evidence:  json.RawMessage(`{"url":"https://ci.example.com/456"}`),
			},
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
		doc        scaiReport
		pol        *policy.Policy
		wantPassed bool
		wantStatus types.CheckStatus
	}{
		{
			name:       "valid report with no policy passes",
			doc:        validReport(),
			pol:        &policy.Policy{},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name: "required attribute present passes",
			doc:  validReport(),
			pol: &policy.Policy{
				Sections: policy.Sections{
					SCAI: &policy.SCAIPolicy{
						RequiredAttributes: []string{testAttrCodeReview},
					},
				},
			},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name: "required attribute missing fails",
			doc:  validReport(),
			pol: &policy.Policy{
				Sections: policy.Sections{
					SCAI: &policy.SCAIPolicy{
						RequiredAttributes: []string{testAttrFuzzTested},
					},
				},
			},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name: "forbidden attribute absent passes",
			doc:  validReport(),
			pol: &policy.Policy{
				Sections: policy.Sections{
					SCAI: &policy.SCAIPolicy{
						ForbiddenAttributes: []string{testAttrKnownVulnerable},
					},
				},
			},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name: "forbidden attribute present fails",
			doc:  validReport(),
			pol: &policy.Policy{
				Sections: policy.Sections{
					SCAI: &policy.SCAIPolicy{
						ForbiddenAttributes: []string{testAttrPassedTests},
					},
				},
			},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name: "require evidence passes when all have evidence",
			doc:  validReport(),
			pol: &policy.Policy{
				Sections: policy.Sections{
					SCAI: &policy.SCAIPolicy{
						RequireEvidence: true,
					},
				},
			},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name: "require evidence fails when attribute lacks evidence",
			doc: scaiReport{
				Attributes: []scaiAttribute{
					{Attribute: testAttrCodeReview, Evidence: nil},
				},
			},
			pol: &policy.Policy{
				Sections: policy.Sections{
					SCAI: &policy.SCAIPolicy{
						RequireEvidence: true,
					},
				},
			},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name: "attribute matching is case-insensitive",
			doc:  validReport(),
			pol: &policy.Policy{
				Sections: policy.Sections{
					SCAI: &policy.SCAIPolicy{
						RequiredAttributes: []string{"passed_code_review"},
					},
				},
			},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			att := wrapInToto(t, test.doc, testDigest)

			result, err := scai.Verify(context.Background(), att, test.pol, testDigest)
			testutil.AssertNoError(t, err)

			testutil.AssertEqual(t, test.wantPassed, result.Passed)
			testutil.AssertEqual(t, test.wantStatus, result.Status)
		})
	}
}

func TestVerifyCheckType(t *testing.T) {
	t.Parallel()

	att := wrapInToto(t, validReport(), testDigest)

	result, err := scai.Verify(context.Background(), att, &policy.Policy{}, testDigest)
	testutil.AssertNoError(t, err)

	testutil.AssertEqual(t, types.CheckType("scai"), result.Type)
}

func TestVerifyMetadata(t *testing.T) {
	t.Parallel()

	att := wrapInToto(t, validReport(), testDigest)

	result, err := scai.Verify(context.Background(), att, &policy.Policy{}, testDigest)
	testutil.AssertNoError(t, err)

	if result.Metadata == nil {
		t.Fatal("expected metadata on SCAI result")
	}

	attrCount, ok := result.Metadata["attributeCount"].(int64)
	if !ok || attrCount != 2 {
		t.Errorf("attributeCount = %v, want 2", result.Metadata["attributeCount"])
	}

	attrs, ok := result.Metadata["attributes"].(string)
	if !ok {
		t.Fatal("expected attributes to be a string")
	}

	if !strings.Contains(attrs, testAttrCodeReview) {
		t.Errorf("attributes = %q, want to contain PASSED_CODE_REVIEW", attrs)
	}

	hasEvidence, ok := result.Metadata["hasEvidence"].(bool)
	if !ok || !hasEvidence {
		t.Errorf("hasEvidence = %v, want true", result.Metadata["hasEvidence"])
	}
}

func TestVerifyMalformedPayloads(t *testing.T) {
	t.Parallel()

	t.Run("empty payload", func(t *testing.T) {
		t.Parallel()

		_, err := scai.Verify(context.Background(), []byte{}, &policy.Policy{}, testDigest)
		if !errors.Is(err, scai.ErrInvalidSCAI) {
			t.Errorf("expected ErrInvalidSCAI, got %v", err)
		}
	})

	t.Run("nil payload", func(t *testing.T) {
		t.Parallel()

		_, err := scai.Verify(context.Background(), nil, &policy.Policy{}, testDigest)
		if !errors.Is(err, scai.ErrInvalidSCAI) {
			t.Errorf("expected ErrInvalidSCAI, got %v", err)
		}
	})

	t.Run("truncated JSON", func(t *testing.T) {
		t.Parallel()

		_, err := scai.Verify(
			context.Background(), []byte(`{"subject":[`), &policy.Policy{}, testDigest,
		)
		if !errors.Is(err, scai.ErrInvalidSCAI) {
			t.Errorf("expected ErrInvalidSCAI, got %v", err)
		}
	})
}

func TestVerifySubjectEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("subject with mismatched digest", func(t *testing.T) {
		t.Parallel()

		att := wrapInToto(t, validReport(), testDigest)

		_, err := scai.Verify(context.Background(),
			att, &policy.Policy{},
			"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		)
		if !errors.Is(err, intoto.ErrSubjectMismatch) {
			t.Errorf("expected ErrSubjectMismatch, got %v", err)
		}
	})

	t.Run("empty digest with subjects rejects for binding", func(t *testing.T) {
		t.Parallel()

		att := wrapInToto(t, validReport(), testDigest)

		_, err := scai.Verify(context.Background(), att, &policy.Policy{}, "")
		if !errors.Is(err, intoto.ErrNoDigestBinding) {
			t.Errorf("expected ErrNoDigestBinding, got %v", err)
		}
	})
}

func TestVerifyEvidenceEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("null evidence counts as missing", func(t *testing.T) {
		t.Parallel()

		doc := scaiReport{
			Attributes: []scaiAttribute{
				{Attribute: testAttrPassedTests, Evidence: json.RawMessage("null")},
			},
		}
		att := wrapInToto(t, doc, testDigest)

		result, err := scai.Verify(context.Background(), att, &policy.Policy{
			Sections: policy.Sections{
				SCAI: &policy.SCAIPolicy{RequireEvidence: true},
			},
		}, testDigest)
		testutil.AssertNoError(t, err)

		if result.Passed {
			t.Error("expected fail: null evidence should count as missing")
		}
	})

	t.Run("empty object evidence counts as missing", func(t *testing.T) {
		t.Parallel()

		doc := scaiReport{
			Attributes: []scaiAttribute{
				{Attribute: testAttrPassedTests, Evidence: json.RawMessage("{}")},
			},
		}
		att := wrapInToto(t, doc, testDigest)

		result, err := scai.Verify(context.Background(), att, &policy.Policy{
			Sections: policy.Sections{
				SCAI: &policy.SCAIPolicy{RequireEvidence: true},
			},
		}, testDigest)
		testutil.AssertNoError(t, err)

		if result.Passed {
			t.Error("expected fail: empty object evidence should count as missing")
		}
	})
}

func TestVerifyMultiple(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		docs       []scaiReport
		pol        *policy.Policy
		wantPassed bool
		wantStatus types.CheckStatus
	}{
		{
			name:       "all pass",
			docs:       []scaiReport{validReport()},
			pol:        &policy.Policy{},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name: "any forbidden attribute fails",
			docs: []scaiReport{validReport()},
			pol: &policy.Policy{
				Sections: policy.Sections{
					SCAI: &policy.SCAIPolicy{
						ForbiddenAttributes: []string{testAttrPassedTests},
					},
				},
			},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name:       "empty attestation list",
			docs:       []scaiReport{},
			pol:        &policy.Policy{},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			attestations := make([][]byte, len(test.docs))
			for idx := range test.docs {
				attestations[idx] = wrapInToto(t, test.docs[idx], testDigest)
			}

			result, err := scai.VerifyMultiple(
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

func TestVerifyMultipleMergesMetadata(t *testing.T) {
	t.Parallel()

	report1 := scaiReport{
		Attributes: []scaiAttribute{
			{
				Attribute: testAttrCodeReview,
				Evidence:  json.RawMessage(`{"url":"https://review.example.com/1"}`),
			},
		},
	}
	report2 := scaiReport{
		Attributes: []scaiAttribute{
			{
				Attribute: testAttrPassedTests,
				Evidence:  json.RawMessage(`{"url":"https://ci.example.com/2"}`),
			},
			{
				Attribute: testAttrFuzzTested,
				Evidence:  json.RawMessage(`{"url":"https://fuzz.example.com/3"}`),
			},
		},
	}

	attestations := [][]byte{
		wrapInToto(t, report1, testDigest),
		wrapInToto(t, report2, testDigest),
	}

	result, err := scai.VerifyMultiple(
		context.Background(), attestations, &policy.Policy{}, testDigest,
	)
	testutil.AssertNoError(t, err)

	if !result.Passed {
		t.Fatalf("expected pass, got: %s", result.Detail)
	}

	if result.Metadata == nil {
		t.Fatal("expected metadata on merged result")
	}

	attrCount, ok := result.Metadata["attributeCount"].(int64)
	if !ok || attrCount != 3 {
		t.Errorf("attributeCount = %v, want 3", result.Metadata["attributeCount"])
	}

	attrs, ok := result.Metadata["attributes"].(string)
	if !ok {
		t.Fatal("expected attributes to be a string")
	}

	if !strings.Contains(attrs, testAttrCodeReview) {
		t.Errorf("attributes = %q, want to contain %s", attrs, testAttrCodeReview)
	}

	if !strings.Contains(attrs, testAttrPassedTests) {
		t.Errorf("attributes = %q, want to contain %s", attrs, testAttrPassedTests)
	}

	if !strings.Contains(attrs, testAttrFuzzTested) {
		t.Errorf("attributes = %q, want to contain %s", attrs, testAttrFuzzTested)
	}

	hasEvidence, ok := result.Metadata["hasEvidence"].(bool)
	if !ok || !hasEvidence {
		t.Errorf("hasEvidence = %v, want true", result.Metadata["hasEvidence"])
	}
}

func TestVerifyMultipleMergesMetadataEvidenceAND(t *testing.T) {
	t.Parallel()

	reportWithEvidence := scaiReport{
		Attributes: []scaiAttribute{
			{
				Attribute: testAttrCodeReview,
				Evidence:  json.RawMessage(`{"url":"https://review.example.com/1"}`),
			},
		},
	}
	reportWithoutEvidence := scaiReport{
		Attributes: []scaiAttribute{
			{Attribute: testAttrPassedTests, Evidence: nil},
		},
	}

	attestations := [][]byte{
		wrapInToto(t, reportWithEvidence, testDigest),
		wrapInToto(t, reportWithoutEvidence, testDigest),
	}

	result, err := scai.VerifyMultiple(
		context.Background(), attestations, &policy.Policy{}, testDigest,
	)
	testutil.AssertNoError(t, err)

	if !result.Passed {
		t.Fatalf("expected pass, got: %s", result.Detail)
	}

	hasEvidence, ok := result.Metadata["hasEvidence"].(bool)
	if !ok {
		t.Fatal("expected hasEvidence to be a bool")
	}

	if hasEvidence {
		t.Error("expected hasEvidence = false (AND of true and false)")
	}
}

func TestVerifyMultipleEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("nil attestation slice", func(t *testing.T) {
		t.Parallel()

		result, err := scai.VerifyMultiple(context.Background(), nil, &policy.Policy{}, testDigest)
		testutil.AssertNoError(t, err)

		if !result.Passed {
			t.Errorf("expected pass for nil attestation slice, got: %s", result.Detail)
		}
	})

	t.Run("all invalid returns fail with parse errors", func(t *testing.T) {
		t.Parallel()

		attestations := [][]byte{
			[]byte("bad json 1"),
			[]byte("bad json 2"),
		}

		result, err := scai.VerifyMultiple(
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
			wrapInToto(t, validReport(), testDigest),
		}

		result, err := scai.VerifyMultiple(
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

func TestVerifyForbiddenDetailMessage(t *testing.T) {
	t.Parallel()

	att := wrapInToto(t, validReport(), testDigest)

	result, err := scai.Verify(context.Background(), att, &policy.Policy{
		Sections: policy.Sections{
			SCAI: &policy.SCAIPolicy{
				ForbiddenAttributes: []string{testAttrPassedTests},
			},
		},
	}, testDigest)
	testutil.AssertNoError(t, err)

	if result.Passed {
		t.Fatal("expected fail")
	}

	if !strings.Contains(result.Detail, "forbidden") {
		t.Errorf("expected detail to mention forbidden, got %q", result.Detail)
	}

	if !strings.Contains(result.Detail, testAttrPassedTests) {
		t.Errorf("expected detail to contain attribute name, got %q", result.Detail)
	}
}

func TestVerifyEmptyAttributes(t *testing.T) {
	t.Parallel()

	doc := scaiReport{
		Attributes: []scaiAttribute{},
	}
	att := wrapInToto(t, doc, testDigest)

	t.Run("empty attributes with no policy passes", func(t *testing.T) {
		t.Parallel()

		result, err := scai.Verify(context.Background(), att, &policy.Policy{}, testDigest)
		testutil.AssertNoError(t, err)

		if !result.Passed {
			t.Errorf("expected pass for empty attributes, got: %s", result.Detail)
		}

		attrCount, ok := result.Metadata["attributeCount"].(int64)
		if !ok || attrCount != 0 {
			t.Errorf("attributeCount = %v, want 0", result.Metadata["attributeCount"])
		}
	})

	t.Run("empty attributes with required attribute fails", func(t *testing.T) {
		t.Parallel()

		result, err := scai.Verify(context.Background(), att, &policy.Policy{
			Sections: policy.Sections{
				SCAI: &policy.SCAIPolicy{
					RequiredAttributes: []string{testAttrCodeReview},
				},
			},
		}, testDigest)
		testutil.AssertNoError(t, err)

		if result.Passed {
			t.Error("expected fail for empty attributes with required attribute")
		}
	})

	t.Run("empty attributes with require evidence fails", func(t *testing.T) {
		t.Parallel()

		result, err := scai.Verify(context.Background(), att, &policy.Policy{
			Sections: policy.Sections{
				SCAI: &policy.SCAIPolicy{
					RequireEvidence: true,
				},
			},
		}, testDigest)
		testutil.AssertNoError(t, err)

		if result.Passed {
			t.Error("expected fail for empty attributes with require evidence")
		}
	})
}

func TestVerifyRequiredDetailMessage(t *testing.T) {
	t.Parallel()

	att := wrapInToto(t, validReport(), testDigest)

	result, err := scai.Verify(context.Background(), att, &policy.Policy{
		Sections: policy.Sections{
			SCAI: &policy.SCAIPolicy{
				RequiredAttributes: []string{testAttrFuzzTested},
			},
		},
	}, testDigest)
	testutil.AssertNoError(t, err)

	if result.Passed {
		t.Fatal("expected fail")
	}

	if !strings.Contains(result.Detail, "required") {
		t.Errorf("expected detail to mention required, got %q", result.Detail)
	}

	if !strings.Contains(result.Detail, testAttrFuzzTested) {
		t.Errorf("expected detail to contain attribute name, got %q", result.Detail)
	}
}

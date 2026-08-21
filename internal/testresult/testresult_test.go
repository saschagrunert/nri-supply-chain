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

package testresult_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/intoto"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/testresult"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	testDigest        = "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	testDigestAlgo    = "sha256"
	testInTotoType    = "https://in-toto.io/Statement/v1"
	testSubjectName   = "test-image"
	testPredicateType = "https://in-toto.io/attestation/test-result/v0.1"
	testSuiteUnit     = "unit"
	testSuiteInteg    = "integration"
	testSuiteE2E      = "e2e"
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

type testResultDoc struct {
	Result string      `json:"result"`
	Suites []testSuite `json:"suites,omitempty"`
}

type testSuite struct {
	Name   string `json:"name"`
	Result string `json:"result"`
	Count  *int   `json:"count,omitempty"`
	Passed *int   `json:"passed,omitempty"`
	Failed *int   `json:"failed,omitempty"`
}

type testResultDocWithMeta struct {
	Result   string      `json:"result"`
	Suites   []testSuite `json:"suites,omitempty"`
	Metadata *testMeta   `json:"metadata,omitempty"`
}

type testMeta struct {
	FinishedOn *string `json:"finishedOn,omitempty"`
}

const (
	testResultPass    = "pass"
	testResultPassCap = "PASS"
	testResultFail    = "fail"
	testResultFailCap = "FAIL"
)

func validDoc() testResultDoc {
	return testResultDoc{
		Result: testResultPassCap,
		Suites: []testSuite{
			{
				Name:   testSuiteUnit,
				Result: testResultPass,
				Count:  new(100),
				Passed: new(100),
				Failed: new(0),
			},
			{
				Name:   testSuiteInteg,
				Result: testResultPass,
				Count:  new(50),
				Passed: new(50),
				Failed: new(0),
			},
		},
	}
}

func failedDoc() testResultDoc {
	return testResultDoc{
		Result: testResultFailCap,
		Suites: []testSuite{
			{
				Name:   testSuiteUnit,
				Result: testResultPass,
				Count:  new(100),
				Passed: new(100),
				Failed: new(0),
			},
			{
				Name:   testSuiteInteg,
				Result: testResultFail,
				Count:  new(50),
				Passed: new(45),
				Failed: new(5),
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
		doc        testResultDoc
		pol        *policy.Policy
		wantPassed bool
		wantStatus types.CheckStatus
	}{
		{
			name:       "all tests pass with no policy passes",
			doc:        validDoc(),
			pol:        &policy.Policy{},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name:       "failed tests fail",
			doc:        failedDoc(),
			pol:        &policy.Policy{},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name: "required suite present and passing passes",
			doc:  validDoc(),
			pol: &policy.Policy{
				TestResult: &policy.TestResultPolicy{
					RequiredSuites: []string{testSuiteUnit},
				},
			},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name: "required suite missing fails",
			doc:  validDoc(),
			pol: &policy.Policy{
				TestResult: &policy.TestResultPolicy{
					RequiredSuites: []string{testSuiteE2E},
				},
			},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name: "required suite present but failed fails",
			doc: testResultDoc{
				Result: testResultPassCap,
				Suites: []testSuite{
					{
						Name:   testSuiteUnit,
						Result: testResultFail,
						Count:  new(10),
						Passed: new(8),
						Failed: new(2),
					},
				},
			},
			pol: &policy.Policy{
				TestResult: &policy.TestResultPolicy{
					RequiredSuites: []string{testSuiteUnit},
				},
			},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name: "result case insensitive pass",
			doc: testResultDoc{
				Result: "Passed",
				Suites: []testSuite{},
			},
			pol:        &policy.Policy{},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name: "result case insensitive fail",
			doc: testResultDoc{
				Result: "FAILED",
				Suites: []testSuite{},
			},
			pol:        &policy.Policy{},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name: "suite name matching is case-insensitive",
			doc:  validDoc(),
			pol: &policy.Policy{
				TestResult: &policy.TestResultPolicy{
					RequiredSuites: []string{"UNIT"},
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

			result, err := testresult.Verify(context.Background(), att, test.pol, testDigest)
			testutil.AssertNoError(t, err)

			testutil.AssertEqual(t, test.wantPassed, result.Passed)
			testutil.AssertEqual(t, test.wantStatus, result.Status)
		})
	}
}

func TestVerifyCheckType(t *testing.T) {
	t.Parallel()

	att := wrapInToto(t, validDoc(), testDigest)

	result, err := testresult.Verify(context.Background(), att, &policy.Policy{}, testDigest)
	testutil.AssertNoError(t, err)

	testutil.AssertEqual(t, types.CheckType("testresult"), result.Type)
}

func TestVerifyMetadata(t *testing.T) {
	t.Parallel()

	att := wrapInToto(t, validDoc(), testDigest)

	result, err := testresult.Verify(context.Background(), att, &policy.Policy{}, testDigest)
	testutil.AssertNoError(t, err)

	if result.Metadata == nil {
		t.Fatal("expected metadata on test result")
	}

	overallResult, ok := result.Metadata["result"].(string)
	if !ok || overallResult != "PASS" {
		t.Errorf("result = %v, want PASS", result.Metadata["result"])
	}

	suiteCount, ok := result.Metadata["suiteCount"].(int64)
	if !ok || suiteCount != 2 {
		t.Errorf("suiteCount = %v, want 2", result.Metadata["suiteCount"])
	}

	suites, ok := result.Metadata["suites"].(string)
	if !ok {
		t.Fatal("expected suites to be a string")
	}

	if !strings.Contains(suites, testSuiteUnit) {
		t.Errorf("suites = %q, want to contain %s", suites, testSuiteUnit)
	}

	if !strings.Contains(suites, testSuiteInteg) {
		t.Errorf("suites = %q, want to contain %s", suites, testSuiteInteg)
	}

	passed, ok := result.Metadata["passed"].(int64)
	if !ok || passed != 150 {
		t.Errorf("passed = %v, want 150", result.Metadata["passed"])
	}

	failed, ok := result.Metadata["failed"].(int64)
	if !ok || failed != 0 {
		t.Errorf("failed = %v, want 0", result.Metadata["failed"])
	}
}

func TestVerifyMalformedPayloads(t *testing.T) {
	t.Parallel()

	t.Run("empty payload", func(t *testing.T) {
		t.Parallel()

		_, err := testresult.Verify(context.Background(), []byte{}, &policy.Policy{}, testDigest)
		if !errors.Is(err, testresult.ErrInvalidTestResult) {
			t.Errorf("expected ErrInvalidTestResult, got %v", err)
		}
	})

	t.Run("nil payload", func(t *testing.T) {
		t.Parallel()

		_, err := testresult.Verify(context.Background(), nil, &policy.Policy{}, testDigest)
		if !errors.Is(err, testresult.ErrInvalidTestResult) {
			t.Errorf("expected ErrInvalidTestResult, got %v", err)
		}
	})

	t.Run("truncated JSON", func(t *testing.T) {
		t.Parallel()

		_, err := testresult.Verify(
			context.Background(), []byte(`{"subject":[`), &policy.Policy{}, testDigest,
		)
		if !errors.Is(err, testresult.ErrInvalidTestResult) {
			t.Errorf("expected ErrInvalidTestResult, got %v", err)
		}
	})
}

func TestVerifySubjectEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("subject with mismatched digest", func(t *testing.T) {
		t.Parallel()

		att := wrapInToto(t, validDoc(), testDigest)

		_, err := testresult.Verify(context.Background(),
			att, &policy.Policy{},
			"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		)
		if !errors.Is(err, intoto.ErrSubjectMismatch) {
			t.Errorf("expected ErrSubjectMismatch, got %v", err)
		}
	})

	t.Run("empty digest with subjects rejects for binding", func(t *testing.T) {
		t.Parallel()

		att := wrapInToto(t, validDoc(), testDigest)

		_, err := testresult.Verify(context.Background(), att, &policy.Policy{}, "")
		if !errors.Is(err, intoto.ErrNoDigestBinding) {
			t.Errorf("expected ErrNoDigestBinding, got %v", err)
		}
	})
}

func TestVerifyFailedDetailMessage(t *testing.T) {
	t.Parallel()

	att := wrapInToto(t, failedDoc(), testDigest)

	result, err := testresult.Verify(context.Background(), att, &policy.Policy{}, testDigest)
	testutil.AssertNoError(t, err)

	if result.Passed {
		t.Fatal("expected fail")
	}

	if !strings.Contains(result.Detail, "tests failed") {
		t.Errorf("expected detail to mention tests failed, got %q", result.Detail)
	}

	if !strings.Contains(result.Detail, testSuiteInteg) {
		t.Errorf("expected detail to contain failed suite name, got %q", result.Detail)
	}
}

func TestVerifyRequiredSuiteDetailMessage(t *testing.T) {
	t.Parallel()

	att := wrapInToto(t, validDoc(), testDigest)

	result, err := testresult.Verify(context.Background(), att, &policy.Policy{
		TestResult: &policy.TestResultPolicy{
			RequiredSuites: []string{testSuiteE2E},
		},
	}, testDigest)
	testutil.AssertNoError(t, err)

	if result.Passed {
		t.Fatal("expected fail")
	}

	if !strings.Contains(result.Detail, "required test suite missing") {
		t.Errorf("expected detail to mention required suite missing, got %q", result.Detail)
	}

	if !strings.Contains(result.Detail, testSuiteE2E) {
		t.Errorf("expected detail to contain suite name, got %q", result.Detail)
	}
}

func TestVerifyEmptySuites(t *testing.T) {
	t.Parallel()

	doc := testResultDoc{
		Result: testResultPassCap,
		Suites: []testSuite{},
	}
	att := wrapInToto(t, doc, testDigest)

	t.Run("empty suites with no policy passes", func(t *testing.T) {
		t.Parallel()

		result, err := testresult.Verify(context.Background(), att, &policy.Policy{}, testDigest)
		testutil.AssertNoError(t, err)

		if !result.Passed {
			t.Errorf("expected pass for empty suites, got: %s", result.Detail)
		}

		suiteCount, ok := result.Metadata["suiteCount"].(int64)
		if !ok || suiteCount != 0 {
			t.Errorf("suiteCount = %v, want 0", result.Metadata["suiteCount"])
		}
	})

	t.Run("empty suites with required suite fails", func(t *testing.T) {
		t.Parallel()

		result, err := testresult.Verify(context.Background(), att, &policy.Policy{
			TestResult: &policy.TestResultPolicy{
				RequiredSuites: []string{testSuiteUnit},
			},
		}, testDigest)
		testutil.AssertNoError(t, err)

		if result.Passed {
			t.Error("expected fail for empty suites with required suite")
		}
	})
}

func TestVerifyMultiple(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		docs       []testResultDoc
		pol        *policy.Policy
		wantPassed bool
		wantStatus types.CheckStatus
	}{
		{
			name:       "all pass",
			docs:       []testResultDoc{validDoc()},
			pol:        &policy.Policy{},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name:       "any failure fails",
			docs:       []testResultDoc{failedDoc()},
			pol:        &policy.Policy{},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name:       "empty attestation list",
			docs:       []testResultDoc{},
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

			result, err := testresult.VerifyMultiple(
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

	doc1 := testResultDoc{
		Result: testResultPassCap,
		Suites: []testSuite{
			{
				Name:   testSuiteUnit,
				Result: testResultPass,
				Count:  new(100),
				Passed: new(100),
				Failed: new(0),
			},
		},
	}
	doc2 := testResultDoc{
		Result: testResultPassCap,
		Suites: []testSuite{
			{
				Name:   testSuiteInteg,
				Result: testResultPass,
				Count:  new(50),
				Passed: new(48),
				Failed: new(2),
			},
		},
	}

	attestations := [][]byte{
		wrapInToto(t, doc1, testDigest),
		wrapInToto(t, doc2, testDigest),
	}

	result, err := testresult.VerifyMultiple(
		context.Background(), attestations, &policy.Policy{}, testDigest,
	)
	testutil.AssertNoError(t, err)

	if !result.Passed {
		t.Fatalf("expected pass, got: %s", result.Detail)
	}

	if result.Metadata == nil {
		t.Fatal("expected metadata on merged result")
	}

	suiteCount, ok := result.Metadata["suiteCount"].(int64)
	if !ok || suiteCount != 2 {
		t.Errorf("suiteCount = %v, want 2", result.Metadata["suiteCount"])
	}

	suites, ok := result.Metadata["suites"].(string)
	if !ok {
		t.Fatal("expected suites to be a string")
	}

	if !strings.Contains(suites, testSuiteUnit) {
		t.Errorf("suites = %q, want to contain %s", suites, testSuiteUnit)
	}

	if !strings.Contains(suites, testSuiteInteg) {
		t.Errorf("suites = %q, want to contain %s", suites, testSuiteInteg)
	}

	passed, ok := result.Metadata["passed"].(int64)
	if !ok || passed != 148 {
		t.Errorf("passed = %v, want 148", result.Metadata["passed"])
	}

	failed, ok := result.Metadata["failed"].(int64)
	if !ok || failed != 2 {
		t.Errorf("failed = %v, want 2", result.Metadata["failed"])
	}
}

func TestVerifyMultipleEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("nil attestation slice", func(t *testing.T) {
		t.Parallel()

		result, err := testresult.VerifyMultiple(
			context.Background(),
			nil,
			&policy.Policy{},
			testDigest,
		)
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

		result, err := testresult.VerifyMultiple(
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
			wrapInToto(t, validDoc(), testDigest),
		}

		result, err := testresult.VerifyMultiple(
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

func TestVerifyFailedSuiteCollection(t *testing.T) {
	t.Parallel()

	doc := testResultDoc{
		Result: testResultFailCap,
		Suites: []testSuite{
			{ //nolint:exhaustruct_v5 // test omits Count/Passed/Failed
				Name:   testSuiteUnit,
				Result: testResultPass,
			},
			{ //nolint:exhaustruct_v5 // test omits Count/Passed/Failed
				Name:   testSuiteInteg,
				Result: testResultFail,
			},
			{ //nolint:exhaustruct_v5 // test omits Count/Passed/Failed
				Name:   testSuiteE2E,
				Result: "error",
			},
		},
	}
	att := wrapInToto(t, doc, testDigest)

	result, err := testresult.Verify(context.Background(), att, &policy.Policy{}, testDigest)
	testutil.AssertNoError(t, err)

	if result.Passed {
		t.Fatal("expected fail")
	}

	if !strings.Contains(result.Detail, testSuiteInteg) {
		t.Errorf("expected detail to contain %s, got %q", testSuiteInteg, result.Detail)
	}

	if !strings.Contains(result.Detail, testSuiteE2E) {
		t.Errorf("expected detail to contain %s, got %q", testSuiteE2E, result.Detail)
	}
}

func TestVerifyNilCountFields(t *testing.T) {
	t.Parallel()

	doc := testResultDoc{
		Result: testResultPassCap,
		Suites: []testSuite{
			{ //nolint:exhaustruct_v5 // test omits Count/Passed/Failed
				Name:   testSuiteUnit,
				Result: testResultPass,
			},
		},
	}
	att := wrapInToto(t, doc, testDigest)

	result, err := testresult.Verify(context.Background(), att, &policy.Policy{}, testDigest)
	testutil.AssertNoError(t, err)

	if !result.Passed {
		t.Errorf("expected pass, got: %s", result.Detail)
	}

	passed, ok := result.Metadata["passed"].(int64)
	if !ok || passed != 0 {
		t.Errorf("passed = %v, want 0 (nil count fields)", result.Metadata["passed"])
	}
}

func TestVerifyFreshness(t *testing.T) {
	t.Parallel()

	staleTime := "2020-01-01T00:00:00Z"
	freshTime := time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339)

	tests := []struct {
		name       string
		doc        testResultDocWithMeta
		pol        *policy.Policy
		wantPassed bool
		wantSubstr string
	}{
		{
			name: "stale result fails",
			doc: testResultDocWithMeta{
				Result:   testResultPassCap,
				Suites:   []testSuite{},
				Metadata: &testMeta{FinishedOn: &staleTime},
			},
			pol: &policy.Policy{
				TestResult: &policy.TestResultPolicy{
					MaxAge:         "1h",
					MaxAgeDuration: time.Hour,
				},
			},
			wantPassed: false,
			wantSubstr: "stale",
		},
		{
			name: "fresh result passes",
			doc: testResultDocWithMeta{
				Result:   testResultPassCap,
				Suites:   []testSuite{},
				Metadata: &testMeta{FinishedOn: &freshTime},
			},
			pol: &policy.Policy{
				TestResult: &policy.TestResultPolicy{
					MaxAge:         "1h",
					MaxAgeDuration: time.Hour,
				},
			},
			wantPassed: true,
			wantSubstr: "",
		},
		{
			name: "no timestamp with maxAge fails",
			doc: testResultDocWithMeta{ //nolint:exhaustruct_v5 // test omits Metadata
				Result: testResultPassCap,
				Suites: []testSuite{},
			},
			pol: &policy.Policy{
				TestResult: &policy.TestResultPolicy{
					MaxAge:         "1h",
					MaxAgeDuration: time.Hour,
				},
			},
			wantPassed: false,
			wantSubstr: "no finished timestamp",
		},
		{
			name: "no timestamp without maxAge passes",
			doc: testResultDocWithMeta{ //nolint:exhaustruct_v5 // test omits Metadata
				Result: testResultPassCap,
				Suites: []testSuite{},
			},
			pol:        &policy.Policy{},
			wantPassed: true,
			wantSubstr: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			att := wrapInToto(t, test.doc, testDigest)

			result, err := testresult.Verify(context.Background(), att, test.pol, testDigest)
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

	_, err := testresult.Verify(ctx, nil, nil, "")
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}

	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

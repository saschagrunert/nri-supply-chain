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

package scorecard_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/scorecard"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	testDigest        = "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	testDigestAlgo    = "sha256"
	testInTotoType    = "https://in-toto.io/Statement/v1"
	testPredicateType = "https://scorecard.dev/result/v0.1"
	testRepo          = "github.com/example/project"
	testVersion       = "v5.4.0"
	testCodeReview    = "Code-Review"
	testBranchProtect = "Branch-Protection"
	testFuzzing       = "Fuzzing"
)

type inTotoWrapper struct {
	Type          string          `json:"_type"` //nolint:tagliatelle // in-toto field name
	Subject       []inTotoSubject `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

type inTotoSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type scorecardDoc struct {
	Date      string        `json:"date"`
	Repo      repoInfo      `json:"repo"`
	Scorecard scorecardInfo `json:"scorecard"`
	Score     float64       `json:"score"`
	Checks    []checkResult `json:"checks"`
}

type repoInfo struct {
	Name   string `json:"name"`
	Commit string `json:"commit"`
}

type scorecardInfo struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

type checkResult struct {
	Name    string   `json:"name"`
	Score   int      `json:"score"`
	Reason  string   `json:"reason,omitempty"`
	Details []string `json:"details,omitempty"`
}

func validDoc() scorecardDoc {
	return scorecardDoc{
		Date: "2026-08-20T12:00:00Z",
		Repo: repoInfo{Name: testRepo, Commit: "abc123"},
		Scorecard: scorecardInfo{
			Version: testVersion,
			Commit:  "def456",
		},
		Score: 8.4,
		Checks: []checkResult{
			{Name: testCodeReview, Score: 8, Reason: "reviews required", Details: nil},
			{Name: testBranchProtect, Score: 9, Reason: "protected", Details: nil},
		},
	}
}

func wrapInToto(t *testing.T, doc any, digest string) []byte {
	t.Helper()

	predicate := testutil.MustMarshal(t, doc)
	wrapper := inTotoWrapper{
		Type: testInTotoType,
		Subject: []inTotoSubject{
			{
				Name:   "test-image",
				Digest: map[string]string{testDigestAlgo: digest[len(testDigestAlgo)+1:]},
			},
		},
		PredicateType: testPredicateType,
		Predicate:     predicate,
	}

	return testutil.MustMarshal(t, wrapper)
}

func TestVerify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		doc        scorecardDoc
		pol        *policy.Policy
		wantPassed bool
		wantDetail string
	}{
		{
			name:       "valid result without policy",
			doc:        validDoc(),
			pol:        &policy.Policy{},
			wantPassed: true,
			wantDetail: "",
		},
		{
			name: "aggregate score meets minimum",
			doc:  validDoc(),
			pol: &policy.Policy{
				Scorecard: &policy.ScorecardPolicy{MinScore: new(8.0)},
			},
			wantPassed: true,
			wantDetail: "",
		},
		{
			name: "aggregate score below minimum",
			doc:  validDoc(),
			pol: &policy.Policy{
				Scorecard: &policy.ScorecardPolicy{MinScore: new(9.0)},
			},
			wantPassed: false,
			wantDetail: "aggregate score",
		},
		{
			name: "per-check scores meet minimums",
			doc:  validDoc(),
			pol: &policy.Policy{
				Scorecard: &policy.ScorecardPolicy{Checks: map[string]int{
					testCodeReview: 8, testBranchProtect: 9,
				}},
			},
			wantPassed: true,
			wantDetail: "",
		},
		{
			name: "per-check score below minimum",
			doc:  validDoc(),
			pol: &policy.Policy{
				Scorecard: &policy.ScorecardPolicy{Checks: map[string]int{
					testCodeReview: 9,
				}},
			},
			wantPassed: false,
			wantDetail: testCodeReview,
		},
		{
			name: "required check missing",
			doc:  validDoc(),
			pol: &policy.Policy{
				Scorecard: &policy.ScorecardPolicy{Checks: map[string]int{
					testFuzzing: 5,
				}},
			},
			wantPassed: false,
			wantDetail: testFuzzing,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			att := wrapInToto(t, test.doc, testDigest)
			result, err := scorecard.Verify(context.Background(), att, test.pol, testDigest)
			testutil.AssertNoError(t, err)

			testutil.AssertEqual(t, test.wantPassed, result.Passed)

			if test.wantDetail != "" && !strings.Contains(result.Detail, test.wantDetail) {
				t.Errorf("detail %q does not contain %q", result.Detail, test.wantDetail)
			}
		})
	}
}

func TestVerifyMetadata(t *testing.T) {
	t.Parallel()

	result, err := scorecard.Verify(
		context.Background(), wrapInToto(t, validDoc(), testDigest), &policy.Policy{}, testDigest,
	)
	testutil.AssertNoError(t, err)

	testutil.AssertEqual(t, types.CheckTypeScorecard, result.Type)
	testutil.AssertEqual(t, testRepo, result.Metadata["repo"])
	testutil.AssertEqual(t, testVersion, result.Metadata["version"])
	testutil.AssertEqual(t, 8.4, result.Metadata["score"])

	checks, ok := result.Metadata["checks"].(map[string]int64)
	if !ok {
		t.Fatalf("checks metadata has type %T, want map[string]int64", result.Metadata["checks"])
	}

	testutil.AssertEqual(t, int64(8), checks[testCodeReview])
	testutil.AssertEqual(t, int64(9), checks[testBranchProtect])
}

func TestVerifyInconclusiveCheck(t *testing.T) {
	t.Parallel()

	doc := validDoc()
	doc.Checks[0].Score = -1

	result, err := scorecard.Verify(
		context.Background(), wrapInToto(t, doc, testDigest), &policy.Policy{}, testDigest,
	)
	testutil.AssertNoError(t, err)

	if !result.Passed {
		t.Fatalf("inconclusive check should be exposed to policy, got %q", result.Detail)
	}

	checks := scorecardChecks(t, result)
	testutil.AssertEqual(t, int64(-1), checks[testCodeReview])
}

func TestVerifyDuplicateCheckUsesLowestScore(t *testing.T) {
	t.Parallel()

	doc := validDoc()
	doc.Checks = append(doc.Checks, checkResult{
		Name: testCodeReview, Score: 3, Reason: "", Details: nil,
	})

	result, err := scorecard.Verify(
		context.Background(), wrapInToto(t, doc, testDigest), &policy.Policy{}, testDigest,
	)
	testutil.AssertNoError(t, err)

	checks := scorecardChecks(t, result)
	testutil.AssertEqual(t, int64(3), checks[testCodeReview])
}

func TestVerifyInvalid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		att  func(*testing.T) []byte
	}{
		{
			name: "invalid statement JSON",
			att:  func(_ *testing.T) []byte { return []byte("not json") },
		},
		{
			name: "subject mismatch",
			att: func(t *testing.T) []byte {
				t.Helper()

				return wrapInToto(t, validDoc(), "sha256:"+strings.Repeat("f", 64))
			},
		},
		{
			name: "missing repository",
			att: func(t *testing.T) []byte {
				t.Helper()

				doc := validDoc()
				doc.Repo.Name = ""

				return wrapInToto(t, doc, testDigest)
			},
		},
		{
			name: "missing version",
			att: func(t *testing.T) []byte {
				t.Helper()

				doc := validDoc()
				doc.Scorecard.Version = ""

				return wrapInToto(t, doc, testDigest)
			},
		},
		{
			name: "score out of range",
			att: func(t *testing.T) []byte {
				t.Helper()

				doc := validDoc()
				doc.Score = 10.1

				return wrapInToto(t, doc, testDigest)
			},
		},
		{
			name: "no checks",
			att: func(t *testing.T) []byte {
				t.Helper()

				doc := validDoc()
				doc.Checks = nil

				return wrapInToto(t, doc, testDigest)
			},
		},
		{
			name: "check score out of range",
			att: func(t *testing.T) []byte {
				t.Helper()

				doc := validDoc()
				doc.Checks[0].Score = 11

				return wrapInToto(t, doc, testDigest)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := scorecard.Verify(
				context.Background(), test.att(t), &policy.Policy{}, testDigest,
			)
			if !errors.Is(err, scorecard.ErrInvalidScorecard) {
				t.Errorf("error = %v, want ErrInvalidScorecard", err)
			}
		})
	}
}

func TestVerifyMultiple(t *testing.T) {
	t.Parallel()

	doc1 := validDoc()
	doc2 := validDoc()
	doc2.Repo.Name = "github.com/example/other"
	doc2.Scorecard.Version = "v5.5.0"
	doc2.Score = 7.2
	doc2.Checks = []checkResult{
		{Name: testCodeReview, Score: 6, Reason: "", Details: nil},
		{Name: testFuzzing, Score: 10, Reason: "", Details: nil},
	}

	result, err := scorecard.VerifyMultiple(
		context.Background(),
		[][]byte{
			wrapInToto(t, doc1, testDigest),
			wrapInToto(t, doc2, testDigest),
		},
		&policy.Policy{},
		testDigest,
	)
	testutil.AssertNoError(t, err)

	if !result.Passed {
		t.Fatalf("expected pass, got %q", result.Detail)
	}

	testutil.AssertEqual(t, 7.2, result.Metadata["score"])
	checks := scorecardChecks(t, result)
	testutil.AssertEqual(t, int64(6), checks[testCodeReview])
	testutil.AssertEqual(t, int64(9), checks[testBranchProtect])
	testutil.AssertEqual(t, int64(10), checks[testFuzzing])

	repo, ok := result.Metadata["repo"].(string)
	if !ok {
		t.Fatalf("repo metadata has type %T, want string", result.Metadata["repo"])
	}

	if !strings.Contains(repo, doc1.Repo.Name) || !strings.Contains(repo, doc2.Repo.Name) {
		t.Errorf("merged repo metadata = %q", result.Metadata["repo"])
	}
}

func scorecardChecks(t *testing.T, result *types.CheckResult) map[string]int64 {
	t.Helper()

	checks, ok := result.Metadata["checks"].(map[string]int64)
	if !ok {
		t.Fatalf("checks metadata has type %T, want map[string]int64", result.Metadata["checks"])
	}

	return checks
}

func TestVerifyMultipleFailureAndInvalidDocuments(t *testing.T) {
	t.Parallel()

	t.Run("policy violation fails all", func(t *testing.T) {
		t.Parallel()

		result, err := scorecard.VerifyMultiple(
			context.Background(),
			[][]byte{wrapInToto(t, validDoc(), testDigest)},
			&policy.Policy{
				Scorecard: &policy.ScorecardPolicy{MinScore: new(9.0)},
			},
			testDigest,
		)
		testutil.AssertNoError(t, err)

		if result.Passed {
			t.Fatal("expected threshold violation to fail")
		}
	})

	t.Run("all invalid fails", func(t *testing.T) {
		t.Parallel()

		result, err := scorecard.VerifyMultiple(
			context.Background(), [][]byte{[]byte("bad")}, &policy.Policy{}, testDigest,
		)
		testutil.AssertNoError(t, err)

		if result.Passed || !strings.Contains(result.Detail, "all OpenSSF Scorecard documents") {
			t.Errorf("unexpected result: %+v", result)
		}
	})

	t.Run("empty list passes for missing-policy handler", func(t *testing.T) {
		t.Parallel()

		result, err := scorecard.VerifyMultiple(
			context.Background(), nil, &policy.Policy{}, testDigest,
		)
		testutil.AssertNoError(t, err)

		if !result.Passed {
			t.Errorf("expected pass, got %q", result.Detail)
		}
	})
}

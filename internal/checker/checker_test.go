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

package checker_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/checker"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	testDigest        = "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	testPredicateType = "https://example.com/predicate/v1"
)

var (
	errTestInvalid = errors.New("invalid test document")
	errTestStale   = errors.New("test document is stale")
	errTestFuture  = errors.New("test document is in the future")
	errNoName      = errors.New("name is required")
)

type testPredicate struct {
	Name      string     `json:"name"`
	Count     int64      `json:"count"`
	Timestamp *time.Time `json:"timestamp,omitempty"`
}

func testSpec(aggregation checker.Aggregation, maxAge *time.Duration) *checker.Spec[testPredicate] {
	return &checker.Spec[testPredicate]{
		Info:        checker.Info{Type: types.CheckTypeSCAI, Label: "test"},
		Aggregation: aggregation,
		ErrInvalid:  errTestInvalid,
		Validate: func(pred *testPredicate) error {
			if pred.Name == "" {
				return errNoName
			}

			return nil
		},
		Meta: func(pred *testPredicate) map[string]any {
			return map[string]any{"name": pred.Name, "count": pred.Count}
		},
		Freshness: &checker.Freshness[testPredicate]{
			Timestamp: func(pred *testPredicate) *time.Time { return pred.Timestamp },
			MaxAge:    func(_ *policy.Policy) *time.Duration { return maxAge },
			Label:     "created",
			ErrStale:  errTestStale,
			ErrFuture: errTestFuture,
		},
		Rules: []checker.Rule[testPredicate]{
			func(pred *testPredicate, _ *policy.Policy) string {
				if pred.Name == "forbidden" {
					return "forbidden name"
				}

				return ""
			},
		},
		Merge: map[string]checker.MergeFunc{
			"name":  checker.CSV(),
			"count": checker.Sum(),
		},
	}
}

func statement(t *testing.T, predicate any) []byte {
	t.Helper()

	return testutil.WrapInToto(t, predicate, testDigest, testPredicateType)
}

func TestSpecVerify(t *testing.T) {
	t.Parallel()

	future := time.Now().Add(time.Hour)
	stale := time.Now().Add(-48 * time.Hour)
	day := 24 * time.Hour

	tests := []struct {
		name       string
		predicate  any
		maxAge     *time.Duration
		wantErr    error
		wantPassed bool
		wantDetail string
	}{
		{
			name:       "valid predicate passes",
			predicate:  testPredicate{Name: "ok", Count: 1, Timestamp: nil},
			maxAge:     nil,
			wantErr:    nil,
			wantPassed: true,
			wantDetail: "test verification passed",
		},
		{
			name:       "null predicate is invalid",
			predicate:  json.RawMessage(`null`),
			maxAge:     nil,
			wantErr:    checker.ErrNotObject,
			wantPassed: false,
			wantDetail: "",
		},
		{
			name:       "array predicate is invalid",
			predicate:  json.RawMessage(`[1]`),
			maxAge:     nil,
			wantErr:    checker.ErrNotObject,
			wantPassed: false,
			wantDetail: "",
		},
		{
			name:       "validation failure is invalid",
			predicate:  json.RawMessage(`{}`),
			maxAge:     nil,
			wantErr:    errNoName,
			wantPassed: false,
			wantDetail: "",
		},
		{
			name:       "rule violation fails",
			predicate:  testPredicate{Name: "forbidden", Count: 1, Timestamp: nil},
			maxAge:     nil,
			wantErr:    nil,
			wantPassed: false,
			wantDetail: "forbidden name",
		},
		{
			name:       "future timestamp fails without max age",
			predicate:  testPredicate{Name: "ok", Count: 1, Timestamp: &future},
			maxAge:     nil,
			wantErr:    nil,
			wantPassed: false,
			wantDetail: "future",
		},
		{
			name:       "stale timestamp fails with max age",
			predicate:  testPredicate{Name: "ok", Count: 1, Timestamp: &stale},
			maxAge:     &day,
			wantErr:    nil,
			wantPassed: false,
			wantDetail: "stale",
		},
		{
			name:       "missing timestamp fails with max age",
			predicate:  testPredicate{Name: "ok", Count: 1, Timestamp: nil},
			maxAge:     &day,
			wantErr:    nil,
			wantPassed: false,
			wantDetail: "no created timestamp",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			result, err := testSpec(checker.FirstPass, tc.maxAge).Verify(
				context.Background(), statement(t, tc.predicate), &policy.Policy{}, testDigest,
			)

			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) || !errors.Is(err, errTestInvalid) {
					t.Fatalf("expected %v wrapped in %v, got %v", tc.wantErr, errTestInvalid, err)
				}

				return
			}

			testutil.AssertNoError(t, err)
			testutil.AssertEqual(t, tc.wantPassed, result.Passed)
			testutil.AssertContains(t, result.Detail, tc.wantDetail)
		})
	}
}

func TestSpecWithoutValidatorRejects(t *testing.T) {
	t.Parallel()

	spec := testSpec(checker.FirstPass, nil)
	spec.Validate = nil

	_, err := spec.Verify(
		context.Background(),
		statement(t, testPredicate{Name: "ok", Count: 1, Timestamp: nil}),
		&policy.Policy{},
		testDigest,
	)
	if !errors.Is(err, checker.ErrNoValidator) {
		t.Fatalf("expected ErrNoValidator, got %v", err)
	}
}

func TestSpecVerifyMultiple(t *testing.T) {
	t.Parallel()

	valid := func(t *testing.T, name string, count int64) []byte {
		t.Helper()

		return statement(t, testPredicate{Name: name, Count: count, Timestamp: nil})
	}

	t.Run("all must pass merges metadata", func(t *testing.T) {
		t.Parallel()

		result, err := testSpec(checker.AllMustPass, nil).VerifyMultiple(
			context.Background(),
			[][]byte{valid(t, "a", 2), valid(t, "b", 3)},
			&policy.Policy{}, testDigest,
		)
		testutil.AssertNoError(t, err)
		testutil.AssertTrue(t, result.Passed)
		testutil.AssertEqual[any](t, int64(5), result.Metadata["count"])
		testutil.AssertEqual[any](t, "a,b", result.Metadata["name"])
	})

	t.Run("all must pass fails on invalid document", func(t *testing.T) {
		t.Parallel()

		result, err := testSpec(checker.AllMustPass, nil).VerifyMultiple(
			context.Background(),
			[][]byte{valid(t, "a", 2), statement(t, json.RawMessage(`{}`))},
			&policy.Policy{}, testDigest,
		)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, false, result.Passed)
		testutil.AssertContains(t, result.Detail, "1 of 2 test documents failed verification")
	})

	t.Run("first pass accepts any passing document", func(t *testing.T) {
		t.Parallel()

		result, err := testSpec(checker.FirstPass, nil).VerifyMultiple(
			context.Background(),
			[][]byte{valid(t, "forbidden", 1), valid(t, "ok", 1)},
			&policy.Policy{}, testDigest,
		)
		testutil.AssertNoError(t, err)
		testutil.AssertTrue(t, result.Passed)
	})
}

func TestMergeFuncs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		merge    checker.MergeFunc
		existing any
		incoming any
		want     any
		wantOK   bool
	}{
		{
			name:     "sum int64",
			merge:    checker.Sum(),
			existing: int64(2),
			incoming: int64(3),
			want:     int64(5),
			wantOK:   true,
		},
		{
			name:     "sum float64",
			merge:    checker.Sum(),
			existing: 1.5,
			incoming: 2.0,
			want:     3.5,
			wantOK:   true,
		},
		{
			name:     "sum mismatch",
			merge:    checker.Sum(),
			existing: int64(2),
			incoming: "x",
			want:     int64(2),
			wantOK:   false,
		},
		{
			name:     "max float64",
			merge:    checker.Max(),
			existing: 1.5,
			incoming: 2.5,
			want:     2.5,
			wantOK:   true,
		},
		{
			name:     "min int64",
			merge:    checker.Min(),
			existing: int64(4),
			incoming: int64(3),
			want:     int64(3),
			wantOK:   true,
		},
		{
			name:     "csv",
			merge:    checker.CSV(),
			existing: "a,b",
			incoming: "B,c",
			want:     "a,b,c",
			wantOK:   true,
		},
		{
			name:     "and",
			merge:    checker.And(),
			existing: true,
			incoming: false,
			want:     false,
			wantOK:   true,
		},
		{
			name:     "and mismatch",
			merge:    checker.And(),
			existing: true,
			incoming: 1,
			want:     false,
			wantOK:   false,
		},
		{
			name:     "max by rank",
			merge:    checker.MaxBy(func(s string) int { return len(s) }),
			existing: "ab",
			incoming: "abc",
			want:     "abc",
			wantOK:   true,
		},
		{
			name:     "max by mismatch",
			merge:    checker.MaxBy(func(string) int { return 0 }),
			existing: 1,
			incoming: "a",
			want:     nil,
			wantOK:   false,
		},
		{
			name:     "default unsupported",
			merge:    checker.Max(),
			existing: "a",
			incoming: "b",
			want:     nil,
			wantOK:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, ok := tc.merge(tc.existing, tc.incoming)
			testutil.AssertEqual(t, tc.wantOK, ok)

			if ok {
				testutil.AssertEqual(t, tc.want, got)
			}
		})
	}
}

func TestMapMergeFuncs(t *testing.T) {
	t.Parallel()

	union, ok := checker.UnionMap()(
		map[string]string{"a": "1"}, map[string]string{"a": "2", "b": "3"},
	)
	testutil.AssertTrue(t, ok)

	unionMap, isMap := union.(map[string]string)
	testutil.AssertTrue(t, isMap)
	testutil.AssertEqual(t, "1", unionMap["a"])
	testutil.AssertEqual(t, "3", unionMap["b"])

	_, ok = checker.UnionMap()(map[string]string{}, "x")
	testutil.AssertEqual(t, false, ok)

	minimum, ok := checker.MinMap()(
		map[string]int64{"a": 5, "b": 1}, map[string]int64{"a": 2, "c": 7},
	)
	testutil.AssertTrue(t, ok)

	minMap, isMap := minimum.(map[string]int64)
	testutil.AssertTrue(t, isMap)
	testutil.AssertEqual(t, int64(2), minMap["a"])
	testutil.AssertEqual(t, int64(1), minMap["b"])
	testutil.AssertEqual(t, int64(7), minMap["c"])

	_, ok = checker.MinMap()("x", map[string]int64{})
	testutil.AssertEqual(t, false, ok)
}

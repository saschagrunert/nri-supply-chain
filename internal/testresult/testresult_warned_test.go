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
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/testresult"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
)

func TestVerifyWarnedResult(t *testing.T) {
	t.Parallel()

	predicate := `{"result":"WARNED","configuration":[{"uri":"https://example.com/ci.yml"}],` +
		`"passedTests":["unit"],"warnedTests":["lint","integration"]}`
	att := testutil.WrapInToto(t, json.RawMessage(predicate), testDigest, testPredicateType)

	t.Run("passes with warned count in metadata", func(t *testing.T) {
		t.Parallel()

		result, err := testresult.Verify(context.Background(), att, &policy.Policy{}, testDigest)
		testutil.AssertNoError(t, err)
		testutil.AssertTrue(t, result.Passed)
		testutil.AssertEqual[any](t, int64(2), result.Metadata["warned"])
		testutil.AssertEqual[any](t, "WARNED", result.Metadata["result"])
	})

	t.Run("required suite found in warnedTests", func(t *testing.T) {
		t.Parallel()

		result, err := testresult.Verify(context.Background(), att, &policy.Policy{
			TestResult: &policy.TestResultPolicy{RequiredSuites: []string{testSuiteInteg}},
		}, testDigest)
		testutil.AssertNoError(t, err)
		testutil.AssertTrue(t, result.Passed)
	})

	t.Run("failed tests still fail a warned result", func(t *testing.T) {
		t.Parallel()

		failing := `{"result":"WARNED","warnedTests":["lint"],"failedTests":["unit"]}`
		failingAtt := testutil.WrapInToto(
			t,
			json.RawMessage(failing),
			testDigest,
			testPredicateType,
		)

		result, err := testresult.Verify(
			context.Background(),
			failingAtt,
			&policy.Policy{},
			testDigest,
		)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, false, result.Passed)
	})
}

func TestVerifyMultipleMergesWarnedCount(t *testing.T) {
	t.Parallel()

	doc := `{"result":"WARNED","warnedTests":["lint"]}`

	attestations := [][]byte{
		testutil.WrapInToto(t, json.RawMessage(doc), testDigest, testPredicateType),
		testutil.WrapInToto(t, json.RawMessage(doc), testDigest, testPredicateType),
	}

	result, err := testresult.VerifyMultiple(
		context.Background(), attestations, &policy.Policy{}, testDigest,
	)
	testutil.AssertNoError(t, err)
	testutil.AssertTrue(t, result.Passed)
	testutil.AssertEqual[any](t, int64(2), result.Metadata["warned"])
}

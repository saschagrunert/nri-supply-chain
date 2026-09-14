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

package buildenv_test

import (
	"context"
	"errors"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/buildenv"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	testPropHermetic  = "HERMETIC"
	testPropRunner    = "RUNNER"
	testRunnerA       = "runner-a"
	testValTrue       = "true"
	testValFalse      = "false"
	testMetaValues    = "propertyValues"
	testMetaConflicts = "conflicts"
)

func TestVerifyConflictingPropertyValuesInDocument(t *testing.T) {
	t.Parallel()

	for name, second := range map[string]string{
		"same case":      testPropHermetic,
		"different case": "hermetic",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			doc := buildEnvDoc{
				Environment: []envProperty{
					{Name: testPropHermetic, Value: testValTrue},
					{Name: second, Value: testValFalse},
				},
			}

			att := testutil.WrapInToto(t, doc, testDigest, testPredicateType)

			_, err := buildenv.Verify(context.Background(), att, &policy.Policy{}, testDigest)
			if !errors.Is(err, buildenv.ErrInvalidBuildEnv) {
				t.Fatalf("expected ErrInvalidBuildEnv, got %v", err)
			}
		})
	}
}

func TestVerifyRepeatedPropertySameValueInDocument(t *testing.T) {
	t.Parallel()

	doc := buildEnvDoc{
		Environment: []envProperty{
			{Name: testPropHermetic, Value: testValTrue},
			{Name: testPropHermetic, Value: testValTrue},
		},
	}

	att := testutil.WrapInToto(t, doc, testDigest, testPredicateType)

	result, err := buildenv.Verify(context.Background(), att, &policy.Policy{}, testDigest)
	testutil.AssertNoError(t, err)
	testutil.AssertTrue(t, result.Passed)
}

func TestVerifyMultipleConflictingPropertyValues(t *testing.T) {
	t.Parallel()

	docA := buildEnvDoc{Environment: []envProperty{
		{Name: testPropHermetic, Value: testValTrue},
		{Name: testPropRunner, Value: testRunnerA},
	}}
	docB := buildEnvDoc{Environment: []envProperty{
		{Name: testPropHermetic, Value: testValFalse},
		{Name: testPropRunner, Value: testRunnerA},
	}}

	pol := &policy.Policy{BuildEnv: &policy.BuildEnvPolicy{
		RequiredProperties: []string{testPropHermetic},
	}}

	for name, order := range map[string][]buildEnvDoc{
		"true first":             {docA, docB},
		"false first":            {docB, docA},
		"conflict stays dropped": {docA, docB, docA},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			attestations := make([][]byte, 0, len(order))
			for idx := range order {
				attestations = append(attestations,
					testutil.WrapInToto(t, order[idx], testDigest, testPredicateType))
			}

			result, err := buildenv.VerifyMultiple(
				context.Background(), attestations, pol, testDigest,
			)
			testutil.AssertNoError(t, err)
			testutil.AssertTrue(t, result.Passed)

			values, ok := result.Metadata[testMetaValues].(map[string]string)
			if !ok {
				t.Fatalf("propertyValues has type %T", result.Metadata[testMetaValues])
			}

			if _, found := values[testPropHermetic]; found {
				t.Errorf("expected conflicting %s to be dropped, got %v", testPropHermetic, values)
			}

			testutil.AssertEqual(t, testRunnerA, values[testPropRunner])

			conflicting, ok := result.Metadata[testMetaConflicts].([]string)
			if !ok {
				t.Fatalf("conflicts has type %T", result.Metadata[testMetaConflicts])
			}

			testutil.AssertEqual(t, 1, len(conflicting))
			testutil.AssertEqual(t, testPropHermetic, conflicting[0])
		})
	}
}

func TestVerifyMultipleConflictDropsEverySpelling(t *testing.T) {
	t.Parallel()

	docA := buildEnvDoc{Environment: []envProperty{
		{Name: testPropHermetic, Value: testValTrue},
		{Name: "hermetic", Value: testValTrue},
	}}
	docB := buildEnvDoc{Environment: []envProperty{{Name: testPropHermetic, Value: testValFalse}}}

	for range 20 {
		result, err := buildenv.VerifyMultiple(context.Background(), [][]byte{
			testutil.WrapInToto(t, docA, testDigest, testPredicateType),
			testutil.WrapInToto(t, docB, testDigest, testPredicateType),
		}, &policy.Policy{}, testDigest)
		testutil.AssertNoError(t, err)

		values, ok := result.Metadata[testMetaValues].(map[string]string)
		if !ok {
			t.Fatalf("propertyValues has type %T", result.Metadata[testMetaValues])
		}

		if len(values) != 0 {
			t.Fatalf("expected every spelling of the conflicting key to be dropped, got %v", values)
		}
	}
}

func TestVerifyConflictingPropertiesEmptyForSingleDocument(t *testing.T) {
	t.Parallel()

	doc := buildEnvDoc{Environment: []envProperty{{Name: testPropHermetic, Value: testValTrue}}}
	att := testutil.WrapInToto(t, doc, testDigest, testPredicateType)

	for name, verify := range map[string]func() (*types.CheckResult, error){
		"verify": func() (*types.CheckResult, error) {
			return buildenv.Verify(context.Background(), att, &policy.Policy{}, testDigest)
		},
		"verify multiple": func() (*types.CheckResult, error) {
			return buildenv.VerifyMultiple(
				context.Background(), [][]byte{att}, &policy.Policy{}, testDigest,
			)
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			result, err := verify()
			testutil.AssertNoError(t, err)
			testutil.AssertTrue(t, result.Passed)

			conflicting, ok := result.Metadata[testMetaConflicts].([]string)
			if !ok {
				t.Fatalf("conflicts has type %T", result.Metadata[testMetaConflicts])
			}

			testutil.AssertEqual(t, 0, len(conflicting))
		})
	}
}

func TestVerifyMultipleSamePropertyValueAcrossDocuments(t *testing.T) {
	t.Parallel()

	doc := buildEnvDoc{Environment: []envProperty{{Name: testPropHermetic, Value: testValTrue}}}

	attestations := [][]byte{
		testutil.WrapInToto(t, doc, testDigest, testPredicateType),
		testutil.WrapInToto(t, doc, testDigest, testPredicateType),
	}

	result, err := buildenv.VerifyMultiple(
		context.Background(), attestations, &policy.Policy{}, testDigest,
	)
	testutil.AssertNoError(t, err)
	testutil.AssertTrue(t, result.Passed)

	values, ok := result.Metadata[testMetaValues].(map[string]string)
	if !ok {
		t.Fatalf("propertyValues has type %T", result.Metadata[testMetaValues])
	}

	testutil.AssertEqual(t, testValTrue, values[testPropHermetic])
}

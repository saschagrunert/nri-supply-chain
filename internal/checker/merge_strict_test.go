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
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/checker"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
)

const (
	testKeyValues  = "values"
	testKeyDropped = "dropped"
)

func mergeMaps(t *testing.T, maps ...map[string]string) map[string]any {
	t.Helper()

	merge := checker.UnionMapDropConflicts()

	var merged any = maps[0]

	for _, next := range maps[1:] {
		result, ok := merge(merged, next)
		testutil.AssertTrue(t, ok)

		merged = result
	}

	meta := map[string]any{testKeyValues: merged}
	checker.ResolveConflictingMap(meta, testKeyValues, testKeyDropped)

	return meta
}

func TestUnionMapDropConflicts(t *testing.T) {
	t.Parallel()

	t.Run("disjoint and equal keys merge", func(t *testing.T) {
		t.Parallel()

		meta := mergeMaps(t, map[string]string{"a": "1"}, map[string]string{"A": "1", "b": "2"})

		values, isMap := meta[testKeyValues].(map[string]string)
		testutil.AssertTrue(t, isMap)
		testutil.AssertEqual(t, "1", values["a"])
		testutil.AssertEqual(t, "2", values["b"])
		testutil.AssertEqual(t, 2, len(values))

		dropped, isList := meta[testKeyDropped].([]string)
		testutil.AssertTrue(t, isList)
		testutil.AssertEqual(t, 0, len(dropped))
	})

	t.Run("different value drops the key for later documents", func(t *testing.T) {
		t.Parallel()

		meta := mergeMaps(t,
			map[string]string{"HERMETIC": "true", "RUNNER": "a"},  //nolint:goconst // test data
			map[string]string{"hermetic": "false", "RUNNER": "a"}, //nolint:goconst // test data
			map[string]string{"HERMETIC": "true"},
		)

		values, isMap := meta[testKeyValues].(map[string]string)
		testutil.AssertTrue(t, isMap)
		testutil.AssertEqual(t, 1, len(values))
		testutil.AssertEqual(t, "a", values["RUNNER"])

		dropped, isList := meta[testKeyDropped].([]string)
		testutil.AssertTrue(t, isList)
		testutil.AssertEqual(t, 1, len(dropped))
		testutil.AssertEqual(t, "HERMETIC", dropped[0])
	})

	t.Run("conflict drops every spelling of a key", func(t *testing.T) {
		t.Parallel()

		// The first document spells the key twice with the same value.
		for range 20 {
			meta := mergeMaps(t,
				map[string]string{"HERMETIC": "true", "hermetic": "true"},
				map[string]string{"HERMETIC": "false"},
			)

			values, isMap := meta[testKeyValues].(map[string]string)
			testutil.AssertTrue(t, isMap)
			testutil.AssertEqual(t, 0, len(values))

			dropped, isList := meta[testKeyDropped].([]string)
			testutil.AssertTrue(t, isList)
			testutil.AssertEqual(t, 1, len(dropped))
		}
	})

	t.Run("later document spelling a key twice conflicts", func(t *testing.T) {
		t.Parallel()

		for range 20 {
			meta := mergeMaps(t,
				map[string]string{"RUNNER": "a"},
				map[string]string{"HERMETIC": "false", "hermetic": "false"},
				map[string]string{"Hermetic": "true"},
			)

			values, isMap := meta[testKeyValues].(map[string]string)
			testutil.AssertTrue(t, isMap)
			testutil.AssertEqual(t, 1, len(values))
			testutil.AssertEqual(t, "a", values["RUNNER"])
		}
	})

	t.Run("single document gets an empty dropped list", func(t *testing.T) {
		t.Parallel()

		meta := map[string]any{testKeyValues: map[string]string{"a": "1"}}
		checker.ResolveConflictingMap(meta, testKeyValues, testKeyDropped)

		dropped, isList := meta[testKeyDropped].([]string)
		testutil.AssertTrue(t, isList)
		testutil.AssertEqual(t, 0, len(dropped))
	})

	t.Run("type mismatch is not merged", func(t *testing.T) {
		t.Parallel()

		_, ok := checker.UnionMapDropConflicts()(map[string]string{}, "x")
		testutil.AssertEqual(t, false, ok)

		_, ok = checker.UnionMapDropConflicts()("x", map[string]string{})
		testutil.AssertEqual(t, false, ok)
	})
}

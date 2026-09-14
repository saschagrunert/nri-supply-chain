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

package cel_test

import (
	"strings"
	"testing"

	celengine "github.com/saschagrunert/nri-supply-chain/internal/cel"
	"github.com/saschagrunert/nri-supply-chain/internal/guac"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

func TestGUACMissingDataHint(t *testing.T) {
	t.Parallel()

	partial := guacResult(&guac.QueryResult{
		Available:                false,
		VulnerabilitiesAvailable: true,
	})

	tests := []struct {
		name     string
		require  string
		wantHint string
	}{
		{
			name:     "missing scorecard",
			require:  "guac.scorecard.aggregate >= 7.0",
			wantHint: "guac.scorecard_available",
		},
		{
			name:     "missing dependency count",
			require:  "guac.dependency_count < 100",
			wantHint: "guac.dependencies_available",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			compiled, err := celengine.Compile([]celengine.Rule{{Require: test.require}})
			if err != nil {
				t.Fatalf("compile error: %v", err)
			}

			vars := celengine.BuildVars(
				testImageRef, testRegistry, testRepository, testDigest, testNamespace,
				map[types.CheckType]*types.CheckResult{types.CheckTypeGUAC: partial},
			)

			result := celengine.Evaluate(compiled, vars)
			if result.Passed {
				t.Fatalf("expected the rule to fail, got %s", result.Detail)
			}

			if !strings.Contains(result.Detail, test.wantHint) {
				t.Errorf("expected hint %q, got detail %q", test.wantHint, result.Detail)
			}
		})
	}
}

func TestGUACScorecardTruncatedVariable(t *testing.T) {
	t.Parallel()

	truncated := guacResult(&guac.QueryResult{
		Available:          true,
		ScorecardAvailable: true,
		Scorecard: &guac.ScorecardResult{
			Aggregate: 0, Checks: nil, Source: guac.TruncatedScorecardSource, Truncated: true,
		},
	})

	runCELVarTests(t, types.CheckTypeGUAC, []celVarTest{
		{
			name:    "truncated scorecard is not an unlinked source",
			require: `guac.scorecard.source == "" || guac.scorecard.aggregate >= 7.0`,
			result:  truncated,
			pass:    false,
		},
		{
			name:    "truncation flag is exposed",
			require: "guac.scorecard.truncated == true",
			result:  truncated,
			pass:    true,
		},
	})
}

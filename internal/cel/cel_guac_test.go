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
	"reflect"
	"testing"

	celengine "github.com/saschagrunert/nri-supply-chain/internal/cel"
	"github.com/saschagrunert/nri-supply-chain/internal/guac"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

func guacResult(queryResult *guac.QueryResult) *types.CheckResult {
	result := types.PassResult(types.CheckTypeGUAC, "ok")
	result.Metadata = guac.BuildMetadata(queryResult)

	return result
}

func TestGUACVarsFailClosed(t *testing.T) {
	t.Parallel()

	const noVulnsRule = "guac.vulnerabilities.size() == 0"

	cleanVulns := guacResult(&guac.QueryResult{
		Available:                true,
		VulnerabilitiesAvailable: true,
	})

	failedVulns := guacResult(&guac.QueryResult{
		Available:             false,
		DependenciesAvailable: true,
		DependencyInfo:        &guac.DependencyInfo{Dependencies: nil, DependencyCount: 3},
	})

	runCELVarTests(t, types.CheckTypeGUAC, []celVarTest{
		{
			name:    "clean vulnerability data passes",
			require: noVulnsRule,
			result:  cleanVulns,
			pass:    true,
		},
		{
			name:    "failed vulnerability query fails",
			require: noVulnsRule,
			result:  failedVulns,
			pass:    false,
		},
		{name: "guac not configured fails", require: noVulnsRule, result: nil, pass: false},
		{
			name:    "availability guard",
			require: "guac.vulnerabilities_available && guac.vulnerabilities.size() == 0",
			result:  failedVulns, pass: false,
		},
		{
			name:    "partial dependency data is kept",
			require: "guac.dependencies_available && guac.dependency_count == 3",
			result:  failedVulns, pass: true,
		},
		{
			name:    "missing dependency data fails upper bound rules",
			require: "guac.dependency_count < 100",
			result:  cleanVulns, pass: false,
		},
		{
			name:    "failed vulnerability query fails negative rules",
			require: `!guac.vulnerabilities.exists(v, v.id == "CVE-2024-1234")`,
			result:  failedVulns, pass: false,
		},
		{
			name:    "guac not configured fails negative rules",
			require: `!guac.transitive_vulns.exists(v, v.id == "CVE-2024-1234")`,
			result:  nil, pass: false,
		},
		{
			name:    "missing dependency data fails lower bound rules",
			require: "guac.dependency_count > 0",
			result:  cleanVulns, pass: false,
		},
		{
			name:    "missing dependency data fails negative dependency rules",
			require: `!guac.dependencies.exists(d, d.startsWith("pkg:npm/evil"))`,
			result:  cleanVulns, pass: false,
		},
		{
			name:    "missing scorecard data fails",
			require: "guac.scorecard.aggregate < 5.0",
			result:  cleanVulns, pass: false,
		},
		{
			name:    "has() reports missing data",
			require: "!has(guac.vulnerabilities)",
			result:  failedVulns, pass: true,
		},
	})
}

func TestGUACVarsDefaultsMatchGUACPackage(t *testing.T) {
	t.Parallel()

	vars := celengine.BuildVars("", "", "", "", "", nil)

	got, ok := vars["guac"].(map[string]any)
	if !ok {
		t.Fatalf("expected guac vars map, got %T", vars["guac"])
	}

	if want := guac.UnavailableMetadata(); !reflect.DeepEqual(got, want) {
		t.Errorf(
			"CEL GUAC defaults drifted from guac.UnavailableMetadata:\n got: %v\nwant: %v",
			got,
			want,
		)
	}
}

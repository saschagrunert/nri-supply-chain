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
	"testing"

	celengine "github.com/saschagrunert/nri-supply-chain/internal/cel"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

func TestEvaluateSLSASourceVariables(t *testing.T) {
	t.Parallel()

	celengine.ResetEnvironmentForTest()

	provenance := func() *types.CheckResult {
		r := types.PassResult(types.CheckTypeSLSA, "ok")
		r.Metadata = map[string]any{
			metaBuilderID:     testRunnerURL,
			metaSource:        testSourceRepo,
			"sourceRef":       "refs/tags/v1.2.3",
			"sourceDigest":    "sha1:bb0fe8075f92bb82b679afe400a47b106f0cec4b",
			"trustConfigured": true,
		}

		return r
	}

	tests := []celVarTest{
		{
			name:    "slsa.sourceRef tag",
			require: `slsa.sourceRef.startsWith("refs/tags/")`,
			result:  provenance(),
			pass:    true,
		},
		{
			name:    "slsa.sourceDigest",
			require: `slsa.sourceDigest == "sha1:bb0fe8075f92bb82b679afe400a47b106f0cec4b"`,
			result:  provenance(),
			pass:    true,
		},
		{
			name:    "slsa.trustConfigured",
			require: `slsa.trustConfigured == true`,
			result:  provenance(),
			pass:    true,
		},
	}

	runCELVarTests(t, types.CheckTypeSLSA, tests)
}

func TestEvaluateBuildEnvConflictingProperties(t *testing.T) {
	t.Parallel()

	celengine.ResetEnvironmentForTest()

	const testMetaPropertyValues = "propertyValues"

	result := types.PassResult(types.CheckTypeBuildEnv, "ok")
	result.Metadata = map[string]any{
		"properties":           "HERMETIC,RUNNER",
		"propertyCount":        int64(2),
		testMetaPropertyValues: map[string]string{"RUNNER": "runner-a"},
		"conflicts":            []string{"HERMETIC"},
	}

	tests := []celVarTest{
		{
			name:    "conflicting property is listed",
			require: `"HERMETIC" in buildenv.conflicts`,
			result:  result,
			pass:    true,
		},
		{
			name:    "rule reading a conflicting property fails closed",
			require: `buildenv.propertyValues["HERMETIC"] == "true"`,
			result:  result,
			pass:    false,
		},
		{
			name:    "rule reading an unambiguous property passes",
			require: `buildenv.propertyValues["RUNNER"] == "runner-a"`,
			result:  result,
			pass:    true,
		},
	}

	runCELVarTests(t, types.CheckTypeBuildEnv, tests)
}

func TestEvaluateVulnScanUnknownCount(t *testing.T) {
	t.Parallel()

	celengine.ResetEnvironmentForTest()

	result := types.PassResult(types.CheckTypeVulnScan, "ok")
	result.Metadata = map[string]any{
		metaScanner:     testScannerURI,
		metaVulnCount:   int64(2),
		metaMaxSeverity: "unknown",
		"unknownCount":  int64(2),
	}

	tests := []celVarTest{
		{
			name:    "vulnscan.unknownCount blocks",
			require: `vulnscan.unknownCount == 0`,
			result:  result,
			pass:    false,
		},
	}

	runCELVarTests(t, types.CheckTypeVulnScan, tests)
}

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

package sbom_test

import (
	"context"
	"strings"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/sbom"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
)

// assemblyCycloneDX lists its inventory under metadata.component.components.
const assemblyCycloneDX = `{"bomFormat":"CycloneDX","metadata":{"component":{` +
	`"type":"container","name":"app","components":[` +
	`{"type":"library","name":"log4j","version":"2.14.1","purl":"pkg:maven/org.apache/log4j@2.14.1",` +
	`"licenses":[{"license":{"id":"GPL-3.0-only"}}]}]}}}`

func TestVerifyCycloneDXAssemblyComponents(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		pol  *policy.Policy
	}{
		{
			name: "component deny list",
			pol: &policy.Policy{SBOM: &policy.SBOMPolicy{
				Component: &policy.SBOMComponentPolicy{
					Deny: []string{"pkg:maven/org.apache/log4j"},
				},
			}},
		},
		{
			name: "license deny list",
			pol: &policy.Policy{SBOM: &policy.SBOMPolicy{
				License: &policy.SBOMLicensePolicy{Deny: []string{"GPL-3.0-only"}},
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			passed, detail := verifyRaw(t, assemblyCycloneDX, test.pol)
			if passed {
				t.Fatalf("expected the assembly component to fail the check, got %q", detail)
			}
		})
	}

	result, err := sbom.VerifyMultipleWithBaseline(
		context.Background(),
		[][]byte{wrapRaw(t, assemblyCycloneDX)},
		nil,
		&policy.Policy{},
		testDigest,
	)
	testutil.AssertNoError(t, err)
	testutil.AssertTrue(t, result.Passed)
	testutil.AssertEqual[any](t, int64(1), result.Metadata["componentCount"])
}

func TestVerifyRejectsAmbiguousFormat(t *testing.T) {
	t.Parallel()

	predicate := `{"spdxVersion":"SPDX-2.3","packages":[{"SPDXID":"SPDXRef-a","name":"a",` +
		`"externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:npm/a@1"}]}],` +
		`"bomFormat":"CycloneDX","vulnerabilities":[{"id":"CVE-1","ratings":[{"score":9.8}]}]}`

	result, err := sbom.VerifyMultipleWithBaseline(
		context.Background(), [][]byte{wrapRaw(t, predicate)}, nil, &policy.Policy{}, testDigest)
	testutil.AssertNoError(t, err)

	if result.Passed || !strings.Contains(result.Detail, "more than one SBOM format") {
		t.Fatalf(
			"expected an ambiguous document to fail, got passed=%v detail=%q",
			result.Passed,
			result.Detail,
		)
	}
}

func TestVerifyCycloneDXAssemblyTooDeep(t *testing.T) {
	t.Parallel()

	nested := `{"type":"library","name":"leaf","purl":"pkg:npm/leaf@1"}`
	for range 33 {
		nested = `{"type":"library","name":"n","purl":"pkg:npm/n@1","components":[` + nested + `]}`
	}

	predicate := `{"bomFormat":"CycloneDX","metadata":{"component":{"type":"container","name":"app",` +
		`"components":[` + nested + `]}}}`

	result, err := sbom.VerifyMultipleWithBaseline(
		context.Background(), [][]byte{wrapRaw(t, predicate)}, nil, &policy.Policy{}, testDigest)
	testutil.AssertNoError(t, err)

	if result.Passed || !strings.Contains(result.Detail, "nested deeper") {
		t.Fatalf(
			"expected deeply nested assembly to fail, got passed=%v detail=%q",
			result.Passed,
			result.Detail,
		)
	}
}

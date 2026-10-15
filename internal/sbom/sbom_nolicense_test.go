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
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
)

// TestVerifyPackagesWithoutLicenseFailAllowList checks that every format
// treats a package without license data alike: it fails an allow list unless
// the list accepts NONE or NOASSERTION.
func TestVerifyPackagesWithoutLicenseFailAllowList(t *testing.T) {
	t.Parallel()

	spdx2 := func(license string) string {
		return `{"spdxVersion":"SPDX-2.3","packages":[{"SPDXID":"SPDXRef-a","name":"a",` +
			`"licenseConcluded":"` + license + `","licenseDeclared":"` + license + `",` +
			`"externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:npm/a@1"}]}]}`
	}
	spdx3 := func(license string) string {
		return `{"specVersion":"3.0.1","@graph":[` +
			`{"type":"software_Package","spdxId":"urn:a","name":"a","software_packageUrl":"pkg:npm/a@1"},` +
			`{"type":"Relationship","spdxId":"urn:r","from":"urn:a","relationshipType":"hasDeclaredLicense",` +
			`"to":["https://spdx.org/rdf/3.0.1/terms/Expanded/` + license + `"]}]}`
	}
	cyclonedx := `{"bomFormat":"CycloneDX","components":[{"type":"library","name":"a","purl":"pkg:npm/a@1"}]}`

	tests := []struct {
		name      string
		predicate string
		accepted  string
	}{
		{name: "SPDX 2 NOASSERTION", predicate: spdx2(testLicenseNone), accepted: testLicenseNone},
		{name: "SPDX 2 NONE", predicate: spdx2("NONE"), accepted: "NONE"},
		{
			name:      "SPDX 3 NoAssertionLicense",
			predicate: spdx3("NoAssertionLicense"),
			accepted:  testLicenseNone,
		},
		{name: "SPDX 3 NoneLicense", predicate: spdx3("NoneLicense"), accepted: "NONE"},
		{name: "CycloneDX without licenses", predicate: cyclonedx, accepted: testLicenseNone},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			allow := func(entries ...string) *policy.Policy {
				return &policy.Policy{SBOM: &policy.SBOMPolicy{
					License: &policy.SBOMLicensePolicy{Allow: entries},
				}}
			}

			passed, detail := verifyRaw(t, test.predicate, allow(testLicenseMIT))
			if passed {
				t.Errorf(
					"expected a package without license to fail the allow list, got %q",
					detail,
				)
			}

			passed, detail = verifyRaw(t, test.predicate, allow(testLicenseMIT, test.accepted))
			if !passed {
				t.Errorf(
					"expected %s in the allow list to accept the package, got %q",
					test.accepted,
					detail,
				)
			}
		})
	}
}

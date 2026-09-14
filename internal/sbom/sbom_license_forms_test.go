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
	"encoding/json"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
)

func licenseExpressionBOM(t *testing.T, expression string) string {
	t.Helper()

	encoded, err := json.Marshal(expression)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	return `{"bomFormat":"CycloneDX","components":[{"name":"a","purl":"pkg:npm/a@1",` +
		`"licenses":[{"expression":` + string(encoded) + `}]}]}`
}

func TestVerifyLicenseVersionForms(t *testing.T) {
	t.Parallel()

	allow := func(ids ...string) *policy.Policy {
		return &policy.Policy{SBOM: &policy.SBOMPolicy{
			License: &policy.SBOMLicensePolicy{Allow: ids},
		}}
	}

	tests := []struct {
		name       string
		expression string
		pol        *policy.Policy
		wantPassed bool
	}{
		{"plus denied by only", testLicenseGPL2OrLater, denyLicensePolicy("GPL-2.0-only"), false},
		{"or-later denied by only", "GPL-2.0-or-later", denyLicensePolicy("GPL-2.0-only"), false},
		{"deprecated denied by only", "GPL-2.0", denyLicensePolicy("GPL-2.0-only"), false},
		{"only denied by deprecated", "GPL-2.0-only", denyLicensePolicy("GPL-2.0"), false},
		{
			"plus denied by or-later",
			testLicenseGPL2OrLater,
			denyLicensePolicy("GPL-2.0-or-later"),
			false,
		},
		{"only plus denied by only", "GPL-2.0-only+", denyLicensePolicy("GPL-2.0-only"), false},
		{"other version not denied", "GPL-3.0-only", denyLicensePolicy("GPL-2.0-only"), true},
		{
			"zero width separators", "MIT\u200bAND\u200bGPL-3.0-only",
			denyLicensePolicy("GPL-3.0-only"), false,
		},
		{"byte order mark prefix", "\ufeffGPL-3.0-only", denyLicensePolicy("GPL-3.0-only"), false},
		{
			"word joiner separator",
			"MIT\u2060OR\u2060GPL-3.0-only",
			denyLicensePolicy("GPL-3.0-only"),
			false,
		},
		{
			"zero width inside an identifier", "GPL\u200b-3.0-only",
			denyLicensePolicy("GPL-3.0-only"), false,
		},
		{
			"zero width inside an identifier in an expression", "MIT AND GPL-3.0\u200c-only",
			denyLicensePolicy("GPL-3.0-only"), false,
		},
		{
			"license ref only suffix is not normalized",
			"LicenseRef-Acme-or-later", allow("LicenseRef-Acme"), false,
		},
		{
			"license ref kept exact for deny",
			"LicenseRef-Acme-only", //nolint:goconst // test data
			denyLicensePolicy("LicenseRef-Acme"), true,
		},
		{
			"license ref exact match allowed",
			"LicenseRef-Acme-only", allow("LicenseRef-Acme-only"), true,
		},
		{
			"license ref only suffix does not widen allow",
			"LicenseRef-Acme-only", allow("LicenseRef-Acme"), false,
		},
		{"deprecated allowed by only", "GPL-2.0", allow("GPL-2.0-only"), true},
		{"plus not allowed by only", testLicenseGPL2OrLater, allow("GPL-2.0-only"), false},
		{"plus allowed by or-later", testLicenseGPL2OrLater, allow("GPL-2.0-or-later"), true},
		{"deprecated plus allowed by or-later", "GPL-2.0-only+", allow("GPL-2.0-or-later"), true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			passed, detail := verifyRaw(t, licenseExpressionBOM(t, test.expression), test.pol)
			if passed != test.wantPassed {
				t.Errorf("expected passed=%v for %q, got %v: %s",
					test.wantPassed, test.expression, passed, detail)
			}
		})
	}
}

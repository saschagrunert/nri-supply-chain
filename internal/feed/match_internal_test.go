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

package feed

import "testing"

func TestUnmappedEcosystemLoggedOnce(t *testing.T) {
	t.Parallel()

	const ecosystem = "openSUSE:Leap 15.5 test-only"

	if got := purlFromEcosystem(ecosystem, "zlib"); got != "" {
		t.Fatalf("expected no purl for an unmapped ecosystem, got %q", got)
	}

	if warnUnmappedEcosystem(ecosystem) {
		t.Error("expected the unmapped ecosystem to be logged only once")
	}
}

func TestTypeAndName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		raw      string
		wantType string
		wantName string
		wantOK   bool
	}{
		{"pkg:npm/%40angular/core@12.0.0?x=y#sub", "npm", "core", true},
		{"PKG:pypi/Typing_Extensions@4.0", "pypi", "Typing_Extensions", true},
		{"pkg:golang/github.com/foo/bar@v1.0.0", "golang", "bar", true},
		{"pkg:npm/%66oo", "npm", "foo", true},
		{"pkg:npm/lodash/@1", purlTypeNPM, "lodash", true},
		{"npm/foo", "", "", false},
		{"pkg:npm", "", "", false},
	}

	for _, test := range tests {
		typ, name, ok := typeAndName(test.raw)
		if typ != test.wantType || name != test.wantName || ok != test.wantOK {
			t.Errorf("typeAndName(%q) = (%q, %q, %v), want (%q, %q, %v)",
				test.raw, typ, name, ok, test.wantType, test.wantName, test.wantOK)
		}
	}
}

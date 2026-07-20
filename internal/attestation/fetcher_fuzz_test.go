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

package attestation_test

import (
	"regexp"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
)

func FuzzGlobToRegex(f *testing.F) {
	f.Add("*")
	f.Add("*.example.com")
	f.Add("foo?bar")
	f.Add("[abc]")
	f.Add("[!abc]")
	f.Add("foo\\*bar")
	f.Add("**/*.json")
	f.Add("")
	f.Add("[a-z]")
	f.Add("test[")

	f.Fuzz(func(t *testing.T, pattern string) {
		result := attestation.ExportGlobToRegex(pattern)

		_, err := regexp.Compile(result)
		if err != nil {
			t.Errorf("globToRegex(%q) produced invalid regexp %q: %v", pattern, result, err)
		}
	})
}

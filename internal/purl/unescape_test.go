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

package purl_test

import (
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/purl"
)

func TestLenientUnescape(t *testing.T) {
	t.Parallel()

	for input, want := range map[string]string{
		"plain":            "plain",
		"pkg:npm/%40scope": "pkg:npm/@scope",
		"100%":             "100%",
		"%zz%41":           "%zzA",
		"%2":               "%2",
		"/etc%2Fpasswd":    "/etc/passwd",
	} {
		if got := purl.LenientUnescape(input); got != want {
			t.Errorf("LenientUnescape(%q) = %q, want %q", input, got, want)
		}
	}
}

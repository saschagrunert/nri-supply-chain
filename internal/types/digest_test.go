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

package types_test

import (
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

func TestParseDigest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		digest   string
		wantAlgo string
		wantHash string
	}{
		{"valid sha256", "sha256:abcdef0123456789", "sha256", "abcdef0123456789"},
		{"valid sha512", "sha512:def456", "sha512", "def456"},
		{"missing colon", "sha256abc123", "", ""},
		{"empty string", "", "", ""},
		{"multiple colons rejected", "sha256:abc:def:ghi", "", ""},
		{"colon only", ":", "", ""},
		{"empty hash", "sha256:", "", ""},
		{"empty algo", ":abc123", "", ""},
		{"non-hex hash", "sha256:xyz123", "", ""},
		{"uppercase hex rejected", "sha256:ABCDEF", "", ""},
		{"uppercase algo rejected", "SHA256:abc123", "", ""},
		{"algo with hyphen rejected", "sha-256:abc123", "", ""},
		{"hash with spaces rejected", "sha256:abc 123", "", ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			algo, hash := types.ParseDigest(test.digest)

			if algo != test.wantAlgo {
				t.Errorf("algo = %q, want %q", algo, test.wantAlgo)
			}

			if hash != test.wantHash {
				t.Errorf("hash = %q, want %q", hash, test.wantHash)
			}
		})
	}
}

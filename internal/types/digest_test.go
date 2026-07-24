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
	"unicode/utf8"

	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	hexBlock64  = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	hexBlock128 = hexBlock64 + hexBlock64
)

func TestParseDigest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		digest   string
		wantAlgo string
		wantHash string
	}{
		{"valid sha256", "sha256:" + hexBlock64, "sha256", hexBlock64},
		{"valid sha512", "sha512:" + hexBlock128, "sha512", hexBlock128},
		{"valid sha3-256", "sha3-256:" + hexBlock64, "sha3-256", hexBlock64},
		{"short hash rejected", "sha256:abcdef0123456789", "", ""},
		{"missing colon", "sha256abc123", "", ""},
		{"empty string", "", "", ""},
		{"multiple colons rejected", "sha256:abc:def:ghi", "", ""},
		{"colon only", ":", "", ""},
		{"empty hash", "sha256:", "", ""},
		{"empty algo", ":abc123", "", ""},
		{"non-hex hash", "sha256:xyz123", "", ""},
		{"uppercase hex rejected", "sha256:ABCDEF", "", ""},
		{"uppercase algo rejected", "SHA256:abc123", "", ""},
		{"unrecognized algo rejected", "sha-256:abc123", "", ""},
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

func FuzzParseDigest(f *testing.F) {
	f.Add("sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
	f.Add("")
	f.Add(":")
	f.Add("sha256:")
	f.Add(":abc")
	f.Add("no-colon")
	f.Add("sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
	f.Add("sha3-256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")

	f.Fuzz(func(t *testing.T, input string) {
		if !utf8.ValidString(input) {
			return
		}

		algo, hash := types.ParseDigest(input)
		if algo != "" {
			if hash == "" {
				t.Error("non-empty algo with empty hash")
			}

			for _, c := range algo {
				if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
					t.Errorf("algo contains invalid character: %q", string(c))
				}
			}

			for _, c := range hash {
				if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
					t.Errorf("hash contains invalid character: %q", string(c))
				}
			}
		}
	})
}

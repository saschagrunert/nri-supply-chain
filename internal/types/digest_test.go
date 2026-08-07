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
	algoSHA256  = "sha256"
	algoSHA384  = "sha384"
	algoSHA512  = "sha512"
	hexBlock64  = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	hexBlock96  = hexBlock64 + "abcdef0123456789abcdef0123456789"
	hexBlock128 = hexBlock64 + hexBlock64
	zeroBlock64 = "0000000000000000000000000000000000000000000000000000000000000000"
)

func TestParseDigest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		digest   string
		wantAlgo string
		wantHash string
	}{
		{"valid sha256", algoSHA256 + ":" + hexBlock64, algoSHA256, hexBlock64},
		{"valid sha384", algoSHA384 + ":" + hexBlock96, algoSHA384, hexBlock96},
		{"valid sha512", algoSHA512 + ":" + hexBlock128, algoSHA512, hexBlock128},
		{"valid sha3-256", "sha3-256:" + hexBlock64, "sha3-256", hexBlock64},
		{"valid sha3-384", "sha3-384:" + hexBlock96, "sha3-384", hexBlock96},
		{"valid sha3-512", "sha3-512:" + hexBlock128, "sha3-512", hexBlock128},
		{"valid sha512-256", "sha512-256:" + hexBlock64, "sha512-256", hexBlock64},
		{"sha256 wrong length rejected", algoSHA256 + ":" + hexBlock128, "", ""},
		{"sha384 wrong length rejected", algoSHA384 + ":" + hexBlock64, "", ""},
		{"sha512 wrong length rejected", algoSHA512 + ":" + hexBlock64, "", ""},
		{"sha512 truncated rejected", algoSHA512 + ":" + hexBlock96, "", ""},
		{"short hash rejected", algoSHA256 + ":abcdef0123456789", "", ""},
		{"missing colon", "sha256abc123", "", ""},
		{"empty string", "", "", ""},
		{"multiple colons rejected", algoSHA256 + ":abc:def:ghi", "", ""},
		{"colon only", ":", "", ""},
		{"empty hash", algoSHA256 + ":", "", ""},
		{"empty algo", ":abc123", "", ""},
		{"non-hex hash", algoSHA256 + ":xyz123", "", ""},
		{"uppercase hex rejected", algoSHA256 + ":ABCDEF", "", ""},
		{"uppercase algo rejected", "SHA256:abc123", "", ""},
		{"unrecognized algo rejected", "sha-256:abc123", "", ""},
		{"hash with spaces rejected", algoSHA256 + ":abc 123", "", ""},
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

func TestMatchDigestInMap(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		imageDigest    string
		subjectDigests map[string]string
		want           bool
	}{
		{
			name:           "exact match",
			imageDigest:    algoSHA256 + ":" + hexBlock64,
			subjectDigests: map[string]string{algoSHA256: hexBlock64},
			want:           true,
		},
		{
			name:           "no match different hash",
			imageDigest:    algoSHA256 + ":" + hexBlock64,
			subjectDigests: map[string]string{algoSHA256: zeroBlock64},
			want:           false,
		},
		{
			name:           "no match wrong algorithm",
			imageDigest:    algoSHA256 + ":" + hexBlock64,
			subjectDigests: map[string]string{algoSHA512: hexBlock64},
			want:           false,
		},
		{
			name:           "empty map",
			imageDigest:    algoSHA256 + ":" + hexBlock64,
			subjectDigests: map[string]string{},
			want:           false,
		},
		{
			name:           "empty digest",
			imageDigest:    "",
			subjectDigests: map[string]string{algoSHA256: hexBlock64},
			want:           false,
		},
		{
			name:           "invalid digest format",
			imageDigest:    "nocolon",
			subjectDigests: map[string]string{algoSHA256: hexBlock64},
			want:           false,
		},
		{
			name:        "multiple algorithms with match",
			imageDigest: algoSHA256 + ":" + hexBlock64,
			subjectDigests: map[string]string{
				algoSHA512: hexBlock128,
				algoSHA256: hexBlock64,
			},
			want: true,
		},
		{
			name:           "nil map",
			imageDigest:    algoSHA256 + ":" + hexBlock64,
			subjectDigests: nil,
			want:           false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := types.MatchDigestInMap(test.imageDigest, test.subjectDigests)
			if got != test.want {
				t.Errorf("MatchDigestInMap(%q, %v) = %v, want %v",
					test.imageDigest, test.subjectDigests, got, test.want)
			}
		})
	}
}

func assertValidParsedDigest(t *testing.T, algo, hash string) {
	t.Helper()

	if hash == "" {
		t.Error("non-empty algo with empty hash")
	}

	expected, ok := wantHexLen[algo]
	if !ok {
		t.Errorf("accepted unrecognized algorithm: %q", algo)
	} else if len(hash) != expected {
		t.Errorf("algo %q: got hash length %d, want %d", algo, len(hash), expected)
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

var wantHexLen = map[string]int{ //nolint:gochecknoglobals // mirrors expectedHexLen for fuzz assertions
	"sha256":     64,
	"sha384":     96,
	"sha512":     128,
	"sha3-256":   64,
	"sha3-384":   96,
	"sha3-512":   128,
	"sha512-256": 64,
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
	f.Add("sha512:" + hexBlock128)
	f.Add("sha384:" + hexBlock96)

	f.Fuzz(func(t *testing.T, input string) {
		if !utf8.ValidString(input) {
			return
		}

		algo, hash := types.ParseDigest(input)
		if algo == "" {
			return
		}

		assertValidParsedDigest(t, algo, hash)
	})
}

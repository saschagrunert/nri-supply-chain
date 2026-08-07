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

package types

import "strings"

const (
	digestPartCount = 2

	hexLenSHA256 = 64
	hexLenSHA384 = 96
	hexLenSHA512 = 128
)

var expectedHexLen = map[string]int{ //nolint:gochecknoglobals // static lookup table
	"sha256":     hexLenSHA256,
	"sha384":     hexLenSHA384,
	"sha512":     hexLenSHA512,
	"sha3-256":   hexLenSHA256,
	"sha3-384":   hexLenSHA384,
	"sha3-512":   hexLenSHA512,
	"sha512-256": hexLenSHA256,
}

// ParseDigest splits a digest string (e.g., "sha256:abc123def...") into algorithm and hash.
// Returns empty strings if the format is invalid. The algorithm must be a recognized
// cryptographically strong algorithm per the OCI image spec, and the hash must be
// a valid hex string whose length matches the algorithm's expected output size.
func ParseDigest(digest string) (algo, hash string) {
	parts := strings.SplitN(digest, ":", digestPartCount)
	if len(parts) != digestPartCount || parts[0] == "" || parts[1] == "" {
		return "", ""
	}

	expected, ok := expectedHexLen[parts[0]]
	if !ok {
		return "", ""
	}

	if len(parts[1]) != expected || !isHex(parts[1]) {
		return "", ""
	}

	return parts[0], parts[1]
}

// MatchDigestInMap returns true if imageDigest matches a key-value pair in the
// given digest map (algorithm -> hex hash).
func MatchDigestInMap(imageDigest string, subjectDigests map[string]string) bool {
	algo, hash := ParseDigest(imageDigest)
	if algo == "" {
		return false
	}

	return subjectDigests[algo] == hash
}

func isHex(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}

	return true
}

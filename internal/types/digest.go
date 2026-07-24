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

	// minDigestHexLen is the minimum hex length for a digest hash.
	// SHA-256 produces 64 hex chars; reject anything shorter.
	minDigestHexLen = 64
)

func isAcceptedAlgorithm(algo string) bool {
	switch algo {
	case "sha256", "sha384", "sha512",
		"sha3-256", "sha3-384", "sha3-512",
		"sha512-256":
		return true
	default:
		return false
	}
}

// ParseDigest splits a digest string (e.g., "sha256:abc123def...") into algorithm and hash.
// Returns empty strings if the format is invalid. The algorithm must be a recognized
// cryptographically strong algorithm per the OCI image spec, and the hash must be
// a valid hex string of at least 64 characters.
func ParseDigest(digest string) (algo, hash string) {
	parts := strings.SplitN(digest, ":", digestPartCount)
	if len(parts) != digestPartCount || parts[0] == "" || parts[1] == "" {
		return "", ""
	}

	if !isAcceptedAlgorithm(parts[0]) {
		return "", ""
	}

	if len(parts[1]) < minDigestHexLen || !isHex(parts[1]) {
		return "", ""
	}

	return parts[0], parts[1]
}

func isHex(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}

	return true
}

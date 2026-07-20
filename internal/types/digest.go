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

const digestPartCount = 2

// ParseDigest splits a digest string (e.g., "sha256:abc123def...") into algorithm and hash.
// Returns empty strings if the format is invalid. The algorithm must contain only
// lowercase alphanumeric characters, and the hash must be a valid hex string.
func ParseDigest(digest string) (algo, hash string) {
	parts := strings.SplitN(digest, ":", digestPartCount)
	if len(parts) != digestPartCount || parts[0] == "" || parts[1] == "" {
		return "", ""
	}

	if !isAlphanumericLower(parts[0]) || !isHex(parts[1]) {
		return "", ""
	}

	return parts[0], parts[1]
}

func isAlphanumericLower(s string) bool {
	for _, c := range s {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}

	return true
}

func isHex(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}

	return true
}

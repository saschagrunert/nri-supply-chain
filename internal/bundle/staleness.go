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

package bundle

import "time"

// maxCreatedAtClockSkew is how far in the future a bundle creation time may
// be, to tolerate clock differences between the creating and verifying hosts.
const maxCreatedAtClockSkew = 5 * time.Minute

// StalenessResult holds the result of a bundle staleness check.
type StalenessResult struct {
	Stale bool
	// Future is set when the creation time lies in the future beyond the
	// allowed clock skew. The age of such a bundle is unknown, so it counts
	// as stale.
	Future  bool
	Age     time.Duration
	MaxAge  time.Duration
	Allowed bool
}

// CheckStaleness evaluates whether the bundle has exceeded its maximum age and
// whether the expiry policy allows continued use. A creation time in the
// future cannot prove freshness and is handled like an exceeded maximum age.
func CheckStaleness(
	manifest *Manifest,
	maxAge time.Duration,
	policy ExpiryPolicy,
) *StalenessResult {
	age := time.Since(manifest.CreatedAt)

	result := &StalenessResult{
		Stale:   false,
		Future:  false,
		Age:     age,
		MaxAge:  maxAge,
		Allowed: false,
	}

	if maxAge <= 0 {
		result.Allowed = true

		return result
	}

	if age < -maxCreatedAtClockSkew {
		result.Stale = true
		result.Future = true
		result.Allowed = policy != ExpiryDeny

		return result
	}

	if age <= maxAge {
		result.Allowed = true

		return result
	}

	result.Stale = true
	result.Allowed = policy != ExpiryDeny

	return result
}

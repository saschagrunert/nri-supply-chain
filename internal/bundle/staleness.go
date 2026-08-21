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

// StalenessResult holds the result of a bundle staleness check.
type StalenessResult struct {
	Stale   bool
	Age     time.Duration
	MaxAge  time.Duration
	Allowed bool
}

// CheckStaleness evaluates whether the bundle has exceeded its maximum age and
// whether the expiry policy allows continued use.
func CheckStaleness(
	manifest *Manifest,
	maxAge time.Duration,
	policy ExpiryPolicy,
) *StalenessResult {
	age := time.Since(manifest.CreatedAt)

	result := &StalenessResult{
		Stale:   false,
		Age:     age,
		MaxAge:  maxAge,
		Allowed: false,
	}

	if maxAge <= 0 {
		result.Allowed = true

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

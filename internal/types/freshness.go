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

import (
	"fmt"
	"time"
)

const (
	// clockSkewTolerance is the maximum acceptable clock skew for
	// timestamp-based freshness checks. Timestamps within this window
	// into the future are accepted to account for clock drift.
	clockSkewTolerance = 60 * time.Second

	// maxReasonableAge caps the computed age to prevent time.Duration
	// overflow on crafted timestamps (e.g., year 0001). time.Duration
	// is int64 nanoseconds, overflowing at ~292 years.
	maxReasonableAge = 200 * 365 * 24 * time.Hour
)

// VerifyFreshness checks whether a timestamp is within acceptable bounds.
// It returns errFuture when the timestamp is too far in the future,
// errUnreasonablyOld when it is beyond maxReasonableAge, and errStale
// when maxAge is non-nil and the computed age exceeds it.
// A nil maxAge means no staleness check is applied. The label
// (e.g., "built", "verified") is included in the stale error message
// for diagnostic context.
func VerifyFreshness(
	timestamp time.Time,
	maxAge *time.Duration,
	label string,
	errFuture, errUnreasonablyOld, errStale error,
) error {
	age := time.Since(timestamp)

	if age < -clockSkewTolerance {
		return fmt.Errorf("%w: %s", errFuture, timestamp.Format(time.RFC3339Nano))
	}

	if age < 0 {
		age = 0
	}

	if age > maxReasonableAge {
		return fmt.Errorf(
			"%w: timestamp %s is unreasonably old",
			errUnreasonablyOld,
			timestamp.Format(time.RFC3339Nano),
		)
	}

	if maxAge != nil && age > *maxAge {
		return fmt.Errorf(
			"%w: %s %s ago, max %s",
			errStale,
			label,
			age.Truncate(time.Second),
			*maxAge,
		)
	}

	return nil
}

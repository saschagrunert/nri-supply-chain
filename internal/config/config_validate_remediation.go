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

package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

func (c *Config) validateRemediationConfig() error {
	rem := &c.Remediation

	if !rem.Enabled() {
		return nil
	}

	var errs []error

	switch rem.Mode {
	case RemediationModeDisabled:
		return nil
	case RemediationModeWarn, RemediationModeThrottle:
	case RemediationModeEvict:
		if c.Verification != ModeEnforce {
			errs = append(errs, ErrRemediationEvictRequiresEnforce)
		}
	default:
		errs = append(errs, fmt.Errorf("%w: %q", ErrRemediationModeInvalid, rem.Mode))
	}

	errs = append(errs, validateRanges(
		numericRange[time.Duration]{
			value: rem.Interval.Duration, minimum: minRemediationInterval,
			maximum: maxRemediationInterval, showMinimum: true,
			errBelow: ErrRemediationIntervalTooShort, errAbove: ErrRemediationIntervalTooLong,
		},
		numericRange[time.Duration]{
			value: rem.Cooldown.Duration, minimum: minRemediationCooldown,
			maximum: maxRemediationCooldown, showMinimum: true,
			errBelow: ErrRemediationCooldownTooShort, errAbove: ErrRemediationCooldownTooLong,
		},
	)...)
	errs = append(errs, validateRanges(numericRange[int]{
		value: rem.BatchSize, minimum: 1, maximum: maxRemediationBatchSize,
		errBelow: ErrRemediationBatchSizeInvalid, errAbove: ErrRemediationBatchSizeTooLarge,
		showMinimum: false,
	})...)

	if rem.FeedDir != "" && !filepath.IsAbs(rem.FeedDir) {
		errs = append(errs, fmt.Errorf(
			"%w: %q", ErrRemediationFeedDirNotAbsolute, rem.FeedDir,
		))
	}

	errs = append(errs, validateThrottleConfig(&rem.Throttle)...)

	return errors.Join(errs...)
}

func validateThrottleConfig(throttle *ThrottleConfig) []error {
	var errs []error

	if throttle.CPUQuotaPercent < minThrottlePercent ||
		throttle.CPUQuotaPercent > maxThrottlePercent {
		errs = append(errs, fmt.Errorf(
			"%w: cpu_quota_percent=%d",
			ErrThrottlePercentOutOfRange, throttle.CPUQuotaPercent,
		))
	}

	if throttle.MemoryLimitPercent < minThrottlePercent ||
		throttle.MemoryLimitPercent > maxThrottlePercent {
		errs = append(errs, fmt.Errorf(
			"%w: memory_limit_percent=%d",
			ErrThrottlePercentOutOfRange, throttle.MemoryLimitPercent,
		))
	}

	return errs
}

func (c *Config) validateRemediationConfigRuntime() []error {
	if !c.Remediation.Enabled() || c.Remediation.FeedDir == "" {
		return nil
	}

	info, err := os.Lstat(c.Remediation.FeedDir)
	if err != nil {
		slog.Warn("Remediation feed directory not found, feed watching will be inactive",
			"path", c.Remediation.FeedDir, "error", err)

		return nil
	}

	if info.Mode()&os.ModeSymlink != 0 {
		return []error{fmt.Errorf(
			"%w: remediation.feed_dir %q", ErrSymlinkNotAllowed, c.Remediation.FeedDir,
		)}
	}

	if !info.IsDir() {
		return []error{fmt.Errorf(
			"%w: %q", ErrRemediationFeedDirNotDirectory, c.Remediation.FeedDir,
		)}
	}

	return nil
}

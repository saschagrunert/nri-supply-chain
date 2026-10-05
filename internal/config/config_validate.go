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
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/fileutil"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

// Validate checks the Config for invalid values.
func (c *Config) Validate() error {
	return errors.Join(
		c.validateConfigVersion(),
		errors.Join(c.validateModeAndLogLevel()...),
		c.validateMetricsAddr(),
		c.validateFetchAndCache(),
		c.validateResilienceFields(),
		c.validateSigstoreConfig(),
		c.validateRegistries(),
		c.validatePolicyConfig(),
		errors.Join(c.validateAllowlistDigests()...),
		c.validateAuditLog(),
		c.validateGUACConfig(),
		c.validateOfflineConfig(),
		c.validateRemediationConfig(),
	)
}

// ValidateRuntime performs runtime checks that require filesystem access.
func (c *Config) ValidateRuntime() error {
	var errs []error

	if c.Enabled() {
		if c.Policy.Source != PolicySourceOCI {
			errs = append(errs, c.validatePolicyDirRuntime()...)
		}

		errs = append(errs, c.validateTUFRootRuntime()...)
	}

	errs = append(errs, c.validatePolicyKeysRuntime()...)
	errs = append(errs, c.validateRegistryCACertsRuntime()...)
	errs = append(errs, c.validateGUACConfigRuntime()...)
	errs = append(errs, c.validateOfflineConfigRuntime()...)
	errs = append(errs, c.validateRemediationConfigRuntime()...)

	return errors.Join(errs...)
}

// containedFile describes a file the plugin reads at runtime with
// fileutil.ReadLimited.
type containedFile struct {
	// label names the config field, e.g. "guac.ca_cert".
	label string
	path  string
	// credential logs a warning for mode bits beyond 0600.
	credential bool
	// errNotFound wraps stat failures and errNotRegular paths that are not
	// regular files.
	errNotFound   error
	errNotRegular error
}

// checkContainedFile checks a file read at runtime, accepting exactly what
// fileutil.ReadLimited reads: a symbolic link is followed only inside the
// file's directory (the layout of Kubernetes ConfigMap and Secret volumes),
// one escaping it returns ErrSymlinkNotAllowed.
func checkContainedFile(file *containedFile) (os.FileInfo, error) {
	info, err := fileutil.StatRegular(file.path)

	switch {
	case errors.Is(err, fileutil.ErrSymlink):
		return nil, fmt.Errorf("%w: %s %q: %w", ErrSymlinkNotAllowed, file.label, file.path, err)
	case errors.Is(err, fileutil.ErrNotRegularFile):
		return nil, fmt.Errorf("%w: %s %q", file.errNotRegular, file.label, file.path)
	case err != nil:
		return nil, fmt.Errorf("%w: %s %q: %w", file.errNotFound, file.label, file.path, err)
	}

	if file.credential {
		permErr := fileutil.CheckCredentialPermissions(file.path)
		if permErr != nil {
			slog.Warn("Credential file has overly permissive mode bits",
				"field", file.label, "path", file.path, "error", permErr)
		}
	}

	return info, nil
}

func (c *Config) validateConfigVersion() error {
	// An explicit `config_version = 0` is normalized to 1 by Migrate()
	// before validation runs. Omitted fields keep DefaultConfig's value (1).
	switch {
	case c.ConfigVersion < 1:
		return fmt.Errorf("%w: got %d", ErrInvalidConfigVersion, c.ConfigVersion)
	case c.ConfigVersion > LatestConfigVersion:
		return fmt.Errorf(
			"%w: got %d, max %d",
			ErrConfigVersionTooNew, c.ConfigVersion, LatestConfigVersion,
		)
	default:
		return nil
	}
}

func (c *Config) validateModeAndLogLevel() []error {
	var errs []error

	switch c.Verification {
	case ModeDisabled, ModeWarn, ModeEnforce:
	default:
		errs = append(errs, fmt.Errorf(
			"%w: %q; see docs/config.md", ErrInvalidVerificationMode, c.Verification,
		))
	}

	if c.LogLevel != "" {
		switch c.LogLevel {
		case "debug", "info", "warn", "error":
		default:
			errs = append(errs, fmt.Errorf("%w: %q", ErrInvalidLogLevel, c.LogLevel))
		}
	}

	return errs
}

func (c *Config) validateMetricsAddr() error {
	if c.MetricsAddr == "" {
		return nil
	}

	host, _, err := net.SplitHostPort(c.MetricsAddr)
	if err != nil {
		return fmt.Errorf("%w: %q: %w", ErrInvalidMetricsAddr, c.MetricsAddr, err)
	}

	if host != "127.0.0.1" && host != "::1" && host != "localhost" && host != "" {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			slog.Warn("Metrics address is not loopback, metrics will be exposed externally",
				"metrics_addr", c.MetricsAddr,
			)
		}
	}

	return nil
}

func (c *Config) validateFetchAndCache() error {
	var errs []error

	err := types.ValidateAction(
		"fetch_failure_policy", c.FetchFailurePolicy,
	)
	if err != nil {
		errs = append(errs, fmt.Errorf("validating config: %w", err))
	}

	if c.Verification == ModeEnforce && c.FetchFailurePolicy == types.ActionAllow {
		errs = append(errs, fmt.Errorf(
			"%w: fetch_failure_policy \"allow\" in enforce mode would let "+
				"unverified containers through on fetch errors",
			ErrInvalidVerificationMode,
		))
	}

	errs = append(errs, c.validateTimeoutFields()...)

	err = c.validateCacheFields()
	if err != nil {
		errs = append(errs, err)
	}

	if c.Enabled() && c.Policy.Source != PolicySourceOCI {
		if c.PolicyDir == "" {
			errs = append(errs, fmt.Errorf("%w; see docs/config.md", ErrPolicyDirEmpty))
		} else if !filepath.IsAbs(c.PolicyDir) {
			errs = append(errs, fmt.Errorf(
				"%w: %q; see docs/config.md", ErrPolicyDirNotAbsolute, c.PolicyDir,
			))
		}
	}

	return errors.Join(errs...)
}

func (c *Config) validateTimeoutFields() []error {
	return validateRanges(
		numericRange[time.Duration]{
			value:       c.FetchTimeout.Duration,
			minimum:     time.Nanosecond,
			maximum:     maxFetchTimeout,
			errBelow:    ErrFetchTimeoutNotPositive,
			errAbove:    ErrFetchTimeoutTooHigh,
			showMinimum: false,
		},
		numericRange[time.Duration]{
			value:       c.DigestResolveTimeout.Duration,
			minimum:     time.Nanosecond,
			maximum:     maxDigestResolveTimeout,
			errBelow:    ErrDigestResolveTimeoutNotPositive,
			errAbove:    ErrDigestResolveTimeoutTooHigh,
			showMinimum: false,
		},
		numericRange[time.Duration]{
			value:       c.AdmissionTimeout.Duration,
			minimum:     time.Nanosecond,
			maximum:     maxAdmissionTimeout,
			errBelow:    ErrAdmissionTimeoutNotPositive,
			errAbove:    ErrAdmissionTimeoutTooHigh,
			showMinimum: false,
		},
	)
}

func (c *Config) validateCacheFields() error {
	return errors.Join(validateRanges(
		numericRange[time.Duration]{
			value: c.CacheTTL.Duration, minimum: 0, maximum: maxCacheTTL,
			errBelow: ErrCacheTTLNegative, errAbove: ErrCacheTTLTooHigh, showMinimum: false,
		},
		numericRange[time.Duration]{
			value:       c.CacheFailureTTL.Duration,
			minimum:     0,
			maximum:     maxCacheFailTTL,
			errBelow:    ErrCacheFailureTTLNegative,
			errAbove:    ErrCacheFailureTTLTooHigh,
			showMinimum: false,
		},
	)...)
}

func (c *Config) validateResilienceFields() error {
	errs := validateRanges(
		numericRange[time.Duration]{
			value: c.CircuitBreakerCooldown.Duration, minimum: time.Nanosecond,
			maximum:  maxCircuitBreakerCooldown,
			errBelow: ErrCircuitBreakerCooldown, errAbove: ErrCircuitBreakerCooldownTooHigh,
			showMinimum: false,
		},
		numericRange[time.Duration]{
			value: c.VerificationTimeout.Duration, minimum: time.Nanosecond,
			maximum:  maxVerificationTimeout,
			errBelow: ErrVerificationTimeoutNotPositive, errAbove: ErrVerificationTimeoutTooHigh,
			showMinimum: false,
		},
	)

	errs = append(errs, validateRanges(numericRange[int]{
		value: c.CircuitBreakerThreshold, minimum: 1, maximum: 0,
		errBelow: ErrCircuitBreakerThreshold, errAbove: nil, showMinimum: false,
	})...)
	errs = append(errs, c.validateCheckTimeout()...)
	errs = append(errs, validateRanges(numericRange[float64]{
		value: c.FetchRateLimit, minimum: 0, maximum: maxFetchRateLimit,
		errBelow: ErrFetchRateLimitNegative, errAbove: ErrFetchRateLimitTooHigh, showMinimum: false,
	})...)
	errs = append(errs, c.validateLimitsFields()...)

	return errors.Join(errs...)
}

func (c *Config) validateCheckTimeout() []error {
	var errs []error

	if c.CheckTimeout.Duration <= 0 {
		errs = append(errs, fmt.Errorf(
			"%w: got %s", ErrCheckTimeoutNotPositive, c.CheckTimeout.Duration,
		))
	}

	if c.CheckTimeout.Duration > c.VerificationTimeout.Duration {
		errs = append(errs, fmt.Errorf(
			"%w: check_timeout %s, verification_timeout %s",
			ErrCheckTimeoutExceedsVerification,
			c.CheckTimeout.Duration, c.VerificationTimeout.Duration,
		))
	}

	return errs
}

func (c *Config) validateLimitsFields() []error {
	return validateRanges(
		numericRange[int64]{
			value: c.MaxAttestationSize, minimum: minAttestationSize, maximum: maxAttestationSize,
			errBelow: ErrMaxAttestationSizeTooSmall, errAbove: ErrMaxAttestationSizeTooLarge,
			showMinimum: false,
		},
		numericRange[int64]{
			value:       int64(c.CacheMaxEntries),
			minimum:     minCacheMaxEntries,
			maximum:     maxCacheMaxEntries,
			errBelow:    ErrCacheMaxEntriesTooSmall,
			errAbove:    ErrCacheMaxEntriesTooLarge,
			showMinimum: false,
		},
	)
}

// numericRange describes a bounded numeric config field. A nil errBelow or
// errAbove disables the corresponding bound.
type numericRange[T int | int64 | float64 | time.Duration] struct {
	value       T
	minimum     T
	maximum     T
	errBelow    error
	errAbove    error
	showMinimum bool
}

// validateRanges checks each range and reports values below the minimum as
// "<err>: got <value>" (with ", min <minimum>" when showMinimum is set) and
// values above the maximum as "<err>: got <value>, max <maximum>".
func validateRanges[T int | int64 | float64 | time.Duration](ranges ...numericRange[T]) []error {
	var errs []error

	for idx := range ranges {
		bounds := &ranges[idx]

		if bounds.errBelow != nil && bounds.value < bounds.minimum {
			if bounds.showMinimum {
				errs = append(errs, fmt.Errorf(
					"%w: got %v, min %v", bounds.errBelow, bounds.value, bounds.minimum,
				))
			} else {
				errs = append(errs, fmt.Errorf("%w: got %v", bounds.errBelow, bounds.value))
			}
		}

		if bounds.errAbove != nil && bounds.value > bounds.maximum {
			errs = append(errs, fmt.Errorf(
				"%w: got %v, max %v", bounds.errAbove, bounds.value, bounds.maximum,
			))
		}
	}

	return errs
}

func (c *Config) validateAllowlistDigests() []error {
	var errs []error

	seen := make(map[string]struct{}, len(c.AllowlistDigests))

	for _, entry := range c.AllowlistDigests {
		digest := types.ExtractDigest(entry)
		if digest == "" {
			errs = append(errs, fmt.Errorf(
				"%w: %q", ErrAllowlistDigestInvalid, entry,
			))

			continue
		}

		if _, dup := seen[digest]; dup {
			errs = append(errs, fmt.Errorf(
				"%w: duplicate digest in %q", ErrAllowlistDigestInvalid, entry,
			))
		}

		seen[digest] = struct{}{}
	}

	return errs
}

func (c *Config) validateAuditLog() error {
	if c.AuditLog != "" && !filepath.IsAbs(c.AuditLog) {
		return fmt.Errorf("%w: %q", ErrAuditLogNotAbsolute, c.AuditLog)
	}

	return nil
}

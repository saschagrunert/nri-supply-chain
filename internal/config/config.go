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

// Package config provides configuration types and validation for the NRI supply chain plugin.
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
)

// VerificationMode controls the supply chain verification behavior.
type VerificationMode string

const (
	// ModeDisabled disables supply chain verification.
	ModeDisabled VerificationMode = "disabled"
	// ModeWarn enables verification in warn (log-only) mode.
	ModeWarn VerificationMode = "warn"
	// ModeEnforce enables verification in enforce (reject on failure) mode.
	ModeEnforce VerificationMode = "enforce"

	defaultFetchTimeout            = 30 * time.Second
	defaultCacheTTL                = 24 * time.Hour
	defaultCacheFailureTTL         = 5 * time.Minute
	defaultCircuitBreakerThreshold = 5
	defaultCircuitBreakerCooldown  = 30 * time.Second
)

var (
	// ErrInvalidVerificationMode indicates an unrecognized verification mode.
	ErrInvalidVerificationMode = errors.New("invalid verification mode")

	// ErrFetchTimeoutNotPositive indicates a non-positive fetch timeout.
	ErrFetchTimeoutNotPositive = errors.New("fetch_timeout must be positive")

	// ErrCacheTTLNegative indicates a negative cache TTL.
	ErrCacheTTLNegative = errors.New("cache_ttl must be non-negative")

	// ErrPolicyDirEmpty indicates an empty policy directory when verification is enabled.
	ErrPolicyDirEmpty = errors.New("policy_dir must not be empty when verification is enabled")

	// ErrPolicyDirNotAbsolute indicates a relative policy directory path.
	ErrPolicyDirNotAbsolute = errors.New("policy_dir is not absolute")

	// ErrPolicyDirNotDirectory indicates the policy dir path is not a directory.
	ErrPolicyDirNotDirectory = errors.New("policy_dir is not a directory")

	// ErrCircuitBreakerThreshold indicates the circuit breaker threshold is invalid.
	ErrCircuitBreakerThreshold = errors.New("circuit_breaker_threshold must be positive")

	// ErrCircuitBreakerCooldown indicates the circuit breaker cooldown is invalid.
	ErrCircuitBreakerCooldown = errors.New("circuit_breaker_cooldown must be positive")

	// ErrFetchRateLimitNegative indicates a negative fetch rate limit.
	ErrFetchRateLimitNegative = errors.New("fetch_rate_limit must be non-negative")

	// ErrCacheFailureTTLNegative indicates a negative cache failure TTL.
	ErrCacheFailureTTLNegative = errors.New("cache_failure_ttl must be non-negative")

	// ErrInvalidMetricsAddr indicates the metrics address is not a valid host:port.
	ErrInvalidMetricsAddr = errors.New("invalid metrics_addr")

	// ErrInvalidLogLevel indicates an unrecognized log level value.
	ErrInvalidLogLevel = errors.New("invalid log_level")

	// ErrUnknownConfigKeys indicates the config file contains unrecognized keys.
	ErrUnknownConfigKeys = errors.New("unknown config keys")
)

// Duration wraps time.Duration to support TOML unmarshalling from strings.
type Duration struct {
	time.Duration
}

// UnmarshalText implements encoding.TextUnmarshaler for TOML string parsing.
func (d *Duration) UnmarshalText(text []byte) error {
	parsed, err := time.ParseDuration(string(text))
	if err != nil {
		return fmt.Errorf("parsing duration: %w", err)
	}

	d.Duration = parsed

	return nil
}

// MarshalText implements encoding.TextMarshaler for TOML serialization.
func (d Duration) MarshalText() ([]byte, error) {
	return []byte(d.String()), nil
}

// Config represents the operational configuration for the NRI supply chain plugin.
type Config struct {
	// Verification is the master toggle for supply chain verification.
	// Valid values: "disabled" (default), "warn" (log-only), "enforce" (reject on failure).
	Verification VerificationMode `toml:"verification"`
	// FetchTimeout is the per-fetch timeout for retrieving attestations.
	FetchTimeout Duration `toml:"fetch_timeout"`
	// FetchFailurePolicy controls behavior when attestation fetch fails due to
	// network errors. Valid values: "allow", "warn" (default), "deny".
	FetchFailurePolicy policy.Action `toml:"fetch_failure_policy"`
	// CacheTTL is how long verification results are cached per image digest + namespace.
	CacheTTL Duration `toml:"cache_ttl"`
	// CacheFailureTTL is how long failed verification results are cached.
	// Defaults to 5m so that transient failures are retried sooner than the
	// full CacheTTL (default 24h).
	CacheFailureTTL Duration `toml:"cache_failure_ttl"`
	// PolicyDir is the path to the directory containing JSON policy files.
	PolicyDir string `toml:"policy_dir"`
	// MetricsAddr is the listen address for the Prometheus metrics HTTP server.
	MetricsAddr string `toml:"metrics_addr"`
	// CircuitBreakerThreshold is the number of consecutive fetch failures
	// before the circuit breaker opens.
	CircuitBreakerThreshold int `toml:"circuit_breaker_threshold"`
	// CircuitBreakerCooldown is how long the circuit breaker stays open
	// before allowing a probe request.
	CircuitBreakerCooldown Duration `toml:"circuit_breaker_cooldown"`
	// FetchRateLimit is the maximum number of registry fetch requests per
	// second. 0 means unlimited.
	FetchRateLimit float64 `toml:"fetch_rate_limit"`
	// LogLevel is the log verbosity level.
	// Valid values: "debug", "info", "warn", "error".
	// Empty means the level is determined by the --log-level CLI flag.
	LogLevel string `toml:"log_level"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() *Config {
	return &Config{
		Verification:            ModeDisabled,
		FetchTimeout:            Duration{Duration: defaultFetchTimeout},
		FetchFailurePolicy:      policy.ActionWarn,
		CacheTTL:                Duration{Duration: defaultCacheTTL},
		CacheFailureTTL:         Duration{Duration: defaultCacheFailureTTL},
		PolicyDir:               "/etc/nri-supply-chain/policies",
		MetricsAddr:             "127.0.0.1:9090",
		CircuitBreakerThreshold: defaultCircuitBreakerThreshold,
		CircuitBreakerCooldown:  Duration{Duration: defaultCircuitBreakerCooldown},
		FetchRateLimit:          0,
		LogLevel:                "",
	}
}

// Enabled returns true if supply chain verification is not disabled.
func (c *Config) Enabled() bool {
	return c.Verification != ModeDisabled
}

// Validate checks the Config for invalid values.
func (c *Config) Validate() error {
	switch c.Verification {
	case ModeDisabled, ModeWarn, ModeEnforce:
	default:
		return fmt.Errorf("%w: %q", ErrInvalidVerificationMode, c.Verification)
	}

	if c.LogLevel != "" {
		switch c.LogLevel {
		case "debug", "info", "warn", "error":
		default:
			return fmt.Errorf("%w: %q", ErrInvalidLogLevel, c.LogLevel)
		}
	}

	if c.MetricsAddr != "" {
		_, _, err := net.SplitHostPort(c.MetricsAddr)
		if err != nil {
			return fmt.Errorf("%w: %q: %w", ErrInvalidMetricsAddr, c.MetricsAddr, err)
		}
	}

	err := c.validateFetchAndCache()
	if err != nil {
		return err
	}

	return c.validateResilienceFields()
}

// ValidateRuntime performs runtime checks that require filesystem access.
func (c *Config) ValidateRuntime() error {
	if !c.Enabled() {
		return nil
	}

	info, err := os.Stat(c.PolicyDir)
	if err != nil {
		return fmt.Errorf("invalid policy_dir %q: %w", c.PolicyDir, err)
	}

	if !info.IsDir() {
		return fmt.Errorf("%w: %q", ErrPolicyDirNotDirectory, c.PolicyDir)
	}

	return nil
}

func (c *Config) validateFetchAndCache() error {
	err := policy.ValidateAction("fetch_failure_policy", c.FetchFailurePolicy)
	if err != nil {
		return fmt.Errorf("validating config: %w", err)
	}

	if c.FetchTimeout.Duration <= 0 {
		return fmt.Errorf("%w: got %s", ErrFetchTimeoutNotPositive, c.FetchTimeout.Duration)
	}

	if c.CacheTTL.Duration < 0 {
		return fmt.Errorf("%w: got %s", ErrCacheTTLNegative, c.CacheTTL.Duration)
	}

	if c.CacheFailureTTL.Duration < 0 {
		return fmt.Errorf("%w: got %s", ErrCacheFailureTTLNegative, c.CacheFailureTTL.Duration)
	}

	if c.Enabled() {
		if c.PolicyDir == "" {
			return ErrPolicyDirEmpty
		}

		if !filepath.IsAbs(c.PolicyDir) {
			return fmt.Errorf("%w: %q", ErrPolicyDirNotAbsolute, c.PolicyDir)
		}
	}

	return nil
}

func (c *Config) validateResilienceFields() error {
	if c.CircuitBreakerThreshold <= 0 {
		return fmt.Errorf(
			"%w: got %d", ErrCircuitBreakerThreshold, c.CircuitBreakerThreshold,
		)
	}

	if c.CircuitBreakerCooldown.Duration <= 0 {
		return fmt.Errorf(
			"%w: got %s", ErrCircuitBreakerCooldown, c.CircuitBreakerCooldown.Duration,
		)
	}

	if c.FetchRateLimit < 0 {
		return fmt.Errorf(
			"%w: got %g", ErrFetchRateLimitNegative, c.FetchRateLimit,
		)
	}

	return nil
}

// LoadFromFile reads and parses a TOML config file.
func LoadFromFile(path string) (*Config, error) {
	cfg := DefaultConfig()

	meta, err := toml.DecodeFile(path, cfg)
	if err != nil {
		return nil, fmt.Errorf("reading config file %q: %w", path, err)
	}

	if undecoded := meta.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, len(undecoded))
		for i, k := range undecoded {
			keys[i] = k.String()
		}

		return nil, fmt.Errorf("%w: %s", ErrUnknownConfigKeys, strings.Join(keys, ", "))
	}

	err = cfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return cfg, nil
}

// LoadFromString parses a TOML config string.
func LoadFromString(data string) (*Config, error) {
	cfg := DefaultConfig()

	meta, err := toml.Decode(data, cfg)
	if err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	if undecoded := meta.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, len(undecoded))
		for i, k := range undecoded {
			keys[i] = k.String()
		}

		return nil, fmt.Errorf("%w: %s", ErrUnknownConfigKeys, strings.Join(keys, ", "))
	}

	err = cfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return cfg, nil
}

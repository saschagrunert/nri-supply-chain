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
	"time"

	"github.com/BurntSushi/toml"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
)

const (
	// ModeDisabled disables supply chain verification.
	ModeDisabled = "disabled"
	// ModeWarn enables verification in warn (log-only) mode.
	ModeWarn = "warn"
	// ModeEnforce enables verification in enforce (reject on failure) mode.
	ModeEnforce = "enforce"

	defaultFetchTimeout            = 30 * time.Second
	defaultCacheTTL                = 24 * time.Hour
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

	// ErrInvalidMetricsAddr indicates the metrics address is not a valid host:port.
	ErrInvalidMetricsAddr = errors.New("invalid metrics_addr")
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
	Verification string `toml:"verification"`
	// FetchTimeout is the per-fetch timeout for retrieving attestations.
	FetchTimeout Duration `toml:"fetch_timeout"`
	// FetchFailurePolicy controls behavior when attestation fetch fails due to
	// network errors. Valid values: "allow", "warn" (default), "deny".
	FetchFailurePolicy string `toml:"fetch_failure_policy"`
	// CacheTTL is how long verification results are cached per image digest + namespace.
	CacheTTL Duration `toml:"cache_ttl"`
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
}

// DefaultConfig returns the default configuration.
func DefaultConfig() *Config {
	return &Config{
		Verification:            ModeDisabled,
		FetchTimeout:            Duration{Duration: defaultFetchTimeout},
		FetchFailurePolicy:      policy.ActionWarn,
		CacheTTL:                Duration{Duration: defaultCacheTTL},
		PolicyDir:               "/etc/nri-supply-chain/policies",
		MetricsAddr:             "127.0.0.1:9090",
		CircuitBreakerThreshold: defaultCircuitBreakerThreshold,
		CircuitBreakerCooldown:  Duration{Duration: defaultCircuitBreakerCooldown},
		FetchRateLimit:          0,
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

	if c.MetricsAddr != "" {
		_, _, err := net.SplitHostPort(c.MetricsAddr)
		if err != nil {
			return fmt.Errorf("%w: %q: %w", ErrInvalidMetricsAddr, c.MetricsAddr, err)
		}
	}

	if !c.Enabled() {
		return nil
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

	if c.PolicyDir == "" {
		return ErrPolicyDirEmpty
	}

	if !filepath.IsAbs(c.PolicyDir) {
		return fmt.Errorf("%w: %q", ErrPolicyDirNotAbsolute, c.PolicyDir)
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

	_, err := toml.DecodeFile(path, cfg)
	if err != nil {
		return nil, fmt.Errorf("reading config file %q: %w", path, err)
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

	_, err := toml.Decode(data, cfg)
	if err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	err = cfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return cfg, nil
}

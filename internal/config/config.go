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
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/google/go-containerregistry/pkg/name"

	"github.com/saschagrunert/nri-supply-chain/internal/types"
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

	// StrictnessDisabled is the strictness level for "disabled" mode.
	StrictnessDisabled = 0
	// StrictnessWarn is the strictness level for "warn" mode.
	StrictnessWarn = 1
	// StrictnessEnforce is the strictness level for "enforce" mode.
	StrictnessEnforce = 2

	defaultFetchTimeout            = 30 * time.Second
	defaultCacheTTL                = 24 * time.Hour
	defaultCacheFailureTTL         = 5 * time.Minute
	defaultCircuitBreakerThreshold = 5
	defaultCircuitBreakerCooldown  = 30 * time.Second
	maxFetchRateLimit              = 10000.0

	// PolicySourceLocal loads policies from the local filesystem (default).
	PolicySourceLocal = "local"
	// PolicySourceOCI loads policies from an OCI registry artifact.
	PolicySourceOCI = "oci"

	defaultPollInterval = 5 * time.Minute
	minPollInterval     = 30 * time.Second
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

	// ErrFetchRateLimitTooHigh indicates the fetch rate limit exceeds the maximum.
	ErrFetchRateLimitTooHigh = errors.New("fetch_rate_limit exceeds maximum")

	// ErrCacheFailureTTLNegative indicates a negative cache failure TTL.
	ErrCacheFailureTTLNegative = errors.New("cache_failure_ttl must be non-negative")

	// ErrInvalidMetricsAddr indicates the metrics address is not a valid host:port.
	ErrInvalidMetricsAddr = errors.New("invalid metrics_addr")

	// ErrInvalidLogLevel indicates an unrecognized log level value.
	ErrInvalidLogLevel = errors.New("invalid log_level")

	// ErrUnknownConfigKeys indicates the config file contains unrecognized keys.
	ErrUnknownConfigKeys = errors.New("unknown config keys")

	// ErrInvalidTUFMirror indicates the sigstore.tuf_mirror URL is not valid.
	ErrInvalidTUFMirror = errors.New("invalid sigstore.tuf_mirror URL")

	// ErrTUFRootNotAbsolute indicates the sigstore.tuf_root path is not absolute.
	ErrTUFRootNotAbsolute = errors.New("sigstore.tuf_root must be an absolute path")

	// ErrTUFRootNotFound indicates the sigstore.tuf_root file does not exist.
	ErrTUFRootNotFound = errors.New("sigstore.tuf_root file not found")

	// ErrTUFRootRequiresMirror indicates tuf_root is set without tuf_mirror.
	ErrTUFRootRequiresMirror = errors.New(
		"sigstore.tuf_root requires sigstore.tuf_mirror to be set",
	)

	// ErrTUFRootEmpty indicates the sigstore.tuf_root file is empty.
	ErrTUFRootEmpty = errors.New("sigstore.tuf_root file is empty")

	// ErrTUFRootNotRegularFile indicates the sigstore.tuf_root path is not a regular file.
	ErrTUFRootNotRegularFile = errors.New("sigstore.tuf_root is not a regular file")

	// ErrRegistryPrefixEmpty indicates a registry entry has an empty prefix.
	ErrRegistryPrefixEmpty = errors.New("registry prefix must not be empty")

	// ErrRegistryCACertNotAbsolute indicates a registry CA cert path is not absolute.
	ErrRegistryCACertNotAbsolute = errors.New("registry ca_cert path must be absolute")

	// ErrRegistryCACertNotFound indicates a registry CA cert file does not exist.
	ErrRegistryCACertNotFound = errors.New("registry ca_cert file not found")

	// ErrDuplicateRegistryPrefix indicates multiple registries share the same prefix.
	ErrDuplicateRegistryPrefix = errors.New("duplicate registry prefix")

	// ErrRegistryPrefixInvalid indicates a registry prefix is not a valid hostname.
	ErrRegistryPrefixInvalid = errors.New("registry prefix is not a valid hostname")

	// ErrRegistryMirrorInvalid indicates a registry mirror is not a valid hostname.
	ErrRegistryMirrorInvalid = errors.New("registry mirror is not a valid hostname")

	// ErrRegistryMirrorSameAsPrefix indicates the mirror equals the prefix.
	ErrRegistryMirrorSameAsPrefix = errors.New("registry mirror must differ from prefix")

	// ErrInvalidPolicySource indicates the policy source is not "local" or "oci".
	ErrInvalidPolicySource = errors.New("policy.source must be \"local\" or \"oci\"")

	// ErrPolicyOCIRefRequired indicates the OCI reference is missing when source is "oci".
	ErrPolicyOCIRefRequired = errors.New("policy.oci_ref is required when policy.source is \"oci\"")

	// ErrPolicyOCIRefInvalid indicates the OCI reference could not be parsed.
	ErrPolicyOCIRefInvalid = errors.New("policy.oci_ref is not a valid OCI reference")

	// ErrPollIntervalTooShort indicates the poll interval is below the minimum.
	ErrPollIntervalTooShort = errors.New("policy.poll_interval must be at least 30s")
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

// SigstoreConfig configures private Sigstore instance endpoints for keyless
// verification. When all fields are empty, the public Sigstore instance is used.
type SigstoreConfig struct {
	// TUFMirror is the URL of a custom TUF mirror for fetching the Sigstore
	// trusted root. When set, the plugin uses this mirror instead of the
	// default public Sigstore TUF repository. The trusted root from the
	// custom mirror contains the Fulcio CA certificates and Rekor log keys
	// for the private Sigstore deployment.
	//
	// When only tuf_mirror is set (without tuf_root), the mirror is treated
	// as a CDN mirror of the public Sigstore TUF repository and the embedded
	// public root.json is used as the trust anchor. This is suitable for
	// air-gapped environments that mirror the public Sigstore infrastructure.
	TUFMirror string `toml:"tuf_mirror"`

	// TUFRoot is the path to a custom root.json file for TUF trust anchor
	// initialization. Required for private Sigstore deployments that use
	// their own root keys (different from the public Sigstore root keys).
	// When set, the file contents replace the embedded public Sigstore
	// root.json so that TUF verification uses the private deployment's
	// trust chain. Must be an absolute path.
	TUFRoot string `toml:"tuf_root"`
}

// Registry represents configuration for an OCI registry endpoint.
type Registry struct {
	// Prefix is the registry host prefix to match (e.g. "ghcr.io", "registry.internal.example.com").
	Prefix string `toml:"prefix"`
	// Mirror is an optional alternative registry host to redirect requests to.
	Mirror string `toml:"mirror"`
	// CACert is the path to a PEM-encoded CA certificate file for TLS verification.
	CACert string `toml:"ca_cert"`
	// Insecure allows connections to registries without TLS verification.
	Insecure bool `toml:"insecure"`
}

// PolicyConfig controls how policy files are sourced: from the local filesystem
// (default) or from an OCI registry artifact.
type PolicyConfig struct {
	// Source selects the policy source: "local" (default) or "oci".
	Source string `toml:"source"`
	// OCIRef is the OCI reference for the remote policy artifact
	// (e.g. "ghcr.io/myorg/policies:v1"). Required when Source is "oci".
	OCIRef string `toml:"oci_ref"`
	// PollInterval is how often the plugin checks for policy updates in the
	// remote registry. Minimum 30s, default 5m.
	PollInterval Duration `toml:"poll_interval"`
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
	// In enforce mode the effective default changes to "deny".
	FetchFailurePolicy types.Action `toml:"fetch_failure_policy"`
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
	// Sigstore configures private Sigstore instance endpoints for keyless
	// verification. When omitted, the public Sigstore instance is used.
	Sigstore SigstoreConfig `toml:"sigstore"`
	// Registries configures per-registry transport settings such as mirrors,
	// custom CA certificates, and insecure (TLS-skip) connections.
	Registries []Registry `toml:"registries"`
	// Policy configures the policy source: local filesystem (default) or OCI registry.
	Policy PolicyConfig `toml:"policy"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() *Config {
	return &Config{
		Verification:            ModeDisabled,
		FetchTimeout:            Duration{Duration: defaultFetchTimeout},
		FetchFailurePolicy:      types.ActionWarn,
		CacheTTL:                Duration{Duration: defaultCacheTTL},
		CacheFailureTTL:         Duration{Duration: defaultCacheFailureTTL},
		PolicyDir:               "/etc/nri-supply-chain/policies",
		MetricsAddr:             "127.0.0.1:9090",
		CircuitBreakerThreshold: defaultCircuitBreakerThreshold,
		CircuitBreakerCooldown:  Duration{Duration: defaultCircuitBreakerCooldown},
		FetchRateLimit:          0,
		LogLevel:                "",
		Sigstore:                SigstoreConfig{TUFMirror: "", TUFRoot: ""},
		Registries:              nil,
		Policy: PolicyConfig{
			Source:       PolicySourceLocal,
			OCIRef:       "",
			PollInterval: Duration{Duration: defaultPollInterval},
		},
	}
}

// Strictness returns the numeric strictness level of the mode.
// disabled=0, warn=1, enforce=2. Unknown modes return -1.
func (m VerificationMode) Strictness() int {
	switch m {
	case ModeDisabled:
		return StrictnessDisabled
	case ModeWarn:
		return StrictnessWarn
	case ModeEnforce:
		return StrictnessEnforce
	default:
		return -1
	}
}

// IsValid returns true if the mode is a recognized verification mode.
func (m VerificationMode) IsValid() bool {
	return m.Strictness() >= 0
}

// Enabled returns true if supply chain verification is not disabled.
func (c *Config) Enabled() bool {
	return c.Verification != ModeDisabled
}

// Validate checks the Config for invalid values.
func (c *Config) Validate() error {
	var errs []error

	errs = append(errs, c.validateModeAndLogLevel()...)

	err := c.validateMetricsAddr()
	if err != nil {
		errs = append(errs, err)
	}

	err = c.validateFetchAndCache()
	if err != nil {
		errs = append(errs, err)
	}

	err = c.validateResilienceFields()
	if err != nil {
		errs = append(errs, err)
	}

	err = c.validateSigstoreConfig()
	if err != nil {
		errs = append(errs, err)
	}

	err = c.validateRegistries()
	if err != nil {
		errs = append(errs, err)
	}

	err = c.validatePolicyConfig()
	if err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

// ValidateRuntime performs runtime checks that require filesystem access.
func (c *Config) ValidateRuntime() error {
	var errs []error

	if c.Enabled() {
		if c.Policy.Source != PolicySourceOCI {
			info, err := os.Stat(c.PolicyDir)
			if err != nil {
				errs = append(errs, fmt.Errorf("invalid policy_dir %q: %w", c.PolicyDir, err))
			} else if !info.IsDir() {
				errs = append(errs, fmt.Errorf("%w: %q", ErrPolicyDirNotDirectory, c.PolicyDir))
			}
		}

		errs = append(errs, c.validateTUFRootRuntime()...)
	}

	for idx := range c.Registries {
		reg := &c.Registries[idx]
		if reg.CACert != "" {
			_, statErr := os.Stat(reg.CACert)
			if statErr != nil {
				errs = append(errs, fmt.Errorf(
					"%w: registries[%d] ca_cert %q: %w",
					ErrRegistryCACertNotFound, idx, reg.CACert, statErr,
				))
			}
		}
	}

	return errors.Join(errs...)
}

// ApplyModeDefaults overrides permissive defaults when the verification mode
// demands stricter behavior. In enforce mode the effective fetch_failure_policy
// changes from "warn" to "deny" unless the user set it explicitly.
func (c *Config) ApplyModeDefaults(fetchFailurePolicyExplicit bool) {
	if c.Verification != ModeEnforce || fetchFailurePolicyExplicit {
		return
	}

	if c.FetchFailurePolicy == types.ActionWarn {
		c.FetchFailurePolicy = types.ActionDeny

		slog.Warn("enforce mode: fetch_failure_policy defaulting to deny")
	}
}

// Normalize clamps fields to valid ranges. Call after Validate.
func (c *Config) Normalize() {
	if c.CacheTTL.Duration == 0 && c.Enabled() {
		slog.Warn("cache_ttl is zero, verification result caching is disabled")
	}

	if c.CacheTTL.Duration == 0 && c.CacheFailureTTL.Duration > 0 {
		slog.Warn("cache_failure_ttl reset to zero because cache_ttl is zero",
			"cache_failure_ttl", c.CacheFailureTTL.Duration,
		)

		c.CacheFailureTTL.Duration = 0
	}

	if c.CacheTTL.Duration > 0 && c.CacheFailureTTL.Duration > c.CacheTTL.Duration {
		slog.Warn("cache_failure_ttl exceeds cache_ttl, clamping to cache_ttl",
			"cache_failure_ttl", c.CacheFailureTTL.Duration,
			"cache_ttl", c.CacheTTL.Duration,
		)

		c.CacheFailureTTL.Duration = c.CacheTTL.Duration
	}

	if c.CacheFailureTTL.Duration == 0 && c.CacheTTL.Duration > 0 {
		slog.Warn("cache_failure_ttl is zero; failure results will use full cache_ttl",
			"cache_ttl", c.CacheTTL.Duration,
		)
	}

	c.normalizeRegistryPrefixes()
}

// WarnInsecureRegistries logs a warning for each registry configured with
// insecure TLS. Call at startup or reload time, not during validation.
func (c *Config) WarnInsecureRegistries() {
	for idx := range c.Registries {
		if c.Registries[idx].Insecure {
			slog.Warn("Registry configured with insecure TLS (skip verify)",
				"prefix", c.Registries[idx].Prefix,
				"index", idx,
			)

			if c.Verification == ModeEnforce {
				slog.Warn(
					"Insecure registry in enforce mode undermines integrity guarantees",
					"prefix", c.Registries[idx].Prefix,
				)
			}
		}
	}
}

// RegistriesChanged reports whether two registry slices differ.
func RegistriesChanged(prev, next []Registry) bool {
	return !slices.Equal(prev, next)
}

func (c *Config) validateModeAndLogLevel() []error {
	var errs []error

	switch c.Verification {
	case ModeDisabled, ModeWarn, ModeEnforce:
	default:
		errs = append(errs, fmt.Errorf("%w: %q", ErrInvalidVerificationMode, c.Verification))
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

func (c *Config) validateTUFRootRuntime() []error {
	if c.Sigstore.TUFRoot == "" {
		return nil
	}

	rootInfo, err := os.Stat(c.Sigstore.TUFRoot)
	if err != nil {
		return []error{fmt.Errorf(
			"%w: %q: %w", ErrTUFRootNotFound, c.Sigstore.TUFRoot, err,
		)}
	}

	if !rootInfo.Mode().IsRegular() {
		return []error{fmt.Errorf(
			"%w: %q", ErrTUFRootNotRegularFile, c.Sigstore.TUFRoot,
		)}
	}

	if rootInfo.Size() == 0 {
		return []error{fmt.Errorf(
			"%w: %q", ErrTUFRootEmpty, c.Sigstore.TUFRoot,
		)}
	}

	return nil
}

func isValidRegistryHost(host string) bool {
	if host == "" || strings.ContainsAny(host, " \t\n/") {
		return false
	}

	if strings.Contains(host, "://") {
		return false
	}

	hostname := host

	h, _, err := net.SplitHostPort(host)
	if err == nil {
		hostname = h
	}

	return !slices.Contains(strings.Split(hostname, "."), "")
}

func normalizePrefix(prefix string) string {
	lower := strings.ToLower(prefix)

	if lower == "docker.io" {
		return "index.docker.io"
	}

	return lower
}

func (c *Config) normalizeRegistryPrefixes() {
	for idx := range c.Registries {
		c.Registries[idx].Prefix = normalizePrefix(c.Registries[idx].Prefix)
		c.Registries[idx].Mirror = normalizePrefix(c.Registries[idx].Mirror)
	}
}

func (c *Config) validateRegistries() error {
	var errs []error //nolint:prealloc // conditional appends

	seen := make(map[string]int, len(c.Registries))

	for idx := range c.Registries {
		errs = append(errs, c.validateRegistry(&c.Registries[idx], idx, seen)...)
	}

	return errors.Join(errs...)
}

func (c *Config) validateRegistry(
	reg *Registry, idx int, seen map[string]int,
) []error {
	var errs []error

	errs = append(errs, validateRegistryPrefix(reg, idx, seen)...)
	errs = append(errs, validateRegistryMirror(reg, idx)...)

	if reg.CACert != "" && !filepath.IsAbs(reg.CACert) {
		errs = append(errs, fmt.Errorf(
			"%w: registries[%d] ca_cert %q",
			ErrRegistryCACertNotAbsolute, idx, reg.CACert,
		))
	}

	return errs
}

func validateRegistryPrefix(
	reg *Registry, idx int, seen map[string]int,
) []error {
	var errs []error

	if reg.Prefix == "" {
		return append(errs, fmt.Errorf(
			"%w: registries[%d]", ErrRegistryPrefixEmpty, idx,
		))
	}

	if !isValidRegistryHost(reg.Prefix) {
		errs = append(errs, fmt.Errorf(
			"%w: registries[%d] %q",
			ErrRegistryPrefixInvalid, idx, reg.Prefix,
		))
	}

	normalized := normalizePrefix(reg.Prefix)

	if prevIdx, ok := seen[normalized]; ok {
		errs = append(errs, fmt.Errorf(
			"%w: %q at registries[%d] and registries[%d]",
			ErrDuplicateRegistryPrefix, reg.Prefix, prevIdx, idx,
		))
	} else {
		seen[normalized] = idx
	}

	return errs
}

func validateRegistryMirror(reg *Registry, idx int) []error {
	if reg.Mirror == "" {
		return nil
	}

	var errs []error

	if !isValidRegistryHost(reg.Mirror) {
		errs = append(errs, fmt.Errorf(
			"%w: registries[%d] %q",
			ErrRegistryMirrorInvalid, idx, reg.Mirror,
		))
	}

	if normalizePrefix(reg.Mirror) == normalizePrefix(reg.Prefix) {
		errs = append(errs, fmt.Errorf(
			"%w: registries[%d] %q",
			ErrRegistryMirrorSameAsPrefix, idx, reg.Prefix,
		))
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

	if c.FetchTimeout.Duration <= 0 {
		errs = append(errs, fmt.Errorf(
			"%w: got %s", ErrFetchTimeoutNotPositive, c.FetchTimeout.Duration,
		))
	}

	err = c.validateCacheFields()
	if err != nil {
		errs = append(errs, err)
	}

	if c.Enabled() && c.Policy.Source != PolicySourceOCI {
		if c.PolicyDir == "" {
			errs = append(errs, ErrPolicyDirEmpty)
		} else if !filepath.IsAbs(c.PolicyDir) {
			errs = append(errs, fmt.Errorf("%w: %q", ErrPolicyDirNotAbsolute, c.PolicyDir))
		}
	}

	return errors.Join(errs...)
}

func (c *Config) validateCacheFields() error {
	var errs []error

	if c.CacheTTL.Duration < 0 {
		errs = append(errs, fmt.Errorf(
			"%w: got %s", ErrCacheTTLNegative, c.CacheTTL.Duration,
		))
	}

	if c.CacheFailureTTL.Duration < 0 {
		errs = append(errs, fmt.Errorf(
			"%w: got %s", ErrCacheFailureTTLNegative, c.CacheFailureTTL.Duration,
		))
	}

	return errors.Join(errs...)
}

func (c *Config) validateResilienceFields() error {
	var errs []error

	if c.CircuitBreakerThreshold <= 0 {
		errs = append(errs, fmt.Errorf(
			"%w: got %d", ErrCircuitBreakerThreshold, c.CircuitBreakerThreshold,
		))
	}

	if c.CircuitBreakerCooldown.Duration <= 0 {
		errs = append(errs, fmt.Errorf(
			"%w: got %s", ErrCircuitBreakerCooldown, c.CircuitBreakerCooldown.Duration,
		))
	}

	if c.FetchRateLimit < 0 {
		errs = append(errs, fmt.Errorf(
			"%w: got %g", ErrFetchRateLimitNegative, c.FetchRateLimit,
		))
	}

	if c.FetchRateLimit > maxFetchRateLimit {
		errs = append(errs, fmt.Errorf(
			"%w: got %g, max %g", ErrFetchRateLimitTooHigh, c.FetchRateLimit, maxFetchRateLimit,
		))
	}

	return errors.Join(errs...)
}

func (c *Config) validateSigstoreConfig() error {
	var errs []error

	if c.Sigstore.TUFMirror != "" {
		err := validateTUFMirrorURL(c.Sigstore.TUFMirror)
		if err != nil {
			errs = append(errs, err)
		}
	}

	if c.Sigstore.TUFRoot != "" {
		if !filepath.IsAbs(c.Sigstore.TUFRoot) {
			errs = append(errs, fmt.Errorf("%w: %q", ErrTUFRootNotAbsolute, c.Sigstore.TUFRoot))
		}

		if c.Sigstore.TUFMirror == "" {
			errs = append(errs, ErrTUFRootRequiresMirror)
		}
	}

	return errors.Join(errs...)
}

func validateTUFMirrorURL(mirror string) error {
	parsed, err := url.Parse(mirror)
	if err != nil {
		return fmt.Errorf("%w: %q: %w", ErrInvalidTUFMirror, mirror, err)
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf(
			"%w: %q: scheme must be http or https", ErrInvalidTUFMirror, mirror,
		)
	}

	if parsed.Host == "" {
		return fmt.Errorf(
			"%w: %q: missing host", ErrInvalidTUFMirror, mirror,
		)
	}

	return nil
}

func (c *Config) validatePolicyConfig() error {
	switch c.Policy.Source {
	case PolicySourceLocal, "":
		return nil
	case PolicySourceOCI:
	default:
		return fmt.Errorf("%w: got %q", ErrInvalidPolicySource, c.Policy.Source)
	}

	var errs []error

	if c.Policy.OCIRef == "" {
		errs = append(errs, ErrPolicyOCIRefRequired)
	} else {
		_, err := name.ParseReference(c.Policy.OCIRef)
		if err != nil {
			errs = append(errs, fmt.Errorf(
				"%w: %q: %w", ErrPolicyOCIRefInvalid, c.Policy.OCIRef, err,
			))
		}
	}

	if c.Policy.PollInterval.Duration < minPollInterval {
		errs = append(errs, fmt.Errorf(
			"%w: got %s", ErrPollIntervalTooShort, c.Policy.PollInterval.Duration,
		))
	}

	return errors.Join(errs...)
}

// LoadFromFile reads and parses a TOML config file.
func LoadFromFile(path string) (*Config, error) {
	cfg, err := load(func(cfg *Config) (toml.MetaData, error) {
		return toml.DecodeFile(path, cfg)
	})
	if err != nil {
		return nil, fmt.Errorf("config file %q: %w", path, err)
	}

	return cfg, nil
}

// LoadFromString parses a TOML config string.
func LoadFromString(data string) (*Config, error) {
	return load(func(cfg *Config) (toml.MetaData, error) {
		return toml.Decode(data, cfg)
	})
}

func load(decode func(*Config) (toml.MetaData, error)) (*Config, error) {
	cfg := DefaultConfig()

	meta, err := decode(cfg)
	if err != nil {
		return nil, fmt.Errorf("decoding config: %w", err)
	}

	if undecoded := meta.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, len(undecoded))
		for i, k := range undecoded {
			keys[i] = k.String()
		}

		return nil, fmt.Errorf("%w: %s", ErrUnknownConfigKeys, strings.Join(keys, ", "))
	}

	cfg.ApplyModeDefaults(meta.IsDefined("fetch_failure_policy"))

	err = cfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	cfg.Normalize()

	return cfg, nil
}

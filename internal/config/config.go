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
	"slices"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/saschagrunert/nri-supply-chain/internal/fileutil"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

// VerificationMode controls the supply chain verification behavior.
type VerificationMode string

// Strictness is a numeric strictness level for verification modes.
type Strictness int

// PolicySource selects where policy files are loaded from.
type PolicySource string

// LatestConfigVersion is the current config schema version.
// Bump this when the config schema changes in a way that requires migration.
const LatestConfigVersion = 1

const (
	// ModeDisabled disables supply chain verification.
	ModeDisabled VerificationMode = "disabled"
	// ModeWarn enables verification in warn (log-only) mode.
	ModeWarn VerificationMode = "warn"
	// ModeEnforce enables verification in enforce (reject on failure) mode.
	ModeEnforce VerificationMode = "enforce"

	// StrictnessDisabled is the strictness level for "disabled" mode.
	StrictnessDisabled Strictness = 0
	// StrictnessWarn is the strictness level for "warn" mode.
	StrictnessWarn Strictness = 1
	// StrictnessEnforce is the strictness level for "enforce" mode.
	StrictnessEnforce Strictness = 2

	defaultFetchTimeout         = 30 * time.Second
	defaultDigestResolveTimeout = 1 * time.Second
	// maxDigestResolveTimeout caps the configurable digest resolution timeout.
	// Keep this low: digest resolution runs inside the NRI CreateContainer
	// callback, which containerd caps at ~2s via its ttrpc deadline. Values
	// above this cause containerd to abort the callback before resolution
	// completes. The 5s ceiling allows headroom for runtimes with higher
	// limits while preventing obviously broken configs.
	maxDigestResolveTimeout        = 5 * time.Second
	defaultCacheTTL                = 24 * time.Hour
	defaultCacheFailureTTL         = 5 * time.Minute
	defaultCircuitBreakerThreshold = 5
	defaultCircuitBreakerCooldown  = 30 * time.Second
	maxFetchRateLimit              = 10000.0

	maxFetchTimeout = 5 * time.Minute
	maxCacheTTL     = 7 * 24 * time.Hour // 7 days
	maxCacheFailTTL = 1 * time.Hour

	defaultVerificationTimeout = 5 * time.Minute
	maxVerificationTimeout     = 30 * time.Minute
	maxCircuitBreakerCooldown  = 10 * time.Minute

	// PolicySourceLocal loads policies from the local filesystem (default).
	PolicySourceLocal PolicySource = "local"
	// PolicySourceOCI loads policies from an OCI registry artifact.
	PolicySourceOCI PolicySource = "oci"

	defaultPollInterval = 5 * time.Minute
	minPollInterval     = 30 * time.Second

	minAttestationSize = 1 << 20   // 1 MiB
	maxAttestationSize = 100 << 20 // 100 MiB
	// DefaultMaxAttestationSize is the default maximum attestation bundle
	// size in bytes. Exported so the attestation package can share the same
	// value without duplicating the constant.
	DefaultMaxAttestationSize = 10 << 20 // 10 MiB
	minCacheMaxEntries        = 100
	maxCacheMaxEntries        = 1_000_000
	defaultCacheMaxEntries    = 10_000
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

// SigstoreRootSource describes a single TUF-based Sigstore trusted root.
// Multiple entries allow verifying attestations signed by different Sigstore
// infrastructures (for example, the public Sigstore instance alongside
// GitHub's private Sigstore deployment).
type SigstoreRootSource struct {
	// Name is a human-readable label for this root source. Must be unique
	// across all entries and non-empty.
	Name string `toml:"name"`

	// TUFMirror is the URL of the TUF mirror serving the trusted root.
	// Must use the https scheme.
	TUFMirror string `toml:"tuf_mirror"`

	// TUFRoot is the path to a custom root.json file for TUF trust anchor
	// initialization. When set, requires TUFMirror and must be absolute.
	TUFRoot string `toml:"tuf_root"`
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
	//
	// Deprecated: use Roots instead for multi-root configurations.
	TUFMirror string `toml:"tuf_mirror"`

	// TUFRoot is the path to a custom root.json file for TUF trust anchor
	// initialization. Required for private Sigstore deployments that use
	// their own root keys (different from the public Sigstore root keys).
	// When set, the file contents replace the embedded public Sigstore
	// root.json so that TUF verification uses the private deployment's
	// trust chain. Must be an absolute path.
	//
	// Deprecated: use Roots instead for multi-root configurations.
	TUFRoot string `toml:"tuf_root"`

	// Roots defines multiple Sigstore trusted root sources. Each entry
	// independently fetches its trusted root from its TUF mirror.
	// Mutually exclusive with the scalar TUFMirror/TUFRoot fields.
	Roots []SigstoreRootSource `toml:"roots"`

	// IncludePublicRoot controls whether the public Sigstore trusted root
	// is included alongside custom roots. Defaults to true (nil means true).
	// Set to false to verify only against the configured custom roots.
	IncludePublicRoot *bool `toml:"include_public_root"`
}

// EffectiveRoots returns the list of root sources to use for verification.
// If Roots is non-empty, it is returned directly.
// If Roots is empty but the scalar TUFMirror is set, a single-element slice
// is synthesized from the legacy fields.
// If Roots is empty and TUFMirror is empty but TUFRoot is set, a
// single-element slice with an empty mirror is synthesized for pre-seeded
// trusted root support (air-gapped fallback).
// If both are empty, nil is returned, signaling that the default
// public Sigstore trusted root should be used.
func (s *SigstoreConfig) EffectiveRoots() []SigstoreRootSource {
	if len(s.Roots) > 0 {
		out := make([]SigstoreRootSource, len(s.Roots))
		copy(out, s.Roots)

		return out
	}

	if s.TUFMirror != "" {
		return []SigstoreRootSource{{
			Name:      "default",
			TUFMirror: s.TUFMirror,
			TUFRoot:   s.TUFRoot,
		}}
	}

	if s.TUFRoot != "" {
		return []SigstoreRootSource{{
			Name:      "default",
			TUFMirror: "",
			TUFRoot:   s.TUFRoot,
		}}
	}

	return nil
}

// ShouldIncludePublicRoot returns true when the public Sigstore trusted root
// should be included in the verification set. True when IncludePublicRoot is
// nil (default) or when *IncludePublicRoot is true.
func (s *SigstoreConfig) ShouldIncludePublicRoot() bool {
	return s.IncludePublicRoot == nil || *s.IncludePublicRoot
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
	Source PolicySource `toml:"source"`
	// OCIRef is the OCI reference for the remote policy artifact
	// (e.g. "ghcr.io/myorg/policies:v1"). Required when Source is "oci".
	OCIRef string `toml:"oci_ref"`
	// PollInterval is how often the plugin checks for policy updates in the
	// remote registry. Minimum 30s, default 5m.
	PollInterval Duration `toml:"poll_interval"`
	// Issuers is a list of trusted OIDC issuers for keyless signature
	// verification of OCI policy artifacts.
	Issuers []string `toml:"issuers"`
	// SANPatterns is a list of Subject Alternative Name patterns to match
	// against the signing certificate. Requires Issuers to be set.
	SANPatterns []string `toml:"san_patterns"`
	// Keys is a list of absolute paths to PEM-encoded public key files for
	// signature verification of OCI policy artifacts.
	Keys []string `toml:"keys"`
}

// SignatureVerificationRequired returns true when trust material (issuers or
// keys) is configured, meaning OCI policy artifacts must be signed.
func (p *PolicyConfig) SignatureVerificationRequired() bool {
	return len(p.Issuers) > 0 || len(p.Keys) > 0
}

// Config represents the operational configuration for the NRI supply chain plugin.
type Config struct {
	// ConfigVersion is the schema version of this config file.
	// When omitted (zero), it is treated as version 1 for backward compatibility.
	ConfigVersion int `toml:"config_version"`
	// Verification is the master toggle for supply chain verification.
	// Valid values: "disabled" (default), "warn" (log-only), "enforce" (reject on failure).
	Verification VerificationMode `toml:"verification"`
	// FetchTimeout is the per-fetch timeout for retrieving attestations.
	FetchTimeout Duration `toml:"fetch_timeout"`
	// DigestResolveTimeout is the timeout for resolving an image tag to its
	// digest via the registry when containerd does not provide a pre-resolved
	// digest. Default 1s, max 5s. Keep this well under containerd's ~2s ttrpc
	// deadline for NRI callbacks; higher values risk containerd aborting the
	// callback before resolution completes.
	DigestResolveTimeout Duration `toml:"digest_resolve_timeout"`
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
	// VerificationTimeout is the maximum time allowed for a single image
	// verification (all checks combined). Defaults to 5m, maximum 30m.
	VerificationTimeout Duration `toml:"verification_timeout"`
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
	// MaxAttestationSize is the maximum allowed size in bytes for a single
	// attestation bundle. Defaults to 10 MiB, minimum 1 MiB, maximum 100 MiB.
	MaxAttestationSize int64 `toml:"max_attestation_size"`
	// CacheMaxEntries is the maximum number of entries in the verification
	// result cache. Defaults to 10,000, minimum 100, maximum 1,000,000.
	CacheMaxEntries int `toml:"cache_max_entries"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() *Config {
	return &Config{
		ConfigVersion:           LatestConfigVersion,
		Verification:            ModeDisabled,
		FetchTimeout:            Duration{Duration: defaultFetchTimeout},
		DigestResolveTimeout:    Duration{Duration: defaultDigestResolveTimeout},
		FetchFailurePolicy:      types.ActionWarn,
		CacheTTL:                Duration{Duration: defaultCacheTTL},
		CacheFailureTTL:         Duration{Duration: defaultCacheFailureTTL},
		PolicyDir:               "/etc/nri-supply-chain/policies",
		MetricsAddr:             "127.0.0.1:9090",
		CircuitBreakerThreshold: defaultCircuitBreakerThreshold,
		CircuitBreakerCooldown:  Duration{Duration: defaultCircuitBreakerCooldown},
		VerificationTimeout:     Duration{Duration: defaultVerificationTimeout},
		FetchRateLimit:          0,
		LogLevel:                "",
		Sigstore: SigstoreConfig{
			TUFMirror:         "",
			TUFRoot:           "",
			Roots:             nil,
			IncludePublicRoot: nil,
		},
		Registries: nil,
		Policy: PolicyConfig{
			Source:       PolicySourceLocal,
			OCIRef:       "",
			PollInterval: Duration{Duration: defaultPollInterval},
			Issuers:      nil,
			SANPatterns:  nil,
			Keys:         nil,
		},
		MaxAttestationSize: DefaultMaxAttestationSize,
		CacheMaxEntries:    defaultCacheMaxEntries,
	}
}

// Strictness returns the numeric strictness level of the mode.
// disabled=0, warn=1, enforce=2. Unknown modes return -1.
func (m VerificationMode) Strictness() Strictness {
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

// ApplyModeDefaults overrides permissive defaults when the verification mode
// demands stricter behavior. In enforce mode the effective fetch_failure_policy
// changes from "warn" to "deny" unless the user set it explicitly.
func (c *Config) ApplyModeDefaults(fetchFailurePolicyExplicit bool) {
	if c.Verification != ModeEnforce || fetchFailurePolicyExplicit {
		return
	}

	if c.FetchFailurePolicy == types.ActionWarn {
		c.FetchFailurePolicy = types.ActionDeny

		slog.Info("Enforce mode: fetch_failure_policy defaulting to deny")
	}
}

// WarnInsecureRegistries logs a warning for each registry configured with
// insecure TLS. Call at startup or reload time, not during validation.
func (c *Config) WarnInsecureRegistries() {
	for idx := range c.Registries {
		if c.Registries[idx].Insecure {
			slog.Warn("Registry configured with insecure TLS (skip verify);"+
				" this setting will be rejected in enforce mode",
				"prefix", c.Registries[idx].Prefix,
				"index", idx,
			)
		}
	}
}

// RegistriesChanged reports whether two registry slices differ.
func RegistriesChanged(prev, next []Registry) bool {
	return !slices.Equal(prev, next)
}

// SigstoreConfigChanged reports whether two SigstoreConfig values differ in a
// way that affects verification (effective roots list, include_public_root).
func SigstoreConfigChanged(prev, next *SigstoreConfig) bool {
	if (len(prev.Roots) > 0) != (len(next.Roots) > 0) {
		return true
	}

	prevRoots := prev.EffectiveRoots()
	nextRoots := next.EffectiveRoots()

	if !slices.Equal(prevRoots, nextRoots) {
		return true
	}

	return prev.ShouldIncludePublicRoot() != next.ShouldIncludePublicRoot()
}

// LoadFromFile reads and parses a TOML config file. The file size is limited
// to fileutil.MaxConfigFileSize (10 MiB) to prevent memory exhaustion.
func LoadFromFile(path string) (*Config, error) {
	data, err := fileutil.ReadLimited(path, fileutil.MaxConfigFileSize)
	if err != nil {
		if errors.Is(err, fileutil.ErrFileTooLarge) {
			return nil, fmt.Errorf("%w: %q", ErrConfigFileTooLarge, path)
		}

		return nil, fmt.Errorf("config file %q: %w", path, err)
	}

	cfg, err := load(func(cfg *Config) (toml.MetaData, error) {
		return toml.Decode(string(data), cfg)
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

	err = Migrate(cfg)
	if err != nil {
		return nil, fmt.Errorf("migrating config: %w", err)
	}

	err = cfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	cfg.Normalize()

	return cfg, nil
}

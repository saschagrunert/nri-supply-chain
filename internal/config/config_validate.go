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
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/saschagrunert/nri-supply-chain/internal/fileutil"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

// Validate checks the Config for invalid values.
func (c *Config) Validate() error {
	var errs []error

	err := c.validateConfigVersion()
	if err != nil {
		errs = append(errs, err)
	}

	errs = append(errs, c.validateModeAndLogLevel()...)

	err = c.validateMetricsAddr()
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

	errs = append(errs, c.validateAllowlistDigests()...)

	err = c.validateGUACConfig()
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
			errs = append(errs, c.validatePolicyDirRuntime()...)
		}

		errs = append(errs, c.validateTUFRootRuntime()...)
	}

	errs = append(errs, c.validatePolicyKeysRuntime()...)
	errs = append(errs, c.validateRegistryCACertsRuntime()...)
	errs = append(errs, c.validateGUACConfigRuntime()...)

	return errors.Join(errs...)
}

func (c *Config) validatePolicyKeysRuntime() []error {
	if !c.Policy.SignatureVerificationRequired() {
		return nil
	}

	var errs []error

	for _, keyPath := range c.Policy.Keys {
		keyInfo, statErr := os.Lstat(keyPath)

		switch {
		case statErr != nil:
			errs = append(errs, fmt.Errorf(
				"policy.keys file %q: %w", keyPath, statErr,
			))
		case keyInfo.Mode()&os.ModeSymlink != 0:
			errs = append(errs, fmt.Errorf(
				"%w: policy.keys %q", ErrSymlinkNotAllowed, keyPath,
			))
		case !keyInfo.Mode().IsRegular():
			errs = append(errs, fmt.Errorf(
				"%w: %q", ErrPolicyKeyNotRegularFile, keyPath,
			))
		default:
			permErr := fileutil.CheckCredentialPermissions(keyPath)
			if permErr != nil {
				slog.Warn("Policy key file has overly permissive mode bits",
					"path", keyPath, "error", permErr)
			}
		}
	}

	return errs
}

func (c *Config) validateRegistryCACertsRuntime() []error {
	var errs []error

	for idx := range c.Registries {
		reg := &c.Registries[idx]
		if reg.CACert != "" {
			caInfo, statErr := os.Lstat(reg.CACert)
			if statErr != nil {
				errs = append(errs, fmt.Errorf(
					"%w: registries[%d] ca_cert %q: %w",
					ErrRegistryCACertNotFound, idx, reg.CACert, statErr,
				))
			} else if caInfo.Mode()&os.ModeSymlink != 0 {
				errs = append(errs, fmt.Errorf(
					"%w: registries[%d] ca_cert %q",
					ErrSymlinkNotAllowed, idx, reg.CACert,
				))
			}
		}
	}

	return errs
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

func (c *Config) validatePolicyDirRuntime() []error {
	info, err := os.Lstat(c.PolicyDir)
	if err != nil {
		return []error{fmt.Errorf("invalid policy_dir %q: %w", c.PolicyDir, err)}
	}

	switch {
	case info.Mode()&os.ModeSymlink != 0:
		return []error{fmt.Errorf(
			"%w: policy_dir %q", ErrSymlinkNotAllowed, c.PolicyDir,
		)}
	case !info.IsDir():
		return []error{fmt.Errorf(
			"%w: %q; see docs/config.md", ErrPolicyDirNotDirectory, c.PolicyDir,
		)}
	}

	return nil
}

func (c *Config) validateTUFRootRuntime() []error {
	var errs []error

	if c.Sigstore.TUFRoot != "" {
		errs = append(errs, validateTUFRootFile(c.Sigstore.TUFRoot, "sigstore.tuf_root")...)
	}

	for idx := range c.Sigstore.Roots {
		if c.Sigstore.Roots[idx].TUFRoot != "" {
			label := fmt.Sprintf("sigstore.roots[%d].tuf_root", idx)
			errs = append(errs, validateTUFRootFile(c.Sigstore.Roots[idx].TUFRoot, label)...)
		}
	}

	if len(errs) == 0 {
		return nil
	}

	return errs
}

func validateTUFRootFile(path, label string) []error {
	rootInfo, err := os.Lstat(path)
	if err != nil {
		return []error{fmt.Errorf(
			"%w: %q: %w", ErrTUFRootNotFound, path, err,
		)}
	}

	if rootInfo.Mode()&os.ModeSymlink != 0 {
		return []error{fmt.Errorf(
			"%w: %s %q", ErrSymlinkNotAllowed, label, path,
		)}
	}

	if !rootInfo.Mode().IsRegular() {
		return []error{fmt.Errorf(
			"%w: %q", ErrTUFRootNotRegularFile, path,
		)}
	}

	if rootInfo.Size() == 0 {
		return []error{fmt.Errorf(
			"%w: %q", ErrTUFRootEmpty, path,
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

	if reg.Insecure && c.Verification == ModeEnforce {
		errs = append(errs, fmt.Errorf(
			"%w: registries[%d] %q",
			ErrInsecureRegistryInEnforceMode, idx, reg.Prefix,
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

	if c.Verification == ModeEnforce && c.FetchFailurePolicy == types.ActionAllow {
		slog.Warn(
			"fetch_failure_policy \"allow\" in enforce mode lets unverified " +
				"containers through on fetch errors; consider \"deny\" or \"warn\"",
		)
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
	var errs []error

	if c.FetchTimeout.Duration <= 0 {
		errs = append(errs, fmt.Errorf(
			"%w: got %s", ErrFetchTimeoutNotPositive, c.FetchTimeout.Duration,
		))
	}

	if c.FetchTimeout.Duration > maxFetchTimeout {
		errs = append(errs, fmt.Errorf(
			"%w: got %s, max %s",
			ErrFetchTimeoutTooHigh, c.FetchTimeout.Duration, maxFetchTimeout,
		))
	}

	if c.DigestResolveTimeout.Duration <= 0 {
		errs = append(errs, fmt.Errorf(
			"%w: got %s", ErrDigestResolveTimeoutNotPositive, c.DigestResolveTimeout.Duration,
		))
	}

	if c.DigestResolveTimeout.Duration > maxDigestResolveTimeout {
		errs = append(errs, fmt.Errorf(
			"%w: got %s, max %s",
			ErrDigestResolveTimeoutTooHigh,
			c.DigestResolveTimeout.Duration,
			maxDigestResolveTimeout,
		))
	}

	return errs
}

func (c *Config) validateCacheFields() error {
	var errs []error

	if c.CacheTTL.Duration < 0 {
		errs = append(errs, fmt.Errorf(
			"%w: got %s", ErrCacheTTLNegative, c.CacheTTL.Duration,
		))
	}

	if c.CacheTTL.Duration > maxCacheTTL {
		errs = append(errs, fmt.Errorf(
			"%w: got %s, max %s",
			ErrCacheTTLTooHigh, c.CacheTTL.Duration, maxCacheTTL,
		))
	}

	if c.CacheFailureTTL.Duration < 0 {
		errs = append(errs, fmt.Errorf(
			"%w: got %s", ErrCacheFailureTTLNegative, c.CacheFailureTTL.Duration,
		))
	}

	if c.CacheFailureTTL.Duration > maxCacheFailTTL {
		errs = append(errs, fmt.Errorf(
			"%w: got %s, max %s",
			ErrCacheFailureTTLTooHigh, c.CacheFailureTTL.Duration, maxCacheFailTTL,
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

	if c.CircuitBreakerCooldown.Duration > maxCircuitBreakerCooldown {
		errs = append(errs, fmt.Errorf(
			"%w: got %s, max %s",
			ErrCircuitBreakerCooldownTooHigh,
			c.CircuitBreakerCooldown.Duration,
			maxCircuitBreakerCooldown,
		))
	}

	if c.VerificationTimeout.Duration <= 0 {
		errs = append(errs, fmt.Errorf(
			"%w: got %s", ErrVerificationTimeoutNotPositive, c.VerificationTimeout.Duration,
		))
	}

	if c.VerificationTimeout.Duration > maxVerificationTimeout {
		errs = append(errs, fmt.Errorf(
			"%w: got %s, max %s",
			ErrVerificationTimeoutTooHigh,
			c.VerificationTimeout.Duration,
			maxVerificationTimeout,
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

	errs = append(errs, c.validateLimitsFields()...)

	return errors.Join(errs...)
}

func (c *Config) validateLimitsFields() []error {
	var errs []error

	if c.MaxAttestationSize < minAttestationSize {
		errs = append(errs, fmt.Errorf(
			"%w: got %d", ErrMaxAttestationSizeTooSmall, c.MaxAttestationSize,
		))
	}

	if c.MaxAttestationSize > maxAttestationSize {
		errs = append(errs, fmt.Errorf(
			"%w: got %d", ErrMaxAttestationSizeTooLarge, c.MaxAttestationSize,
		))
	}

	if c.CacheMaxEntries < minCacheMaxEntries {
		errs = append(errs, fmt.Errorf(
			"%w: got %d", ErrCacheMaxEntriesTooSmall, c.CacheMaxEntries,
		))
	}

	if c.CacheMaxEntries > maxCacheMaxEntries {
		errs = append(errs, fmt.Errorf(
			"%w: got %d", ErrCacheMaxEntriesTooLarge, c.CacheMaxEntries,
		))
	}

	return errs
}

func (c *Config) validateSigstoreConfig() error {
	var errs []error

	hasScalarFields := c.Sigstore.TUFMirror != "" || c.Sigstore.TUFRoot != ""
	hasRoots := len(c.Sigstore.Roots) > 0

	if hasScalarFields && hasRoots {
		errs = append(errs, ErrSigstoreRootsMutualExclusion)

		return errors.Join(errs...)
	}

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
	}

	errs = append(errs, validateSigstoreRoots(c.Sigstore.Roots)...)

	return errors.Join(errs...)
}

func validateSigstoreRoots(roots []SigstoreRootSource) []error {
	if len(roots) == 0 {
		return nil
	}

	var errs []error

	seen := make(map[string]int, len(roots))

	for idx := range roots {
		root := &roots[idx]

		if root.Name == "" {
			errs = append(errs, fmt.Errorf(
				"%w: roots[%d]", ErrSigstoreRootNameRequired, idx,
			))
		} else {
			if prevIdx, ok := seen[root.Name]; ok {
				errs = append(errs, fmt.Errorf(
					"%w: %q at roots[%d] and roots[%d]",
					ErrSigstoreRootNameDuplicate, root.Name, prevIdx, idx,
				))
			} else {
				seen[root.Name] = idx
			}
		}

		if root.TUFMirror != "" {
			err := validateTUFMirrorURL(root.TUFMirror)
			if err != nil {
				errs = append(errs, fmt.Errorf("roots[%d]: %w", idx, err))
			}
		}

		if root.TUFRoot != "" {
			if !filepath.IsAbs(root.TUFRoot) {
				errs = append(errs, fmt.Errorf(
					"%w: roots[%d] %q", ErrTUFRootNotAbsolute, idx, root.TUFRoot,
				))
			}

			if root.TUFMirror == "" {
				errs = append(errs, fmt.Errorf(
					"%w: roots[%d]", ErrTUFRootRequiresMirror, idx,
				))
			}
		}
	}

	return errs
}

func validateTUFMirrorURL(mirror string) error {
	parsed, err := url.Parse(mirror)
	if err != nil {
		return fmt.Errorf("%w: %q: %w", ErrInvalidTUFMirror, mirror, err)
	}

	if parsed.Scheme != "https" {
		return fmt.Errorf(
			"%w: %q: scheme must be https", ErrInvalidTUFMirror, mirror,
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
	errs := c.validatePolicySignatureFields()

	switch c.Policy.Source {
	case PolicySourceLocal, "":
		return errors.Join(errs...)
	case PolicySourceOCI:
	default:
		errs = append(errs, fmt.Errorf("%w: got %q", ErrInvalidPolicySource, c.Policy.Source))

		return errors.Join(errs...)
	}

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

// validatePolicySignatureFields checks structural constraints on signature
// fields, catching misconfigurations early.
func (c *Config) validatePolicySignatureFields() []error {
	var errs []error

	hasIssuers := len(c.Policy.Issuers) > 0
	hasKeys := len(c.Policy.Keys) > 0

	if hasIssuers && hasKeys {
		errs = append(errs, ErrPolicyIssuersAndKeysMutuallyExclusive)
	}

	if len(c.Policy.SANPatterns) > 0 && !hasIssuers {
		errs = append(errs, ErrPolicySANPatternsWithoutIssuers)
	}

	errs = append(errs, validatePolicySignatureEntries(&c.Policy)...)
	errs = append(errs, validatePolicyKeyPaths(c.Policy.Keys)...)
	warnSignatureSourceMismatch(c, len(errs) == 0)

	sanErr := warnOrRejectIssuersWithoutSANPatterns(c, len(errs) == 0)
	if sanErr != nil {
		errs = append(errs, sanErr)
	}

	return errs
}

func validatePolicySignatureEntries(pol *PolicyConfig) []error {
	var errs []error

	if slices.Contains(pol.Issuers, "") {
		errs = append(errs, ErrPolicyIssuerEmpty)
	}

	if slices.Contains(pol.SANPatterns, "") {
		errs = append(errs, ErrPolicySANPatternEmpty)
	}

	if slices.Contains(pol.Keys, "") {
		errs = append(errs, ErrPolicyKeyEmpty)
	}

	return errs
}

func validatePolicyKeyPaths(keys []string) []error {
	var errs []error

	seen := make(map[string]struct{}, len(keys))

	for _, keyPath := range keys {
		if !filepath.IsAbs(keyPath) {
			errs = append(errs, fmt.Errorf(
				"%w: %q", ErrPolicySignatureKeyNotAbsolute, keyPath,
			))
		}

		if _, dup := seen[keyPath]; dup {
			errs = append(errs, fmt.Errorf(
				"%w: %q", ErrPolicySignatureKeyDuplicate, keyPath,
			))
		}

		seen[keyPath] = struct{}{}
	}

	return errs
}

func warnSignatureSourceMismatch(cfg *Config, valid bool) {
	if !valid || !cfg.Policy.SignatureVerificationRequired() {
		return
	}

	if cfg.Policy.Source != PolicySourceOCI {
		slog.Warn(
			"signature trust material (issuers/keys) is configured but "+
				"policy.source is not \"oci\"; "+
				"signature verification only applies to OCI policies",
			"source", cfg.Policy.Source,
		)
	}
}

func warnOrRejectIssuersWithoutSANPatterns(cfg *Config, valid bool) error {
	if !valid || !cfg.Policy.SignatureVerificationRequired() {
		return nil
	}

	if len(cfg.Policy.Issuers) > 0 && len(cfg.Policy.SANPatterns) == 0 {
		if cfg.Verification == ModeEnforce {
			return ErrIssuersWithoutSANPatternsInEnforce
		}

		slog.Warn(
			"policy.issuers is set without policy.san_patterns; " +
				"any identity from the configured issuers will be accepted",
		)
	}

	return nil
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

func (c *Config) validateGUACConfig() error { //nolint:cyclop // sequential field checks
	guacCfg := &c.Guac

	if !guacCfg.Enabled() {
		return nil
	}

	var errs []error

	u, err := url.Parse(guacCfg.Endpoint)
	if err != nil || u.Scheme == "" || u.Host == "" {
		errs = append(errs, fmt.Errorf("%w: %s", ErrGUACEndpointInvalid, guacCfg.Endpoint))
	}

	if guacCfg.Timeout.Duration <= 0 {
		errs = append(errs, ErrGUACTimeoutNotPositive)
	} else if guacCfg.Timeout.Duration > maxGUACTimeout {
		errs = append(errs, fmt.Errorf("%w: %s (max %s)",
			ErrGUACTimeoutTooHigh, guacCfg.Timeout.Duration, maxGUACTimeout))
	}

	switch guacCfg.FallbackPolicy {
	case types.ActionAllow, types.ActionWarn, types.ActionDeny:
	case "":
	default:
		errs = append(errs, fmt.Errorf("%w: %q",
			ErrGUACInvalidFallbackPolicy, guacCfg.FallbackPolicy))
	}

	if len(guacCfg.Checks) == 0 {
		errs = append(errs, ErrGUACChecksEmpty)
	} else {
		for _, check := range guacCfg.Checks {
			if !slices.Contains(GUACValidChecks, check) {
				errs = append(errs, fmt.Errorf("%w: %q", ErrGUACInvalidCheck, check))
			}
		}
	}

	if guacCfg.MaxDependencies < 1 || guacCfg.MaxDependencies > maxGUACMaxDeps {
		errs = append(errs, fmt.Errorf("%w: got %d",
			ErrGUACMaxDepsRange, guacCfg.MaxDependencies))
	}

	if guacCfg.AuthTokenPath != "" && !filepath.IsAbs(guacCfg.AuthTokenPath) {
		errs = append(errs, ErrGUACAuthTokenPathNotAbsolute)
	}

	if guacCfg.CACertPath != "" && !filepath.IsAbs(guacCfg.CACertPath) {
		errs = append(errs, ErrGUACCACertPathNotAbsolute)
	}

	return errors.Join(errs...)
}

func (c *Config) validateGUACConfigRuntime() []error {
	if !c.Guac.Enabled() {
		return nil
	}

	var errs []error

	if c.Guac.AuthTokenPath != "" {
		// Use os.Stat (not Lstat) because K8s mounts secrets as symlinks.
		info, err := os.Stat(c.Guac.AuthTokenPath)
		if err != nil {
			slog.Warn("GUAC auth token file not found, token auth will be unavailable",
				"path", c.Guac.AuthTokenPath, "error", err)
		} else if !info.Mode().IsRegular() {
			errs = append(errs, fmt.Errorf("%w: %s",
				ErrGUACAuthTokenNotRegularFile, c.Guac.AuthTokenPath))
		}
	}

	if c.Guac.CACertPath != "" {
		info, err := os.Lstat(c.Guac.CACertPath)
		if err != nil {
			errs = append(errs, fmt.Errorf("%w: %s",
				ErrGUACCACertNotFound, c.Guac.CACertPath))
		} else if !info.Mode().IsRegular() {
			errs = append(errs, fmt.Errorf("%w: %s",
				ErrGUACCACertNotRegularFile, c.Guac.CACertPath))
		}
	}

	return errs
}

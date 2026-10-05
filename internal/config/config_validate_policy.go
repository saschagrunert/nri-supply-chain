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
	"slices"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/saschagrunert/nri-supply-chain/internal/glob"
)

func (c *Config) validatePolicyKeysRuntime() []error {
	if !c.Policy.SignatureVerificationRequired() {
		return nil
	}

	var errs []error

	for _, keyPath := range c.Policy.Keys {
		_, err := checkContainedFile(&containedFile{
			label:         "policy.keys",
			path:          keyPath,
			credential:    true,
			errNotFound:   ErrPolicyKeyNotFound,
			errNotRegular: ErrPolicyKeyNotRegularFile,
		})
		if err != nil {
			errs = append(errs, err)
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

func (c *Config) validatePolicyConfig() error {
	errs := c.validatePolicySignatureFields()

	switch c.Policy.Source {
	case PolicySourceLocal, "":
		warnOCIFieldsIgnored(&c.Policy)

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

	err := c.Policy.validateMaxStaleness()
	if err != nil {
		errs = append(errs, err)
	}

	if !c.Policy.SignatureVerificationRequired() {
		if c.Verification == ModeEnforce {
			errs = append(errs, ErrPolicyOCIUnsignedInEnforce)
		} else {
			slog.Warn(
				"policy.source \"oci\" without policy.issuers or policy.keys accepts "+
					"unsigned policy artifacts; anyone with push access can change policies",
				"oci_ref", c.Policy.OCIRef,
			)
		}
	}

	return errors.Join(errs...)
}

// validateMaxStaleness checks that oci_max_staleness is either unlimited (0)
// or at least one poll interval.
func (p *PolicyConfig) validateMaxStaleness() error {
	maxStaleness := p.OCIMaxStaleness.Duration
	if maxStaleness == 0 || maxStaleness >= p.PollInterval.Duration {
		return nil
	}

	return fmt.Errorf(
		"%w: got %s, poll_interval %s",
		ErrOCIMaxStalenessInvalid, maxStaleness, p.PollInterval.Duration,
	)
}

// warnOCIFieldsIgnored warns about OCI policy source fields set while
// policies are loaded from policy_dir, where they have no effect.
func warnOCIFieldsIgnored(pol *PolicyConfig) {
	var fields []string

	if pol.OCIRef != "" {
		fields = append(fields, "policy.oci_ref")
	}

	if pol.PollInterval.Duration != defaultPollInterval {
		fields = append(fields, "policy.poll_interval")
	}

	if pol.OCIMaxStaleness.Duration != 0 {
		fields = append(fields, "policy.oci_max_staleness")
	}

	if len(fields) > 0 {
		slog.Warn("OCI policy fields are set but policy.source is not \"oci\"; they are ignored",
			"source", pol.Source,
			"fields", fields,
		)
	}
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

	for _, pattern := range pol.SANPatterns {
		err := glob.Validate(pattern)
		if err != nil {
			errs = append(errs, fmt.Errorf("%w: %q: %w", ErrPolicySANPatternInvalid, pattern, err))
		}

		if glob.HasBangNegation(pattern) {
			slog.Warn("policy.san_patterns entry uses a \"[!...]\" character class, "+
				"which negates the class; earlier releases matched \"!\" literally",
				"pattern", pattern,
			)
		}
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

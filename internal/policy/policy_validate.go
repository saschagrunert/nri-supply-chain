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

package policy

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/fileutil"
	"github.com/saschagrunert/nri-supply-chain/internal/glob"
)

const (
	notationLevelSkip = "skip"

	revocationModeStrict = "strict"
	revocationModeSoft   = "soft"
	revocationModeSkip   = "skip"
)

// ValidateModeStrictness checks that the per-namespace mode is at least as
// strict as the global verification mode. Returns nil if Mode is empty (no
// per-namespace override).
func (p *Policy) ValidateModeStrictness(global config.VerificationMode) error {
	if p.Mode == "" {
		return nil
	}

	if p.Mode.Strictness() < global.Strictness() {
		return fmt.Errorf(
			"%w: global %q, namespace %q",
			ErrModeNotStricter, global, p.Mode,
		)
	}

	return nil
}

// Validate checks the policy for invalid values.
func (p *Policy) Validate() error {
	var errs []error

	if p.Mode != "" && !p.Mode.IsValid() {
		errs = append(errs, fmt.Errorf("%w: %q", ErrInvalidPolicyMode, p.Mode))
	}

	errs = append(errs, p.validateSections()...)

	err := p.validateRules()
	if err != nil {
		errs = append(errs, err)
	}

	celErr := p.validateAndCompileCEL()
	if celErr != nil {
		errs = append(errs, celErr)
	}

	return errors.Join(errs...)
}

// ValidateEnforce runs additional checks required for enforce mode.
// Keyless verification (issuers set) requires explicit SANPatterns.
// The mode parameter is the effective mode for this policy (per-namespace
// mode if set, otherwise the global mode).
func (p *Policy) ValidateEnforce() error {
	if p.Notation != nil && p.Notation.VerificationLevel == notationLevelSkip {
		return ErrNotationSkipInEnforceMode
	}

	if p.Trust != nil {
		if len(p.Trust.Issuers) > 0 && len(p.Trust.SANPatterns) == 0 {
			return ErrSANPatternsRequired
		}
	}

	return p.validateRulesEnforce()
}

func (p *Policy) validateRulesEnforce() error {
	for idx := range p.Rules {
		if p.Rules[idx].Notation != nil &&
			p.Rules[idx].Notation.VerificationLevel == notationLevelSkip {
			return fmt.Errorf("rules[%d]: %w", idx, ErrNotationSkipInEnforceMode)
		}

		if p.Rules[idx].Trust == nil {
			continue
		}

		if len(p.Rules[idx].Trust.Issuers) > 0 && len(p.Rules[idx].Trust.SANPatterns) == 0 {
			return fmt.Errorf("rules[%d]: %w", idx, ErrSANPatternsRequired)
		}
	}

	return nil
}

// ValidateRuntime performs runtime checks that require filesystem access,
// such as verifying that verifier key files exist on disk. Uses Lstat to
// detect symlinks (Stat would silently follow them).
//
// TOCTOU: the file could change between Lstat and loadPublicKeyFromPEM.
func (p *Policy) ValidateRuntime() error {
	var errs []error

	if p.Trust != nil {
		for idx, verif := range p.Trust.Verifiers {
			for kidx, key := range verif.Keys {
				prefix := fmt.Sprintf("trust.verifiers[%d]", idx)

				err := validateKeyFile(prefix, verif.ID, key, kidx)
				if err != nil {
					errs = append(errs, err)
				}
			}
		}
	}

	errs = append(errs, validateNotationCertFiles("", p.Notation)...)

	for rIdx := range p.Rules {
		if p.Rules[rIdx].Trust != nil {
			for idx, verif := range p.Rules[rIdx].Trust.Verifiers {
				for kidx, key := range verif.Keys {
					prefix := fmt.Sprintf("rules[%d].trust.verifiers[%d]", rIdx, idx)

					err := validateKeyFile(prefix, verif.ID, key, kidx)
					if err != nil {
						errs = append(errs, err)
					}
				}
			}
		}

		errs = append(errs, validateNotationCertFiles(
			fmt.Sprintf("rules[%d].", rIdx), p.Rules[rIdx].Notation,
		)...)
	}

	return errors.Join(errs...)
}

func (p *Policy) validateSections() []error { //nolint:funlen // one block per section type
	var errs []error

	appendErr := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}

	appendErr(p.validateTrust())
	appendErr(p.validateInclude())
	appendErr(p.validateExclude())

	slsaErr := p.validateSLSA()
	if slsaErr != nil {
		errs = append(errs, slsaErr)
	} else {
		p.resolveSLSADuration()
	}

	appendErr(p.validateVEX())

	err := p.validateVSA()
	if err != nil {
		errs = append(errs, err)
	} else {
		p.resolveVSADuration()
	}

	appendErr(p.validateNotation())
	appendErr(p.validateSBOM())
	appendErr(p.validateSCAI())

	sourceErr := p.validateSource()
	if sourceErr != nil {
		errs = append(errs, sourceErr)
	} else {
		p.resolveSourceDuration()
	}

	appendErr(p.validateBuildEnv())

	vulnErr := p.validateVulnScan()
	if vulnErr != nil {
		errs = append(errs, vulnErr)
	} else {
		p.resolveVulnScanDuration()
	}

	testErr := p.validateTestResult()
	if testErr != nil {
		errs = append(errs, testErr)
	} else {
		p.resolveTestResultDuration()
	}

	appendErr(p.validateRelease())

	runtimeTraceErr := p.validateRuntimeTrace()
	if runtimeTraceErr != nil {
		errs = append(errs, runtimeTraceErr)
	} else {
		p.resolveRuntimeTraceDuration()
	}

	return errs
}

func validateKeyFile(prefix, verifierID, keyPath string, keyIdx int) error {
	label := fmt.Sprintf("%s %q: keys[%d] file %q", prefix, verifierID, keyIdx, keyPath)

	info, err := os.Lstat(keyPath)
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}

	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf(
			"%s: %w (symlinks are not allowed)", label, ErrNotRegularFile,
		)
	}

	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s: %w", label, ErrNotRegularFile)
	}

	permErr := fileutil.CheckCredentialPermissions(keyPath)
	if permErr != nil {
		slog.Warn("Key file has overly permissive mode bits", "path", keyPath, "error", permErr)
	}

	return nil
}

func (p *Policy) validateTrust() error {
	if p.Trust == nil {
		return nil
	}

	warnEmptyTrust(p.Trust)

	var errs []error

	seenBuilders := make(map[string]bool, len(p.Trust.Builders))

	for idx, builder := range p.Trust.Builders {
		if builder.ID == "" {
			errs = append(errs, fmt.Errorf(
				"%w: trust.builders[%d]", ErrBuilderIDRequired, idx,
			))

			continue
		}

		if seenBuilders[builder.ID] {
			errs = append(errs, fmt.Errorf(
				"%w %q at trust.builders[%d]", ErrDuplicateBuilderID, builder.ID, idx,
			))

			continue
		}

		seenBuilders[builder.ID] = true

		if builder.MaxLevel < 0 || builder.MaxLevel > maxSLSALevel {
			errs = append(errs, fmt.Errorf(
				"%w: trust.builders[%d] %q: got %d",
				ErrBuilderMaxLevel, idx, builder.ID, builder.MaxLevel,
			))
		}
	}

	err := p.validateTrustStringFields()
	if err != nil {
		errs = append(errs, err)
	}

	err = p.validateVerifiers()
	if err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

func (p *Policy) validateTrustStringFields() error {
	var errs []error

	err := validateNonEmpty("trust.issuers", p.Trust.Issuers)
	if err != nil {
		errs = append(errs, err)
	}

	err = validateNonEmpty("trust.sources", p.Trust.Sources)
	if err != nil {
		errs = append(errs, err)
	}

	err = validateGlobPatterns("trust.sources", p.Trust.Sources)
	if err != nil {
		errs = append(errs, err)
	}

	err = validateNonEmpty("trust.buildTypes", p.Trust.BuildTypes)
	if err != nil {
		errs = append(errs, err)
	}

	err = validateNonEmpty("trust.sanPatterns", p.Trust.SANPatterns)
	if err != nil {
		errs = append(errs, err)
	}

	err = validateGlobPatterns("trust.sanPatterns", p.Trust.SANPatterns)
	if err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

func (p *Policy) validateVerifiers() error {
	var errs []error

	seenVerifiers := make(map[string]bool, len(p.Trust.Verifiers))

	for idx := range p.Trust.Verifiers {
		verif := &p.Trust.Verifiers[idx]

		if verif.ID == "" {
			errs = append(errs, fmt.Errorf(
				"%w: trust.verifiers[%d]", ErrVerifierIDRequired, idx,
			))

			continue
		}

		if seenVerifiers[verif.ID] {
			errs = append(errs, fmt.Errorf(
				"%w %q at trust.verifiers[%d]", ErrDuplicateVerifierID, verif.ID, idx,
			))

			continue
		}

		seenVerifiers[verif.ID] = true

		errs = append(errs, validateVerifierKeys(p, idx, verif)...)
	}

	errs = append(errs, validateNoDuplicateKeysAcrossVerifiers(
		p.Trust.Verifiers,
	)...)

	return errors.Join(errs...)
}

// validateNoDuplicateKeysAcrossVerifiers checks that no key path appears in
// more than one verifier. The same physical key in two verifiers with
// different time bounds would cause one to silently overwrite the other in
// the key material map.
func validateNoDuplicateKeysAcrossVerifiers(
	verifiers []TrustedVerifier,
) []error {
	// keyPath -> first verifier ID that claimed it
	seen := make(map[string]string)

	var errs []error

	for _, verif := range verifiers {
		if verif.ID == "" {
			continue
		}

		for _, key := range verif.Keys {
			if key == "" {
				continue
			}

			if firstID, exists := seen[key]; exists {
				errs = append(errs, fmt.Errorf(
					"%w: key %q appears in verifier %q and %q",
					ErrDuplicateKeyAcrossVerifiers, key, firstID, verif.ID,
				))
			} else {
				seen[key] = verif.ID
			}
		}
	}

	return errs
}

func validateVerifierKeys(
	pol *Policy, idx int, verif *TrustedVerifier,
) []error {
	var errs []error

	if len(verif.Keys) == 0 {
		if len(pol.Trust.Issuers) == 0 {
			errs = append(errs, fmt.Errorf(
				"%w: trust.verifiers[%d] %q",
				ErrKeylessVerifierRequiresIssuers, idx, verif.ID,
			))
		}

		if verif.NotBefore != "" || verif.NotAfter != "" {
			errs = append(errs, fmt.Errorf(
				"%w: trust.verifiers[%d] %q",
				ErrTimeBoundsWithoutKeys, idx, verif.ID,
			))
		}

		return errs
	}

	seen := make(map[string]bool, len(verif.Keys))

	for kidx, key := range verif.Keys {
		if key == "" {
			errs = append(errs, fmt.Errorf(
				"%w in trust.verifiers[%d].keys[%d]",
				ErrEmptyValue, idx, kidx,
			))

			continue
		}

		if seen[key] {
			errs = append(errs, fmt.Errorf(
				"%w %q at trust.verifiers[%d].keys[%d]",
				ErrDuplicateVerifierKey, key, idx, kidx,
			))

			continue
		}

		seen[key] = true

		if !filepath.IsAbs(key) {
			errs = append(errs, fmt.Errorf(
				"%w: trust.verifiers[%d] %q: keys[%d] got %q",
				ErrVerifierKeyNotAbsolute, idx, verif.ID, kidx, key,
			))
		}
	}

	errs = append(errs, validateVerifierTimeBounds(idx, verif)...)

	return errs
}

func validateVerifierTimeBounds(idx int, verif *TrustedVerifier) []error {
	var errs []error

	if verif.NotBefore != "" {
		notBefore, err := time.Parse(time.RFC3339, verif.NotBefore)
		if err != nil {
			errs = append(errs, fmt.Errorf(
				"%w: trust.verifiers[%d] %q: got %q",
				ErrInvalidNotBefore, idx, verif.ID, verif.NotBefore,
			))
		} else {
			verif.NotBeforeTime = notBefore
		}
	}

	if verif.NotAfter != "" {
		notAfter, err := time.Parse(time.RFC3339, verif.NotAfter)
		if err != nil {
			errs = append(errs, fmt.Errorf(
				"%w: trust.verifiers[%d] %q: got %q",
				ErrInvalidNotAfter, idx, verif.ID, verif.NotAfter,
			))
		} else {
			verif.NotAfterTime = notAfter
		}
	}

	if len(errs) > 0 {
		return errs
	}

	if !verif.NotBeforeTime.IsZero() && !verif.NotAfterTime.IsZero() {
		if !verif.NotAfterTime.After(verif.NotBeforeTime) {
			errs = append(errs, fmt.Errorf(
				"%w: trust.verifiers[%d] %q: notBefore=%q notAfter=%q",
				ErrNotAfterBeforeNotBefore, idx, verif.ID,
				verif.NotBefore, verif.NotAfter,
			))
		}
	}

	return errs
}

func validateGlobPatterns(field string, patterns []string) error {
	var errs []error

	for idx, pattern := range patterns {
		_, err := glob.Match(pattern, "")
		if err != nil {
			errs = append(errs, fmt.Errorf(
				"invalid %s[%d] pattern %q: %w", field, idx, pattern, err,
			))
		}
	}

	return errors.Join(errs...)
}

func validateNonEmpty(field string, values []string) error {
	var errs []error

	for idx, val := range values {
		if val == "" {
			errs = append(errs, fmt.Errorf("%w in %s[%d]", ErrEmptyValue, field, idx))
		}
	}

	return errors.Join(errs...)
}

func warnEmptyTrust(trust *TrustPolicy) {
	if len(trust.Builders) == 0 && len(trust.Verifiers) == 0 && len(trust.Issuers) == 0 {
		slog.Warn("trust section is configured but has no builders, verifiers, or issuers")
	}
}

func (p *Policy) validateInclude() error {
	return validateGlobPatterns("include", p.Include)
}

func (p *Policy) validateExclude() error {
	return validateGlobPatterns("exclude", p.Exclude)
}

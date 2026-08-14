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
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	celengine "github.com/saschagrunert/nri-supply-chain/internal/cel"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/glob"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
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

	runtimeTraceErr := p.validateRuntimeTrace()
	if runtimeTraceErr != nil {
		errs = append(errs, runtimeTraceErr)
	} else {
		p.resolveRuntimeTraceDuration()
	}

	return errs
}

func validateNotationCertFiles(
	prefix string, notationPolicy *NotationPolicy,
) []error {
	if notationPolicy == nil {
		return nil
	}

	var errs []error

	for idx, store := range notationPolicy.TrustStores {
		for cidx, certPath := range store.Certificates {
			label := fmt.Sprintf(
				"%snotation.trustStores[%d] %q: certificates[%d] file %q",
				prefix, idx, store.Name, cidx, certPath,
			)

			info, err := os.Lstat(certPath)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", label, err))

				continue
			}

			if info.Mode()&os.ModeSymlink != 0 {
				errs = append(errs, fmt.Errorf(
					"%s: %w (symlinks are not allowed)", label, ErrNotRegularFile,
				))

				continue
			}

			if !info.Mode().IsRegular() {
				errs = append(errs, fmt.Errorf("%s: %w", label, ErrNotRegularFile))
			}
		}
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

//nolint:dupl // validation functions share structure but differ in field names
func (p *Policy) validateSLSA() error {
	if p.SLSA == nil {
		return nil
	}

	var errs []error

	if p.SLSA.MissingPolicy != "" {
		err := types.ValidateAction(
			"slsa.missingPolicy", p.SLSA.MissingPolicy,
		)
		if err != nil {
			errs = append(errs, fmt.Errorf("validating slsa policy: %w", err))
		}
	}

	err := validateNonEmpty(
		"slsa.knownParameters", p.SLSA.KnownParameters,
	)
	if err != nil {
		errs = append(errs, err)
	}

	if p.SLSA.MaxAge != "" {
		maxAge, parseErr := time.ParseDuration(p.SLSA.MaxAge)
		if parseErr != nil {
			errs = append(errs, fmt.Errorf("invalid slsa.maxAge %q: %w", p.SLSA.MaxAge, parseErr))
		} else if maxAge <= 0 {
			errs = append(errs, fmt.Errorf("%w, got %q", ErrSLSAMaxAgeNotPositive, p.SLSA.MaxAge))
		}
	}

	return errors.Join(errs...)
}

func (p *Policy) validateVEX() error {
	if p.VEX == nil {
		return nil
	}

	var errs []error

	if p.VEX.MissingPolicy != "" {
		err := types.ValidateAction(
			"vex.missingPolicy", p.VEX.MissingPolicy,
		)
		if err != nil {
			errs = append(errs, fmt.Errorf("validating vex missing policy: %w", err))
		}
	}

	if p.VEX.UnderInvestigationPolicy != "" {
		err := types.ValidateAction(
			"vex.underInvestigationPolicy",
			p.VEX.UnderInvestigationPolicy,
		)
		if err != nil {
			errs = append(errs, fmt.Errorf(
				"validating vex under investigation policy: %w", err,
			))
		}
	}

	return errors.Join(errs...)
}

//nolint:dupl // validation functions share structure but differ in field names
func (p *Policy) validateVSA() error {
	if p.VSA == nil {
		return nil
	}

	var errs []error

	if p.VSA.MissingPolicy != "" {
		err := types.ValidateAction(
			"vsa.missingPolicy", p.VSA.MissingPolicy,
		)
		if err != nil {
			errs = append(errs, fmt.Errorf("validating vsa missing policy: %w", err))
		}
	}

	if p.VSA.MinimumLevel < 0 || p.VSA.MinimumLevel > maxSLSALevel {
		errs = append(errs, fmt.Errorf(
			"%w: got %d", ErrVSAMinimumLevel, p.VSA.MinimumLevel,
		))
	}

	if p.VSA.MaxAge != "" {
		maxAge, err := time.ParseDuration(p.VSA.MaxAge)
		if err != nil {
			errs = append(errs, fmt.Errorf("invalid vsa.maxAge %q: %w", p.VSA.MaxAge, err))
		} else if maxAge <= 0 {
			errs = append(errs, fmt.Errorf("%w, got %q", ErrVSAMaxAgeNotPositive, p.VSA.MaxAge))
		}
	}

	return errors.Join(errs...)
}

func (p *Policy) validateNotation() error {
	if p.Notation == nil {
		return nil
	}

	var errs []error

	if p.Notation.MissingPolicy != "" {
		err := types.ValidateAction(
			"notation.missingPolicy", p.Notation.MissingPolicy,
		)
		if err != nil {
			errs = append(errs, fmt.Errorf("validating notation policy: %w", err))
		}
	}

	errs = append(errs, validateNotationLevels(p.Notation)...)
	errs = append(errs, validateNotationTrustStores(p.Notation.TrustStores)...)
	errs = append(errs, validateNotationTrustPolicy(p.Notation.TrustPolicy)...)

	return errors.Join(errs...)
}

func validateNotationLevels(notation *NotationPolicy) []error {
	var errs []error

	if notation.VerificationLevel != "" {
		switch notation.VerificationLevel {
		case "strict", "permissive", "audit", notationLevelSkip:
		default:
			errs = append(errs, fmt.Errorf(
				"%w: got %q",
				ErrNotationVerificationLevelInvalid,
				notation.VerificationLevel,
			))
		}
	}

	if notation.RevocationMode != "" {
		switch notation.RevocationMode {
		case revocationModeStrict, revocationModeSoft, revocationModeSkip:
		default:
			errs = append(errs, fmt.Errorf(
				"%w: got %q",
				ErrNotationRevocationModeInvalid,
				notation.RevocationMode,
			))
		}
	}

	if notation.VerificationLevel == notationLevelSkip &&
		notation.RevocationMode != "" {
		errs = append(errs, ErrNotationRevocationWithSkipLevel)
	}

	return errs
}

func validateNotationTrustStores(stores []NotationTrustStore) []error {
	var errs []error

	seenNames := make(map[string]bool, len(stores))

	for idx, store := range stores {
		if store.Name == "" {
			errs = append(errs, fmt.Errorf(
				"%w: notation.trustStores[%d]",
				ErrNotationTrustStoreNameRequired, idx,
			))

			continue
		}

		if seenNames[store.Name] {
			errs = append(errs, fmt.Errorf(
				"%w %q at notation.trustStores[%d]",
				ErrDuplicateNotationTrustStoreName, store.Name, idx,
			))

			continue
		}

		seenNames[store.Name] = true

		if store.Type != "ca" && store.Type != "signingAuthority" {
			errs = append(errs, fmt.Errorf(
				"%w: notation.trustStores[%d] %q: got %q",
				ErrNotationTrustStoreTypeInvalid,
				idx, store.Name, store.Type,
			))
		}

		if len(store.Certificates) == 0 {
			errs = append(errs, fmt.Errorf(
				"%w: notation.trustStores[%d] %q",
				ErrNotationTrustStoreCertsRequired, idx, store.Name,
			))
		}

		errs = append(errs, validateNotationStoreCerts(idx, &store)...)
	}

	return errs
}

func validateNotationStoreCerts(idx int, store *NotationTrustStore) []error {
	var errs []error

	for cidx, cert := range store.Certificates {
		if cert == "" {
			errs = append(errs, fmt.Errorf(
				"%w in notation.trustStores[%d].certificates[%d]",
				ErrEmptyValue, idx, cidx,
			))

			continue
		}

		if !filepath.IsAbs(cert) {
			errs = append(errs, fmt.Errorf(
				"%w: notation.trustStores[%d] %q: certificates[%d] got %q",
				ErrNotationCertNotAbsolute, idx, store.Name, cidx, cert,
			))
		}
	}

	return errs
}

func validateNotationTrustPolicy(rules []NotationTrustPolicyRule) []error {
	errs := make([]error, 0, len(rules))

	seenNames := make(map[string]bool, len(rules))

	for idx, rule := range rules {
		errs = append(errs, validateSingleNotationTrustPolicy(
			idx, &rule, seenNames,
		)...)
	}

	return errs
}

func validateSingleNotationTrustPolicy(
	idx int, rule *NotationTrustPolicyRule, seenNames map[string]bool,
) []error {
	var errs []error

	if rule.Name == "" {
		return append(errs, fmt.Errorf(
			"%w: notation.trustPolicy[%d]",
			ErrNotationTrustPolicyNameRequired, idx,
		))
	}

	if seenNames[rule.Name] {
		return append(errs, fmt.Errorf(
			"%w %q at notation.trustPolicy[%d]",
			ErrDuplicateNotationTrustPolicyName, rule.Name, idx,
		))
	}

	seenNames[rule.Name] = true

	if len(rule.RegistryScopes) == 0 {
		errs = append(errs, fmt.Errorf(
			"%w: notation.trustPolicy[%d] %q",
			ErrNotationTrustPolicyScopesRequired, idx, rule.Name,
		))
	}

	if len(rule.TrustStores) == 0 {
		errs = append(errs, fmt.Errorf(
			"%w: notation.trustPolicy[%d] %q",
			ErrNotationTrustPolicyStoresRequired, idx, rule.Name,
		))
	}

	if len(rule.TrustedIdentities) == 0 {
		errs = append(errs, fmt.Errorf(
			"%w: notation.trustPolicy[%d] %q",
			ErrNotationTrustPolicyIdentitiesRequired, idx, rule.Name,
		))
	}

	errs = append(errs, validateNotationTrustPolicyFields(idx, rule)...)

	return errs
}

func validateNotationTrustPolicyFields(
	idx int, rule *NotationTrustPolicyRule,
) []error {
	var errs []error

	prefix := fmt.Sprintf("notation.trustPolicy[%d]", idx)

	err := validateNonEmpty(prefix+".registryScopes", rule.RegistryScopes)
	if err != nil {
		errs = append(errs, err)
	}

	err = validateNonEmpty(prefix+".trustStores", rule.TrustStores)
	if err != nil {
		errs = append(errs, err)
	}

	err = validateNonEmpty(prefix+".trustedIdentities", rule.TrustedIdentities)
	if err != nil {
		errs = append(errs, err)
	}

	return errs
}

func (p *Policy) validateSBOM() error {
	if p.SBOM == nil {
		return nil
	}

	var errs []error

	if p.SBOM.MissingPolicy != "" {
		err := types.ValidateAction(
			"sbom.missingPolicy", p.SBOM.MissingPolicy,
		)
		if err != nil {
			errs = append(errs, fmt.Errorf("validating sbom policy: %w", err))
		}
	}

	errs = append(errs, validateSBOMFormats(p.SBOM.Formats)...)

	if p.SBOM.License != nil {
		err := validateNonEmpty("sbom.license.deny", p.SBOM.License.Deny)
		if err != nil {
			errs = append(errs, err)
		}

		err = validateNonEmpty("sbom.license.allow", p.SBOM.License.Allow)
		if err != nil {
			errs = append(errs, err)
		}
	}

	if p.SBOM.Component != nil {
		errs = append(errs, validateComponentPURLs(
			"sbom.component.deny", p.SBOM.Component.Deny,
		)...)
		errs = append(errs, validateComponentPURLs(
			"sbom.component.allow", p.SBOM.Component.Allow,
		)...)
	}

	if p.SBOM.CVSS != nil {
		errs = append(errs, validateCVSSPolicy(p.SBOM.CVSS)...)
	}

	return errors.Join(errs...)
}

func validateSBOMFormats(formats []string) []error {
	var errs []error

	for idx, format := range formats {
		switch strings.ToLower(format) {
		case "spdx", "cyclonedx":
		default:
			errs = append(errs, fmt.Errorf(
				"%w: sbom.formats[%d] got %q",
				ErrInvalidSBOMFormat, idx, format,
			))
		}
	}

	return errs
}

func validateComponentPURLs(field string, components []string) []error {
	var errs []error

	for idx, comp := range components {
		if comp == "" {
			errs = append(errs, fmt.Errorf(
				"%w in %s[%d]",
				ErrEmptyValue, field, idx,
			))

			continue
		}

		parsed, err := url.Parse(comp)
		if err != nil || parsed.Scheme != "pkg" || parsed.Opaque == "" ||
			!strings.Contains(parsed.Opaque, "/") {
			errs = append(errs, fmt.Errorf(
				"%w: %s[%d] got %q",
				ErrInvalidComponentPURL, field, idx, comp,
			))
		}
	}

	return errs
}

const (
	cvssMaxScoreUpper = 10.0
)

func validateCVSSPolicy(cvss *SBOMCVSSPolicy) []error {
	var errs []error

	if cvss.MaxScore != nil {
		if *cvss.MaxScore < 0 || *cvss.MaxScore > cvssMaxScoreUpper {
			errs = append(errs, ErrCVSSMaxScoreRange)
		}
	}

	if cvss.MinSeverity != "" {
		switch strings.ToLower(cvss.MinSeverity) {
		case "low", "medium", "high", "critical":
		default:
			errs = append(errs, ErrCVSSMinSeverityInvalid)
		}
	}

	err := validateNonEmpty("sbom.cvss.ignoreCVEs", cvss.IgnoreCVEs)
	if err != nil {
		errs = append(errs, err)
	}

	return errs
}

func (p *Policy) validateRules() error {
	if len(p.Rules) == 0 {
		return nil
	}

	var errs []error

	for idx := range p.Rules {
		errs = append(errs, p.validateRule(idx)...)
	}

	return errors.Join(errs...)
}

func (p *Policy) validateRule(idx int) []error {
	rule := &p.Rules[idx]

	if len(rule.Images) == 0 {
		return []error{fmt.Errorf(
			"%w: rules[%d]", ErrRuleImagesRequired, idx,
		)}
	}

	var errs []error

	err := validateNonEmpty(fmt.Sprintf("rules[%d].images", idx), rule.Images)
	if err != nil {
		errs = append(errs, err)
	}

	err = validateGlobPatterns(fmt.Sprintf("rules[%d].images", idx), rule.Images)
	if err != nil {
		errs = append(errs, err)
	}

	rulePol := &Policy{
		Sections: rule.Sections,
	}

	errs = append(errs, validateRuleSections(rulePol, idx)...)

	celErr := rulePol.validateAndCompileCEL()
	if celErr != nil {
		errs = append(errs, fmt.Errorf("rules[%d]: %w", idx, celErr))
	} else {
		p.Rules[idx].CompiledCEL = rulePol.CompiledCEL
	}

	return errs
}

//nolint:funlen // one block per section type
func validateRuleSections(
	rulePol *Policy,
	idx int,
) []error {
	var errs []error

	for _, validator := range []struct {
		name string
		fn   func() error
	}{
		{"trust", rulePol.validateTrust},
		{"vex", rulePol.validateVEX},
		{"notation", rulePol.validateNotation},
		{"sbom", rulePol.validateSBOM},
		{"scai", rulePol.validateSCAI},
		{"buildEnv", rulePol.validateBuildEnv},
	} {
		err := validator.fn()
		if err != nil {
			errs = append(errs, fmt.Errorf("rules[%d]: %w", idx, err))
		}
	}

	slsaErr := rulePol.validateSLSA()
	if slsaErr != nil {
		errs = append(errs, fmt.Errorf("rules[%d]: %w", idx, slsaErr))
	} else {
		// resolveSLSADuration mutates rulePol.SLSA.MaxAgeDuration, which
		// is the same pointer as the rule's SLSA, so no copy-back needed.
		rulePol.resolveSLSADuration()
	}

	err := rulePol.validateVSA()
	if err != nil {
		errs = append(errs, fmt.Errorf("rules[%d]: %w", idx, err))
	} else {
		rulePol.resolveVSADuration()
	}

	sourceErr := rulePol.validateSource()
	if sourceErr != nil {
		errs = append(errs, fmt.Errorf("rules[%d]: %w", idx, sourceErr))
	} else {
		rulePol.resolveSourceDuration()
	}

	vulnErr := rulePol.validateVulnScan()
	if vulnErr != nil {
		errs = append(errs, fmt.Errorf("rules[%d]: %w", idx, vulnErr))
	} else {
		rulePol.resolveVulnScanDuration()
	}

	testErr := rulePol.validateTestResult()
	if testErr != nil {
		errs = append(errs, fmt.Errorf("rules[%d]: %w", idx, testErr))
	} else {
		rulePol.resolveTestResultDuration()
	}

	runtimeTraceErr := rulePol.validateRuntimeTrace()
	if runtimeTraceErr != nil {
		errs = append(errs, fmt.Errorf("rules[%d]: %w", idx, runtimeTraceErr))
	} else {
		rulePol.resolveRuntimeTraceDuration()
	}

	return errs
}

// resolveSLSADuration parses MaxAge into MaxAgeDuration. Safe to call only
// after validateSLSA, which guarantees the duration string is valid.
func (p *Policy) resolveSLSADuration() {
	if p.SLSA == nil || p.SLSA.MaxAge == "" {
		return
	}

	maxAge, err := time.ParseDuration(p.SLSA.MaxAge)
	if err != nil {
		return
	}

	p.SLSA.MaxAgeDuration = maxAge
}

// resolveVSADuration parses MaxAge into MaxAgeDuration. Safe to call only
// after validateVSA, which guarantees the duration string is valid.
func (p *Policy) resolveVSADuration() {
	if p.VSA == nil || p.VSA.MaxAge == "" {
		return
	}

	maxAge, err := time.ParseDuration(p.VSA.MaxAge)
	if err != nil {
		return
	}

	p.VSA.MaxAgeDuration = maxAge
}

func (p *Policy) validateSCAI() error {
	if p.SCAI == nil {
		return nil
	}

	var errs []error

	if p.SCAI.MissingPolicy != "" {
		err := types.ValidateAction(
			"scai.missingPolicy", p.SCAI.MissingPolicy,
		)
		if err != nil {
			errs = append(errs, fmt.Errorf("validating scai policy: %w", err))
		}
	}

	err := validateNonEmpty("scai.requiredAttributes", p.SCAI.RequiredAttributes)
	if err != nil {
		errs = append(errs, err)
	}

	err = validateNonEmpty("scai.forbiddenAttributes", p.SCAI.ForbiddenAttributes)
	if err != nil {
		errs = append(errs, err)
	}

	errs = append(errs, validateSCAINoOverlap(p.SCAI)...)

	return errors.Join(errs...)
}

func validateSCAINoOverlap(scai *SCAIPolicy) []error {
	if len(scai.RequiredAttributes) == 0 || len(scai.ForbiddenAttributes) == 0 {
		return nil
	}

	forbidden := make(map[string]bool, len(scai.ForbiddenAttributes))
	for _, attr := range scai.ForbiddenAttributes {
		forbidden[strings.ToLower(attr)] = true
	}

	var errs []error

	for _, attr := range scai.RequiredAttributes {
		if forbidden[strings.ToLower(attr)] {
			errs = append(errs, fmt.Errorf(
				"%w: %q", ErrSCAIOverlappingAttributes, attr,
			))
		}
	}

	return errs
}

//nolint:dupl // validation functions share structure but differ in field names
func (p *Policy) validateSource() error {
	if p.Source == nil {
		return nil
	}

	var errs []error

	if p.Source.MissingPolicy != "" {
		err := types.ValidateAction(
			"source.missingPolicy", p.Source.MissingPolicy,
		)
		if err != nil {
			errs = append(errs, fmt.Errorf("validating source policy: %w", err))
		}
	}

	if p.Source.MinimumLevel < 0 || p.Source.MinimumLevel > maxSLSALevel {
		errs = append(errs, fmt.Errorf(
			"%w: got %d", ErrInvalidSourceLevel, p.Source.MinimumLevel,
		))
	}

	if p.Source.MaxAge != "" {
		maxAge, parseErr := time.ParseDuration(p.Source.MaxAge)
		if parseErr != nil {
			errs = append(errs, fmt.Errorf(
				"invalid source.maxAge %q: %w", p.Source.MaxAge, parseErr,
			))
		} else if maxAge <= 0 {
			errs = append(
				errs,
				fmt.Errorf("%w, got %q", ErrSourceMaxAgeNotPositive, p.Source.MaxAge),
			)
		}
	}

	return errors.Join(errs...)
}

func (p *Policy) resolveSourceDuration() {
	if p.Source == nil || p.Source.MaxAge == "" {
		return
	}

	maxAge, err := time.ParseDuration(p.Source.MaxAge)
	if err != nil {
		return
	}

	p.Source.MaxAgeDuration = maxAge
}

func (p *Policy) validateBuildEnv() error {
	if p.BuildEnv == nil {
		return nil
	}

	var errs []error

	if p.BuildEnv.MissingPolicy != "" {
		err := types.ValidateAction(
			"buildEnv.missingPolicy", p.BuildEnv.MissingPolicy,
		)
		if err != nil {
			errs = append(errs, fmt.Errorf("validating buildEnv policy: %w", err))
		}
	}

	err := validateNonEmpty("buildEnv.requiredProperties", p.BuildEnv.RequiredProperties)
	if err != nil {
		errs = append(errs, err)
	}

	err = validateNonEmpty("buildEnv.forbiddenProperties", p.BuildEnv.ForbiddenProperties)
	if err != nil {
		errs = append(errs, err)
	}

	errs = append(errs, validateBuildEnvNoOverlap(p.BuildEnv)...)

	return errors.Join(errs...)
}

func validateBuildEnvNoOverlap(buildEnv *BuildEnvPolicy) []error {
	if len(buildEnv.RequiredProperties) == 0 || len(buildEnv.ForbiddenProperties) == 0 {
		return nil
	}

	forbidden := make(map[string]bool, len(buildEnv.ForbiddenProperties))
	for _, prop := range buildEnv.ForbiddenProperties {
		forbidden[strings.ToLower(prop)] = true
	}

	var errs []error

	for _, prop := range buildEnv.RequiredProperties {
		if forbidden[strings.ToLower(prop)] {
			errs = append(errs, fmt.Errorf(
				"%w: %q", ErrBuildEnvOverlappingProperties, prop,
			))
		}
	}

	return errs
}

func (p *Policy) validateVulnScan() error { //nolint:cyclop // sequential validation steps
	if p.VulnScan == nil {
		return nil
	}

	var errs []error

	if p.VulnScan.MissingPolicy != "" {
		err := types.ValidateAction(
			"vulnScan.missingPolicy", p.VulnScan.MissingPolicy,
		)
		if err != nil {
			errs = append(errs, fmt.Errorf("validating vulnScan policy: %w", err))
		}
	}

	if p.VulnScan.MaxScore != nil {
		if *p.VulnScan.MaxScore < 0 || *p.VulnScan.MaxScore > cvssMaxScoreUpper {
			errs = append(errs, ErrVulnScanMaxScoreRange)
		}
	}

	if p.VulnScan.MinSeverity != "" {
		switch strings.ToLower(p.VulnScan.MinSeverity) {
		case "low", "medium", "high", "critical":
		default:
			errs = append(errs, ErrVulnScanMinSeverityInvalid)
		}
	}

	err := validateNonEmpty("vulnScan.ignoreCVEs", p.VulnScan.IgnoreCVEs)
	if err != nil {
		errs = append(errs, err)
	}

	if p.VulnScan.MaxAge != "" {
		maxAge, parseErr := time.ParseDuration(p.VulnScan.MaxAge)
		if parseErr != nil {
			errs = append(
				errs,
				fmt.Errorf("invalid vulnScan.maxAge %q: %w", p.VulnScan.MaxAge, parseErr),
			)
		} else if maxAge <= 0 {
			errs = append(
				errs,
				fmt.Errorf("%w, got %q", ErrVulnScanMaxAgeNotPositive, p.VulnScan.MaxAge),
			)
		}
	}

	return errors.Join(errs...)
}

func (p *Policy) resolveVulnScanDuration() {
	if p.VulnScan == nil || p.VulnScan.MaxAge == "" {
		return
	}

	maxAge, err := time.ParseDuration(p.VulnScan.MaxAge)
	if err != nil {
		return
	}

	p.VulnScan.MaxAgeDuration = maxAge
}

//nolint:dupl // validation functions share structure but differ in field names
func (p *Policy) validateTestResult() error {
	if p.TestResult == nil {
		return nil
	}

	var errs []error

	if p.TestResult.MissingPolicy != "" {
		err := types.ValidateAction(
			"testResult.missingPolicy", p.TestResult.MissingPolicy,
		)
		if err != nil {
			errs = append(errs, fmt.Errorf("validating testResult policy: %w", err))
		}
	}

	err := validateNonEmpty("testResult.requiredSuites", p.TestResult.RequiredSuites)
	if err != nil {
		errs = append(errs, err)
	}

	if p.TestResult.MaxAge != "" {
		maxAge, parseErr := time.ParseDuration(p.TestResult.MaxAge)
		if parseErr != nil {
			errs = append(
				errs,
				fmt.Errorf("invalid testResult.maxAge %q: %w", p.TestResult.MaxAge, parseErr),
			)
		} else if maxAge <= 0 {
			errs = append(
				errs,
				fmt.Errorf("%w, got %q", ErrTestResultMaxAgeNotPositive, p.TestResult.MaxAge),
			)
		}
	}

	return errors.Join(errs...)
}

func (p *Policy) resolveTestResultDuration() {
	if p.TestResult == nil || p.TestResult.MaxAge == "" {
		return
	}

	maxAge, err := time.ParseDuration(p.TestResult.MaxAge)
	if err != nil {
		return
	}

	p.TestResult.MaxAgeDuration = maxAge
}

func (p *Policy) validateRuntimeTrace() error { //nolint:cyclop // validation requires checking each field
	if p.RuntimeTrace == nil {
		return nil
	}

	var errs []error

	if p.RuntimeTrace.MissingPolicy != "" {
		err := types.ValidateAction(
			"runtimeTrace.missingPolicy", p.RuntimeTrace.MissingPolicy,
		)
		if err != nil {
			errs = append(errs, fmt.Errorf("validating runtimeTrace policy: %w", err))
		}
	}

	err := validateNonEmpty("runtimeTrace.trustedMonitors", p.RuntimeTrace.TrustedMonitors)
	if err != nil {
		errs = append(errs, err)
	}

	err = validateGlobPatterns("runtimeTrace.trustedMonitors", p.RuntimeTrace.TrustedMonitors)
	if err != nil {
		errs = append(errs, err)
	}

	err = validateNonEmpty(
		"runtimeTrace.forbiddenFilePatterns", p.RuntimeTrace.ForbiddenFilePatterns,
	)
	if err != nil {
		errs = append(errs, err)
	}

	err = validateGlobPatterns(
		"runtimeTrace.forbiddenFilePatterns", p.RuntimeTrace.ForbiddenFilePatterns,
	)
	if err != nil {
		errs = append(errs, err)
	}

	if p.RuntimeTrace.MaxAge != "" {
		maxAge, parseErr := time.ParseDuration(p.RuntimeTrace.MaxAge)
		if parseErr != nil {
			errs = append(
				errs,
				fmt.Errorf("invalid runtimeTrace.maxAge %q: %w", p.RuntimeTrace.MaxAge, parseErr),
			)
		} else if maxAge <= 0 {
			errs = append(
				errs,
				fmt.Errorf("%w, got %q", ErrRuntimeTraceMaxAgeNotPositive, p.RuntimeTrace.MaxAge),
			)
		}
	}

	return errors.Join(errs...)
}

func (p *Policy) resolveRuntimeTraceDuration() {
	if p.RuntimeTrace == nil || p.RuntimeTrace.MaxAge == "" {
		return
	}

	maxAge, err := time.ParseDuration(p.RuntimeTrace.MaxAge)
	if err != nil {
		return
	}

	p.RuntimeTrace.MaxAgeDuration = maxAge
}

func (p *Policy) validateAndCompileCEL() error {
	if p.CEL == nil || len(p.CEL.Rules) == 0 {
		return nil
	}

	compiled, err := celengine.Compile(p.CEL.Rules)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCELCompileFailed, err)
	}

	p.CompiledCEL = compiled

	return nil
}

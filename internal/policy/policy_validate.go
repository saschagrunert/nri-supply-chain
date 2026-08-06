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

const notationLevelSkip = "skip"

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
	for idx, rule := range p.Rules {
		if rule.Notation != nil && rule.Notation.VerificationLevel == notationLevelSkip {
			return fmt.Errorf("rules[%d]: %w", idx, ErrNotationSkipInEnforceMode)
		}

		if rule.Trust == nil {
			continue
		}

		if len(rule.Trust.Issuers) > 0 && len(rule.Trust.SANPatterns) == 0 {
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

	for rIdx, rule := range p.Rules {
		if rule.Trust != nil {
			for idx, verif := range rule.Trust.Verifiers {
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
			fmt.Sprintf("rules[%d].", rIdx), rule.Notation,
		)...)
	}

	return errors.Join(errs...)
}

func (p *Policy) validateSections() []error {
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

	for idx, verif := range p.Trust.Verifiers {
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

		errs = append(errs, validateVerifierKeys(p, idx, &verif)...)
	}

	return errors.Join(errs...)
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

	if p.Notation.VerificationLevel != "" {
		switch p.Notation.VerificationLevel {
		case "strict", "permissive", "audit", notationLevelSkip:
		default:
			errs = append(errs, fmt.Errorf(
				"%w: got %q",
				ErrNotationVerificationLevelInvalid,
				p.Notation.VerificationLevel,
			))
		}
	}

	errs = append(errs, validateNotationTrustStores(p.Notation.TrustStores)...)
	errs = append(errs, validateNotationTrustPolicy(p.Notation.TrustPolicy)...)

	return errors.Join(errs...)
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

func validateRuleSections(rulePol *Policy, idx int) []error {
	var errs []error

	for _, validator := range []struct {
		name string
		fn   func() error
	}{
		{"trust", rulePol.validateTrust},
		{"vex", rulePol.validateVEX},
		{"notation", rulePol.validateNotation},
		{"sbom", rulePol.validateSBOM},
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
		// resolveVSADuration mutates rulePol.VSA.MaxAgeDuration, which
		// is the same pointer as the rule's VSA, so no copy-back needed.
		rulePol.resolveVSADuration()
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

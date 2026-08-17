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
	"net/url"
	"strings"
	"time"

	celengine "github.com/saschagrunert/nri-supply-chain/internal/cel"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

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

func (p *Policy) validateRelease() error {
	if p.Release == nil {
		return nil
	}

	var errs []error

	if p.Release.MissingPolicy != "" {
		err := types.ValidateAction(
			"release.missingPolicy", p.Release.MissingPolicy,
		)
		if err != nil {
			errs = append(errs, fmt.Errorf("validating release policy: %w", err))
		}
	}

	err := validateNonEmpty("release.trustedRegistries", p.Release.TrustedRegistries)
	if err != nil {
		errs = append(errs, err)
	}

	err = validateGlobPatterns("release.trustedRegistries", p.Release.TrustedRegistries)
	if err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
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
		{"scai", rulePol.validateSCAI},
		{"buildEnv", rulePol.validateBuildEnv},
		{"release", rulePol.validateRelease},
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

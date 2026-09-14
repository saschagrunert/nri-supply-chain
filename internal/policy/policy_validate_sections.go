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

	celengine "github.com/saschagrunert/nri-supply-chain/internal/cel"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

// The section validators below only cover section specific fields. The
// missingPolicy action and maxAge durations are validated generically for
// every section by validateSections using the section registry.

func (s *Sections) validateSLSA() error {
	return validateNonEmpty("slsa.knownParameters", s.SLSA.KnownParameters)
}

func (s *Sections) validateVEX() error {
	if s.VEX.UnderInvestigationPolicy == "" {
		return nil
	}

	err := types.ValidateAction("vex.underInvestigationPolicy", s.VEX.UnderInvestigationPolicy)
	if err != nil {
		return fmt.Errorf("validating vex under investigation policy: %w", err)
	}

	return nil
}

func (s *Sections) validateVSA() error {
	if s.VSA.MinimumLevel < 0 || s.VSA.MinimumLevel > maxSLSALevel {
		return fmt.Errorf("%w: got %d", ErrVSAMinimumLevel, s.VSA.MinimumLevel)
	}

	return nil
}

func (s *Sections) validateSBOM() error {
	var errs []error

	errs = append(errs, validateSBOMFormats(s.SBOM.Formats)...)

	if s.SBOM.License != nil {
		errs = append(errs,
			validateNonEmpty("sbom.license.deny", s.SBOM.License.Deny),
			validateNonEmpty("sbom.license.allow", s.SBOM.License.Allow),
		)
	}

	if s.SBOM.Component != nil {
		errs = append(errs, validateComponentPURLs(
			"sbom.component.deny", s.SBOM.Component.Deny,
		)...)
		errs = append(errs, validateComponentPURLs(
			"sbom.component.allow", s.SBOM.Component.Allow,
		)...)
	}

	if s.SBOM.CVSS != nil {
		errs = append(errs, validateCVSSPolicy(s.SBOM.CVSS)...)
	}

	if s.SBOM.Drift != nil {
		errs = append(errs, validateDriftPolicy(s.SBOM.Drift)...)
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

	if cvss.MinSeverity != "" && !isValidSeverity(cvss.MinSeverity) {
		errs = append(errs, ErrCVSSMinSeverityInvalid)
	}

	err := validateNonEmpty("sbom.cvss.ignoreCVEs", cvss.IgnoreCVEs)
	if err != nil {
		errs = append(errs, err)
	}

	return errs
}

func isValidSeverity(severity string) bool {
	switch strings.ToLower(severity) {
	case "low", "medium", "high", "critical":
		return true
	default:
		return false
	}
}

func validateDriftPolicy(drift *SBOMDriftPolicy) []error {
	var errs []error

	for _, threshold := range []struct {
		name     string
		negative bool
	}{
		{"maxAdded", drift.MaxAdded != nil && *drift.MaxAdded < 0},
		{"maxRemoved", drift.MaxRemoved != nil && *drift.MaxRemoved < 0},
		{"maxModified", drift.MaxModified != nil && *drift.MaxModified < 0},
		{"maxScore", drift.MaxScore != nil && *drift.MaxScore < 0},
	} {
		if threshold.negative {
			errs = append(errs, fmt.Errorf(
				"sbom.drift.%s: %w", threshold.name, ErrDriftThresholdNegative,
			))
		}
	}

	return errs
}

func (s *Sections) validateSCAI() error {
	return errors.Join(
		validateNonEmpty("scai.requiredAttributes", s.SCAI.RequiredAttributes),
		validateNonEmpty("scai.forbiddenAttributes", s.SCAI.ForbiddenAttributes),
		validateNoOverlap(
			s.SCAI.RequiredAttributes, s.SCAI.ForbiddenAttributes, ErrSCAIOverlappingAttributes,
		),
	)
}

func (s *Sections) validateSource() error {
	if s.Source.MinimumLevel < 0 || s.Source.MinimumLevel > maxSLSALevel {
		return fmt.Errorf("%w: got %d", ErrInvalidSourceLevel, s.Source.MinimumLevel)
	}

	return nil
}

func (s *Sections) validateBuildEnv() error {
	return errors.Join(
		validateNonEmpty("buildEnv.requiredProperties", s.BuildEnv.RequiredProperties),
		validateNonEmpty("buildEnv.forbiddenProperties", s.BuildEnv.ForbiddenProperties),
		validateNoOverlap(
			s.BuildEnv.RequiredProperties, s.BuildEnv.ForbiddenProperties,
			ErrBuildEnvOverlappingProperties,
		),
	)
}

// validateNoOverlap reports entries that appear (case-insensitively) in both
// the required and the forbidden list.
func validateNoOverlap(required, forbidden []string, sentinel error) error {
	if len(required) == 0 || len(forbidden) == 0 {
		return nil
	}

	forbiddenSet := make(map[string]bool, len(forbidden))
	for _, entry := range forbidden {
		forbiddenSet[strings.ToLower(entry)] = true
	}

	var errs []error

	for _, entry := range required {
		if forbiddenSet[strings.ToLower(entry)] {
			errs = append(errs, fmt.Errorf("%w: %q", sentinel, entry))
		}
	}

	return errors.Join(errs...)
}

func (s *Sections) validateVulnScan() error {
	var errs []error

	if s.VulnScan.MaxScore != nil {
		if *s.VulnScan.MaxScore < 0 || *s.VulnScan.MaxScore > cvssMaxScoreUpper {
			errs = append(errs, ErrVulnScanMaxScoreRange)
		}
	}

	if s.VulnScan.MinSeverity != "" && !isValidSeverity(s.VulnScan.MinSeverity) {
		errs = append(errs, ErrVulnScanMinSeverityInvalid)
	}

	errs = append(errs, validateNonEmpty("vulnScan.ignoreCVEs", s.VulnScan.IgnoreCVEs))

	return errors.Join(errs...)
}

func (s *Sections) validateTestResult() error {
	return validateNonEmpty("testResult.requiredSuites", s.TestResult.RequiredSuites)
}

func (s *Sections) validateRelease() error {
	return errors.Join(
		validateNonEmpty("release.trustedRegistries", s.Release.TrustedRegistries),
		validateGlobPatterns("release.trustedRegistries", s.Release.TrustedRegistries),
	)
}

func (s *Sections) validateRuntimeTrace() error {
	return errors.Join(
		validateNonEmpty("runtimeTrace.trustedMonitors", s.RuntimeTrace.TrustedMonitors),
		validateGlobPatterns("runtimeTrace.trustedMonitors", s.RuntimeTrace.TrustedMonitors),
		validateNonEmpty(
			"runtimeTrace.forbiddenFilePatterns", s.RuntimeTrace.ForbiddenFilePatterns,
		),
		validateGlobPatterns(
			"runtimeTrace.forbiddenFilePatterns", s.RuntimeTrace.ForbiddenFilePatterns,
		),
	)
}

const scorecardMaxScoreUpper = 10.0

func (s *Sections) validateScorecard() error {
	var errs []error

	if s.Scorecard.MinScore != nil &&
		(*s.Scorecard.MinScore < 0 || *s.Scorecard.MinScore > scorecardMaxScoreUpper) {
		errs = append(errs, ErrScorecardMinScoreRange)
	}

	for name, score := range s.Scorecard.Checks {
		if name == "" {
			errs = append(errs, fmt.Errorf("scorecard.checks: %w", ErrEmptyValue))
		}

		if score < 0 || score > int(scorecardMaxScoreUpper) {
			errs = append(errs, fmt.Errorf(
				"%w: %q has score %d", ErrScorecardCheckScoreRange, name, score,
			))
		}
	}

	return errors.Join(errs...)
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

	warnTagScopedPatterns(fmt.Sprintf("rules[%d].images", idx), rule.Images)

	err = validateGlobPatterns(fmt.Sprintf("rules[%d].images", idx), rule.Images)
	if err != nil {
		errs = append(errs, err)
	}

	for _, sectionErr := range rule.validateSections() {
		errs = append(errs, fmt.Errorf("rules[%d]: %w", idx, sectionErr))
	}

	compiled, celErr := compileCEL(rule.CEL)
	if celErr != nil {
		errs = append(errs, fmt.Errorf("rules[%d]: %w", idx, celErr))
	} else {
		rule.CompiledCEL = compiled
	}

	return errs
}

func (p *Policy) validateAndCompileCEL() error {
	compiled, err := compileCEL(p.CEL)
	if err != nil {
		return err
	}

	p.CompiledCEL = compiled

	return nil
}

// compileCEL compiles the CEL rules of a section. It returns nil programs
// when the section is unset or has no rules.
func compileCEL(celPolicy *celengine.Policy) (*celengine.CompiledPolicy, error) {
	if celPolicy == nil || len(celPolicy.Rules) == 0 {
		return nil, nil //nolint:nilnil // no rules means no compiled programs
	}

	compiled, err := celengine.Compile(celPolicy.Rules)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCELCompileFailed, err)
	}

	return compiled, nil
}

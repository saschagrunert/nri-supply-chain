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

package sbom

import (
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

// severityUnknown is the CycloneDX severity of an unrated vulnerability.
const severityUnknown = "unknown"

// maxComponentDepth bounds recursion into nested CycloneDX components. A
// document nesting components deeper is rejected rather than truncated, so
// deeply nested components cannot escape the license and component lists.
const maxComponentDepth = 32

const (
	// formatCycloneDXName is the bomFormat value of CycloneDX documents.
	formatCycloneDXName = "CycloneDX"

	componentTypeApplication = "application"

	// trivyClassProperty and trivyLangPkgsClass identify Trivy components
	// that stand for a language lock or manifest file.
	trivyClassProperty = "aquasecurity:trivy:Class"
	trivyLangPkgsClass = "lang-pkgs"
)

var (
	errNotCycloneDX = errors.New("no components found, not a valid CycloneDX document")

	errComponentsTooDeep = fmt.Errorf(
		"components nested deeper than %d levels", maxComponentDepth,
	)

	// errNoSBOMContent marks a CycloneDX document without components and
	// without a subject, such as a VEX-only document. It is not an SBOM, so
	// the SBOM check treats it as not applicable.
	errNoSBOMContent = fmt.Errorf(
		"%w: CycloneDX document has neither components nor metadata.component",
		types.ErrNotApplicable,
	)
)

// cyclonedxExemptTypes lists component types that are not packages and are
// therefore not expected to carry a purl.
var cyclonedxExemptTypes = map[string]struct{}{ //nolint:gochecknoglobals // immutable lookup table
	"operating-system":    {},
	"file":                {},
	"data":                {},
	"device":              {},
	"firmware":            {},
	"platform":            {},
	"cryptographic-asset": {},
}

type cyclonedxBOM struct {
	Components      []cyclonedxComponent     `json:"components"`
	Vulnerabilities []cyclonedxVulnerability `json:"vulnerabilities"`
}

type cyclonedxVulnerability struct {
	ID       string             `json:"id"`
	Ratings  []cyclonedxRating  `json:"ratings"`
	Analysis *cyclonedxAnalysis `json:"analysis,omitempty"`
}

// cyclonedxAnalysis is the impact analysis of a vulnerability.
type cyclonedxAnalysis struct {
	State         string `json:"state,omitempty"`
	Justification string `json:"justification,omitempty"`
	Detail        string `json:"detail,omitempty"`
}

// cyclonedxStateNotAffected is the analysis state that only resolves a
// vulnerability together with a justification or a detail.
const cyclonedxStateNotAffected = "not_affected"

// cyclonedxResolvedStates lists the analysis states that resolve a
// vulnerability. not_affected resolves it only with a justification or a
// detail (like an OpenVEX not_affected statement). Every other state (exploitable,
// in_triage, or none) leaves it unresolved.
var cyclonedxResolvedStates = map[string]struct{}{ //nolint:gochecknoglobals // immutable lookup set
	"resolved":                {},
	"resolved_with_pedigree":  {},
	"false_positive":          {},
	cyclonedxStateNotAffected: {},
}

type cyclonedxRating struct {
	Score    *float64 `json:"score"`
	Severity string   `json:"severity"`
	Method   string   `json:"method"`
}

type cyclonedxComponent struct {
	Type       string               `json:"type,omitempty"`
	Name       string               `json:"name"`
	Version    string               `json:"version"`
	PURL       string               `json:"purl"`
	Licenses   []cyclonedxLicense   `json:"licenses"`
	Hashes     []cyclonedxHash      `json:"hashes"`
	Properties []cyclonedxProperty  `json:"properties,omitempty"`
	Components []cyclonedxComponent `json:"components,omitempty"`
}

type cyclonedxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// cyclonedxMetadata holds the document subject of a CycloneDX BOM.
type cyclonedxMetadata struct {
	Component *cyclonedxComponent `json:"component,omitempty"`
}

type cyclonedxHash struct {
	Algorithm string `json:"alg"`
	Content   string `json:"content"`
}

// cyclonedxLicense is a CycloneDX license choice: either a license object or
// an SPDX license expression.
type cyclonedxLicense struct {
	License    *cyclonedxLicenseRef `json:"license,omitempty"`
	Expression string               `json:"expression,omitempty"`
}

type cyclonedxLicenseRef struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

func parseCycloneDX(data []byte) (sbomData, error) {
	raw, err := decodeRawSBOM(data)
	if err != nil {
		return sbomData{}, err
	}

	return cyclonedxFromRaw(raw)
}

// cyclonedxFromRaw extracts SBOM data from a CycloneDX BOM. A BOM declaring
// bomFormat CycloneDX (or carrying a components array) without components is
// an SBOM only when it names its subject (metadata.component), which is
// normal for scratch and static images. Without components and subject, the
// document carries no inventory (for example a VEX-only document) and
// errNoSBOMContent is returned. The licenses of the document subject are
// checked like component licenses.
func cyclonedxFromRaw(raw *rawSBOM) (sbomData, error) {
	if raw.Components == nil && !strings.EqualFold(raw.BOMFormat, formatCycloneDXName) {
		return sbomData{}, errNotCycloneDX
	}

	hasSubject := raw.Metadata != nil && raw.Metadata.Component != nil

	var result sbomData

	if hasSubject {
		addCycloneDXLicenses(raw.Metadata.Component, &result)
	}

	err := walkCycloneDXComponents(raw.Components, 0, &result)
	if err != nil {
		return sbomData{}, err
	}

	if len(result.Packages) == 0 && !hasSubject {
		return vulnerabilityOnlyData(raw.Vulnerabilities)
	}

	result.componentCount = len(result.Packages)
	result.vulns = unresolvedRatedVulnerabilities(raw.Vulnerabilities)

	return result, nil
}

// vulnerabilityOnlyData returns the unresolved, rated vulnerabilities of a
// CycloneDX document without components and subject (a vulnerability
// disclosure report or VEX document). Such a document is not an SBOM, but its
// unresolved findings must still be evaluated against sbom.cvss, otherwise
// moving them into a separate document would hide them. Without unresolved
// rated findings there is nothing to evaluate and errNoSBOMContent is
// returned.
func vulnerabilityOnlyData(vulns []cyclonedxVulnerability) (sbomData, error) {
	unresolved := unresolvedRatedVulnerabilities(vulns)
	if len(unresolved) == 0 {
		return sbomData{}, errNoSBOMContent
	}

	return sbomData{ //nolint:exhaustruct_v5 // a vulnerability-only document has no inventory
		vulns:             unresolved,
		vulnerabilityOnly: true,
	}, nil
}

// unresolvedRatedVulnerabilities returns the vulnerabilities that carry a
// rating and whose analysis state does not resolve them. SBOMs and
// vulnerability-only documents are evaluated against sbom.cvss alike.
func unresolvedRatedVulnerabilities(vulns []cyclonedxVulnerability) []cyclonedxVulnerability {
	var unresolved []cyclonedxVulnerability

	for idx := range vulns {
		if vulnerabilityResolved(&vulns[idx]) || !vulnerabilityRated(&vulns[idx]) {
			continue
		}

		unresolved = append(unresolved, vulns[idx])
	}

	return unresolved
}

// vulnerabilityResolved reports whether the analysis state of a
// vulnerability resolves it. States are compared case-sensitively, like in
// the VEX check, so an invalid state leaves the vulnerability unresolved. A
// not_affected state without a justification or a detail is an unsupported
// claim and leaves the vulnerability unresolved, so it still fails the CVSS
// thresholds.
func vulnerabilityResolved(vuln *cyclonedxVulnerability) bool {
	if vuln.Analysis == nil {
		return false
	}

	state := vuln.Analysis.State
	if _, resolved := cyclonedxResolvedStates[state]; !resolved {
		return false
	}

	return state != cyclonedxStateNotAffected ||
		strings.TrimSpace(vuln.Analysis.Justification) != "" ||
		strings.TrimSpace(vuln.Analysis.Detail) != ""
}

// vulnerabilityRated reports whether a vulnerability carries a rating. A
// rating without score whose severity is empty, "unknown", or "none" (in any
// case, including the aliases "info" and "informational") says nothing about
// the impact; scanners such as Trivy and Grype emit
// it for unscored findings, so it counts as no rating. Any other severity,
// including an unrecognized one, makes the vulnerability rated, and an
// unrecognized severity then fails the thresholds closed.
func vulnerabilityRated(vuln *cyclonedxVulnerability) bool {
	for idx := range vuln.Ratings {
		if vuln.Ratings[idx].Score != nil || !unratedSeverity(vuln.Ratings[idx].Severity) {
			return true
		}
	}

	return false
}

func unratedSeverity(severity string) bool {
	normalized := strings.ToLower(strings.TrimSpace(severity))
	if normalized == "" || normalized == severityUnknown {
		return true
	}

	rank, known := types.SeverityRankOf(normalized)

	return known && rank == types.SeverityRankNone
}

// walkCycloneDXComponents flattens nested components into result. It fails
// when components are nested deeper than maxComponentDepth.
func walkCycloneDXComponents(
	components []cyclonedxComponent, depth int, result *sbomData,
) error {
	if len(components) > 0 && depth > maxComponentDepth {
		return errComponentsTooDeep
	}

	for idx := range components {
		comp := &components[idx]
		sp := buildCycloneDXPackage(comp, result)

		result.addPackage(&sp, cyclonedxPURLExempt(comp))

		err := walkCycloneDXComponents(comp.Components, depth+1, result)
		if err != nil {
			return err
		}
	}

	return nil
}

// cyclonedxPURLExempt reports whether a component is not expected to carry a
// purl: non-package component types, and application components that
// describe a lock or manifest file rather than a versioned package (Trivy
// emits one per lock file, classified as lang-pkgs, without purl or version).
func cyclonedxPURLExempt(comp *cyclonedxComponent) bool {
	if _, exempt := cyclonedxExemptTypes[strings.ToLower(comp.Type)]; exempt {
		return true
	}

	if !strings.EqualFold(comp.Type, componentTypeApplication) || comp.PURL != "" {
		return false
	}

	if comp.Version == "" {
		return true
	}

	for idx := range comp.Properties {
		if comp.Properties[idx].Name == trivyClassProperty &&
			comp.Properties[idx].Value == trivyLangPkgsClass {
			return true
		}
	}

	return false
}

func addCycloneDXLicenses(comp *cyclonedxComponent, result *sbomData) {
	for lidx := range comp.Licenses {
		value, expression := cyclonedxLicenseValue(&comp.Licenses[lidx])
		if value != "" {
			result.addLicense(value, expression)
		}
	}
}

func buildCycloneDXPackage(comp *cyclonedxComponent, result *sbomData) sbomPackage {
	pkg := sbomPackage{
		Name:      comp.Name,
		Version:   comp.Version,
		PURL:      comp.PURL,
		Licenses:  nil,
		Checksums: nil,
	}

	for lidx := range comp.Licenses {
		value, expression := cyclonedxLicenseValue(&comp.Licenses[lidx])
		if value == "" {
			continue
		}

		result.addLicense(value, expression)
		pkg.Licenses = append(pkg.Licenses, value)
	}

	if comp.PURL != "" {
		result.purls = append(result.purls, comp.PURL)
	}

	if len(comp.Hashes) > 0 {
		pkg.Checksums = make(map[string]string, len(comp.Hashes))
		for hidx := range comp.Hashes {
			hash := &comp.Hashes[hidx]
			if hash.Algorithm != "" && hash.Content != "" {
				pkg.Checksums[hash.Algorithm] = hash.Content
			}
		}
	}

	return pkg
}

// cyclonedxLicenseValue returns the license value of a license choice and
// whether it is an SPDX expression or identifier (as opposed to a free-text
// name).
func cyclonedxLicenseValue(lic *cyclonedxLicense) (value string, expression bool) {
	switch {
	case lic.Expression != "":
		return lic.Expression, true
	case lic.License == nil:
		return "", false
	case lic.License.ID != "":
		return lic.License.ID, true
	default:
		return lic.License.Name, false
	}
}

// vulnAggregate is the combined rating of a vulnerability. The rank is the
// most severe of the textual severities and the severities derived from the
// scores; score is nil when no rating carries a valid CVSS base score.
type vulnAggregate struct {
	score *float64
	rank  int
}

// effectiveScore returns the score, or for vulnerabilities without a numeric
// score the lowest score of their severity.
func (a *vulnAggregate) effectiveScore() float64 {
	if a.score != nil {
		return *a.score
	}

	return types.SeverityMinimumCVSS(a.rank)
}

func checkCVSSThresholds(
	vulns []cyclonedxVulnerability, cvssPolicy *policy.SBOMCVSSPolicy,
) *types.CheckResult {
	cached, meta := computeVulnAggregates(vulns)

	violation := findThresholdViolation(vulns, cached, cvssPolicy)
	if violation != "" {
		result := check.Fail(violation)
		result.Metadata = meta

		return result
	}

	result := check.Pass()
	result.Metadata = meta

	return result
}

// computeVulnAggregates computes statistics across ALL vulnerabilities,
// including ignored CVEs, so they remain visible in CEL rules.
func computeVulnAggregates(
	vulns []cyclonedxVulnerability,
) (cached []vulnAggregate, meta map[string]any) {
	var (
		globalMaxScore float64
		criticalCount  int64
		highCount      int64
		mediumCount    int64
	)

	cached = make([]vulnAggregate, len(vulns))

	for idx := range vulns {
		cached[idx] = aggregateRatings(vulns[idx].Ratings)

		globalMaxScore = max(globalMaxScore, cached[idx].effectiveScore())

		switch cached[idx].rank {
		case types.SeverityRankCritical:
			criticalCount++
		case types.SeverityRankHigh:
			highCount++
		case types.SeverityRankMedium:
			mediumCount++
		default:
		}
	}

	meta = map[string]any{
		"cvssMax":           globalMaxScore,
		"cvssCriticalCount": criticalCount,
		"cvssHighCount":     highCount,
		"cvssMediumCount":   mediumCount,
	}

	return cached, meta
}

// findThresholdViolation applies maxScore and minSeverity. A score without
// severity is ranked by its CVSS range and a severity without score is
// compared against maxScore with the lowest score of its range. When a
// threshold is configured, a vulnerability whose severity cannot be
// determined fails closed; it can be accepted explicitly through ignoreCVEs.
func findThresholdViolation(
	vulns []cyclonedxVulnerability,
	cached []vulnAggregate,
	cvssPolicy *policy.SBOMCVSSPolicy,
) string {
	if cvssPolicy.MaxScore == nil && cvssPolicy.MinSeverity == "" {
		return ""
	}

	ignoredCVEs := make(map[string]bool, len(cvssPolicy.IgnoreCVEs))
	for _, cve := range cvssPolicy.IgnoreCVEs {
		ignoredCVEs[cve] = true
	}

	for idx := range vulns {
		if ignoredCVEs[vulns[idx].ID] {
			continue
		}

		violation := cached[idx].thresholdViolation(vulns[idx].ID, cvssPolicy)
		if violation != "" {
			return violation
		}
	}

	return ""
}

// thresholdViolation evaluates one vulnerability against maxScore and
// minSeverity. An unknown rank fails closed.
func (a *vulnAggregate) thresholdViolation(
	vulnID string,
	cvssPolicy *policy.SBOMCVSSPolicy,
) string {
	if a.rank == types.SeverityRankUnknown {
		return fmt.Sprintf(
			"CVSS threshold cannot be evaluated: %s has no recognizable severity or score", vulnID,
		)
	}

	exceeded := cvssPolicy.MaxScore != nil && a.effectiveScore() > *cvssPolicy.MaxScore

	if cvssPolicy.MinSeverity != "" {
		// Policy validation rejects unknown severities; one that slips
		// through flags every vulnerability.
		minRank, known := types.SeverityRankOf(cvssPolicy.MinSeverity)
		if !known || a.rank >= minRank {
			exceeded = true
		}
	}

	if !exceeded {
		return ""
	}

	return fmt.Sprintf(
		"CVSS threshold exceeded: %s (score %.1f, severity %s)",
		vulnID, a.effectiveScore(), types.SeverityName(a.rank),
	)
}

// aggregateRatings combines the ratings of a vulnerability, keeping the
// highest valid score and the most severe rank. Scores outside the CVSS range
// and unrecognized severities (including "unknown") are ignored, so a
// vulnerability rated only by them has an unknown rank.
func aggregateRatings(ratings []cyclonedxRating) vulnAggregate {
	agg := vulnAggregate{score: nil, rank: types.SeverityRankUnknown}

	for idx := range ratings {
		rating := &ratings[idx]

		if rating.Score != nil {
			if rank, valid := types.SeverityRankFromCVSS(*rating.Score); valid {
				if agg.score == nil || *rating.Score > *agg.score {
					agg.score = rating.Score
				}

				agg.rank = max(agg.rank, rank)
			}
		}

		if rating.Severity == "" {
			continue
		}

		rank, known := types.SeverityRankOf(rating.Severity)
		if !known {
			if !strings.EqualFold(rating.Severity, severityUnknown) {
				slog.Warn("Unrecognized CVSS severity", "severity", rating.Severity)
			}

			continue
		}

		agg.rank = max(agg.rank, rank)
	}

	return agg
}

func mergeCVSSMeta(dst, src map[string]any) { //nolint:cyclop // type assertions on known keys
	for key, val := range src {
		existing, hasPrev := dst[key]
		if !hasPrev {
			dst[key] = val

			continue
		}

		switch key {
		case "cvssMax":
			if srcScore, ok := val.(float64); ok {
				if dstScore, ok := existing.(float64); ok && srcScore > dstScore {
					dst[key] = srcScore
				}
			}
		case metaKeyFormat:
			dst[key] = mergeFormats(existing, val)
		case "cvssCriticalCount", "cvssHighCount", "cvssMediumCount",
			metaKeyComponentCount, metaKeyComponentsWithoutPURL:
			if srcCount, ok := val.(int64); ok {
				if dstCount, ok := existing.(int64); ok {
					dst[key] = dstCount + srcCount
				}
			}
		case "purls":
			srcSlice := toStringSlice(val)
			dstSlice := toStringSlice(existing)

			if len(srcSlice) > 0 || len(dstSlice) > 0 {
				combined := make([]string, 0, len(dstSlice)+len(srcSlice))
				combined = append(combined, dstSlice...)
				combined = append(combined, srcSlice...)
				slices.Sort(combined)
				dst[key] = slices.Compact(combined)
			}
		default:
		}
	}
}

// mergeFormats combines the format metadata of two documents into a sorted,
// comma separated set such as "CycloneDX,SPDX".
func mergeFormats(existing, val any) string {
	existingFormat, _ := existing.(string)
	valFormat, _ := val.(string)

	formats := slices.Concat(strings.Split(existingFormat, ","), strings.Split(valFormat, ","))
	formats = slices.DeleteFunc(formats, func(format string) bool { return format == "" })
	slices.Sort(formats)

	return strings.Join(slices.Compact(formats), ",")
}

func toStringSlice(v any) []string {
	if s, ok := v.([]string); ok {
		return s
	}

	items, ok := v.([]any)
	if !ok {
		return nil
	}

	result := make([]string, 0, len(items))

	for _, item := range items {
		if s, ok := item.(string); ok {
			result = append(result, s)
		}
	}

	return result
}

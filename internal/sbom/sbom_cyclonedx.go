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

const (
	severityRankMedium   = 2
	severityRankHigh     = 3
	severityRankCritical = 4
)

// severityRank maps CVSS severity strings to numeric ranks for comparison.
var severityRank = map[string]int{ //nolint:gochecknoglobals // immutable lookup table
	"none":     0,
	"low":      1,
	"medium":   severityRankMedium,
	"high":     severityRankHigh,
	"critical": severityRankCritical,
}

// maxComponentDepth bounds recursion into nested CycloneDX components.
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
	State string `json:"state,omitempty"`
}

// cyclonedxResolvedStates lists the analysis states that resolve a
// vulnerability. Every other state (exploitable, in_triage, or none) leaves
// it unresolved.
var cyclonedxResolvedStates = map[string]struct{}{ //nolint:gochecknoglobals // immutable lookup set
	"resolved":               {},
	"resolved_with_pedigree": {},
	"false_positive":         {},
	"not_affected":           {},
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

	walkCycloneDXComponents(raw.Components, 0, &result)

	if len(result.Packages) == 0 && !hasSubject {
		return vulnerabilityOnlyData(raw.Vulnerabilities)
	}

	result.componentCount = len(result.Packages)
	result.vulns = raw.Vulnerabilities

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
	var unresolved []cyclonedxVulnerability

	for idx := range vulns {
		if vulnerabilityResolved(&vulns[idx]) || !vulnerabilityRated(&vulns[idx]) {
			continue
		}

		unresolved = append(unresolved, vulns[idx])
	}

	if len(unresolved) == 0 {
		return sbomData{}, errNoSBOMContent
	}

	return sbomData{ //nolint:exhaustruct_v5 // a vulnerability-only document has no inventory
		vulns:             unresolved,
		vulnerabilityOnly: true,
	}, nil
}

func vulnerabilityResolved(vuln *cyclonedxVulnerability) bool {
	if vuln.Analysis == nil {
		return false
	}

	_, resolved := cyclonedxResolvedStates[strings.ToLower(vuln.Analysis.State)]

	return resolved
}

func vulnerabilityRated(vuln *cyclonedxVulnerability) bool {
	for idx := range vuln.Ratings {
		if vuln.Ratings[idx].Score != nil || vuln.Ratings[idx].Severity != "" {
			return true
		}
	}

	return false
}

// walkCycloneDXComponents flattens nested components into result.
func walkCycloneDXComponents(components []cyclonedxComponent, depth int, result *sbomData) {
	if depth > maxComponentDepth {
		return
	}

	for idx := range components {
		comp := &components[idx]
		sp := buildCycloneDXPackage(comp, result)

		result.addPackage(&sp, cyclonedxPURLExempt(comp))

		walkCycloneDXComponents(comp.Components, depth+1, result)
	}
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

type vulnAggregate struct {
	maxScore    float64
	maxSeverity string
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
		score, sev := aggregateRatings(vulns[idx].Ratings)
		cached[idx] = vulnAggregate{maxScore: score, maxSeverity: sev}

		if score > globalMaxScore {
			globalMaxScore = score
		}

		switch sevRank := severityRank[strings.ToLower(sev)]; {
		case sevRank >= severityRankCritical:
			criticalCount++
		case sevRank >= severityRankHigh:
			highCount++
		case sevRank >= severityRankMedium:
			mediumCount++
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

func findThresholdViolation(
	vulns []cyclonedxVulnerability,
	cached []vulnAggregate,
	cvssPolicy *policy.SBOMCVSSPolicy,
) string {
	ignoredCVEs := make(map[string]bool, len(cvssPolicy.IgnoreCVEs))
	for _, cve := range cvssPolicy.IgnoreCVEs {
		ignoredCVEs[cve] = true
	}

	minSeverityRank := 0
	if cvssPolicy.MinSeverity != "" {
		minSeverityRank = severityRank[strings.ToLower(cvssPolicy.MinSeverity)]
	}

	for idx := range vulns {
		if ignoredCVEs[vulns[idx].ID] {
			continue
		}

		agg := &cached[idx]
		exceeded := false

		if cvssPolicy.MaxScore != nil && agg.maxScore > *cvssPolicy.MaxScore {
			exceeded = true
		}

		vulnSevRank := severityRank[strings.ToLower(agg.maxSeverity)]
		if cvssPolicy.MinSeverity != "" && vulnSevRank >= minSeverityRank {
			exceeded = true
		}

		if exceeded {
			return fmt.Sprintf(
				"CVSS threshold exceeded: %s (score %.1f, severity %s)",
				vulns[idx].ID, agg.maxScore, strings.ToLower(agg.maxSeverity),
			)
		}
	}

	return ""
}

func aggregateRatings(ratings []cyclonedxRating) (maxScore float64, maxSeverity string) {
	maxSevRank := -1

	for idx := range ratings {
		rating := &ratings[idx]

		if rating.Score != nil && *rating.Score > maxScore {
			maxScore = *rating.Score
		}

		sev := strings.ToLower(rating.Severity)

		rank, known := severityRank[sev]
		if !known && rating.Severity != "" {
			slog.Warn("Unrecognized CVSS severity, treating as none",
				"severity", rating.Severity)
		}

		if rank > maxSevRank {
			maxSevRank = rank
			maxSeverity = rating.Severity
		}
	}

	if maxSeverity == "" {
		maxSeverity = "none"
	}

	return maxScore, maxSeverity
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

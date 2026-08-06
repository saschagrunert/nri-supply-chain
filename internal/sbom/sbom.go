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

// Package sbom provides SBOM attestation verification for supply chain checks.
package sbom

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"strings"

	"github.com/saschagrunert/nri-supply-chain/internal/intoto"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const checkType = types.CheckTypeSBOM

const (
	severityRankMedium   = 2
	severityRankHigh     = 3
	severityRankCritical = 4
)

var (
	// ErrInvalidSBOM indicates the SBOM document could not be parsed.
	ErrInvalidSBOM = errors.New("invalid SBOM document")

	// ErrUnsupportedFormat indicates the SBOM format is not recognized.
	ErrUnsupportedFormat = errors.New("unsupported SBOM format")

	// ErrDeniedLicense indicates the SBOM contains a denied license.
	ErrDeniedLicense = errors.New("denied license found in SBOM")

	// ErrDeniedComponent indicates the SBOM contains a denied component.
	ErrDeniedComponent = errors.New("denied component found in SBOM")

	// ErrLicenseNotAllowed indicates the SBOM contains a license not in the allow list.
	ErrLicenseNotAllowed = errors.New("license not in allow list")

	// ErrComponentNotAllowed indicates the SBOM contains a component not in the allow list.
	ErrComponentNotAllowed = errors.New("component not in allow list")

	// errNotSPDX indicates the document is not a valid SPDX document.
	errNotSPDX = errors.New("no packages found, not a valid SPDX document")

	// errNotCycloneDX indicates the document is not a valid CycloneDX document.
	errNotCycloneDX = errors.New("no components found, not a valid CycloneDX document")
)

// spdxDocument represents the subset of an SPDX 2.3 JSON document needed for
// license and component deny-list checks.
type spdxDocument struct {
	SPDXVersion string        `json:"spdxVersion"`
	Packages    []spdxPackage `json:"packages"`
}

type spdxPackage struct {
	Name             string            `json:"name"`
	LicenseConcluded string            `json:"licenseConcluded"`
	LicenseDeclared  string            `json:"licenseDeclared"`
	ExternalRefs     []spdxExternalRef `json:"externalRefs"`
	Checksums        []spdxChecksum    `json:"checksums"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type spdxChecksum struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"checksumValue"`
}

// severityRank maps CVSS severity strings to numeric ranks for comparison.
var severityRank = map[string]int{ //nolint:gochecknoglobals // immutable lookup table
	"none":     0,
	"low":      1,
	"medium":   severityRankMedium,
	"high":     severityRankHigh,
	"critical": severityRankCritical,
}

// cyclonedxBOM represents the subset of a CycloneDX 1.x JSON BOM needed
// for license and component deny-list checks.
type cyclonedxBOM struct {
	Components      []cyclonedxComponent     `json:"components"`
	Vulnerabilities []cyclonedxVulnerability `json:"vulnerabilities"`
}

type cyclonedxVulnerability struct {
	ID      string            `json:"id"`
	Ratings []cyclonedxRating `json:"ratings"`
}

type cyclonedxRating struct {
	Score    *float64 `json:"score"`
	Severity string   `json:"severity"`
	Method   string   `json:"method"`
}

type cyclonedxComponent struct {
	Name     string             `json:"name"`
	PURL     string             `json:"purl"`
	Licenses []cyclonedxLicense `json:"licenses"`
}

type cyclonedxLicense struct {
	License *cyclonedxLicenseRef `json:"license,omitempty"`
}

type cyclonedxLicenseRef struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// Verify checks a single SBOM attestation against the given policy.
func Verify( //nolint:revive // ctx reserved for future context-aware logging
	ctx context.Context,
	att []byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	predicate, err := intoto.VerifySubjectAndExtractPredicate(att, imageDigest)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSBOM, err)
	}

	return verifySBOMPredicate(predicate, pol)
}

// VerifyMultiple checks multiple SBOM attestations. Any denied license or
// component in any document causes failure.
func VerifyMultiple( //nolint:cyclop // metadata accumulation adds branches
	ctx context.Context,
	attestations [][]byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	var (
		failDetails  []string
		verifyErrors []string
		anyValid     bool
		passedMeta   map[string]any
	)

	for _, att := range attestations {
		result, err := Verify(ctx, att, pol, imageDigest)
		if err != nil {
			verifyErrors = append(verifyErrors, err.Error())

			continue
		}

		anyValid = true

		if !result.Passed && result.Status == types.StatusFail {
			failDetails = append(failDetails, result.Detail)
		}

		if result.Passed && result.Metadata != nil {
			if passedMeta == nil {
				passedMeta = make(map[string]any)
			}

			mergeCVSSMeta(passedMeta, result.Metadata)
		}
	}

	if len(failDetails) > 0 {
		return failResult(strings.Join(failDetails, "; ")), nil
	}

	if len(attestations) > 0 && !anyValid {
		return failResult(
			"all SBOM documents failed verification: " + strings.Join(verifyErrors, "; "),
		), nil
	}

	result := passResult()
	result.Metadata = passedMeta

	return result, nil
}

func verifySBOMPredicate(
	predicate []byte, pol *policy.Policy,
) (*types.CheckResult, error) {
	licenses, purls, format, componentCount, licenseCount, vulns, err := extractSBOMData(
		predicate, pol,
	)
	if err != nil {
		return nil, err
	}

	result := checkDenyLists(licenses, purls, pol)
	result.Metadata = map[string]any{
		"format":         format,
		"componentCount": int64(componentCount),
		"licenseCount":   int64(licenseCount),
	}

	if !result.Passed {
		return result, nil
	}

	if format == "cyclonedx" && pol.SBOM != nil && pol.SBOM.CVSS != nil {
		cvssResult := checkCVSSThresholds(vulns, pol.SBOM.CVSS)
		if !cvssResult.Passed {
			maps.Copy(cvssResult.Metadata, result.Metadata)

			return cvssResult, nil
		}

		maps.Copy(result.Metadata, cvssResult.Metadata)
	}

	return result, nil
}

//nolint:gocritic // returns are tightly coupled
func extractSBOMData(
	predicate []byte, pol *policy.Policy,
) (
	licenses, purls []string, format string,
	componentCount, licenseCount int,
	vulns []cyclonedxVulnerability, err error,
) {
	licenses, purls, componentCount, licenseCount, spdxErr := parseSPDX(predicate)
	if spdxErr == nil {
		if !formatAllowed(pol, "spdx") {
			return nil, nil, "", 0, 0, nil, fmt.Errorf(
				"%w: spdx not in allowed formats", ErrUnsupportedFormat,
			)
		}

		return licenses, purls, "spdx", componentCount, licenseCount, nil, nil
	}

	licenses, purls, componentCount, licenseCount, vulns, cdxErr := parseCycloneDX(predicate)
	if cdxErr == nil {
		if !formatAllowed(pol, "cyclonedx") {
			return nil, nil, "", 0, 0, nil, fmt.Errorf(
				"%w: cyclonedx not in allowed formats", ErrUnsupportedFormat,
			)
		}

		return licenses, purls, "cyclonedx", componentCount, licenseCount, vulns, nil
	}

	return nil, nil, "", 0, 0, nil, fmt.Errorf(
		"%w: not valid SPDX (%w) or CycloneDX (%w)",
		ErrInvalidSBOM, spdxErr, cdxErr,
	)
}

func formatAllowed(pol *policy.Policy, format string) bool {
	if pol.SBOM == nil || len(pol.SBOM.Formats) == 0 {
		return true
	}

	for _, allowed := range pol.SBOM.Formats {
		if strings.EqualFold(allowed, format) {
			return true
		}
	}

	return false
}

func parseSPDX(
	data []byte,
) (licenses, purls []string, componentCount, licenseCount int, err error) {
	var doc spdxDocument

	err = json.Unmarshal(data, &doc)
	if err != nil {
		return nil, nil, 0, 0, fmt.Errorf("parsing SPDX: %w", err)
	}

	if doc.SPDXVersion == "" || len(doc.Packages) == 0 {
		return nil, nil, 0, 0, errNotSPDX
	}

	for idx := range doc.Packages {
		pkg := &doc.Packages[idx]
		licenses = appendSPDXLicenses(licenses, pkg)
		purls = appendSPDXPURLs(purls, pkg)
	}

	uniqueLicenses := make(map[string]struct{}, len(licenses))
	for _, lic := range licenses {
		uniqueLicenses[lic] = struct{}{}
	}

	return licenses, purls, len(doc.Packages), len(uniqueLicenses), nil
}

func appendSPDXLicenses(licenses []string, pkg *spdxPackage) []string {
	if pkg.LicenseConcluded != "" && pkg.LicenseConcluded != "NOASSERTION" {
		licenses = append(licenses, pkg.LicenseConcluded)
	}

	if pkg.LicenseDeclared != "" && pkg.LicenseDeclared != "NOASSERTION" {
		licenses = append(licenses, pkg.LicenseDeclared)
	}

	return licenses
}

func appendSPDXPURLs(purls []string, pkg *spdxPackage) []string {
	for idx := range pkg.ExternalRefs {
		ref := &pkg.ExternalRefs[idx]

		if ref.ReferenceType == "purl" && ref.ReferenceLocator != "" {
			purls = append(purls, ref.ReferenceLocator)
		}
	}

	return purls
}

func parseCycloneDX( //nolint:gocritic // tightly coupled returns
	data []byte,
) (licenses, purls []string, componentCount, licenseCount int, vulns []cyclonedxVulnerability, err error) {
	var bom cyclonedxBOM

	err = json.Unmarshal(data, &bom)
	if err != nil {
		return nil, nil, 0, 0, nil, fmt.Errorf("parsing CycloneDX: %w", err)
	}

	if len(bom.Components) == 0 {
		return nil, nil, 0, 0, nil, errNotCycloneDX
	}

	uniqueLicenses := make(map[string]struct{})

	for idx := range bom.Components {
		comp := &bom.Components[idx]

		for lidx := range comp.Licenses {
			lic := &comp.Licenses[lidx]
			if lic.License == nil {
				continue
			}

			if lic.License.ID != "" {
				licenses = append(licenses, lic.License.ID)
				uniqueLicenses[lic.License.ID] = struct{}{}
			} else if lic.License.Name != "" {
				licenses = append(licenses, lic.License.Name)
				uniqueLicenses[lic.License.Name] = struct{}{}
			}
		}

		if comp.PURL != "" {
			purls = append(purls, comp.PURL)
		}
	}

	return licenses, purls, len(bom.Components), len(uniqueLicenses), bom.Vulnerabilities, nil
}

func checkDenyLists(
	licenses, purls []string, pol *policy.Policy,
) *types.CheckResult {
	if pol.SBOM == nil {
		return passResult()
	}

	result := checkLicensePolicy(licenses, pol.SBOM.License)
	if result != nil {
		return result
	}

	result = checkComponentPolicy(purls, pol.SBOM.Component)
	if result != nil {
		return result
	}

	return passResult()
}

func checkLicensePolicy(
	licenses []string, licPolicy *policy.SBOMLicensePolicy,
) *types.CheckResult {
	if licPolicy == nil {
		return nil
	}

	// Deny takes precedence: check deny list first.
	denied := checkLicenseDenyList(licenses, licPolicy.Deny)
	if denied != nil {
		return denied
	}

	return checkLicenseAllowList(licenses, licPolicy.Allow)
}

func checkLicenseDenyList(
	licenses, denyList []string,
) *types.CheckResult {
	if len(denyList) == 0 {
		return nil
	}

	for _, license := range licenses {
		for _, id := range splitSPDXExpression(license) {
			for _, denied := range denyList {
				if strings.EqualFold(id, denied) {
					detail := fmt.Sprintf(
						"SBOM contains denied license %q", id,
					)

					return failResult(detail)
				}
			}
		}
	}

	return nil
}

func checkLicenseAllowList(
	licenses, allowList []string,
) *types.CheckResult {
	if len(allowList) == 0 {
		return nil
	}

	for _, license := range licenses {
		for _, id := range splitSPDXExpression(license) {
			if !licenseInList(id, allowList) {
				detail := fmt.Sprintf(
					"SBOM contains license %q not in allow list", id,
				)

				return failResult(detail)
			}
		}
	}

	return nil
}

func licenseInList(id string, list []string) bool {
	for _, entry := range list {
		if strings.EqualFold(id, entry) {
			return true
		}
	}

	return false
}

func splitSPDXExpression(expr string) []string {
	if !containsSPDXOperator(expr) {
		return []string{expr}
	}

	tokens := strings.Fields(expr)
	ids := make([]string, 0, len(tokens))

	skipNext := false

	for _, tok := range tokens {
		upper := strings.ToUpper(tok)

		if upper == "WITH" {
			skipNext = true

			continue
		}

		if skipNext {
			skipNext = false

			continue
		}

		if upper == "AND" || upper == "OR" {
			continue
		}

		tok = strings.Trim(tok, "()")
		if tok != "" {
			ids = append(ids, tok)
		}
	}

	if len(ids) == 0 {
		return []string{expr}
	}

	return ids
}

func containsSPDXOperator(expr string) bool {
	for _, op := range []string{" AND ", " OR ", " WITH "} {
		if strings.Contains(expr, op) {
			return true
		}
	}

	return false
}

func checkComponentPolicy(
	purls []string, compPolicy *policy.SBOMComponentPolicy,
) *types.CheckResult {
	if compPolicy == nil {
		return nil
	}

	// Deny takes precedence: check deny list first.
	denied := checkComponentDenyList(purls, compPolicy.Deny)
	if denied != nil {
		return denied
	}

	return checkComponentAllowList(purls, compPolicy.Allow)
}

func checkComponentDenyList(
	purls, denyList []string,
) *types.CheckResult {
	if len(denyList) == 0 {
		return nil
	}

	for _, purl := range purls {
		for _, denied := range denyList {
			if strings.HasPrefix(purl, denied) {
				detail := fmt.Sprintf(
					"SBOM contains denied component %q", purl,
				)

				return failResult(detail)
			}
		}
	}

	return nil
}

func checkComponentAllowList(
	purls, allowList []string,
) *types.CheckResult {
	if len(allowList) == 0 {
		return nil
	}

	for _, purl := range purls {
		if !componentInList(purl, allowList) {
			detail := fmt.Sprintf(
				"SBOM contains component %q not in allow list", purl,
			)

			return failResult(detail)
		}
	}

	return nil
}

func componentInList(purl string, list []string) bool {
	for _, entry := range list {
		if strings.HasPrefix(purl, entry) {
			return true
		}
	}

	return false
}

type vulnAggregate struct {
	maxScore    float64
	maxSeverity string
}

func checkCVSSThresholds( //nolint:cyclop,funlen // two-pass design requires branches
	vulns []cyclonedxVulnerability, cvssPolicy *policy.SBOMCVSSPolicy,
) *types.CheckResult {
	ignoredCVEs := make(map[string]bool, len(cvssPolicy.IgnoreCVEs))
	for _, cve := range cvssPolicy.IgnoreCVEs {
		ignoredCVEs[cve] = true
	}

	minSeverityRank := 0
	if cvssPolicy.MinSeverity != "" {
		minSeverityRank = severityRank[strings.ToLower(cvssPolicy.MinSeverity)]
	}

	var (
		globalMaxScore float64
		criticalCount  int64
		highCount      int64
		mediumCount    int64
	)

	cached := make([]vulnAggregate, len(vulns))

	// First pass: compute aggregate statistics across ALL vulnerabilities.
	// Ignored CVEs still contribute to aggregate statistics for visibility
	// in CEL rules.
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

	meta := map[string]any{
		"cvssMax":           globalMaxScore,
		"cvssCriticalCount": criticalCount,
		"cvssHighCount":     highCount,
		"cvssMediumCount":   mediumCount,
	}

	// Second pass: check each non-ignored vulnerability against thresholds,
	// using cached aggregates from the first pass.
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
			detail := fmt.Sprintf(
				"CVSS threshold exceeded: %s (score %.1f, severity %s)",
				vulns[idx].ID, agg.maxScore, strings.ToLower(agg.maxSeverity),
			)

			result := failResult(detail)
			result.Metadata = meta

			return result
		}
	}

	result := passResult()
	result.Metadata = meta

	return result
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
		case "cvssCriticalCount", "cvssHighCount", "cvssMediumCount":
			if srcCount, ok := val.(int64); ok {
				if dstCount, ok := existing.(int64); ok {
					dst[key] = dstCount + srcCount
				}
			}
		default:
		}
	}
}

func passResult() *types.CheckResult {
	return types.PassResult(checkType, "SBOM verification passed")
}

func failResult(detail string) *types.CheckResult {
	return types.FailResult(checkType, detail, nil)
}

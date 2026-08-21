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
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
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

var errNotCycloneDX = errors.New("no components found, not a valid CycloneDX document")

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
	Version  string             `json:"version"`
	PURL     string             `json:"purl"`
	Licenses []cyclonedxLicense `json:"licenses"`
	Hashes   []cyclonedxHash    `json:"hashes"`
}

type cyclonedxHash struct {
	Algorithm string `json:"alg"`
	Content   string `json:"content"`
}

type cyclonedxLicense struct {
	License *cyclonedxLicenseRef `json:"license,omitempty"`
}

type cyclonedxLicenseRef struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

func parseCycloneDX(data []byte) (sbomData, error) {
	var bom cyclonedxBOM

	err := json.Unmarshal(data, &bom)
	if err != nil {
		return sbomData{}, fmt.Errorf("parsing CycloneDX: %w", err)
	}

	if len(bom.Components) == 0 {
		return sbomData{}, errNotCycloneDX
	}

	var result sbomData

	uniqueLicenses := make(map[string]struct{})

	for idx := range bom.Components {
		comp := &bom.Components[idx]
		sp := buildCycloneDXPackage(comp, &result, uniqueLicenses)
		result.Packages = append(result.Packages, sp)
	}

	result.componentCount = len(bom.Components)
	result.licenseCount = len(uniqueLicenses)
	result.vulns = bom.Vulnerabilities

	return result, nil
}

func buildCycloneDXPackage(
	comp *cyclonedxComponent, result *sbomData, uniqueLicenses map[string]struct{},
) sbomPackage {
	pkg := sbomPackage{
		Name:    comp.Name,
		Version: comp.Version,
		PURL:    comp.PURL,
	}

	for lidx := range comp.Licenses {
		lic := &comp.Licenses[lidx]
		if lic.License == nil {
			continue
		}

		if lic.License.ID != "" {
			result.licenses = append(result.licenses, lic.License.ID)
			uniqueLicenses[lic.License.ID] = struct{}{}
			pkg.Licenses = append(pkg.Licenses, lic.License.ID)
		} else if lic.License.Name != "" {
			result.licenses = append(result.licenses, lic.License.Name)
			uniqueLicenses[lic.License.Name] = struct{}{}
			pkg.Licenses = append(pkg.Licenses, lic.License.Name)
		}
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

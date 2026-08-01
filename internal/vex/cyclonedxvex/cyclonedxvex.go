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

// Package cyclonedxvex implements VEX verification using the CycloneDX format.
package cyclonedxvex

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// digestSeparatorParts is the expected number of parts when splitting
// a digest string on ":".
const digestSeparatorParts = 2

// Result holds the outcome of a CycloneDX VEX verification.
type Result struct {
	AffectedNames         []string
	HasUnderInvestigation bool
}

// Verify checks a CycloneDX BOM predicate for VEX vulnerability data
// and returns the verification result.
// The purl parameter is the pre-computed OCI Package URL for the image.
func Verify(
	predicate []byte,
	imageDigest, purl string,
) (*Result, error) {
	bom := new(cdx.BOM)

	decoder := cdx.NewBOMDecoder(bytes.NewReader(predicate), cdx.BOMFileFormatJSON)

	err := decoder.Decode(bom)
	if err != nil {
		return nil, fmt.Errorf("parsing CycloneDX BOM: %w", err)
	}

	if bom.Vulnerabilities == nil || len(*bom.Vulnerabilities) == 0 {
		return &Result{
			AffectedNames:         nil,
			HasUnderInvestigation: false,
		}, nil
	}

	componentIndex := buildComponentIndex(bom)

	return classifyVulnerabilities(bom.Vulnerabilities, componentIndex, imageDigest, purl), nil
}

// classifyVulnerabilities iterates over the BOM vulnerabilities, matches
// them against the image, and classifies their analysis states.
func classifyVulnerabilities(
	vulns *[]cdx.Vulnerability,
	componentIndex map[string]*cdx.Component,
	imageDigest, purl string,
) *Result {
	var (
		affectedNames         []string
		hasUnderInvestigation bool
	)

	for idx := range *vulns {
		vuln := &(*vulns)[idx]

		if !vulnerabilityAffectsImage(vuln, componentIndex, imageDigest, purl) {
			continue
		}

		if vuln.Analysis == nil || vuln.Analysis.State == "" {
			continue
		}

		switch vuln.Analysis.State {
		case cdx.IASExploitable:
			affectedNames = append(affectedNames, vulnerabilityName(vuln))

		case cdx.IASInTriage:
			hasUnderInvestigation = true

		case cdx.IASNotAffected, cdx.IASFalsePositive,
			cdx.IASResolved, cdx.IASResolvedWithPedigree:
			// These states are acceptable.

		default:
			slog.Warn("Unrecognized CycloneDX analysis state, treating as affected",
				"state", vuln.Analysis.State,
				"vulnerability", vulnerabilityName(vuln),
			)

			affectedNames = append(affectedNames, vulnerabilityName(vuln))
		}
	}

	return &Result{
		AffectedNames:         affectedNames,
		HasUnderInvestigation: hasUnderInvestigation,
	}
}

func vulnerabilityName(vuln *cdx.Vulnerability) string {
	if vuln.ID != "" {
		return vuln.ID
	}

	return "unknown"
}

// buildComponentIndex creates a map from BOM-ref to component for quick lookups.
func buildComponentIndex(bom *cdx.BOM) map[string]*cdx.Component {
	index := make(map[string]*cdx.Component)

	if bom.Components == nil {
		return index
	}

	for idx := range *bom.Components {
		comp := &(*bom.Components)[idx]
		if comp.BOMRef != "" {
			index[comp.BOMRef] = comp
		}
	}

	return index
}

// vulnerabilityAffectsImage checks whether a vulnerability targets the image
// being verified. It resolves each Affects[].Ref to a component via the
// BOM-ref index and matches via digest or PURL.
func vulnerabilityAffectsImage(
	vuln *cdx.Vulnerability,
	componentIndex map[string]*cdx.Component,
	imageDigest, purl string,
) bool {
	if vuln.Affects == nil || len(*vuln.Affects) == 0 {
		return false
	}

	for idx := range *vuln.Affects {
		ref := (*vuln.Affects)[idx].Ref

		if matchesRef(ref, imageDigest, purl) {
			return true
		}

		comp, ok := componentIndex[ref]
		if ok && matchesComponent(comp, imageDigest, purl) {
			return true
		}
	}

	return false
}

// matchesRef checks if a raw affects reference matches the image digest or PURL.
func matchesRef(ref, imageDigest, purl string) bool {
	if imageDigest != "" && strings.Contains(ref, imageDigest) {
		return true
	}

	return purl != "" && ref == purl
}

// matchesComponent checks whether a CycloneDX component matches the image
// by comparing its PURL or hashes against the image digest.
func matchesComponent(comp *cdx.Component, imageDigest, purl string) bool {
	if purl != "" && comp.PackageURL == purl {
		return true
	}

	if imageDigest != "" && strings.Contains(comp.PackageURL, imageDigest) {
		return true
	}

	return matchesComponentHash(comp, imageDigest)
}

// matchesComponentHash checks if any of the component's hashes match the
// image digest, normalizing algorithm names between CycloneDX ("SHA-256")
// and OCI ("sha256") conventions.
func matchesComponentHash(comp *cdx.Component, imageDigest string) bool {
	if imageDigest == "" || comp.Hashes == nil {
		return false
	}

	parts := strings.SplitN(imageDigest, ":", digestSeparatorParts)
	if len(parts) != digestSeparatorParts {
		return false
	}

	normalizedAlgo := normalizeHashAlgorithm(parts[0])

	for idx := range *comp.Hashes {
		hash := &(*comp.Hashes)[idx]
		if normalizeHashAlgorithm(string(hash.Algorithm)) == normalizedAlgo &&
			strings.EqualFold(hash.Value, parts[1]) {
			return true
		}
	}

	return false
}

// normalizeHashAlgorithm converts hash algorithm names to a canonical
// lowercase form without hyphens. CycloneDX uses "SHA-256" while OCI
// digests use "sha256"; this normalization makes them comparable.
func normalizeHashAlgorithm(algo string) string {
	return strings.ToLower(strings.ReplaceAll(algo, "-", ""))
}

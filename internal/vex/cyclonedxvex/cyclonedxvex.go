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

	"github.com/saschagrunert/nri-supply-chain/internal/vex/imagematch"
)

// bomLinkPrefix identifies CycloneDX BOM-Link references, which point into a
// BOM describing the attested image.
const bomLinkPrefix = "urn:cdx:"

// maxComponentDepth bounds recursion into nested components.
const maxComponentDepth = 32

// Result holds the outcome of a CycloneDX VEX verification.
type Result struct {
	// AffectedNames lists vulnerabilities that apply to the image and are
	// exploitable or have an unknown analysis state.
	AffectedNames []string
	// HasUnderInvestigation is true when an applicable vulnerability is in
	// triage.
	HasUnderInvestigation bool
	// MatchedVulnerabilities counts vulnerabilities with an analysis state
	// that apply to the image. Zero means the document makes no VEX statement
	// about the image.
	MatchedVulnerabilities int
}

// Verify checks a CycloneDX BOM predicate for VEX vulnerability data and
// returns the verification result.
//
// The in-toto statement carrying the BOM is bound to the image digest, so
// the BOM describes the image: vulnerabilities that affect components of the
// BOM (including metadata.component, nested components, BOM-Links, and
// package purls) apply to the image. Only references that clearly identify a
// different image (another digest or OCI purl) are ignored. Vulnerabilities
// without any affects entry apply to the BOM subject, which is the image.
func Verify(predicate []byte, image *imagematch.Image) (*Result, error) {
	bom := new(cdx.BOM)

	decoder := cdx.NewBOMDecoder(bytes.NewReader(predicate), cdx.BOMFileFormatJSON)

	err := decoder.Decode(bom)
	if err != nil {
		return nil, fmt.Errorf("parsing CycloneDX BOM: %w", err)
	}

	return Evaluate(bom, image), nil
}

// Evaluate classifies the vulnerabilities of a decoded BOM for the image.
func Evaluate(bom *cdx.BOM, image *imagematch.Image) *Result {
	result := &Result{
		AffectedNames:          nil,
		HasUnderInvestigation:  false,
		MatchedVulnerabilities: 0,
	}

	if bom == nil || bom.Vulnerabilities == nil || len(*bom.Vulnerabilities) == 0 {
		return result
	}

	index := buildComponentIndex(bom)
	subject := subjectRef(bom)

	for idx := range *bom.Vulnerabilities {
		vuln := &(*bom.Vulnerabilities)[idx]

		// A vulnerability without an analysis state is a finding (for example
		// scanner output in an SBOM), not a VEX statement. Its severity is
		// gated by the sbom.cvss policy instead.
		if vuln.Analysis == nil || vuln.Analysis.State == "" {
			continue
		}

		if !vulnerabilityAffectsImage(vuln, index, subject, image) {
			continue
		}

		result.MatchedVulnerabilities++

		classifyVulnerability(vuln, result)
	}

	return result
}

func classifyVulnerability(vuln *cdx.Vulnerability, result *Result) {
	switch vuln.Analysis.State {
	case cdx.IASExploitable:
		result.AffectedNames = append(result.AffectedNames, vulnerabilityName(vuln))

	case cdx.IASInTriage:
		result.HasUnderInvestigation = true

	case cdx.IASNotAffected, cdx.IASFalsePositive,
		cdx.IASResolved, cdx.IASResolvedWithPedigree:
		// These states are acceptable.

	default:
		slog.Warn("Unrecognized CycloneDX analysis state, treating as affected",
			"state", vuln.Analysis.State,
			"vulnerability", vulnerabilityName(vuln),
		)

		result.AffectedNames = append(result.AffectedNames, vulnerabilityName(vuln))
	}
}

func vulnerabilityName(vuln *cdx.Vulnerability) string {
	if vuln.ID != "" {
		return vuln.ID
	}

	return "unknown"
}

// buildComponentIndex maps BOM-refs to components, including
// metadata.component and nested components.
func buildComponentIndex(bom *cdx.BOM) map[string]*cdx.Component {
	index := make(map[string]*cdx.Component)

	if bom.Metadata != nil && bom.Metadata.Component != nil {
		indexComponent(index, bom.Metadata.Component, 0)
	}

	if bom.Components != nil {
		for idx := range *bom.Components {
			indexComponent(index, &(*bom.Components)[idx], 0)
		}
	}

	return index
}

func indexComponent(index map[string]*cdx.Component, comp *cdx.Component, depth int) {
	if depth > maxComponentDepth {
		return
	}

	if comp.BOMRef != "" {
		index[comp.BOMRef] = comp
	}

	if comp.Components == nil {
		return
	}

	for idx := range *comp.Components {
		indexComponent(index, &(*comp.Components)[idx], depth+1)
	}
}

// vulnerabilityAffectsImage reports whether a vulnerability applies to the
// image. See Verify for the rules. Entries that are not resolved
// (exploitable, in triage, or unknown state) are matched leniently:
// only references that carry a different image digest are excluded, so
// unknown BOM-refs, CPEs, and renamed or retagged image components still
// apply. Resolved entries must identify the image or one of its components.
func vulnerabilityAffectsImage(
	vuln *cdx.Vulnerability,
	index map[string]*cdx.Component,
	subject string,
	image *imagematch.Image,
) bool {
	if vuln.Affects == nil || len(*vuln.Affects) == 0 {
		return true
	}

	lenient := !isResolved(vuln)

	for idx := range *vuln.Affects {
		ref := (*vuln.Affects)[idx].Ref
		if refAffectsImage(ref, index, image, lenient, subject != "" && ref == subject) {
			return true
		}
	}

	return false
}

func isResolved(vuln *cdx.Vulnerability) bool {
	if vuln.Analysis == nil {
		return false
	}

	switch vuln.Analysis.State {
	case cdx.IASNotAffected, cdx.IASFalsePositive, cdx.IASResolved, cdx.IASResolvedWithPedigree:
		return true
	case cdx.IASExploitable, cdx.IASInTriage:
		return false
	default:
		return false
	}
}

func refAffectsImage(
	ref string, index map[string]*cdx.Component, image *imagematch.Image, lenient, subject bool,
) bool {
	if comp, ok := index[ref]; ok {
		return componentAffectsImage(comp, image, lenient, subject)
	}

	if strings.HasPrefix(strings.ToLower(ref), bomLinkPrefix) {
		return true
	}

	kind := classify(image, ref, lenient)

	switch kind {
	case imagematch.KindImage, imagematch.KindPackage:
		return true
	case imagematch.KindOtherImage:
		return false
	case imagematch.KindUnrelated:
		return lenient && !image.ConflictsByDigest(ref)
	default:
		return lenient && !image.ConflictsByDigest(ref)
	}
}

// classify matches an identifier strictly, or leniently for entries that can
// only raise severity: an image purl with the image name still applies when
// its tag or namespace differ, while a purl naming another image does not.
func classify(image *imagematch.Image, identifier string, lenient bool) imagematch.Kind {
	if lenient {
		kind, _ := image.MatchLenient(identifier)

		return kind
	}

	return image.Classify(identifier)
}

// subjectRef returns the BOM-ref of metadata.component, the subject the
// digest-bound BOM describes, or "" when there is none.
func subjectRef(bom *cdx.BOM) string {
	if bom.Metadata == nil || bom.Metadata.Component == nil {
		return ""
	}

	return bom.Metadata.Component.BOMRef
}

// componentAffectsImage reports whether a BOM component is the image or a
// component of it. Components that identify a different image by digest or
// hash are excluded; in strict mode components that name a different image
// are excluded too. In lenient mode only the BOM subject (metadata.component)
// may carry a different image name, since the digest-bound BOM describes the
// image under whatever name it was built; other image components must match
// the image name.
func componentAffectsImage(
	comp *cdx.Component,
	image *imagematch.Image,
	lenient, subject bool,
) bool {
	if comp.PackageURL != "" {
		if classify(image, comp.PackageURL, lenient) != imagematch.KindOtherImage {
			return true
		}

		return lenient && subject && !image.ConflictsByDigest(comp.PackageURL)
	}

	if comp.Type == cdx.ComponentTypeContainer && comp.Hashes != nil {
		for idx := range *comp.Hashes {
			hash := &(*comp.Hashes)[idx]
			if image.MatchesHash(string(hash.Algorithm), hash.Value) {
				return true
			}
		}

		return !hasComparableHash(comp, image)
	}

	return true
}

// hasComparableHash reports whether the component carries a hash using the
// image digest algorithm, which makes a mismatch meaningful.
func hasComparableHash(comp *cdx.Component, image *imagematch.Image) bool {
	algorithm, _, _ := strings.Cut(image.Digest, ":")

	for idx := range *comp.Hashes {
		if imagematch.NormalizeAlgorithm(string((*comp.Hashes)[idx].Algorithm)) ==
			imagematch.NormalizeAlgorithm(algorithm) {
			return true
		}
	}

	return false
}

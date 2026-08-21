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
	"strings"
)

const refTypePURL = "purl"

var (
	errNotSPDX  = errors.New("no packages found, not a valid SPDX document")
	errNotSPDX3 = errors.New("not a valid SPDX 3.0 document")
)

type spdxDocument struct {
	SPDXVersion string        `json:"spdxVersion"`
	Packages    []spdxPackage `json:"packages"`
}

type spdxPackage struct {
	Name             string            `json:"name"`
	VersionInfo      string            `json:"versionInfo"`
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

func parseSPDX(data []byte) (sbomData, error) {
	var doc spdxDocument

	err := json.Unmarshal(data, &doc)
	if err != nil {
		return sbomData{}, fmt.Errorf("parsing SPDX: %w", err)
	}

	if doc.SPDXVersion == "" || len(doc.Packages) == 0 {
		return sbomData{}, errNotSPDX
	}

	var result sbomData

	for idx := range doc.Packages {
		pkg := &doc.Packages[idx]
		result.licenses = appendSPDXLicenses(result.licenses, pkg)
		result.purls = appendSPDXPURLs(result.purls, pkg)
		result.Packages = append(result.Packages, buildSPDXPackage(pkg))
	}

	uniqueLicenses := make(map[string]struct{}, len(result.licenses))
	for _, lic := range result.licenses {
		uniqueLicenses[lic] = struct{}{}
	}

	result.componentCount = len(doc.Packages)
	result.licenseCount = len(uniqueLicenses)

	return result, nil
}

func buildSPDXPackage(pkg *spdxPackage) sbomPackage {
	sbomPkg := sbomPackage{
		Name:    pkg.Name,
		Version: pkg.VersionInfo,
	}

	sbomPkg.PURL = findSPDXPURL(pkg.ExternalRefs)
	sbomPkg.Licenses = collectSPDXLicensePair(pkg.LicenseConcluded, pkg.LicenseDeclared)
	sbomPkg.Checksums = buildChecksumMap(pkg.Checksums)

	return sbomPkg
}

func findSPDXPURL(refs []spdxExternalRef) string {
	for idx := range refs {
		ref := &refs[idx]
		if ref.ReferenceType == refTypePURL && ref.ReferenceLocator != "" {
			return ref.ReferenceLocator
		}
	}

	return ""
}

func collectSPDXLicensePair(concluded, declared string) []string {
	var licenses []string

	if concluded != "" && concluded != noAssertionLicense {
		licenses = append(licenses, concluded)
	}

	if declared != "" && declared != noAssertionLicense {
		licenses = append(licenses, declared)
	}

	return licenses
}

func buildChecksumMap(checksums []spdxChecksum) map[string]string {
	if len(checksums) == 0 {
		return nil
	}

	result := make(map[string]string, len(checksums))

	for idx := range checksums {
		cs := &checksums[idx]
		if cs.Algorithm != "" && cs.Value != "" {
			result[cs.Algorithm] = cs.Value
		}
	}

	return result
}

func appendSPDXLicenses(licenses []string, pkg *spdxPackage) []string {
	if pkg.LicenseConcluded != "" && pkg.LicenseConcluded != noAssertionLicense {
		licenses = append(licenses, pkg.LicenseConcluded)
	}

	if pkg.LicenseDeclared != "" && pkg.LicenseDeclared != noAssertionLicense {
		licenses = append(licenses, pkg.LicenseDeclared)
	}

	return licenses
}

func appendSPDXPURLs(purls []string, pkg *spdxPackage) []string {
	for idx := range pkg.ExternalRefs {
		ref := &pkg.ExternalRefs[idx]

		if ref.ReferenceType == refTypePURL && ref.ReferenceLocator != "" {
			purls = append(purls, ref.ReferenceLocator)
		}
	}

	return purls
}

type spdx3Document struct {
	Context  string         `json:"@context,omitempty"`
	Type     string         `json:"@type,omitempty"`
	SpdxID   string         `json:"spdxId,omitempty"` //nolint:tagliatelle // SPDX spec field name
	SpecVer  string         `json:"specVersion,omitempty"`
	Elements []spdx3Element `json:"@graph,omitempty"`
}

type spdx3Element struct {
	Type                string               `json:"@type,omitempty"`
	Name                string               `json:"name,omitempty"`
	SoftwareVersion     string               `json:"software:softwareVersion,omitempty"`
	ExternalIdentifiers []spdx3ExtIdentifier `json:"externalIdentifier,omitempty"`
	DeclaredLicense     string               `json:"declaredLicense,omitempty"`
	ConcludedLicense    string               `json:"concludedLicense,omitempty"`
	VerifiedUsing       []spdx3Verification  `json:"verifiedUsing,omitempty"`
}

type spdx3Verification struct {
	Type      string `json:"@type,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`
	Value     string `json:"hashValue,omitempty"`
}

type spdx3ExtIdentifier struct {
	Type       string `json:"@type,omitempty"`
	IDType     string `json:"externalIdentifierType,omitempty"`
	Identifier string `json:"identifier,omitempty"`
}

func parseSPDX3(data []byte) (sbomData, error) {
	var doc spdx3Document

	err := json.Unmarshal(data, &doc)
	if err != nil {
		return sbomData{}, fmt.Errorf("parsing SPDX 3.0: %w", err)
	}

	if !isSPDX3(&doc) {
		return sbomData{}, errNotSPDX3
	}

	var result sbomData

	uniqueLicenses := make(map[string]struct{})

	for idx := range doc.Elements {
		elem := &doc.Elements[idx]

		if !isSPDX3Package(elem.Type) {
			continue
		}

		sp := buildSPDX3Package(elem, &result, uniqueLicenses)
		result.Packages = append(result.Packages, sp)
	}

	if len(result.Packages) == 0 {
		return sbomData{}, errNotSPDX3
	}

	result.componentCount = len(result.Packages)
	result.licenseCount = len(uniqueLicenses)

	return result, nil
}

func buildSPDX3Package(
	elem *spdx3Element, result *sbomData, uniqueLicenses map[string]struct{},
) sbomPackage {
	sbomPkg := sbomPackage{
		Name:    elem.Name,
		Version: elem.SoftwareVersion,
	}

	sbomPkg.Licenses = collectSPDX3Licenses(elem, result, uniqueLicenses)

	for eidx := range elem.ExternalIdentifiers {
		eid := &elem.ExternalIdentifiers[eidx]
		if isSPDX3PURL(eid) && eid.Identifier != "" {
			result.purls = append(result.purls, eid.Identifier)
			sbomPkg.PURL = eid.Identifier
		}
	}

	sbomPkg.Checksums = buildSPDX3Checksums(elem.VerifiedUsing)

	return sbomPkg
}

func collectSPDX3Licenses(
	elem *spdx3Element, result *sbomData, uniqueLicenses map[string]struct{},
) []string {
	var licenses []string

	if elem.ConcludedLicense != "" && elem.ConcludedLicense != noAssertionLicense {
		result.licenses = append(result.licenses, elem.ConcludedLicense)
		uniqueLicenses[elem.ConcludedLicense] = struct{}{}
		licenses = append(licenses, elem.ConcludedLicense)
	}

	if elem.DeclaredLicense != "" && elem.DeclaredLicense != noAssertionLicense {
		result.licenses = append(result.licenses, elem.DeclaredLicense)
		uniqueLicenses[elem.DeclaredLicense] = struct{}{}
		licenses = append(licenses, elem.DeclaredLicense)
	}

	return licenses
}

func buildSPDX3Checksums(verifications []spdx3Verification) map[string]string {
	if len(verifications) == 0 {
		return nil
	}

	checksums := make(map[string]string, len(verifications))

	for idx := range verifications {
		verification := &verifications[idx]
		if verification.Algorithm != "" && verification.Value != "" {
			checksums[verification.Algorithm] = verification.Value
		}
	}

	return checksums
}

func isSPDX3(doc *spdx3Document) bool {
	if strings.HasPrefix(doc.SpecVer, "3.") {
		return true
	}

	if strings.Contains(doc.Context, "spdx.org") && len(doc.Elements) > 0 {
		return true
	}

	return false
}

func isSPDX3Package(elemType string) bool {
	return strings.EqualFold(elemType, "software_SoftwarePackage") ||
		strings.EqualFold(elemType, "SoftwarePackage") ||
		strings.EqualFold(elemType, "software:SoftwarePackage")
}

func isSPDX3PURL(eid *spdx3ExtIdentifier) bool {
	return strings.EqualFold(eid.IDType, "packageUrl") ||
		strings.EqualFold(eid.IDType, "purl")
}

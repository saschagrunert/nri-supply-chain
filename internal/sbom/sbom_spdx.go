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
	"strings"
)

const (
	refTypePURL = "purl"

	spdxDocumentRef       = "SPDXRef-DOCUMENT"
	spdxRelDescribes      = "DESCRIBES"
	spdxListedLicensesIRI = "https://spdx.org/licenses/"

	spdx3RelConcluded = "hasconcludedlicense"
	spdx3RelDeclared  = "hasdeclaredlicense"

	// maxLicenseDepth bounds recursion into SPDX 3 license sets.
	maxLicenseDepth = 16

	// unresolvedLicensePrefix marks SPDX 3 license references that could not
	// be resolved to an identifier or name.
	unresolvedLicensePrefix = "unresolved-license:"
)

var (
	errNotSPDX  = errors.New("no packages found, not a valid SPDX document")
	errNotSPDX3 = errors.New("not a valid SPDX 3.0 document")
)

// spdxExemptPurposes lists SPDX 2.3 primaryPackagePurpose values (and SPDX 3
// software_primaryPurpose values, compared case-insensitively without
// separators) for packages that are not expected to carry a purl.
var spdxExemptPurposes = map[string]struct{}{ //nolint:gochecknoglobals // immutable lookup table
	"operatingsystem": {},
	"file":            {},
	"container":       {},
	"source":          {},
	"archive":         {},
	"device":          {},
	"firmware":        {},
}

type spdxDocument struct {
	SPDXVersion       string             `json:"spdxVersion"`
	DocumentDescribes []string           `json:"documentDescribes,omitempty"`
	Packages          []spdxPackage      `json:"packages"`
	Relationships     []spdxRelationship `json:"relationships,omitempty"`
}

type spdxPackage struct {
	SPDXID                string            `json:"SPDXID,omitempty"` //nolint:tagliatelle // SPDX spec field name
	Name                  string            `json:"name"`
	VersionInfo           string            `json:"versionInfo"`
	LicenseConcluded      string            `json:"licenseConcluded"`
	LicenseDeclared       string            `json:"licenseDeclared"`
	PrimaryPackagePurpose string            `json:"primaryPackagePurpose,omitempty"`
	ExternalRefs          []spdxExternalRef `json:"externalRefs"`
	Checksums             []spdxChecksum    `json:"checksums"`
}

type spdxRelationship struct {
	Element          string `json:"spdxElementId"` //nolint:tagliatelle // SPDX spec field name
	RelationshipType string `json:"relationshipType"`
	Related          string `json:"relatedSpdxElement"`
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
	raw, err := decodeRawSBOM(data)
	if err != nil {
		return sbomData{}, err
	}

	return spdxFromRaw(raw)
}

func spdxFromRaw(raw *rawSBOM) (sbomData, error) {
	doc := spdxDocument{
		SPDXVersion:       raw.SPDXVersion,
		DocumentDescribes: raw.DocumentDescribes,
		Packages:          raw.Packages,
		Relationships:     raw.Relationships,
	}

	if doc.SPDXVersion == "" || len(doc.Packages) == 0 {
		return sbomData{}, errNotSPDX
	}

	subjects := spdxSubjects(&doc)

	var result sbomData

	for idx := range doc.Packages {
		pkg := &doc.Packages[idx]
		sbomPkg := buildSPDXPackage(pkg)

		for _, license := range sbomPkg.Licenses {
			result.addLicense(license, true)
		}

		result.addPURLs(pkg)
		result.addPackage(&sbomPkg, spdxPackageExempt(pkg, subjects))
	}

	result.componentCount = len(doc.Packages)

	return result, nil
}

// spdxSubjects returns the SPDX IDs the document describes (the image
// itself), which are exempt from the purl requirement.
func spdxSubjects(doc *spdxDocument) map[string]struct{} {
	subjects := make(map[string]struct{}, len(doc.DocumentDescribes))

	for _, id := range doc.DocumentDescribes {
		subjects[id] = struct{}{}
	}

	for idx := range doc.Relationships {
		rel := &doc.Relationships[idx]
		if rel.Element == spdxDocumentRef &&
			strings.EqualFold(rel.RelationshipType, spdxRelDescribes) {
			subjects[rel.Related] = struct{}{}
		}
	}

	return subjects
}

func spdxPackageExempt(pkg *spdxPackage, subjects map[string]struct{}) bool {
	if _, ok := subjects[pkg.SPDXID]; ok && pkg.SPDXID != "" {
		return true
	}

	return purposeExempt(pkg.PrimaryPackagePurpose, pkg.VersionInfo)
}

// purposeExempt reports whether a package with the given primary purpose is
// not expected to carry a purl. Versionless APPLICATION packages describe
// lock or manifest files (as emitted by Trivy) rather than packages.
func purposeExempt(purpose, version string) bool {
	normalized := strings.ToLower(strings.NewReplacer("-", "", "_", "").Replace(purpose))
	_, ok := spdxExemptPurposes[normalized]

	return ok || (normalized == componentTypeApplication && version == "")
}

func buildSPDXPackage(pkg *spdxPackage) sbomPackage {
	return sbomPackage{
		Name:      pkg.Name,
		Version:   pkg.VersionInfo,
		PURL:      findSPDXPURL(pkg.ExternalRefs),
		Licenses:  collectSPDXLicensePair(pkg.LicenseConcluded, pkg.LicenseDeclared),
		Checksums: buildChecksumMap(pkg.Checksums),
	}
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

	if isAssertedLicense(concluded) {
		licenses = append(licenses, concluded)
	}

	if isAssertedLicense(declared) {
		licenses = append(licenses, declared)
	}

	return licenses
}

func isAssertedLicense(license string) bool {
	return license != "" && license != noAssertionLicense
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

func (d *sbomData) addPURLs(pkg *spdxPackage) {
	for idx := range pkg.ExternalRefs {
		ref := &pkg.ExternalRefs[idx]

		if ref.ReferenceType == refTypePURL && ref.ReferenceLocator != "" {
			d.purls = append(d.purls, ref.ReferenceLocator)
		}
	}
}

// spdx3Document is the SPDX 3 JSON-LD serialization. Both the 3.0 draft
// shapes ("@type", "declaredLicense") and the 3.0.1 shapes ("type",
// "software_packageVersion", license Relationship elements) are accepted.
type spdx3Document struct {
	Context  string         `json:"@context,omitempty"`
	Type     string         `json:"@type,omitempty"`
	SpdxID   string         `json:"spdxId,omitempty"` //nolint:tagliatelle // SPDX spec field name
	SpecVer  string         `json:"specVersion,omitempty"`
	Elements []spdx3Element `json:"@graph,omitempty"`
}

//nolint:tagliatelle // SPDX 3 JSON-LD property names
type spdx3Element struct {
	Type                string               `json:"@type,omitempty"`
	TypeV301            string               `json:"type,omitempty"`
	SpdxID              string               `json:"spdxId,omitempty"`
	Name                string               `json:"name,omitempty"`
	SoftwareVersion     string               `json:"software:softwareVersion,omitempty"`
	PackageVersion      string               `json:"software_packageVersion,omitempty"`
	PackageURL          string               `json:"software_packageUrl,omitempty"`
	PrimaryPurpose      string               `json:"software_primaryPurpose,omitempty"`
	ExternalIdentifiers []spdx3ExtIdentifier `json:"externalIdentifier,omitempty"`
	DeclaredLicense     string               `json:"declaredLicense,omitempty"`
	ConcludedLicense    string               `json:"concludedLicense,omitempty"`
	VerifiedUsing       []spdx3Verification  `json:"verifiedUsing,omitempty"`
	RootElement         []string             `json:"rootElement,omitempty"`
	From                string               `json:"from,omitempty"`
	To                  []string             `json:"to,omitempty"`
	RelationshipType    string               `json:"relationshipType,omitempty"`
	LicenseExpression   string               `json:"simplelicensing_licenseExpression,omitempty"`
	LicenseMembers      []string             `json:"expandedlicensing_member,omitempty"`
	// SubjectLicense is the license an OrLaterOperator applies to.
	SubjectLicense string `json:"expandedlicensing_subjectLicense,omitempty"`
	// SubjectExtendableLicense is the license a WithAdditionOperator extends.
	SubjectExtendableLicense string `json:"expandedlicensing_subjectExtendableLicense,omitempty"`
	// SubjectAddition is the exception a WithAdditionOperator adds.
	SubjectAddition string `json:"expandedlicensing_subjectAddition,omitempty"`
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

func (e *spdx3Element) elementType() string {
	if e.TypeV301 != "" {
		return e.TypeV301
	}

	return e.Type
}

func parseSPDX3(data []byte) (sbomData, error) {
	raw, err := decodeRawSBOM(data)
	if err != nil {
		return sbomData{}, err
	}

	return spdx3FromRaw(raw)
}

func spdx3FromRaw(raw *rawSBOM) (sbomData, error) {
	if !isSPDX3(raw) {
		return sbomData{}, errNotSPDX3
	}

	graph := newSPDX3Graph(raw.Graph)

	var result sbomData

	for idx := range raw.Graph {
		elem := &raw.Graph[idx]

		if !isSPDX3Package(elem.elementType()) {
			continue
		}

		sbomPkg := buildSPDX3Package(elem, graph, &result)
		_, isRoot := graph.roots[elem.SpdxID]
		exempt := (isRoot && elem.SpdxID != "") ||
			purposeExempt(elem.PrimaryPurpose, sbomPkg.Version)
		result.addPackage(&sbomPkg, exempt)
	}

	if len(result.Packages) == 0 {
		return sbomData{}, errNotSPDX3
	}

	result.componentCount = len(result.Packages)

	return result, nil
}

// spdx3Graph indexes the elements needed to resolve licenses and roots.
type spdx3Graph struct {
	elements map[string]*spdx3Element
	licenses map[string][]string // package spdxId -> license element ids
	roots    map[string]struct{}
}

func newSPDX3Graph(elements []spdx3Element) *spdx3Graph {
	graph := &spdx3Graph{
		elements: make(map[string]*spdx3Element, len(elements)),
		licenses: make(map[string][]string),
		roots:    make(map[string]struct{}),
	}

	for idx := range elements {
		elem := &elements[idx]

		if elem.SpdxID != "" {
			graph.elements[elem.SpdxID] = elem
		}

		for _, root := range elem.RootElement {
			graph.roots[root] = struct{}{}
		}

		if strings.EqualFold(elem.elementType(), "Relationship") {
			relType := strings.ToLower(elem.RelationshipType)
			if relType == spdx3RelConcluded || relType == spdx3RelDeclared {
				graph.licenses[elem.From] = append(graph.licenses[elem.From], elem.To...)
			}
		}
	}

	return graph
}

func buildSPDX3Package(elem *spdx3Element, graph *spdx3Graph, result *sbomData) sbomPackage {
	sbomPkg := sbomPackage{
		Name:      elem.Name,
		Version:   elem.PackageVersion,
		PURL:      elem.PackageURL,
		Licenses:  nil,
		Checksums: buildSPDX3Checksums(elem.VerifiedUsing),
	}

	if sbomPkg.Version == "" {
		sbomPkg.Version = elem.SoftwareVersion
	}

	if sbomPkg.PURL != "" {
		result.purls = append(result.purls, sbomPkg.PURL)
	}

	for _, license := range []string{elem.ConcludedLicense, elem.DeclaredLicense} {
		if isAssertedLicense(license) {
			result.addLicense(license, true)
			sbomPkg.Licenses = append(sbomPkg.Licenses, license)
		}
	}

	for _, licenseID := range graph.licenses[elem.SpdxID] {
		for _, entry := range graph.resolveLicense(licenseID, 0) {
			result.addLicense(entry.value, entry.expression)
			sbomPkg.Licenses = append(sbomPkg.Licenses, entry.value)
		}
	}

	for eidx := range elem.ExternalIdentifiers {
		eid := &elem.ExternalIdentifiers[eidx]
		if isSPDX3PURL(eid) && eid.Identifier != "" {
			result.purls = append(result.purls, eid.Identifier)
			sbomPkg.PURL = eid.Identifier
		}
	}

	return sbomPkg
}

// resolveLicense turns a license element reference into license entries.
// Listed license IRIs that are not present in the graph resolve to their
// identifier; NoAssertion and None individuals resolve to nothing.
// OrLaterOperator subjects resolve with a "+" suffix, WithAdditionOperator
// resolves to its subject license (the addition is an exception). References
// that cannot be resolved produce an unknown license so allow lists fail.
func (g *spdx3Graph) resolveLicense(elementID string, depth int) []licenseEntry {
	if depth > maxLicenseDepth {
		return unknownLicense(elementID)
	}

	elem, ok := g.elements[elementID]
	if !ok {
		return externalLicense(elementID)
	}

	elemType := strings.ToLower(elem.elementType())

	switch {
	case elem.LicenseExpression != "":
		return []licenseEntry{{value: elem.LicenseExpression, expression: true}}

	case len(elem.LicenseMembers) > 0:
		var entries []licenseEntry
		for _, member := range elem.LicenseMembers {
			entries = append(entries, g.resolveLicense(member, depth+1)...)
		}

		return entries

	case strings.Contains(elemType, "orlateroperator"):
		return orLater(g.resolveLicense(elem.SubjectLicense, depth+1))

	case strings.Contains(elemType, "withadditionoperator"):
		return g.resolveLicense(elem.SubjectExtendableLicense, depth+1)

	default:
		return namedLicense(elem, elementID, elemType)
	}
}

// externalLicense resolves a license reference that is not an element of the
// graph: a listed license IRI, a NoAssertion or None individual, or an
// unresolvable reference.
func externalLicense(elementID string) []licenseEntry {
	if isNoLicenseIndividual(elementID) {
		return nil
	}

	if entries := licenseFromIRI(elementID); entries != nil {
		return entries
	}

	return unknownLicense(elementID)
}

// namedLicense resolves a license element by its listed license IRI or name.
func namedLicense(elem *spdx3Element, elementID, elemType string) []licenseEntry {
	if strings.Contains(elemType, "listedlicense") {
		if entries := licenseFromIRI(elementID); entries != nil {
			return entries
		}
	}

	return nameOrUnknown(elem.Name, elementID)
}

// orLater marks license identifiers as "or later" versions.
func orLater(entries []licenseEntry) []licenseEntry {
	for idx := range entries {
		if !strings.HasSuffix(entries[idx].value, "+") {
			entries[idx].value += "+"
		}
	}

	return entries
}

func isNoLicenseIndividual(id string) bool {
	return strings.HasSuffix(id, "NoAssertionLicense") || strings.HasSuffix(id, "NoneLicense")
}

func licenseFromIRI(id string) []licenseEntry {
	if isNoLicenseIndividual(id) {
		return nil
	}

	if after, found := strings.CutPrefix(id, spdxListedLicensesIRI); found && after != "" {
		return []licenseEntry{{value: after, expression: true}}
	}

	return nil
}

func nameOrUnknown(name, elementID string) []licenseEntry {
	if name == "" {
		return unknownLicense(elementID)
	}

	return []licenseEntry{{value: name, expression: false}}
}

// unknownLicense records a license reference that could not be resolved. It
// never matches a deny list entry but fails any allow list.
func unknownLicense(elementID string) []licenseEntry {
	return []licenseEntry{{value: unresolvedLicensePrefix + elementID, expression: false}}
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

func isSPDX3(raw *rawSBOM) bool {
	if strings.HasPrefix(raw.SpecVersion, "3.") && len(raw.Graph) > 0 {
		return true
	}

	return strings.Contains(string(raw.Context), "spdx.org") && len(raw.Graph) > 0
}

func isSPDX3Package(elemType string) bool {
	switch strings.ToLower(elemType) {
	case "software_softwarepackage", "softwarepackage", "software:softwarepackage",
		"software_package", "software:package":
		return true
	default:
		return false
	}
}

func isSPDX3PURL(eid *spdx3ExtIdentifier) bool {
	return strings.EqualFold(eid.IDType, "packageUrl") ||
		strings.EqualFold(eid.IDType, "purl")
}

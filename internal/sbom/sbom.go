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
	"maps"
	"net/url"
	"slices"
	"strings"
	"unicode"

	"github.com/saschagrunert/nri-supply-chain/internal/intoto"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/purl"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	checkType = types.CheckTypeSBOM

	noAssertionLicense = "NOASSERTION"

	formatSPDX      = "spdx"
	formatCycloneDX = "cyclonedx"

	metaKeyPURLs                 = "purls"
	metaKeyComponentsWithoutPURL = "componentsWithoutPURL"
	metaKeyFormat                = "format"
	metaKeyComponentCount        = "componentCount"
	metaKeyLicenseCount          = "licenseCount"

	// MaxMetadataPURLs caps the purls kept in check result metadata (and
	// therefore in the verification cache). When the cap is hit the list
	// ends with purl.TruncatedMarker so feed matching treats the image as
	// potentially affected by any feed entry.
	MaxMetadataPURLs = 10000

	// maxReportedMissingPURL caps component names listed in failure details.
	maxReportedMissingPURL = 5
)

var (
	// ErrInvalidSBOM indicates the SBOM document could not be parsed.
	ErrInvalidSBOM = errors.New("invalid SBOM document")

	// ErrUnsupportedFormat indicates the SBOM format is not recognized.
	ErrUnsupportedFormat = errors.New("unsupported SBOM format")
)

type sbomPackage struct {
	PURL      string
	Name      string
	Version   string
	Licenses  []string
	Checksums map[string]string
}

// licenseEntry is a license value found in an SBOM. Expressions are SPDX
// license expressions (or single identifiers) that are tokenized before
// matching; free-text license names are matched verbatim.
type licenseEntry struct {
	value      string
	expression bool
}

type sbomData struct {
	licenses       []licenseEntry
	uniqueLicenses map[string]struct{}
	purls          []string
	Packages       []sbomPackage
	format         string
	componentCount int
	licenseCount   int
	vulns          []cyclonedxVulnerability
	// missingPURL lists names of package components without a purl that
	// are not exempt (operating systems, files, document subjects).
	missingPURL []string
	// vulnerabilityOnly marks a CycloneDX document without inventory that
	// only carries unresolved vulnerabilities (see vulnerabilityOnlyData).
	vulnerabilityOnly bool
}

// rawSBOM decodes all supported SBOM formats in a single JSON pass. Only
// the fields used by the parsers are declared.
type rawSBOM struct {
	// SPDX 2.x
	SPDXVersion       string             `json:"spdxVersion"`
	DocumentDescribes []string           `json:"documentDescribes"`
	Packages          []spdxPackage      `json:"packages"`
	Relationships     []spdxRelationship `json:"relationships"`

	// SPDX 3.x (JSON-LD)
	Context     json.RawMessage `json:"@context"`
	SpecVersion string          `json:"specVersion"`
	Graph       []spdx3Element  `json:"@graph"`

	// CycloneDX
	BOMFormat       string                   `json:"bomFormat"`
	Metadata        *cyclonedxMetadata       `json:"metadata"`
	Components      []cyclonedxComponent     `json:"components"`
	Vulnerabilities []cyclonedxVulnerability `json:"vulnerabilities"`
}

func (d *sbomData) addLicense(value string, expression bool) {
	d.licenses = append(d.licenses, licenseEntry{value: value, expression: expression})

	if d.uniqueLicenses == nil {
		d.uniqueLicenses = make(map[string]struct{})
	}

	d.uniqueLicenses[value] = struct{}{}
	d.licenseCount = len(d.uniqueLicenses)
}

func (d *sbomData) addPackage(pkg *sbomPackage, exemptFromPURL bool) {
	if pkg.PURL == "" && !exemptFromPURL {
		d.missingPURL = append(d.missingPURL, pkg.Name)
	}

	d.Packages = append(d.Packages, *pkg)
}

// Verify checks a single SBOM attestation against the given policy.
func Verify(
	ctx context.Context,
	att []byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	ctxErr := ctx.Err()
	if ctxErr != nil {
		return nil, fmt.Errorf("verification cancelled: %w", ctxErr)
	}

	predicate, err := intoto.VerifySubjectAndExtractPredicate(att, imageDigest)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSBOM, err)
	}

	result, _, err := verifySBOMPredicateWithData(predicate, pol)
	if err != nil {
		return nil, err
	}

	finalizeMetadata(result.Metadata)

	return result, nil
}

// VerifyMultiple checks multiple SBOM attestations. Every document must parse
// and pass; any denied license or component in any document causes failure.
//
// CycloneDX documents without components and subject (for example VEX-only
// documents) are skipped. When no attestation is an SBOM, the returned error
// wraps types.ErrNotApplicable so the missing policy applies.
func VerifyMultiple(
	ctx context.Context,
	attestations [][]byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	verifyResult, err := verifyAllAttestations(ctx, attestations, pol, imageDigest)
	if err != nil {
		return nil, err
	}

	return verifyResult.checkResult(), nil
}

// VerifyMultipleWithBaseline checks multiple SBOM attestations and performs
// drift detection against baseline SBOM documents. When drift thresholds are
// configured, a missing or unparsable baseline fails the check.
func VerifyMultipleWithBaseline(
	ctx context.Context,
	attestations, baselinePayloads [][]byte,
	pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	verifyResult, err := verifyAllAttestations(ctx, attestations, pol, imageDigest)
	if err != nil {
		return nil, err
	}

	result := verifyResult.checkResult()
	if !result.Passed || verifyResult.evaluated == 0 {
		return result, nil
	}

	return applyDriftDetection(
		ctx, result, verifyResult.currentPackages, baselinePayloads, pol,
	)
}

type attestationVerifyResult struct {
	failDetails     []string
	verifyErrors    []string
	passedMeta      map[string]any
	currentPackages []sbomPackage
	// licenses is the union of license identifiers of passing documents.
	licenses map[string]struct{}
	// evaluated counts the attestations that are SBOM documents.
	evaluated int
}

func (r *attestationVerifyResult) checkResult() *types.CheckResult {
	if len(r.failDetails) > 0 || len(r.verifyErrors) > 0 {
		details := slices.Clone(r.failDetails)

		if len(r.verifyErrors) > 0 {
			details = append(details, fmt.Sprintf(
				"%d of %d SBOM documents failed verification: %s",
				len(r.verifyErrors), r.evaluated, strings.Join(r.verifyErrors, "; "),
			))
		}

		return check.Fail(strings.Join(details, "; "))
	}

	result := check.Pass()
	result.Metadata = r.passedMeta

	if result.Metadata != nil {
		result.Metadata[metaKeyLicenseCount] = int64(len(r.licenses))
	}

	finalizeMetadata(result.Metadata)

	return result
}

func verifyAllAttestations(
	ctx context.Context,
	attestations [][]byte, pol *policy.Policy, imageDigest string,
) (*attestationVerifyResult, error) {
	var verifyResult attestationVerifyResult

	notApplicable := 0

	for _, att := range attestations {
		ctxErr := ctx.Err()
		if ctxErr != nil {
			return nil, fmt.Errorf("verification cancelled: %w", ctxErr)
		}

		if !verifyResult.add(att, pol, imageDigest) {
			notApplicable++
		}
	}

	if len(attestations) > 0 && notApplicable == len(attestations) {
		return nil, fmt.Errorf(
			"%w: %d CycloneDX documents without components or subject",
			types.ErrNotApplicable, notApplicable,
		)
	}

	return &verifyResult, nil
}

// add verifies one attestation and records its outcome. It returns false when
// the attestation is not an SBOM document (see errNoSBOMContent).
func (r *attestationVerifyResult) add(att []byte, pol *policy.Policy, imageDigest string) bool {
	predicate, err := intoto.VerifySubjectAndExtractPredicate(att, imageDigest)
	if err != nil {
		r.evaluated++
		r.verifyErrors = append(r.verifyErrors, fmt.Errorf("%w: %w", ErrInvalidSBOM, err).Error())

		return true
	}

	checkResult, data, verifyErr := verifySBOMPredicateWithData(predicate, pol)
	if errors.Is(verifyErr, types.ErrNotApplicable) {
		return false
	}

	// A vulnerability-only document within the CVSS thresholds is still not
	// an SBOM: it contributes its CVSS statistics but no inventory, and it
	// does not count as present for sbom.missingPolicy.
	if verifyErr == nil && data.vulnerabilityOnly && checkResult.Passed {
		r.addCVSSMeta(checkResult.Metadata)

		return false
	}

	r.evaluated++

	switch {
	case verifyErr != nil:
		r.verifyErrors = append(r.verifyErrors, verifyErr.Error())
	case !checkResult.Passed:
		r.failDetails = append(r.failDetails, checkResult.Detail)
	default:
		r.addPassed(checkResult, &data)
	}

	return true
}

func (r *attestationVerifyResult) addCVSSMeta(meta map[string]any) {
	if len(meta) == 0 {
		return
	}

	if r.passedMeta == nil {
		r.passedMeta = make(map[string]any)
	}

	mergeCVSSMeta(r.passedMeta, meta)
}

func (r *attestationVerifyResult) addPassed(checkResult *types.CheckResult, data *sbomData) {
	r.currentPackages = append(r.currentPackages, data.Packages...)

	if r.licenses == nil {
		r.licenses = make(map[string]struct{})
	}

	maps.Copy(r.licenses, data.uniqueLicenses)

	if checkResult.Metadata == nil {
		return
	}

	if r.passedMeta == nil {
		r.passedMeta = make(map[string]any)
	}

	mergeCVSSMeta(r.passedMeta, checkResult.Metadata)
}

func applyDriftDetection(
	ctx context.Context,
	result *types.CheckResult,
	currentPackages []sbomPackage,
	baselinePayloads [][]byte,
	pol *policy.Policy,
) (*types.CheckResult, error) {
	baselines, err := parseBaselines(ctx, baselinePayloads)
	if err != nil {
		return nil, err
	}

	driftCheck := evaluateDrift(currentPackages, baselines, pol)
	if driftCheck == nil {
		return result, nil
	}

	if result.Metadata == nil {
		result.Metadata = make(map[string]any)
	}

	if driftMeta, hasDrift := driftCheck.Metadata["drift"]; hasDrift {
		result.Metadata["drift"] = driftMeta
	}

	if !driftCheck.Passed {
		result.Passed = false
		result.Status = driftCheck.Status
		result.Detail = driftCheck.Detail
	}

	return result, nil
}

// driftThresholdsConfigured reports whether the policy sets any drift
// threshold, which makes a baseline mandatory.
func driftThresholdsConfigured(pol *policy.Policy) bool {
	if pol == nil || pol.SBOM == nil || pol.SBOM.Drift == nil {
		return false
	}

	drift := pol.SBOM.Drift

	return drift.MaxAdded != nil || drift.MaxRemoved != nil ||
		drift.MaxModified != nil || drift.MaxScore != nil
}

// baselineSet holds the parsed baseline SBOMs for drift detection.
type baselineSet struct {
	packages    []sbomPackage
	parseErrors []string
	total       int
}

func parseBaselines(ctx context.Context, payloads [][]byte) (*baselineSet, error) {
	baselines := &baselineSet{packages: nil, parseErrors: nil, total: len(payloads)}

	for _, payload := range payloads {
		ctxErr := ctx.Err()
		if ctxErr != nil {
			return nil, fmt.Errorf("verification cancelled: %w", ctxErr)
		}

		data, err := extractSBOMData(payload, nil)
		if err != nil {
			baselines.parseErrors = append(baselines.parseErrors, err.Error())

			continue
		}

		baselines.packages = append(baselines.packages, data.Packages...)
	}

	return baselines, nil
}

// evaluateDrift compares the current packages with the baselines. It returns
// nil when drift detection is skipped, which only happens when no thresholds
// are configured. With thresholds, a missing or unparsable baseline fails.
func evaluateDrift(
	currentPackages []sbomPackage, baselines *baselineSet, pol *policy.Policy,
) *types.CheckResult {
	required := driftThresholdsConfigured(pol)

	switch {
	case baselines.total == 0 && required:
		return check.Fail("SBOM drift thresholds are configured but no baseline SBOM was found")

	case (len(baselines.parseErrors) > 0 || len(baselines.packages) == 0) && required:
		return check.Fail(fmt.Sprintf(
			"SBOM drift detection failed: %d of %d baseline SBOMs could not be parsed: %s",
			len(baselines.parseErrors), baselines.total,
			strings.Join(baselines.parseErrors, "; "),
		))

	case len(baselines.packages) == 0:
		// Informational drift only: nothing usable to compare against.
		return nil
	}

	drift := computeDrift(baselines.packages, currentPackages)
	driftMeta := drift.ToMetadata()

	if required {
		thresholdResult := checkDriftThresholds(&drift, pol.SBOM.Drift)
		if thresholdResult != nil {
			thresholdResult.Metadata = map[string]any{"drift": driftMeta}

			return thresholdResult
		}
	}

	result := check.Pass()
	result.Metadata = map[string]any{"drift": driftMeta}

	return result
}

func verifySBOMPredicateWithData(
	predicate []byte, pol *policy.Policy,
) (*types.CheckResult, sbomData, error) {
	data, err := extractSBOMData(predicate, pol)
	if err != nil {
		return nil, sbomData{}, err
	}

	if data.vulnerabilityOnly {
		return verifyVulnerabilityOnly(&data, pol)
	}

	result := checkDenyLists(&data, pol)
	result.Metadata = map[string]any{
		metaKeyFormat:                data.format,
		metaKeyComponentCount:        int64(data.componentCount),
		metaKeyLicenseCount:          int64(data.licenseCount),
		metaKeyComponentsWithoutPURL: int64(len(data.missingPURL)),
		metaKeyPURLs:                 compactPURLs(data.purls),
	}

	if !result.Passed {
		return result, data, nil
	}

	if data.format == formatCycloneDX && pol.SBOM != nil && pol.SBOM.CVSS != nil {
		cvssResult := checkCVSSThresholds(data.vulns, pol.SBOM.CVSS)
		if !cvssResult.Passed {
			maps.Copy(cvssResult.Metadata, result.Metadata)

			return cvssResult, data, nil
		}

		maps.Copy(result.Metadata, cvssResult.Metadata)
	}

	return result, data, nil
}

// verifyVulnerabilityOnly evaluates the findings of a vulnerability-only
// document against sbom.cvss. The result carries only CVSS metadata, since
// the document has no inventory. Without CVSS thresholds there is nothing to
// evaluate, and the document is not applicable.
func verifyVulnerabilityOnly(
	data *sbomData, pol *policy.Policy,
) (*types.CheckResult, sbomData, error) {
	if pol == nil || pol.SBOM == nil || pol.SBOM.CVSS == nil {
		return nil, sbomData{}, errNoSBOMContent
	}

	return checkCVSSThresholds(data.vulns, pol.SBOM.CVSS), *data, nil
}

// decodeRawSBOM decodes a predicate once into the union of all supported
// SBOM formats.
func decodeRawSBOM(predicate []byte) (*rawSBOM, error) {
	var raw rawSBOM

	err := json.Unmarshal(predicate, &raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSBOM, err)
	}

	return &raw, nil
}

func extractSBOMData(
	predicate []byte, pol *policy.Policy,
) (sbomData, error) {
	raw, err := decodeRawSBOM(predicate)
	if err != nil {
		return sbomData{}, err
	}

	spdx3, spdx3Err := spdx3FromRaw(raw)
	if spdx3Err == nil {
		err = setFormat(&spdx3, formatSPDX, pol)

		return spdx3, err
	}

	spdx, spdxErr := spdxFromRaw(raw)
	if spdxErr == nil {
		err = setFormat(&spdx, formatSPDX, pol)

		return spdx, err
	}

	cdx, cdxErr := cyclonedxFromRaw(raw)
	if cdxErr == nil && cdx.vulnerabilityOnly {
		// Not an SBOM, so the allowed SBOM formats don't apply.
		cdx.format = formatCycloneDX

		return cdx, nil
	}

	if cdxErr == nil {
		err = setFormat(&cdx, formatCycloneDX, pol)

		return cdx, err
	}

	if errors.Is(cdxErr, types.ErrNotApplicable) {
		return sbomData{}, cdxErr
	}

	return sbomData{}, fmt.Errorf(
		"%w: not valid SPDX 3.0 (%w), SPDX 2.x (%w), or CycloneDX (%w)",
		ErrInvalidSBOM, spdx3Err, spdxErr, cdxErr,
	)
}

func setFormat(data *sbomData, format string, pol *policy.Policy) error {
	if !formatAllowed(pol, format) {
		return fmt.Errorf("%w: %s not in allowed formats", ErrUnsupportedFormat, format)
	}

	data.format = format

	return nil
}

func formatAllowed(pol *policy.Policy, format string) bool {
	if pol == nil || pol.SBOM == nil || len(pol.SBOM.Formats) == 0 {
		return true
	}

	for _, allowed := range pol.SBOM.Formats {
		if strings.EqualFold(allowed, format) {
			return true
		}
	}

	return false
}

// compactPURLs strips qualifiers and subpaths, deduplicates, sorts, and caps
// the purl list stored in metadata. Feed matching only needs the package
// identity and version, plus the upstream qualifier that names the source
// package distribution feeds refer to.
func compactPURLs(purls []string) []string {
	compacted := make([]string, 0, len(purls))
	for _, raw := range purls {
		compacted = append(compacted, compactPURL(raw))
	}

	slices.Sort(compacted)

	return slices.Compact(compacted)
}

// compactPURL strips all qualifiers except "upstream" and the subpath.
func compactPURL(raw string) string {
	stripped := purl.StripQualifiers(raw)

	// Qualifier keys are case-insensitive, like in purl.Parse.
	if !strings.Contains(strings.ToLower(raw), "upstream=") {
		return stripped
	}

	parsed, err := purl.Parse(raw)
	if err != nil {
		return stripped
	}

	upstream := parsed.Qualifiers["upstream"]
	if upstream == "" {
		return stripped
	}

	return stripped + "?upstream=" + url.PathEscape(upstream)
}

// finalizeMetadata applies the purl cap once all documents are merged.
func finalizeMetadata(meta map[string]any) {
	if meta == nil {
		return
	}

	purls := toStringSlice(meta[metaKeyPURLs])
	if len(purls) <= MaxMetadataPURLs {
		return
	}

	capped := make([]string, 0, MaxMetadataPURLs+1)
	capped = append(capped, purls[:MaxMetadataPURLs]...)
	capped = append(capped, purl.TruncatedMarker)
	meta[metaKeyPURLs] = capped
}

func checkDenyLists(data *sbomData, pol *policy.Policy) *types.CheckResult {
	if pol == nil || pol.SBOM == nil {
		return check.Pass()
	}

	result := checkLicensePolicy(data.licenses, pol.SBOM.License)
	if result != nil {
		return result
	}

	result = checkComponentPolicy(data, pol.SBOM.Component)
	if result != nil {
		return result
	}

	return check.Pass()
}

func checkLicensePolicy(
	licenses []licenseEntry, licPolicy *policy.SBOMLicensePolicy,
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
	licenses []licenseEntry, denyList []string,
) *types.CheckResult {
	if len(denyList) == 0 {
		return nil
	}

	for idx := range licenses {
		for _, id := range licenseIdentifiers(&licenses[idx]) {
			if licenseDenied(id, denyList) {
				return check.Fail(fmt.Sprintf("SBOM contains denied license %q", id))
			}
		}
	}

	return nil
}

func checkLicenseAllowList(
	licenses []licenseEntry, allowList []string,
) *types.CheckResult {
	if len(allowList) == 0 {
		return nil
	}

	for idx := range licenses {
		for _, id := range licenseIdentifiers(&licenses[idx]) {
			if !licenseAllowed(id, allowList) {
				return check.Fail(fmt.Sprintf(
					"SBOM contains license %q not in allow list", id,
				))
			}
		}
	}

	return nil
}

func licenseIdentifiers(entry *licenseEntry) []string {
	if !entry.expression {
		return []string{strings.TrimSpace(entry.value)}
	}

	return splitSPDXExpression(entry.value)
}

// licenseForm is a license identifier reduced to its base license and
// whether it covers later versions. "GPL-2.0", "GPL-2.0-only" and
// "gpl-2.0-only" share a form; "GPL-2.0+", "GPL-2.0-or-later" and the SPDX 3
// "GPL-2.0-only+" share another one with the same base.
type licenseForm struct {
	base    string
	orLater bool
}

func parseLicenseForm(id string) licenseForm {
	normalized := strings.ToLower(strings.TrimSpace(strings.Map(dropInvisible, id)))

	// Custom license references are opaque names: "-only" or "-or-later" in
	// them carries no SPDX version semantics.
	if strings.HasPrefix(normalized, "licenseref-") ||
		strings.HasPrefix(normalized, "documentref-") {
		return licenseForm{base: normalized, orLater: false}
	}

	base, orLater := strings.CutSuffix(normalized, "+")

	if trimmed, found := strings.CutSuffix(base, "-or-later"); found {
		base, orLater = trimmed, true
	}

	base = strings.TrimSuffix(base, "-only")

	if base == "" {
		return licenseForm{base: normalized, orLater: false}
	}

	return licenseForm{base: base, orLater: orLater}
}

// licenseDenied reports whether a license identifier matches a deny list.
// Identifiers are compared by base license, so a deny entry covers the
// deprecated, "-only" and "or later" forms alike: an "or later" license
// can be used under the denied version, and denying "-or-later" also denies
// the version it starts from.
func licenseDenied(id string, denyList []string) bool {
	form := parseLicenseForm(id)

	for _, entry := range denyList {
		if parseLicenseForm(entry).base == form.base {
			return true
		}
	}

	return false
}

// licenseAllowed reports whether a license identifier is in an allow list.
// The deprecated and "-only" forms are equivalent, but an "or later"
// identifier is only allowed by an "or later" entry: the narrower "-only"
// identifier does not cover later versions, and the reverse is kept strict
// as well.
func licenseAllowed(id string, allowList []string) bool {
	form := parseLicenseForm(id)

	for _, entry := range allowList {
		if parseLicenseForm(entry) == form {
			return true
		}
	}

	return false
}

// invisibleSeparators are zero-width and byte-order characters that render
// as nothing and must not glue license identifiers together or hide them.
const invisibleSeparators = "\u200b\u200c\u200d\u2060\ufeff"

// dropInvisible removes invisible separator characters from an identifier.
func dropInvisible(char rune) rune {
	if strings.ContainsRune(invisibleSeparators, char) {
		return -1
	}

	return char
}

// isLicenseException reports whether a token following WITH is an SPDX
// license exception (or a custom addition) rather than a license. Anything
// else is checked like a license so "MIT WITH GPL-3.0-only" cannot hide a
// denied identifier.
func isLicenseException(token string) bool {
	lower := strings.ToLower(token)

	return strings.Contains(lower, "exception") ||
		strings.HasSuffix(lower, "-note") ||
		strings.HasPrefix(lower, "additionref-")
}

// splitSPDXExpression extracts license identifiers from an SPDX license
// expression. Parentheses and any Unicode whitespace are token boundaries,
// operators are matched case-insensitively, and exception identifiers
// following WITH are skipped. Invisible characters are ambiguous: they may
// hide a separator ("MIT<ZWSP>AND<ZWSP>GPL-3.0-only") or split an identifier
// ("GPL<ZWSP>-3.0-only"), so the expression is split both ways and the
// identifiers of both readings are returned.
func splitSPDXExpression(expr string) []string {
	ids := splitSPDXTokens(expr, tokenizeSPDXExpression(expr))

	if strings.ContainsAny(expr, invisibleSeparators) {
		joined := strings.Map(dropInvisible, expr)

		for _, id := range splitSPDXTokens(joined, tokenizeSPDXExpression(joined)) {
			if !slices.Contains(ids, id) {
				ids = append(ids, id)
			}
		}
	}

	return ids
}

// splitSPDXTokens extracts license identifiers from the tokens of expr.
func splitSPDXTokens(expr string, tokens []string) []string {
	var (
		ids       []string
		afterWith bool
	)

	for _, tok := range tokens {
		switch strings.ToUpper(tok) {
		case "(", ")", "AND", "OR":
			afterWith = false

			continue
		case "WITH":
			afterWith = true

			continue
		}

		if afterWith {
			afterWith = false

			if isLicenseException(tok) {
				continue
			}
		}

		ids = append(ids, tok)
	}

	if len(ids) == 0 {
		trimmed := strings.TrimSpace(expr)
		if trimmed == "" {
			return nil
		}

		return []string{trimmed}
	}

	return ids
}

func tokenizeSPDXExpression(expr string) []string {
	var (
		tokens  []string
		current strings.Builder
	)

	flush := func() {
		if current.Len() > 0 {
			tokens = append(tokens, current.String())
			current.Reset()
		}
	}

	for _, char := range expr {
		switch {
		case char == '(' || char == ')':
			flush()

			tokens = append(tokens, string(char))
		case unicode.IsSpace(char) || strings.ContainsRune(invisibleSeparators, char):
			flush()
		default:
			current.WriteRune(char)
		}
	}

	flush()

	return tokens
}

func checkComponentPolicy(
	data *sbomData, compPolicy *policy.SBOMComponentPolicy,
) *types.CheckResult {
	if compPolicy == nil {
		return nil
	}

	// Deny takes precedence: check deny list first.
	denied := checkComponentDenyList(data.purls, compPolicy.Deny)
	if denied != nil {
		return denied
	}

	if len(compPolicy.Allow) > 0 && len(data.missingPURL) > 0 {
		return check.Fail(fmt.Sprintf(
			"SBOM contains %d package components without a purl that cannot be "+
				"checked against the component allow list: %s",
			len(data.missingPURL), summarizeNames(data.missingPURL),
		))
	}

	return checkComponentAllowList(data.purls, compPolicy.Allow)
}

func summarizeNames(names []string) string {
	if len(names) <= maxReportedMissingPURL {
		return strings.Join(names, ", ")
	}

	return strings.Join(names[:maxReportedMissingPURL], ", ") +
		fmt.Sprintf(" and %d more", len(names)-maxReportedMissingPURL)
}

func checkComponentDenyList(
	purls, denyList []string,
) *types.CheckResult {
	if len(denyList) == 0 {
		return nil
	}

	for _, purlValue := range purls {
		for _, denied := range denyList {
			if strings.HasPrefix(purlValue, denied) {
				return check.Fail(fmt.Sprintf(
					"SBOM contains denied component %q", purlValue,
				))
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

	for _, purlValue := range purls {
		if !componentInList(purlValue, allowList) {
			return check.Fail(fmt.Sprintf(
				"SBOM contains component %q not in allow list", purlValue,
			))
		}
	}

	return nil
}

func componentInList(purlValue string, list []string) bool {
	for _, entry := range list {
		if strings.HasPrefix(purlValue, entry) {
			return true
		}
	}

	return false
}

var check = types.Checker{ //nolint:gochecknoglobals,gosec // package-scoped helper
	Type:    checkType,
	PassMsg: "SBOM verification passed",
}

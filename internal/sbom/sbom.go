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

const noAssertionLicense = "NOASSERTION"

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
)

type sbomPackage struct {
	PURL      string
	Name      string
	Version   string
	Licenses  []string
	Checksums map[string]string
}

type sbomData struct {
	licenses       []string
	purls          []string
	Packages       []sbomPackage
	format         string
	componentCount int
	licenseCount   int
	vulns          []cyclonedxVulnerability
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

	return verifySBOMPredicate(predicate, pol)
}

// VerifyMultiple checks multiple SBOM attestations. Any denied license or
// component in any document causes failure.
func VerifyMultiple(
	ctx context.Context,
	attestations [][]byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	return types.VerifyMultipleWithMerge( //nolint:wrapcheck // direct delegation to shared helper
		ctx, checkType, "SBOM", check.PassMsg, attestations,
		func(att []byte) (*types.CheckResult, error) {
			return Verify(ctx, att, pol, imageDigest)
		},
		mergeCVSSMeta,
	)
}

// VerifyMultipleWithBaseline checks multiple SBOM attestations and optionally
// performs drift detection against baseline SBOM documents.
func VerifyMultipleWithBaseline(
	ctx context.Context,
	attestations, baselinePayloads [][]byte,
	pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	verifyResult, err := verifyAllAttestations(ctx, attestations, pol, imageDigest)
	if err != nil {
		return nil, err
	}

	if len(verifyResult.failDetails) > 0 {
		return check.Fail(strings.Join(verifyResult.failDetails, "; ")), nil
	}

	if len(attestations) > 0 && !verifyResult.anyValid {
		return check.Fail(
			"all SBOM documents failed verification: " +
				strings.Join(verifyResult.verifyErrors, "; "),
		), nil
	}

	result := check.Pass()
	result.Metadata = verifyResult.passedMeta

	return applyDriftDetection(
		result, verifyResult.currentPackages, baselinePayloads, pol,
	), nil
}

type attestationVerifyResult struct {
	failDetails     []string
	verifyErrors    []string
	anyValid        bool
	passedMeta      map[string]any
	currentPackages []sbomPackage
}

func verifyAllAttestations(
	ctx context.Context,
	attestations [][]byte, pol *policy.Policy, imageDigest string,
) (*attestationVerifyResult, error) {
	var verifyResult attestationVerifyResult

	for _, att := range attestations {
		ctxErr := ctx.Err()
		if ctxErr != nil {
			return nil, fmt.Errorf("verification cancelled: %w", ctxErr)
		}

		predicate, err := intoto.VerifySubjectAndExtractPredicate(att, imageDigest)
		if err != nil {
			verifyResult.verifyErrors = append(
				verifyResult.verifyErrors,
				fmt.Errorf("%w: %w", ErrInvalidSBOM, err).Error(),
			)

			continue
		}

		checkResult, data, verifyErr := verifySBOMPredicateWithData(predicate, pol)
		if verifyErr != nil {
			verifyResult.verifyErrors = append(verifyResult.verifyErrors, verifyErr.Error())

			continue
		}

		verifyResult.anyValid = true

		if !checkResult.Passed && checkResult.Status == types.StatusFail {
			verifyResult.failDetails = append(verifyResult.failDetails, checkResult.Detail)
		}

		if checkResult.Passed {
			verifyResult.currentPackages = append(
				verifyResult.currentPackages, data.Packages...,
			)

			if checkResult.Metadata != nil {
				if verifyResult.passedMeta == nil {
					verifyResult.passedMeta = make(map[string]any)
				}

				mergeCVSSMeta(verifyResult.passedMeta, checkResult.Metadata)
			}
		}
	}

	return &verifyResult, nil
}

func applyDriftDetection(
	result *types.CheckResult,
	currentPackages []sbomPackage,
	baselinePayloads [][]byte,
	pol *policy.Policy,
) *types.CheckResult {
	driftCheck := runDriftDetection(currentPackages, baselinePayloads, pol)
	if driftCheck == nil {
		return result
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

		return result
	}

	return result
}

func runDriftDetection(
	currentPackages []sbomPackage,
	baselinePayloads [][]byte,
	pol *policy.Policy,
) *types.CheckResult {
	if len(baselinePayloads) == 0 {
		return nil
	}

	var baselinePackages []sbomPackage

	for _, payload := range baselinePayloads {
		data, err := extractSBOMData(payload, nil)
		if err != nil {
			slog.Warn("Failed to parse baseline SBOM, skipping", "error", err)

			continue
		}

		baselinePackages = append(baselinePackages, data.Packages...)
	}

	if len(baselinePackages) == 0 {
		slog.Warn(
			"Baseline SBOM referrers found but none parsed, skipping drift detection",
			"baselineCount", len(baselinePayloads),
		)

		return nil
	}

	drift := computeDrift(baselinePackages, currentPackages)
	driftMeta := drift.ToMetadata()

	if pol.SBOM != nil && pol.SBOM.Drift != nil {
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

func verifySBOMPredicate(
	predicate []byte, pol *policy.Policy,
) (*types.CheckResult, error) {
	result, _, err := verifySBOMPredicateWithData(predicate, pol)

	return result, err
}

func verifySBOMPredicateWithData(
	predicate []byte, pol *policy.Policy,
) (*types.CheckResult, sbomData, error) {
	data, err := extractSBOMData(predicate, pol)
	if err != nil {
		return nil, sbomData{}, err
	}

	result := checkDenyLists(data.licenses, data.purls, pol)
	result.Metadata = map[string]any{
		"format":         data.format,
		"componentCount": int64(data.componentCount),
		"licenseCount":   int64(data.licenseCount),
		"purls":          data.purls,
	}

	if !result.Passed {
		return result, data, nil
	}

	if data.format == "cyclonedx" && pol.SBOM != nil && pol.SBOM.CVSS != nil {
		cvssResult := checkCVSSThresholds(data.vulns, pol.SBOM.CVSS)
		if !cvssResult.Passed {
			maps.Copy(cvssResult.Metadata, result.Metadata)

			return cvssResult, data, nil
		}

		maps.Copy(result.Metadata, cvssResult.Metadata)
	}

	return result, data, nil
}

func extractSBOMData(
	predicate []byte, pol *policy.Policy,
) (sbomData, error) {
	spdx3, spdx3Err := parseSPDX3(predicate)
	if spdx3Err == nil {
		if !formatAllowed(pol, "spdx") {
			return sbomData{}, fmt.Errorf(
				"%w: spdx not in allowed formats", ErrUnsupportedFormat,
			)
		}

		spdx3.format = "spdx"

		return spdx3, nil
	}

	spdx, spdxErr := parseSPDX(predicate)
	if spdxErr == nil {
		if !formatAllowed(pol, "spdx") {
			return sbomData{}, fmt.Errorf(
				"%w: spdx not in allowed formats", ErrUnsupportedFormat,
			)
		}

		spdx.format = "spdx"

		return spdx, nil
	}

	cdx, cdxErr := parseCycloneDX(predicate)
	if cdxErr == nil {
		if !formatAllowed(pol, "cyclonedx") {
			return sbomData{}, fmt.Errorf(
				"%w: cyclonedx not in allowed formats", ErrUnsupportedFormat,
			)
		}

		cdx.format = "cyclonedx"

		return cdx, nil
	}

	return sbomData{}, fmt.Errorf(
		"%w: not valid SPDX 3.0 (%w), SPDX 2.x (%w), or CycloneDX (%w)",
		ErrInvalidSBOM, spdx3Err, spdxErr, cdxErr,
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

func checkDenyLists(
	licenses, purls []string, pol *policy.Policy,
) *types.CheckResult {
	if pol.SBOM == nil {
		return check.Pass()
	}

	result := checkLicensePolicy(licenses, pol.SBOM.License)
	if result != nil {
		return result
	}

	result = checkComponentPolicy(purls, pol.SBOM.Component)
	if result != nil {
		return result
	}

	return check.Pass()
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

					return check.Fail(detail)
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

				return check.Fail(detail)
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

				return check.Fail(detail)
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

			return check.Fail(detail)
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

var check = types.Checker{ //nolint:gochecknoglobals,gosec // package-scoped helper
	Type:    checkType,
	PassMsg: "SBOM verification passed",
}

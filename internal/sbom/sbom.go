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

type sbomData struct {
	licenses       []string
	purls          []string
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

func verifySBOMPredicate(
	predicate []byte, pol *policy.Policy,
) (*types.CheckResult, error) {
	data, err := extractSBOMData(predicate, pol)
	if err != nil {
		return nil, err
	}

	result := checkDenyLists(data.licenses, data.purls, pol)
	result.Metadata = map[string]any{
		"format":         data.format,
		"componentCount": int64(data.componentCount),
		"licenseCount":   int64(data.licenseCount),
	}

	if !result.Passed {
		return result, nil
	}

	if data.format == "cyclonedx" && pol.SBOM != nil && pol.SBOM.CVSS != nil {
		cvssResult := checkCVSSThresholds(data.vulns, pol.SBOM.CVSS)
		if !cvssResult.Passed {
			maps.Copy(cvssResult.Metadata, result.Metadata)

			return cvssResult, nil
		}

		maps.Copy(result.Metadata, cvssResult.Metadata)
	}

	return result, nil
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

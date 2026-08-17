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

// Package vex provides VEX verification for supply chain attestations.
// It supports both OpenVEX and CycloneDX VEX formats, dispatching
// automatically based on the document content.
package vex

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/saschagrunert/nri-supply-chain/internal/intoto"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
	"github.com/saschagrunert/nri-supply-chain/internal/vex/cyclonedxvex"
	"github.com/saschagrunert/nri-supply-chain/internal/vex/openvex"
)

const (
	checkType                = types.CheckTypeVEX
	metaKeyStatus            = "status"
	statusAffected           = "affected"
	statusNotAffected        = "not_affected"
	statusUnderInvestigation = "under_investigation"
)

// ErrInvalidVEX indicates the VEX document could not be parsed.
var ErrInvalidVEX = errors.New("invalid VEX document")

// formatHint is used for lightweight format detection on the predicate JSON.
type formatHint struct {
	// OpenVEX documents contain a @context field.
	Context string `json:"@context"`
	// CycloneDX BOMs contain a bomFormat field.
	BOMFormat string `json:"bomFormat"`
}

// Verify checks a VEX attestation against the given policy.
// It auto-detects whether the predicate is OpenVEX or CycloneDX format.
// When parsedImageRef is non-nil it is used instead of re-parsing imageRef.
func Verify(
	ctx context.Context,
	att []byte, pol *policy.Policy, imageRef, imageDigest string,
	parsedImageRef name.Reference,
) (*types.CheckResult, error) {
	predicate, err := intoto.VerifySubjectAndExtractPredicate(att, imageDigest)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidVEX, err)
	}

	purl := buildOCIPURL(imageRef, imageDigest, parsedImageRef)

	affectedNames, hasUnderInvestigation, err := verifyPredicate(
		ctx, predicate, imageDigest, purl,
	)
	if err != nil {
		return nil, err
	}

	return buildResult(affectedNames, hasUnderInvestigation, pol), nil
}

// verifyPredicate dispatches to the appropriate format handler based on
// document content. It tries OpenVEX first (check for @context), then
// CycloneDX (check for bomFormat == "CycloneDX"). If neither matches,
// it falls back to OpenVEX parsing.
func verifyPredicate(
	ctx context.Context,
	predicate []byte,
	imageDigest, purl string,
) (affectedNames []string, hasUnderInvestigation bool, err error) {
	var hint formatHint

	// Best-effort hint detection; ignore errors (invalid JSON will fail in the parser).
	_ = json.Unmarshal(predicate, &hint)

	if hint.BOMFormat == "CycloneDX" {
		return verifyCycloneDX(predicate, imageDigest, purl)
	}

	// Default to OpenVEX (either @context is present, or we let the parser
	// report the error for unrecognized content).
	return verifyOpenVEX(ctx, predicate, imageDigest, purl)
}

func verifyOpenVEX(
	ctx context.Context,
	predicate []byte,
	imageDigest, purl string,
) (affectedNames []string, hasUnderInvestigation bool, err error) {
	result, err := openvex.Verify(ctx, predicate, imageDigest, purl)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %w", ErrInvalidVEX, err)
	}

	return result.AffectedNames, result.HasUnderInvestigation, nil
}

func verifyCycloneDX(
	predicate []byte,
	imageDigest, purl string,
) (affectedNames []string, hasUnderInvestigation bool, err error) {
	result, err := cyclonedxvex.Verify(predicate, imageDigest, purl)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %w", ErrInvalidVEX, err)
	}

	return result.AffectedNames, result.HasUnderInvestigation, nil
}

// buildOCIPURL constructs an OCI Package URL for the given image.
func buildOCIPURL(imageRef, imageDigest string, parsedImageRef name.Reference) string {
	ref := parsedImageRef
	if ref == nil {
		var err error

		ref, err = name.ParseReference(imageRef)
		if err != nil {
			slog.Debug("Failed to parse image reference for PURL construction",
				"image", imageRef,
				"error", err,
			)

			return ""
		}
	}

	repo := ref.Context()
	repoStr := repo.RepositoryStr()

	lastSlash := strings.LastIndex(repoStr, "/")

	var imgName, namespace string

	if lastSlash >= 0 {
		imgName = repoStr[lastSlash+1:]
		namespace = repoStr[:lastSlash]
	} else {
		imgName = repoStr
	}

	repoURL := repo.RegistryStr()
	if namespace != "" {
		repoURL += "/" + namespace
	}

	return fmt.Sprintf(
		"pkg:oci/%s@%s?repository_url=%s",
		imgName, imageDigest, url.QueryEscape(repoURL),
	)
}

func buildResult(
	affectedNames []string,
	hasUnderInvestigation bool,
	pol *policy.Policy,
) *types.CheckResult {
	if len(affectedNames) > 0 {
		detail := fmt.Sprintf(
			"vulnerabilities %s have status %q",
			strings.Join(affectedNames, ", "), statusAffected,
		)

		result := check.Fail(detail)
		result.Metadata = map[string]any{metaKeyStatus: statusAffected}

		return result
	}

	if hasUnderInvestigation {
		result := handleUnderInvestigation(pol)
		result.Metadata = map[string]any{metaKeyStatus: statusUnderInvestigation}

		return result
	}

	result := check.Pass()
	result.Metadata = map[string]any{metaKeyStatus: statusNotAffected}

	return result
}

// VerifyMultiple checks multiple VEX documents. Most restrictive wins:
// any affected statement causes failure.
// When parsedImageRef is non-nil it is used instead of re-parsing imageRef.
func VerifyMultiple(
	ctx context.Context,
	attestations [][]byte,
	pol *policy.Policy,
	imageRef, imageDigest string,
	parsedImageRef name.Reference,
) (*types.CheckResult, error) {
	var (
		failDetails           []string
		parseErrors           []string
		anyUnderInvestigation bool
		anyValid              bool
	)

	for _, att := range attestations {
		result, err := Verify(ctx, att, pol, imageRef, imageDigest, parsedImageRef)
		if err != nil {
			parseErrors = append(parseErrors, err.Error())

			continue
		}

		anyValid = true

		if !result.Passed && result.Status == types.StatusFail {
			failDetails = append(failDetails, result.Detail)
		}

		if isUnderInvestigation(result) {
			anyUnderInvestigation = true
		}
	}

	if len(failDetails) > 0 {
		result := check.Fail(strings.Join(failDetails, "; "))
		result.Metadata = map[string]any{metaKeyStatus: statusAffected}

		return result, nil
	}

	if anyUnderInvestigation {
		result := handleUnderInvestigation(pol)
		result.Metadata = map[string]any{metaKeyStatus: statusUnderInvestigation}

		return result, nil
	}

	if len(attestations) > 0 && !anyValid {
		return check.Fail(
			"all VEX documents failed to parse: " + strings.Join(parseErrors, "; "),
		), nil
	}

	result := check.Pass()
	result.Metadata = map[string]any{metaKeyStatus: statusNotAffected}

	return result, nil
}

func isUnderInvestigation(result *types.CheckResult) bool {
	return result.Status == types.StatusWarn
}

func handleUnderInvestigation(pol *policy.Policy) *types.CheckResult {
	uiPolicy := types.ActionAllow
	if pol.VEX != nil && pol.VEX.UnderInvestigationPolicy != "" {
		uiPolicy = pol.VEX.UnderInvestigationPolicy
	}

	detail := "vulnerability under investigation"

	switch uiPolicy {
	case types.ActionDeny:
		return check.Fail(detail)
	case types.ActionWarn:
		return types.WarnResult(checkType, detail)
	case types.ActionAllow:
		return types.PassResult(checkType, detail)
	default:
		slog.Warn("Unrecognized under_investigation policy, defaulting to deny",
			"policy", uiPolicy,
		)

		return check.Fail(detail)
	}
}

var check = types.Checker{ //nolint:gochecknoglobals // package-scoped helper
	Type:    checkType,
	PassMsg: "VEX verification passed",
}

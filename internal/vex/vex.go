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

// Package vex provides OpenVEX verification for supply chain attestations.
package vex

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	openvex "github.com/openvex/go-vex/pkg/vex"

	"github.com/saschagrunert/nri-supply-chain/internal/types"
	"github.com/saschagrunert/nri-supply-chain/policy"
)

const checkType = "vex"

// ErrInvalidVEX indicates the VEX document could not be parsed.
var ErrInvalidVEX = errors.New("invalid VEX document")

// Verify checks a VEX attestation against the given policy.
func Verify(
	ctx context.Context,
	att []byte, pol *policy.Policy, imageRef, imageDigest string,
) (*types.CheckResult, error) {
	doc, err := openvex.Parse(att)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidVEX, err)
	}

	var (
		affectedNames         []string
		hasUnderInvestigation bool
	)

	purl := buildOCIPURL(imageRef, imageDigest)

	for idx := range doc.Statements {
		stmt := &doc.Statements[idx]

		if !matchesImage(ctx, stmt, imageDigest, purl) {
			continue
		}

		switch stmt.Status {
		case openvex.StatusAffected:
			affectedNames = append(affectedNames, string(stmt.Vulnerability.Name))

		case openvex.StatusUnderInvestigation:
			hasUnderInvestigation = true

		case openvex.StatusNotAffected, openvex.StatusFixed:
			// These statuses are acceptable.
		}
	}

	if len(affectedNames) > 0 {
		detail := fmt.Sprintf(
			"vulnerabilities %s have status %q",
			strings.Join(affectedNames, ", "), openvex.StatusAffected,
		)

		return failResult(detail), nil
	}

	if hasUnderInvestigation {
		return handleUnderInvestigation(pol), nil
	}

	return passResult(), nil
}

// VerifyMultiple checks multiple VEX documents. Most restrictive wins:
// any affected statement causes failure.
func VerifyMultiple(
	ctx context.Context,
	attestations [][]byte,
	pol *policy.Policy,
	imageRef, imageDigest string,
) (*types.CheckResult, error) {
	var (
		failDetails           []string
		anyUnderInvestigation bool
		anyValid              bool
	)

	for _, att := range attestations {
		result, err := Verify(ctx, att, pol, imageRef, imageDigest)
		if err != nil {
			continue
		}

		anyValid = true

		if !result.Passed && result.Status == types.StatusFail {
			failDetails = append(failDetails, result.Detail)
		}

		if result.Status == types.StatusWarn {
			anyUnderInvestigation = true
		}
	}

	if len(failDetails) > 0 {
		return failResult(strings.Join(failDetails, "; ")), nil
	}

	if anyUnderInvestigation {
		return handleUnderInvestigation(pol), nil
	}

	if len(attestations) > 0 && !anyValid {
		return failResult("all VEX documents failed to parse"), nil
	}

	return passResult(), nil
}

func matchesImage(ctx context.Context, stmt *openvex.Statement, imageDigest, purl string) bool {
	if len(stmt.Products) == 0 {
		slog.WarnContext(
			ctx,
			"VEX statement has no products, skipping (requires explicit product match)",
		)

		return false
	}

	for idx := range stmt.Products {
		product := &stmt.Products[idx]

		if product.Component.Matches(imageDigest) {
			return true
		}

		if purl != "" && product.Component.Matches(purl) {
			return true
		}
	}

	return false
}

func buildOCIPURL(imageRef, imageDigest string) string {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return ""
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

func handleUnderInvestigation(pol *policy.Policy) *types.CheckResult {
	uiPolicy := "allow"
	if pol.VEX != nil && pol.VEX.UnderInvestigationPolicy != "" {
		uiPolicy = pol.VEX.UnderInvestigationPolicy
	}

	detail := "vulnerability under investigation"

	switch uiPolicy {
	case "deny":
		return failResult(detail)
	case "warn":
		return &types.CheckResult{
			Type:   checkType,
			Passed: true,
			Status: types.StatusWarn,
			Detail: detail,
		}
	default:
		return &types.CheckResult{
			Type:   checkType,
			Passed: true,
			Status: types.StatusPass,
			Detail: detail,
		}
	}
}

func passResult() *types.CheckResult {
	return &types.CheckResult{
		Type:   checkType,
		Passed: true,
		Status: types.StatusPass,
		Detail: "VEX verification passed",
	}
}

func failResult(detail string) *types.CheckResult {
	return &types.CheckResult{
		Type:   checkType,
		Passed: false,
		Status: types.StatusFail,
		Detail: detail,
	}
}

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
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	openvex "github.com/openvex/go-vex/pkg/vex"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const checkType = "vex"

var (
	// ErrInvalidVEX indicates the VEX document could not be parsed.
	ErrInvalidVEX = errors.New("invalid VEX document")

	// ErrSubjectMismatch indicates the in-toto subject does not match the image.
	ErrSubjectMismatch = errors.New("VEX subject digest mismatch")
)

type inTotoStatement struct {
	Subject   []inTotoSubject `json:"subject"`
	Predicate json.RawMessage `json:"predicate"`
}

type inTotoSubject struct {
	Digest map[string]string `json:"digest"`
}

// Verify checks a VEX attestation against the given policy.
func Verify(
	ctx context.Context,
	att []byte, pol *policy.Policy, imageRef, imageDigest string,
) (*types.CheckResult, error) {
	predicate, err := verifySubjectAndExtract(att, imageDigest)
	if err != nil {
		return nil, err
	}

	doc, err := openvex.Parse(predicate)
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
			affectedNames = append(affectedNames, vulnerabilityName(stmt))

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

func vulnerabilityName(stmt *openvex.Statement) string {
	if vulnName := string(stmt.Vulnerability.Name); vulnName != "" {
		return vulnName
	}

	return "unknown"
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
		parseErrors           []string
		anyUnderInvestigation bool
		anyValid              bool
	)

	for _, att := range attestations {
		result, err := Verify(ctx, att, pol, imageRef, imageDigest)
		if err != nil {
			parseErrors = append(parseErrors, err.Error())

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
		return failResult(
			"all VEX documents failed to parse: " + strings.Join(parseErrors, "; "),
		), nil
	}

	return passResult(), nil
}

func verifySubjectAndExtract(att []byte, imageDigest string) ([]byte, error) {
	var stmt inTotoStatement

	err := json.Unmarshal(att, &stmt)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidVEX, err)
	}

	if len(stmt.Subject) > 0 && imageDigest != "" {
		if !subjectMatchesDigest(stmt.Subject, imageDigest) {
			return nil, fmt.Errorf(
				"%w: none of the subjects match %q",
				ErrSubjectMismatch, imageDigest,
			)
		}
	} else {
		slog.Warn("VEX subject verification skipped",
			"subjectCount", len(stmt.Subject),
			"hasDigest", imageDigest != "",
		)
	}

	if len(stmt.Predicate) > 0 {
		return stmt.Predicate, nil
	}

	return att, nil
}

func subjectMatchesDigest(subjects []inTotoSubject, imageDigest string) bool {
	algo, hash := types.ParseDigest(imageDigest)
	if algo == "" {
		return false
	}

	for _, subject := range subjects {
		if subject.Digest[algo] == hash {
			return true
		}
	}

	return false
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
	uiPolicy := policy.ActionAllow
	if pol.VEX != nil && pol.VEX.UnderInvestigationPolicy != "" {
		uiPolicy = pol.VEX.UnderInvestigationPolicy
	}

	detail := "vulnerability under investigation"

	switch uiPolicy {
	case policy.ActionDeny:
		return failResult(detail)
	case policy.ActionWarn:
		return types.WarnResult(checkType, detail)
	default:
		return types.PassResult(checkType, detail)
	}
}

func passResult() *types.CheckResult {
	return types.PassResult(checkType, "VEX verification passed")
}

func failResult(detail string) *types.CheckResult {
	return types.FailResult(checkType, detail)
}

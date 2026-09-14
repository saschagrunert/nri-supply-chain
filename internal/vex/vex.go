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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/saschagrunert/nri-supply-chain/internal/intoto"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
	"github.com/saschagrunert/nri-supply-chain/internal/vex/cyclonedxvex"
	"github.com/saschagrunert/nri-supply-chain/internal/vex/imagematch"
	"github.com/saschagrunert/nri-supply-chain/internal/vex/openvex"
)

const (
	checkType         = types.CheckTypeVEX
	metaKeyStatus     = "status"
	metaKeyMatched    = "matchedStatements"
	statusAffected    = "affected"
	statusNotAffected = "not_affected"
	// StatusNoMatch is reported when valid VEX documents contain no
	// statements that apply to the image. It is distinct from not_affected so
	// policies can tell "vendor says not affected" from "VEX says nothing".
	StatusNoMatch            = "no_match"
	statusUnderInvestigation = "under_investigation"
	formatCycloneDX          = "CycloneDX"
)

var (
	// ErrInvalidVEX indicates the VEX document could not be parsed.
	ErrInvalidVEX = errors.New("invalid VEX document")

	errUnrecognizedFormat = errors.New("neither OpenVEX nor CycloneDX")
)

// formatHint is used for lightweight format detection on the predicate JSON.
type formatHint struct {
	// OpenVEX documents contain a @context field.
	Context string `json:"@context"`
	// OpenVEX documents contain a statements array.
	Statements json.RawMessage `json:"statements"`
	// CycloneDX BOMs contain a bomFormat field.
	BOMFormat string `json:"bomFormat"`
}

type documentFormat int

const (
	formatOpenVEX documentFormat = iota
	formatCDX
	formatEmpty
	formatUnknown
)

// evaluation accumulates VEX outcomes across documents.
type evaluation struct {
	affectedNames      []string
	underInvestigation bool
	matched            int
}

// Verify checks a VEX attestation against the given policy.
// It auto-detects whether the predicate is OpenVEX or CycloneDX format.
// When parsedImageRef is non-nil it is used instead of re-parsing imageRef.
func Verify(
	ctx context.Context,
	att []byte, pol *policy.Policy, imageRef, imageDigest string,
	parsedImageRef name.Reference,
) (*types.CheckResult, error) {
	ctxErr := ctx.Err()
	if ctxErr != nil {
		return nil, fmt.Errorf("verification cancelled: %w", ctxErr)
	}

	docs := newCollector(imageRef, imageDigest, parsedImageRef)

	err := docs.add(att)
	if err != nil {
		return nil, err
	}

	err = docs.evaluateOpenVEX(ctx)
	if err != nil {
		return nil, err
	}

	return buildResult(&docs.eval, pol), nil
}

// VerifyMultiple checks multiple VEX documents. Every document must parse
// and bind to the image; a document that fails to parse fails the check.
// OpenVEX statements from all documents are merged with timestamp precedence
// and the most restrictive outcome across formats wins.
// When parsedImageRef is non-nil it is used instead of re-parsing imageRef.
// Documents must be bound to imageDigest; statements naming imageDigest or
// any of relatedDigests (for example the platform manifest digest when the
// attestations were found on the index digest) refer to the image.
func VerifyMultiple(
	ctx context.Context,
	attestations [][]byte,
	pol *policy.Policy,
	imageRef, imageDigest string,
	parsedImageRef name.Reference,
	relatedDigests ...string,
) (*types.CheckResult, error) {
	docs := newCollector(imageRef, imageDigest, parsedImageRef, relatedDigests...)

	var parseErrors []string

	for _, att := range attestations {
		ctxErr := ctx.Err()
		if ctxErr != nil {
			return nil, fmt.Errorf("verification cancelled: %w", ctxErr)
		}

		err := docs.add(att)
		if err != nil {
			parseErrors = append(parseErrors, err.Error())
		}
	}

	err := docs.evaluateOpenVEX(ctx)
	if err != nil {
		return nil, err
	}

	if len(parseErrors) > 0 {
		return buildParseFailure(&docs.eval, parseErrors, len(attestations)), nil
	}

	return buildResult(&docs.eval, pol), nil
}

// collector gathers VEX documents for one image. CycloneDX documents are
// evaluated as they are added; OpenVEX documents are merged and evaluated
// together so statement precedence spans documents.
type collector struct {
	image    *imagematch.Image
	digest   string
	eval     evaluation
	openDocs []*openvex.Document
}

func newCollector(
	imageRef, imageDigest string, parsedImageRef name.Reference, relatedDigests ...string,
) *collector {
	return &collector{
		image:    imagematch.New(imageRef, imageDigest, parsedImageRef, relatedDigests...),
		digest:   imageDigest,
		eval:     evaluation{affectedNames: nil, underInvestigation: false, matched: 0},
		openDocs: nil,
	}
}

// add verifies subject binding, detects the format, and records the
// document.
func (c *collector) add(att []byte) error {
	predicate, err := intoto.VerifySubjectAndExtractPredicate(att, c.digest)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidVEX, err)
	}

	switch detectFormat(predicate) {
	case formatCDX:
		result, cdxErr := cyclonedxvex.Verify(predicate, c.image)
		if cdxErr != nil {
			return fmt.Errorf("%w: %w", ErrInvalidVEX, cdxErr)
		}

		c.eval.affectedNames = append(c.eval.affectedNames, result.AffectedNames...)
		c.eval.underInvestigation = c.eval.underInvestigation || result.HasUnderInvestigation
		c.eval.matched += result.MatchedVulnerabilities

		return nil

	case formatEmpty:
		return nil

	case formatOpenVEX:
		doc, parseErr := openvex.Parse(predicate)
		if parseErr != nil {
			return fmt.Errorf("%w: %w", ErrInvalidVEX, parseErr)
		}

		c.openDocs = append(c.openDocs, doc)

		return nil

	case formatUnknown:
		return fmt.Errorf("%w: %w", ErrInvalidVEX, errUnrecognizedFormat)

	default:
		return fmt.Errorf("%w: %w", ErrInvalidVEX, errUnrecognizedFormat)
	}
}

func (c *collector) evaluateOpenVEX(ctx context.Context) error {
	if len(c.openDocs) == 0 {
		return nil
	}

	result, err := openvex.Evaluate(ctx, c.openDocs, c.image)
	if err != nil {
		return fmt.Errorf("evaluating OpenVEX: %w", err)
	}

	c.eval.affectedNames = append(c.eval.affectedNames, result.AffectedNames...)
	c.eval.underInvestigation = c.eval.underInvestigation || result.HasUnderInvestigation
	c.eval.matched += result.MatchedStatements

	return nil
}

// detectFormat classifies a predicate. OpenVEX is recognized by @context or
// statements, CycloneDX by bomFormat. A JSON null or empty object is an empty
// document that says nothing about the image. Anything else is rejected.
func detectFormat(predicate []byte) documentFormat {
	trimmed := bytes.TrimSpace(predicate)
	if bytes.Equal(trimmed, []byte("null")) || isEmptyObject(trimmed) {
		return formatEmpty
	}

	var hint formatHint

	err := json.Unmarshal(trimmed, &hint)
	if err != nil {
		// Let the OpenVEX parser report the syntax error.
		return formatOpenVEX
	}

	switch {
	case hint.BOMFormat == formatCycloneDX:
		return formatCDX
	case hint.Context != "" || len(hint.Statements) > 0:
		return formatOpenVEX
	default:
		return formatUnknown
	}
}

func isEmptyObject(trimmed []byte) bool {
	return len(trimmed) >= 2 && trimmed[0] == '{' && trimmed[len(trimmed)-1] == '}' &&
		len(bytes.TrimSpace(trimmed[1:len(trimmed)-1])) == 0
}

func buildParseFailure(eval *evaluation, parseErrors []string, total int) *types.CheckResult {
	details := make([]string, 0, 2) //nolint:mnd // affected detail plus parse errors

	if len(eval.affectedNames) > 0 {
		details = append(details, affectedDetail(eval.affectedNames))
	}

	details = append(details, fmt.Sprintf(
		"%d of %d VEX documents failed verification: %s",
		len(parseErrors), total, strings.Join(parseErrors, "; "),
	))

	result := check.Fail(strings.Join(details, "; "))
	result.Metadata = map[string]any{
		metaKeyStatus:  statusAffected,
		metaKeyMatched: int64(eval.matched),
	}

	return result
}

func affectedDetail(names []string) string {
	return fmt.Sprintf(
		"vulnerabilities %s have status %q",
		strings.Join(names, ", "), statusAffected,
	)
}

func buildResult(eval *evaluation, pol *policy.Policy) *types.CheckResult {
	meta := map[string]any{metaKeyMatched: int64(eval.matched)}

	var result *types.CheckResult

	switch {
	case len(eval.affectedNames) > 0:
		result = check.Fail(affectedDetail(eval.affectedNames))
		meta[metaKeyStatus] = statusAffected

	case eval.underInvestigation:
		result = handleUnderInvestigation(pol)
		meta[metaKeyStatus] = statusUnderInvestigation

	case eval.matched > 0:
		result = check.Pass()
		meta[metaKeyStatus] = statusNotAffected

	default:
		result = types.PassResult(checkType, "no VEX statements apply to the image")
		meta[metaKeyStatus] = StatusNoMatch
	}

	result.Metadata = meta

	return result
}

func handleUnderInvestigation(pol *policy.Policy) *types.CheckResult {
	uiPolicy := types.ActionAllow
	if pol != nil && pol.VEX != nil && pol.VEX.UnderInvestigationPolicy != "" {
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

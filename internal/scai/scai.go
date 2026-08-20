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

// Package scai provides SCAI attribute report verification for supply chain checks.
package scai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/saschagrunert/nri-supply-chain/internal/intoto"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const checkType = types.CheckTypeSCAI

var (
	// ErrInvalidSCAI indicates the SCAI document could not be parsed.
	ErrInvalidSCAI = errors.New("invalid SCAI document")

	errMissingAttribute   = errors.New("required attribute missing")
	errForbiddenAttribute = errors.New("forbidden attribute present")
	errMissingEvidence    = errors.New("attribute missing required evidence")
)

// resourceDescriptor represents a SCAI resource descriptor for identifying
// producers or evidence sources.
type resourceDescriptor struct {
	Name   string            `json:"name,omitempty"`
	URI    string            `json:"uri,omitempty"`
	Digest map[string]string `json:"digest,omitempty"`
}

// attributeReport represents the subset of a SCAI attribute report needed
// for policy checks.
type attributeReport struct {
	Attributes []attribute         `json:"attributes"`
	Producer   *resourceDescriptor `json:"producer,omitempty"`
}

// attribute represents a single SCAI attribute with optional evidence.
type attribute struct {
	Attribute string          `json:"attribute"`
	Evidence  json.RawMessage `json:"evidence,omitempty"`
}

// Verify checks a single SCAI attestation against the given policy.
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
		return nil, fmt.Errorf("%w: %w", ErrInvalidSCAI, err)
	}

	return verifySCAIPredicate(predicate, pol)
}

// VerifyMultiple checks multiple SCAI attestations. Any policy violation
// in any document causes failure.
func VerifyMultiple(
	ctx context.Context,
	attestations [][]byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	//nolint:wrapcheck // VerifyMultipleWithMerge returns domain errors
	return types.VerifyMultipleWithMerge(
		ctx, checkType, "SCAI", "SCAI verification passed",
		attestations,
		func(att []byte) (*types.CheckResult, error) {
			return Verify(ctx, att, pol, imageDigest)
		},
		mergeAttributeMeta,
	)
}

func verifySCAIPredicate(
	predicate []byte, pol *policy.Policy,
) (*types.CheckResult, error) {
	var report attributeReport

	err := json.Unmarshal(predicate, &report)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSCAI, err)
	}

	attrNames := make([]string, 0, len(report.Attributes))
	for idx := range report.Attributes {
		attrNames = append(attrNames, report.Attributes[idx].Attribute)
	}

	hasEvidence := allHaveEvidence(report.Attributes)

	meta := map[string]any{
		"attributeCount": int64(len(report.Attributes)),
		"attributes":     strings.Join(attrNames, ","),
		"hasEvidence":    hasEvidence,
	}

	if pol.SCAI == nil {
		result := check.Pass()
		result.Metadata = meta

		return result, nil
	}

	violation := checkAttributePolicy(report.Attributes, pol.SCAI, hasEvidence)
	if violation != "" {
		result := check.Fail(violation)
		result.Metadata = meta

		return result, nil
	}

	result := check.Pass()
	result.Metadata = meta

	return result, nil
}

func checkAttributePolicy(attrs []attribute, pol *policy.SCAIPolicy, hasEvidence bool) string {
	for _, required := range pol.RequiredAttributes {
		if !containsAttribute(attrs, required) {
			return fmt.Sprintf("%s: %q", errMissingAttribute, required)
		}
	}

	for _, forbidden := range pol.ForbiddenAttributes {
		if containsAttribute(attrs, forbidden) {
			return fmt.Sprintf("%s: %q", errForbiddenAttribute, forbidden)
		}
	}

	if pol.RequireEvidence && !hasEvidence {
		return errMissingEvidence.Error()
	}

	return ""
}

func containsAttribute(attrs []attribute, name string) bool {
	for idx := range attrs {
		if strings.EqualFold(attrs[idx].Attribute, name) {
			return true
		}
	}

	return false
}

func allHaveEvidence(attrs []attribute) bool {
	for idx := range attrs {
		if len(attrs[idx].Evidence) == 0 ||
			string(attrs[idx].Evidence) == "null" ||
			string(attrs[idx].Evidence) == "{}" ||
			string(attrs[idx].Evidence) == "[]" {
			return false
		}
	}

	return len(attrs) > 0
}

func mergeAttributeMeta(dst, src map[string]any) {
	for key, val := range src {
		existing, hasPrev := dst[key]
		if !hasPrev {
			dst[key] = val

			continue
		}

		if merged, ok := mergeMetaValue(key, existing, val); ok {
			dst[key] = merged
		}
	}
}

func mergeMetaValue(key string, existing, incoming any) (any, bool) {
	switch key {
	case "attributeCount":
		return mergeInt64Sum(existing, incoming)
	case "attributes":
		return mergeStringAttrs(existing, incoming)
	case "hasEvidence":
		return mergeBoolAND(existing, incoming)
	default:
		return nil, false
	}
}

func mergeInt64Sum(existing, incoming any) (any, bool) {
	dstCount, dstOK := existing.(int64)
	srcCount, srcOK := incoming.(int64)

	if !dstOK || !srcOK {
		return nil, false
	}

	return dstCount + srcCount, true
}

func mergeStringAttrs(existing, incoming any) (any, bool) {
	dstAttrs, dstOK := existing.(string)
	srcAttrs, srcOK := incoming.(string)

	if !dstOK || !srcOK {
		return nil, false
	}

	return types.MergeCommaSeparated(dstAttrs, srcAttrs), true
}

func mergeBoolAND(existing, incoming any) (any, bool) {
	dstEvidence, dstOK := existing.(bool)
	srcEvidence, srcOK := incoming.(bool)

	if !dstOK || !srcOK {
		return nil, false
	}

	return dstEvidence && srcEvidence, true
}

var check = types.Checker{ //nolint:gochecknoglobals,gosec // package-scoped helper
	Type:    checkType,
	PassMsg: "SCAI verification passed",
}

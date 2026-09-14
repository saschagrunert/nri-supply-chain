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

	"github.com/saschagrunert/nri-supply-chain/internal/checker"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

var (
	// ErrInvalidSCAI indicates the SCAI document could not be parsed.
	ErrInvalidSCAI = errors.New("invalid SCAI document")

	errNoAttributes       = errors.New("attribute report has no attributes")
	errEmptyAttribute     = errors.New("attribute assertion has an empty attribute name")
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

//nolint:gochecknoglobals // immutable check declaration
var spec = &checker.Spec[attributeReport]{
	Info: checker.Info{
		Type:  types.CheckTypeSCAI,
		Label: "SCAI",
	},
	Aggregation: checker.AllMustPass,
	ErrInvalid:  ErrInvalidSCAI,
	Validate:    validateReport,
	Meta:        reportMeta,
	Freshness:   nil,
	Rules:       []checker.Rule[attributeReport]{checkAttributePolicy},
	Merge: map[string]checker.MergeFunc{
		"attributeCount": checker.Sum(),
		"attributes":     checker.CSV(),
		"hasEvidence":    checker.And(),
	},
}

// Info returns the check type and label of the SCAI check.
func Info() checker.Info {
	return spec.Info
}

// Verify checks a single SCAI attestation against the given policy.
func Verify(
	ctx context.Context,
	att []byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	//nolint:wrapcheck // the generic checker returns domain errors
	return spec.Verify(ctx, att, pol, imageDigest)
}

// VerifyMultiple checks multiple SCAI attestations. Any policy violation or
// invalid document causes failure.
func VerifyMultiple(
	ctx context.Context,
	attestations [][]byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	//nolint:wrapcheck // the generic checker returns domain errors
	return spec.VerifyMultiple(ctx, attestations, pol, imageDigest)
}

// validateReport enforces the SCAI v0.3 requirement that a report carries
// at least one attribute assertion with a non-empty attribute.
func validateReport(report *attributeReport) error {
	if len(report.Attributes) == 0 {
		return errNoAttributes
	}

	for idx := range report.Attributes {
		if strings.TrimSpace(report.Attributes[idx].Attribute) == "" {
			return fmt.Errorf("%w: attributes[%d]", errEmptyAttribute, idx)
		}
	}

	return nil
}

func reportMeta(report *attributeReport) map[string]any {
	attrNames := make([]string, 0, len(report.Attributes))
	for idx := range report.Attributes {
		attrNames = append(attrNames, report.Attributes[idx].Attribute)
	}

	return map[string]any{
		"attributeCount": int64(len(report.Attributes)),
		"attributes":     strings.Join(attrNames, ","),
		"hasEvidence":    allHaveEvidence(report.Attributes),
	}
}

func checkAttributePolicy(report *attributeReport, pol *policy.Policy) string {
	if pol.SCAI == nil {
		return ""
	}

	for _, required := range pol.SCAI.RequiredAttributes {
		if !containsAttribute(report.Attributes, required) {
			return fmt.Sprintf("%s: %q", errMissingAttribute, required)
		}
	}

	for _, forbidden := range pol.SCAI.ForbiddenAttributes {
		if containsAttribute(report.Attributes, forbidden) {
			return fmt.Sprintf("%s: %q", errForbiddenAttribute, forbidden)
		}
	}

	if pol.SCAI.RequireEvidence && !allHaveEvidence(report.Attributes) {
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
		evidence := strings.TrimSpace(string(attrs[idx].Evidence))
		if evidence == "" || evidence == "null" || evidence == "{}" || evidence == "[]" {
			return false
		}
	}

	return len(attrs) > 0
}

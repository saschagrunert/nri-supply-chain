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
	"bytes"
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

// attribute represents a single SCAI attribute assertion with optional
// target and evidence. Its conditions describe how the attribute arose (for
// example the compiler flags of WITH_STACK_PROTECTION in the SCAI
// specification) and do not change what it applies to, so they are not
// decoded.
type attribute struct {
	Attribute string `json:"attribute"`
	// Target names the artifact the attribute applies to; without it the
	// attribute applies to the attestation subject.
	Target   json.RawMessage `json:"target,omitempty"`
	Evidence json.RawMessage `json:"evidence,omitempty"`
}

// aboutSubject reports whether the assertion applies to the attestation
// subject. An assertion about another target (for example a dependency)
// does not establish the attribute for the image.
func (a *attribute) aboutSubject() bool {
	return isAbsent(a.Target)
}

// isAbsent reports whether an optional JSON field is missing, null, or an
// empty object.
func isAbsent(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return true
	}

	var fields map[string]json.RawMessage

	return json.Unmarshal(trimmed, &fields) == nil && len(fields) == 0
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

// reportMeta exposes the attributes asserted for the subject, the ones that
// satisfy requiredAttributes.
func reportMeta(report *attributeReport) map[string]any {
	attrNames := make([]string, 0, len(report.Attributes))
	for idx := range report.Attributes {
		if report.Attributes[idx].aboutSubject() {
			attrNames = append(attrNames, report.Attributes[idx].Attribute)
		}
	}

	return map[string]any{
		"attributeCount": int64(len(attrNames)),
		"attributes":     strings.Join(attrNames, ","),
		"hasEvidence":    allHaveEvidence(report.Attributes),
	}
}

func checkAttributePolicy(report *attributeReport, pol *policy.Policy) string {
	if pol.SCAI == nil {
		return ""
	}

	// A required attribute must be asserted for the subject, while a
	// forbidden attribute fails the check in any assertion, whatever its
	// target.
	for _, required := range pol.SCAI.RequiredAttributes {
		if containsAttribute(report.Attributes, required, true) {
			continue
		}

		if containsAttribute(report.Attributes, required, false) {
			return fmt.Sprintf(
				"%s: %q (only asserted for another target)", errMissingAttribute, required,
			)
		}

		return fmt.Sprintf("%s: %q", errMissingAttribute, required)
	}

	for _, forbidden := range pol.SCAI.ForbiddenAttributes {
		if containsAttribute(report.Attributes, forbidden, false) {
			return fmt.Sprintf("%s: %q", errForbiddenAttribute, forbidden)
		}
	}

	if pol.SCAI.RequireEvidence && !allHaveEvidence(report.Attributes) {
		return errMissingEvidence.Error()
	}

	return ""
}

// containsAttribute reports whether an assertion names the attribute. With
// subjectOnly, only assertions about the subject count.
func containsAttribute(attrs []attribute, name string, subjectOnly bool) bool {
	for idx := range attrs {
		if subjectOnly && !attrs[idx].aboutSubject() {
			continue
		}

		if strings.EqualFold(strings.TrimSpace(attrs[idx].Attribute), strings.TrimSpace(name)) {
			return true
		}
	}

	return false
}

func allHaveEvidence(attrs []attribute) bool {
	for idx := range attrs {
		if !hasEvidence(attrs[idx].Evidence) {
			return false
		}
	}

	return len(attrs) > 0
}

// evidenceDescriptor is the subset of an in-toto ResourceDescriptor that
// identifies evidence.
type evidenceDescriptor struct {
	URI     string            `json:"uri"`
	Digest  map[string]string `json:"digest"`
	Content string            `json:"content"`
}

// hasEvidence reports whether raw is a ResourceDescriptor object that
// identifies its evidence by uri, digest, or content, of which the in-toto
// ResourceDescriptor specification requires at least one. Scalars, arrays,
// and descriptors without any of them, such as a descriptor with only a
// name, do not count as evidence.
func hasEvidence(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return false
	}

	var descriptor evidenceDescriptor

	err := json.Unmarshal(trimmed, &descriptor)
	if err != nil {
		return false
	}

	if strings.TrimSpace(descriptor.URI) != "" ||
		strings.TrimSpace(descriptor.Content) != "" {
		return true
	}

	for _, value := range descriptor.Digest {
		if strings.TrimSpace(value) != "" {
			return true
		}
	}

	return false
}

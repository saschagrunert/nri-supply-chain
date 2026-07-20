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

package vex_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	openvex "github.com/openvex/go-vex/pkg/vex"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
	"github.com/saschagrunert/nri-supply-chain/internal/vex"
)

const (
	testImageRef      = "docker.io/library/nginx:latest"
	testDigest        = "sha256:abc123def456"
	testVEXContext    = "https://openvex.dev/ns/v0.2.0"
	testInTotoType    = "https://in-toto.io/Statement/v1"
	testPredicateType = "https://openvex.dev/ns"
)

type inTotoWrapper struct {
	Type          string          `json:"_type"` //nolint:tagliatelle // In-toto spec field name.
	Subject       []inTotoSubj    `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

type inTotoSubj struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

func validVEXDoc(status openvex.Status) openvex.VEX {
	return openvex.VEX{
		Metadata: openvex.Metadata{
			Context: testVEXContext,
			ID:      "https://openvex.dev/docs/example/vex-1",
		},
		Statements: []openvex.Statement{
			{
				Vulnerability: openvex.Vulnerability{
					Name: "CVE-2024-1234",
				},
				Products: []openvex.Product{
					{Component: openvex.Component{ID: testDigest}},
				},
				Status: status,
			},
		},
	}
}

func wrapInToto(t *testing.T, doc any, digest string) []byte {
	t.Helper()

	predBytes := mustMarshal(t, doc)

	wrapper := inTotoWrapper{
		Type: testInTotoType,
		Subject: []inTotoSubj{
			{
				Name:   "test-image",
				Digest: map[string]string{"sha256": digest[len("sha256:"):]},
			},
		},
		PredicateType: testPredicateType,
		Predicate:     predBytes,
	}

	return mustMarshal(t, wrapper)
}

func mustMarshal(t *testing.T, val any) []byte {
	t.Helper()

	data, err := json.Marshal(val)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}

	return data
}

func TestVerify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		doc        openvex.VEX
		pol        *policy.Policy
		wantPassed bool
		wantStatus string
	}{
		{
			name:       "not affected passes",
			doc:        validVEXDoc(openvex.StatusNotAffected),
			pol:        &policy.Policy{},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name:       "fixed passes",
			doc:        validVEXDoc(openvex.StatusFixed),
			pol:        &policy.Policy{},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name:       "affected fails with no threshold",
			doc:        validVEXDoc(openvex.StatusAffected),
			pol:        &policy.Policy{},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name: "affected fails with VEX policy",
			doc:  validVEXDoc(openvex.StatusAffected),
			pol: &policy.Policy{
				VEX: &policy.VEXPolicy{},
			},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name:       "under investigation default allow",
			doc:        validVEXDoc(openvex.StatusUnderInvestigation),
			pol:        &policy.Policy{},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name: "under investigation warn",
			doc:  validVEXDoc(openvex.StatusUnderInvestigation),
			pol: &policy.Policy{
				VEX: &policy.VEXPolicy{UnderInvestigationPolicy: policy.ActionWarn},
			},
			wantPassed: true,
			wantStatus: types.StatusWarn,
		},
		{
			name: "under investigation deny",
			doc:  validVEXDoc(openvex.StatusUnderInvestigation),
			pol: &policy.Policy{
				VEX: &policy.VEXPolicy{UnderInvestigationPolicy: policy.ActionDeny},
			},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name: "empty statements pass",
			doc: openvex.VEX{
				Metadata: openvex.Metadata{
					Context: testVEXContext,
					ID:      "https://openvex.dev/docs/example/vex-empty",
				},
				Statements: []openvex.Statement{},
			},
			pol:        &policy.Policy{},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name: "empty products does not match (skipped)",
			doc: openvex.VEX{
				Metadata: openvex.Metadata{
					Context: testVEXContext,
					ID:      "https://openvex.dev/docs/example/vex-noproducts",
				},
				Statements: []openvex.Statement{
					{
						Vulnerability: openvex.Vulnerability{Name: "CVE-2024-0001"},
						Status:        openvex.StatusAffected,
					},
				},
			},
			pol:        &policy.Policy{},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name: "product digest match",
			doc: openvex.VEX{
				Metadata: openvex.Metadata{
					Context: testVEXContext,
					ID:      "https://openvex.dev/docs/example/vex-product",
				},
				Statements: []openvex.Statement{
					{
						Vulnerability: openvex.Vulnerability{Name: "CVE-2024-5678"},
						Products: []openvex.Product{
							{Component: openvex.Component{ID: testDigest}},
						},
						Status: openvex.StatusAffected,
					},
				},
			},
			pol:        &policy.Policy{},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name: "product digest no match",
			doc: openvex.VEX{
				Metadata: openvex.Metadata{
					Context: testVEXContext,
					ID:      "https://openvex.dev/docs/example/vex-product",
				},
				Statements: []openvex.Statement{
					{
						Vulnerability: openvex.Vulnerability{Name: "CVE-2024-5678"},
						Products: []openvex.Product{
							{Component: openvex.Component{ID: "sha256:differentdigest"}},
						},
						Status: openvex.StatusAffected,
					},
				},
			},
			pol:        &policy.Policy{},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name: "PURL match",
			doc: openvex.VEX{
				Metadata: openvex.Metadata{
					Context: testVEXContext,
					ID:      "https://openvex.dev/docs/example/vex-purl",
				},
				Statements: []openvex.Statement{
					{
						Vulnerability: openvex.Vulnerability{Name: "CVE-2024-9999"},
						Products: []openvex.Product{
							{Component: openvex.Component{
								ID: "pkg:oci/nginx@" + testDigest + "?repository_url=index.docker.io/library",
							}},
						},
						Status: openvex.StatusAffected,
					},
				},
			},
			pol:        &policy.Policy{},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Wrap VEX docs in in-toto format with a subject to satisfy
			// subject binding requirements when digest is provided.
			att := wrapInToto(t, test.doc, testDigest)

			result, err := vex.Verify(
				context.Background(), att,
				test.pol, testImageRef, testDigest,
			)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Passed != test.wantPassed {
				t.Errorf("expected passed=%v, got passed=%v (detail: %s)",
					test.wantPassed, result.Passed, result.Detail)
			}

			if result.Status != test.wantStatus {
				t.Errorf("expected status %q, got %q", test.wantStatus, result.Status)
			}
		})
	}
}

func TestVerifyInvalidJSON(t *testing.T) {
	t.Parallel()

	_, err := vex.Verify(
		context.Background(), []byte("not json"),
		&policy.Policy{}, testImageRef, testDigest,
	)
	if !errors.Is(err, vex.ErrInvalidVEX) {
		t.Errorf("expected ErrInvalidVEX, got %v", err)
	}
}

func TestVerifyCheckType(t *testing.T) {
	t.Parallel()

	doc := validVEXDoc(openvex.StatusAffected)

	result, err := vex.Verify(
		context.Background(), wrapInToto(t, doc, testDigest),
		&policy.Policy{}, testImageRef, testDigest,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Type != "vex" {
		t.Errorf("expected type vex, got %q", result.Type)
	}
}

func TestVerifyPURLSingleSegmentRepo(t *testing.T) {
	t.Parallel()

	const (
		imageRef = "quay.io/myimage:latest"
		digest   = "sha256:def456"
	)

	purl := "pkg:oci/myimage@" + digest + "?repository_url=quay.io"

	doc := openvex.VEX{
		Metadata: openvex.Metadata{
			Context: testVEXContext,
			ID:      "https://openvex.dev/docs/example/vex-single-seg",
		},
		Statements: []openvex.Statement{
			{
				Vulnerability: openvex.Vulnerability{Name: "CVE-2024-8888"},
				Products: []openvex.Product{
					{Component: openvex.Component{ID: purl}},
				},
				Status: openvex.StatusAffected,
			},
		},
	}

	result, err := vex.Verify(
		context.Background(), wrapInToto(t, doc, digest),
		&policy.Policy{}, imageRef, digest,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Passed {
		t.Error("expected fail for affected product matching via purl (single-segment repo)")
	}
}

func TestVerifyMultiple(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		docs       []openvex.VEX
		pol        *policy.Policy
		wantPassed bool
		wantStatus string
	}{
		{
			name: "most restrictive wins",
			docs: []openvex.VEX{
				validVEXDoc(openvex.StatusNotAffected),
				validVEXDoc(openvex.StatusAffected),
			},
			pol:        &policy.Policy{},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name: "all pass",
			docs: []openvex.VEX{
				validVEXDoc(openvex.StatusNotAffected),
				validVEXDoc(openvex.StatusFixed),
			},
			pol:        &policy.Policy{},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name:       "empty attestation list",
			docs:       []openvex.VEX{},
			pol:        &policy.Policy{},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name: "under investigation",
			docs: []openvex.VEX{
				validVEXDoc(openvex.StatusUnderInvestigation),
			},
			pol:        &policy.Policy{},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			attestations := make([][]byte, len(test.docs))
			for idx := range test.docs {
				attestations[idx] = wrapInToto(t, test.docs[idx], testDigest)
			}

			result, err := vex.VerifyMultiple(
				context.Background(), attestations,
				test.pol, testImageRef, testDigest,
			)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Passed != test.wantPassed {
				t.Errorf("expected passed=%v, got passed=%v (detail: %s)",
					test.wantPassed, result.Passed, result.Detail)
			}

			if result.Status != test.wantStatus {
				t.Errorf("expected status %q, got %q", test.wantStatus, result.Status)
			}
		})
	}
}

func TestVerifyMultipleSkipsInvalid(t *testing.T) {
	t.Parallel()

	goodDoc := validVEXDoc(openvex.StatusNotAffected)

	attestations := [][]byte{
		[]byte("invalid json"),
		wrapInToto(t, goodDoc, testDigest),
	}

	result, err := vex.VerifyMultiple(
		context.Background(), attestations,
		&policy.Policy{}, testImageRef, testDigest,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Passed {
		t.Errorf("expected pass after skipping invalid, got: %s", result.Detail)
	}
}

func TestVerifyInTotoWrapped(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		doc        openvex.VEX
		digest     string
		wantErr    error
		wantPassed bool
	}{
		{
			name:       "matching subject digest passes",
			doc:        validVEXDoc(openvex.StatusNotAffected),
			digest:     testDigest,
			wantErr:    nil,
			wantPassed: true,
		},
		{
			name:       "mismatching subject digest fails",
			doc:        validVEXDoc(openvex.StatusNotAffected),
			digest:     "sha256:000000000000",
			wantErr:    vex.ErrSubjectMismatch,
			wantPassed: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			att := wrapInToto(t, test.doc, testDigest)

			result, err := vex.Verify(
				context.Background(), att,
				&policy.Policy{}, testImageRef, test.digest,
			)

			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) {
					t.Fatalf("expected %v, got %v", test.wantErr, err)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Passed != test.wantPassed {
				t.Errorf("expected passed=%v, got passed=%v", test.wantPassed, result.Passed)
			}
		})
	}
}

func TestVerifyInTotoEmptySubjectWithDigest(t *testing.T) {
	t.Parallel()

	doc := validVEXDoc(openvex.StatusFixed)
	predBytes := mustMarshal(t, doc)

	wrapper := inTotoWrapper{
		Type:          testInTotoType,
		Subject:       []inTotoSubj{},
		PredicateType: testPredicateType,
		Predicate:     predBytes,
	}

	att := mustMarshal(t, wrapper)

	_, err := vex.Verify(
		context.Background(), att,
		&policy.Policy{}, testImageRef, testDigest,
	)
	if !errors.Is(err, vex.ErrEmptySubjects) {
		t.Errorf(
			"expected ErrEmptySubjects when digest is available but subjects are empty, got: %v",
			err,
		)
	}
}

func TestVerifyInTotoEmptySubjectWithoutDigest(t *testing.T) {
	t.Parallel()

	doc := validVEXDoc(openvex.StatusFixed)
	predBytes := mustMarshal(t, doc)

	wrapper := inTotoWrapper{
		Type:          testInTotoType,
		Subject:       []inTotoSubj{},
		PredicateType: testPredicateType,
		Predicate:     predBytes,
	}

	att := mustMarshal(t, wrapper)

	// When no digest is available, empty subjects should be allowed (skip subject binding).
	result, err := vex.Verify(
		context.Background(), att,
		&policy.Policy{}, testImageRef, "",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Passed {
		t.Errorf("expected pass for empty subject without digest, got: %s", result.Detail)
	}
}

func TestVerifyInTotoNilSubjectWithDigest(t *testing.T) {
	t.Parallel()

	doc := validVEXDoc(openvex.StatusFixed)
	predBytes := mustMarshal(t, doc)

	wrapper := struct {
		Type          string          `json:"_type"` //nolint:tagliatelle // In-toto spec field name.
		PredicateType string          `json:"predicateType"`
		Predicate     json.RawMessage `json:"predicate"`
	}{
		Type:          testInTotoType,
		PredicateType: testPredicateType,
		Predicate:     predBytes,
	}

	att := mustMarshal(t, wrapper)

	// nil subject with a digest available should be rejected
	_, err := vex.Verify(
		context.Background(), att,
		&policy.Policy{}, testImageRef, testDigest,
	)
	if !errors.Is(err, vex.ErrEmptySubjects) {
		t.Errorf("expected ErrEmptySubjects for nil subjects with digest, got: %v", err)
	}
}

func TestVerifyMultipleAllInvalid(t *testing.T) {
	t.Parallel()

	attestations := [][]byte{
		[]byte("invalid json 1"),
		[]byte("invalid json 2"),
	}

	result, err := vex.VerifyMultiple(
		context.Background(), attestations,
		&policy.Policy{}, testImageRef, testDigest,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Passed {
		t.Error("expected fail when all VEX documents are invalid")
	}

	if result.Status != types.StatusFail {
		t.Errorf("expected fail status, got %q", result.Status)
	}
}

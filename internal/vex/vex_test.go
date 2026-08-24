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
	"fmt"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	openvex "github.com/openvex/go-vex/pkg/vex"

	"github.com/saschagrunert/nri-supply-chain/internal/intoto"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
	"github.com/saschagrunert/nri-supply-chain/internal/vex"
)

const (
	testImageRef      = "docker.io/library/nginx:latest"
	testDigest        = "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	testVEXContext    = "https://openvex.dev/ns/v0.2.0"
	testPredicateType = "https://openvex.dev/ns"
)

func validVEXDoc(status openvex.Status) openvex.VEX {
	return openvex.VEX{
		Context: testVEXContext,
		ID:      "https://openvex.dev/docs/example/vex-1",
		Statements: []openvex.Statement{
			{
				Vulnerability: openvex.Vulnerability{
					Name: "CVE-2024-1234",
				},
				Products: []openvex.Product{
					{ID: testDigest},
				},
				Status: status,
			},
		},
	}
}

func TestVerify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		doc        openvex.VEX
		pol        *policy.Policy
		wantPassed bool
		wantStatus types.CheckStatus
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
				VEX: &policy.VEXPolicy{UnderInvestigationPolicy: types.ActionWarn},
			},
			wantPassed: true,
			wantStatus: types.StatusWarn,
		},
		{
			name: "under investigation deny",
			doc:  validVEXDoc(openvex.StatusUnderInvestigation),
			pol: &policy.Policy{
				VEX: &policy.VEXPolicy{UnderInvestigationPolicy: types.ActionDeny},
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
							{ID: testDigest},
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
							{
								ID: "sha256:ffffffffffffffffffffffffffffffff" +
									"ffffffffffffffffffffffffffffffff",
							},
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
							{
								ID: "pkg:oci/nginx@" + testDigest + "?repository_url=index.docker.io/library",
							},
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
			att := testutil.WrapInToto(t, test.doc, testDigest, testPredicateType)

			result, err := vex.Verify(
				context.Background(), att,
				test.pol, testImageRef, testDigest,
				nil,
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

func TestVerifyMalformedPayloads(t *testing.T) {
	t.Parallel()

	t.Run("empty payload", func(t *testing.T) {
		t.Parallel()

		_, err := vex.Verify(
			context.Background(), []byte{},
			&policy.Policy{}, testImageRef, testDigest,
			nil,
		)

		if !errors.Is(err, vex.ErrInvalidVEX) {
			t.Errorf("expected ErrInvalidVEX, got %v", err)
		}
	})

	t.Run("nil payload", func(t *testing.T) {
		t.Parallel()

		_, err := vex.Verify(
			context.Background(), nil,
			&policy.Policy{}, testImageRef, testDigest,
			nil,
		)

		if !errors.Is(err, vex.ErrInvalidVEX) {
			t.Errorf("expected ErrInvalidVEX, got %v", err)
		}
	})

	t.Run("truncated JSON", func(t *testing.T) {
		t.Parallel()

		_, err := vex.Verify(
			context.Background(), []byte(`{"subject":[`),
			&policy.Policy{}, testImageRef, testDigest,
			nil,
		)

		if !errors.Is(err, vex.ErrInvalidVEX) {
			t.Errorf("expected ErrInvalidVEX, got %v", err)
		}
	})

	t.Run("empty JSON object with digest triggers empty subjects", func(t *testing.T) {
		t.Parallel()

		_, err := vex.Verify(
			context.Background(), []byte("{}"),
			&policy.Policy{}, testImageRef, testDigest,
			nil,
		)

		if !errors.Is(err, intoto.ErrEmptySubjects) {
			t.Errorf("expected ErrEmptySubjects, got %v", err)
		}
	})

	t.Run("empty JSON object without digest skips subject check", func(t *testing.T) {
		t.Parallel()

		result, err := vex.Verify(
			context.Background(), []byte("{}"),
			&policy.Policy{}, testImageRef, "",
			nil,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !result.Passed {
			t.Errorf("expected pass with empty doc and no digest, got: %s", result.Detail)
		}
	})

	t.Run("predicate is not embedded uses full attestation", func(t *testing.T) {
		t.Parallel()

		doc := validVEXDoc(openvex.StatusFixed)
		att := testutil.MustMarshal(t, doc)

		result, err := vex.Verify(
			context.Background(), att,
			&policy.Policy{}, testImageRef, "",
			nil,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !result.Passed {
			t.Errorf("expected pass for standalone VEX doc, got: %s", result.Detail)
		}
	})
}

func TestVerifySubjectEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("subject with invalid digest format", func(t *testing.T) {
		t.Parallel()

		doc := validVEXDoc(openvex.StatusNotAffected)
		att := testutil.WrapInToto(t, doc, testDigest, testPredicateType)

		_, err := vex.Verify(
			context.Background(), att,
			&policy.Policy{}, testImageRef, "nocolon",
			nil,
		)

		if !errors.Is(err, intoto.ErrSubjectMismatch) {
			t.Errorf("expected ErrSubjectMismatch for invalid digest format, got %v", err)
		}
	})

	t.Run("multiple subjects with one matching", func(t *testing.T) {
		t.Parallel()

		doc := validVEXDoc(openvex.StatusNotAffected)
		predBytes := testutil.MustMarshal(t, doc)

		wrapper := testutil.InTotoWrapper{
			Type: testutil.InTotoStatementType,
			Subject: []testutil.InTotoSubj{
				{
					Name:   "other-image",
					Digest: map[string]string{testutil.TestDigestAlgo: "000000"},
				},
				{
					Name: testutil.TestSubjectName,
					Digest: map[string]string{
						testutil.TestDigestAlgo: testDigest[len(testutil.TestDigestAlgo)+1:],
					},
				},
			},
			PredicateType: testPredicateType,
			Predicate:     predBytes,
		}

		att := testutil.MustMarshal(t, wrapper)

		result, err := vex.Verify(
			context.Background(), att,
			&policy.Policy{}, testImageRef, testDigest,
			nil,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !result.Passed {
			t.Errorf("expected pass with one matching subject, got: %s", result.Detail)
		}
	})

	t.Run("multiple subjects none matching", func(t *testing.T) {
		t.Parallel()

		doc := validVEXDoc(openvex.StatusNotAffected)
		predBytes := testutil.MustMarshal(t, doc)

		wrapper := testutil.InTotoWrapper{
			Type: testutil.InTotoStatementType,
			Subject: []testutil.InTotoSubj{
				{
					Name:   "image-a",
					Digest: map[string]string{testutil.TestDigestAlgo: "aaa111"},
				},
				{
					Name:   "image-b",
					Digest: map[string]string{testutil.TestDigestAlgo: "bbb222"},
				},
			},
			PredicateType: testPredicateType,
			Predicate:     predBytes,
		}

		att := testutil.MustMarshal(t, wrapper)

		_, err := vex.Verify(
			context.Background(), att,
			&policy.Policy{}, testImageRef, testDigest,
			nil,
		)

		if !errors.Is(err, intoto.ErrSubjectMismatch) {
			t.Errorf("expected ErrSubjectMismatch, got %v", err)
		}
	})
}

// multiStatusVEXDoc builds a VEX document containing statements with the given
// statuses. Each statement gets a unique CVE name and targets testDigest.
func multiStatusVEXDoc(statuses ...openvex.Status) openvex.VEX {
	stmts := make([]openvex.Statement, 0, len(statuses))

	for idx, status := range statuses {
		stmts = append(stmts, openvex.Statement{
			Vulnerability: openvex.Vulnerability{
				Name: openvex.VulnerabilityID(
					fmt.Sprintf("CVE-2024-%04d", idx),
				),
			},
			Products: []openvex.Product{
				{ID: testDigest},
			},
			Status: status,
		})
	}

	return openvex.VEX{
		Context:    testVEXContext,
		ID:         "https://openvex.dev/docs/example/vex-multi-status",
		Statements: stmts,
	}
}

func TestVerifyStatementEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("vulnerability without name shows unknown", func(t *testing.T) {
		t.Parallel()

		doc := openvex.VEX{
			Context: testVEXContext,
			ID:      "https://openvex.dev/docs/example/vex-noname",
			Statements: []openvex.Statement{
				{
					Vulnerability: openvex.Vulnerability{},
					Products: []openvex.Product{
						{ID: testDigest},
					},
					Status: openvex.StatusAffected,
				},
			},
		}

		att := testutil.WrapInToto(t, doc, testDigest, testPredicateType)

		result, err := vex.Verify(
			context.Background(), att,
			&policy.Policy{}, testImageRef, testDigest,
			nil,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Passed {
			t.Error("expected fail for affected status")
		}

		if result.Status != types.StatusFail {
			t.Errorf("expected fail status, got %q", result.Status)
		}
	})

	t.Run("mixed statuses with affected takes priority", func(t *testing.T) {
		t.Parallel()

		doc := multiStatusVEXDoc(openvex.StatusNotAffected, openvex.StatusAffected)
		att := testutil.WrapInToto(t, doc, testDigest, testPredicateType)

		result, err := vex.Verify(
			context.Background(), att,
			&policy.Policy{}, testImageRef, testDigest,
			nil,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Passed {
			t.Error("expected fail when any statement is affected")
		}
	})

	t.Run("affected takes priority over under investigation", func(t *testing.T) {
		t.Parallel()

		doc := multiStatusVEXDoc(openvex.StatusUnderInvestigation, openvex.StatusAffected)
		att := testutil.WrapInToto(t, doc, testDigest, testPredicateType)

		result, err := vex.Verify(
			context.Background(), att,
			&policy.Policy{}, testImageRef, testDigest,
			nil,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Passed {
			t.Error("expected fail: affected should take priority over under_investigation")
		}

		if result.Status != types.StatusFail {
			t.Errorf("expected fail status, got %q", result.Status)
		}
	})

	t.Run("under investigation with unknown policy action defaults to warn", func(t *testing.T) {
		t.Parallel()

		doc := validVEXDoc(openvex.StatusUnderInvestigation)
		att := testutil.WrapInToto(t, doc, testDigest, testPredicateType)

		result, err := vex.Verify(
			context.Background(), att,
			&policy.Policy{
				VEX: &policy.VEXPolicy{UnderInvestigationPolicy: "unknown_action"},
			},
			testImageRef, testDigest,
			nil,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Passed {
			t.Errorf("expected fail for unknown action (defaults to deny), got: %s", result.Detail)
		}

		if result.Status != types.StatusFail {
			t.Errorf("expected fail status for unknown action, got %q", result.Status)
		}
	})

	t.Run("multiple affected vulnerabilities", func(t *testing.T) {
		t.Parallel()

		doc := multiStatusVEXDoc(openvex.StatusAffected, openvex.StatusAffected)
		att := testutil.WrapInToto(t, doc, testDigest, testPredicateType)

		result, err := vex.Verify(
			context.Background(), att,
			&policy.Policy{}, testImageRef, testDigest,
			nil,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Passed {
			t.Error("expected fail for multiple affected vulnerabilities")
		}
	})
}

func TestVerifyMultipleEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("nil attestation slice", func(t *testing.T) {
		t.Parallel()

		result, err := vex.VerifyMultiple(
			context.Background(), nil,
			&policy.Policy{}, testImageRef, testDigest,
			nil,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !result.Passed {
			t.Errorf("expected pass for nil attestation slice, got: %s", result.Detail)
		}
	})

	t.Run("all invalid returns fail with parse errors", func(t *testing.T) {
		t.Parallel()

		attestations := [][]byte{
			[]byte("bad json 1"),
			[]byte("bad json 2"),
			[]byte("bad json 3"),
		}

		result, err := vex.VerifyMultiple(
			context.Background(), attestations,
			&policy.Policy{}, testImageRef, testDigest,
			nil,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Passed {
			t.Error("expected fail when all documents are invalid")
		}

		if result.Status != types.StatusFail {
			t.Errorf("expected fail status, got %q", result.Status)
		}
	})

	t.Run("under investigation across multiple docs", func(t *testing.T) {
		t.Parallel()

		docs := []openvex.VEX{
			validVEXDoc(openvex.StatusNotAffected),
			validVEXDoc(openvex.StatusUnderInvestigation),
		}

		attestations := make([][]byte, len(docs))
		for idx := range docs {
			attestations[idx] = testutil.WrapInToto(t, docs[idx], testDigest, testPredicateType)
		}

		result, err := vex.VerifyMultiple(
			context.Background(), attestations,
			&policy.Policy{
				VEX: &policy.VEXPolicy{UnderInvestigationPolicy: types.ActionWarn},
			},
			testImageRef, testDigest,
			nil,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !result.Passed {
			t.Errorf("expected pass (warn) for under investigation, got: %s", result.Detail)
		}

		if result.Status != types.StatusWarn {
			t.Errorf("expected warn status, got %q", result.Status)
		}
	})

	t.Run("affected in any doc causes failure", func(t *testing.T) {
		t.Parallel()

		docs := []openvex.VEX{
			validVEXDoc(openvex.StatusFixed),
			validVEXDoc(openvex.StatusAffected),
			validVEXDoc(openvex.StatusNotAffected),
		}

		attestations := make([][]byte, len(docs))
		for idx := range docs {
			attestations[idx] = testutil.WrapInToto(t, docs[idx], testDigest, testPredicateType)
		}

		result, err := vex.VerifyMultiple(
			context.Background(), attestations,
			&policy.Policy{}, testImageRef, testDigest,
			nil,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Passed {
			t.Error("expected fail when any doc has affected status")
		}
	})

	t.Run("mix of valid and invalid with valid passing", func(t *testing.T) {
		t.Parallel()

		attestations := [][]byte{
			[]byte("invalid 1"),
			testutil.WrapInToto(t, validVEXDoc(openvex.StatusFixed), testDigest, testPredicateType),
			[]byte("invalid 2"),
		}

		result, err := vex.VerifyMultiple(
			context.Background(), attestations,
			&policy.Policy{}, testImageRef, testDigest,
			nil,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !result.Passed {
			t.Errorf("expected pass when at least one valid doc passes, got: %s", result.Detail)
		}
	})
}

func TestVerifyInvalidJSON(t *testing.T) {
	t.Parallel()

	_, err := vex.Verify(
		context.Background(), []byte("not json"),
		&policy.Policy{}, testImageRef, testDigest,
		nil,
	)
	if !errors.Is(err, vex.ErrInvalidVEX) {
		t.Errorf("expected ErrInvalidVEX, got %v", err)
	}
}

func TestVerifyCheckType(t *testing.T) {
	t.Parallel()

	doc := validVEXDoc(openvex.StatusAffected)

	result, err := vex.Verify(
		context.Background(), testutil.WrapInToto(t, doc, testDigest, testPredicateType),
		&policy.Policy{}, testImageRef, testDigest,
		nil,
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
		digest   = "sha256:b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3"
	)

	purl := "pkg:oci/myimage@" + digest + "?repository_url=quay.io"

	doc := openvex.VEX{
		Context: testVEXContext,
		ID:      "https://openvex.dev/docs/example/vex-single-seg",
		Statements: []openvex.Statement{
			{
				Vulnerability: openvex.Vulnerability{Name: "CVE-2024-8888"},
				Products: []openvex.Product{
					{ID: purl},
				},
				Status: openvex.StatusAffected,
			},
		},
	}

	result, err := vex.Verify(
		context.Background(), testutil.WrapInToto(t, doc, digest, testPredicateType),
		&policy.Policy{}, imageRef, digest,
		nil,
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
		wantStatus types.CheckStatus
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
				attestations[idx] = testutil.WrapInToto(
					t,
					test.docs[idx],
					testDigest,
					testPredicateType,
				)
			}

			result, err := vex.VerifyMultiple(
				context.Background(), attestations,
				test.pol, testImageRef, testDigest,
				nil,
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
		testutil.WrapInToto(t, goodDoc, testDigest, testPredicateType),
	}

	result, err := vex.VerifyMultiple(
		context.Background(), attestations,
		&policy.Policy{}, testImageRef, testDigest,
		nil,
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
			digest:     "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			wantErr:    intoto.ErrSubjectMismatch,
			wantPassed: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			att := testutil.WrapInToto(t, test.doc, testDigest, testPredicateType)

			result, err := vex.Verify(
				context.Background(), att,
				&policy.Policy{}, testImageRef, test.digest,
				nil,
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
	predBytes := testutil.MustMarshal(t, doc)

	wrapper := testutil.InTotoWrapper{
		Type:          testutil.InTotoStatementType,
		Subject:       []testutil.InTotoSubj{},
		PredicateType: testPredicateType,
		Predicate:     predBytes,
	}

	att := testutil.MustMarshal(t, wrapper)

	_, err := vex.Verify(
		context.Background(), att,
		&policy.Policy{}, testImageRef, testDigest,
		nil,
	)
	if !errors.Is(err, intoto.ErrEmptySubjects) {
		t.Errorf(
			"expected ErrEmptySubjects when digest is available but subjects are empty, got: %v",
			err,
		)
	}
}

func TestVerifyInTotoEmptySubjectWithoutDigest(t *testing.T) {
	t.Parallel()

	doc := validVEXDoc(openvex.StatusFixed)
	predBytes := testutil.MustMarshal(t, doc)

	wrapper := testutil.InTotoWrapper{
		Type:          testutil.InTotoStatementType,
		Subject:       []testutil.InTotoSubj{},
		PredicateType: testPredicateType,
		Predicate:     predBytes,
	}

	att := testutil.MustMarshal(t, wrapper)

	// When no digest is available, empty subjects should be allowed (skip subject binding).
	result, err := vex.Verify(
		context.Background(), att,
		&policy.Policy{}, testImageRef, "",
		nil,
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
	predBytes := testutil.MustMarshal(t, doc)

	wrapper := struct {
		Type          string          `json:"_type"` //nolint:tagliatelle // In-toto spec field name.
		PredicateType string          `json:"predicateType"`
		Predicate     json.RawMessage `json:"predicate"`
	}{
		Type:          testutil.InTotoStatementType,
		PredicateType: testPredicateType,
		Predicate:     predBytes,
	}

	att := testutil.MustMarshal(t, wrapper)

	// nil subject with a digest available should be rejected
	_, err := vex.Verify(
		context.Background(), att,
		&policy.Policy{}, testImageRef, testDigest,
		nil,
	)
	if !errors.Is(err, intoto.ErrEmptySubjects) {
		t.Errorf("expected ErrEmptySubjects for nil subjects with digest, got: %v", err)
	}
}

func TestVerifySubjectsWithoutDigestRejected(t *testing.T) {
	t.Parallel()

	doc := validVEXDoc(openvex.StatusFixed)
	predBytes := testutil.MustMarshal(t, doc)

	wrapper := testutil.InTotoWrapper{
		Type: testutil.InTotoStatementType,
		Subject: []testutil.InTotoSubj{
			{
				Name:   testutil.TestSubjectName,
				Digest: map[string]string{testutil.TestDigestAlgo: "abc123"},
			},
		},
		PredicateType: testPredicateType,
		Predicate:     predBytes,
	}

	att := testutil.MustMarshal(t, wrapper)

	_, err := vex.Verify(
		context.Background(), att,
		&policy.Policy{}, testImageRef, "",
		nil,
	)
	if !errors.Is(err, intoto.ErrNoDigestBinding) {
		t.Errorf(
			"expected ErrNoDigestBinding when subjects present but no digest, got: %v",
			err,
		)
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
		nil,
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

// CycloneDX VEX format detection and integration tests.

func cycloneDXBOM(state cdx.ImpactAnalysisState) *cdx.BOM {
	bom := cdx.NewBOM()
	bom.Components = &[]cdx.Component{
		{
			BOMRef: "comp-nginx",
			Type:   cdx.ComponentTypeContainer,
			Name:   "nginx",
			Hashes: &[]cdx.Hash{
				{
					Algorithm: cdx.HashAlgoSHA256,
					Value:     testDigest[len(testutil.TestDigestAlgo)+1:],
				},
			},
		},
	}
	bom.Vulnerabilities = &[]cdx.Vulnerability{
		{
			ID:       "CVE-2024-1234",
			Analysis: &cdx.VulnerabilityAnalysis{State: state},
			Affects: &[]cdx.Affects{
				{Ref: "comp-nginx"},
			},
		},
	}

	return bom
}

func wrapCycloneDXInToto(t *testing.T, bom *cdx.BOM, digest string) []byte {
	t.Helper()

	predBytes := testutil.MustMarshal(t, bom)

	wrapper := testutil.InTotoWrapper{
		Type: testutil.InTotoStatementType,
		Subject: []testutil.InTotoSubj{
			{
				Name: testutil.TestSubjectName,
				Digest: map[string]string{
					testutil.TestDigestAlgo: digest[len(testutil.TestDigestAlgo)+1:],
				},
			},
		},
		PredicateType: "https://cyclonedx.org/bom",
		Predicate:     predBytes,
	}

	return testutil.MustMarshal(t, wrapper)
}

func TestVerifyCycloneDXFormatDetection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		state      cdx.ImpactAnalysisState
		wantPassed bool
		wantStatus types.CheckStatus
	}{
		{
			name:       "CycloneDX not_affected passes",
			state:      cdx.IASNotAffected,
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name:       "CycloneDX exploitable fails",
			state:      cdx.IASExploitable,
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name:       "CycloneDX resolved passes",
			state:      cdx.IASResolved,
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name:       "CycloneDX false_positive passes",
			state:      cdx.IASFalsePositive,
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name:       "CycloneDX in_triage default allow",
			state:      cdx.IASInTriage,
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			bom := cycloneDXBOM(test.state)
			att := wrapCycloneDXInToto(t, bom, testDigest)

			result, err := vex.Verify(
				context.Background(), att,
				&policy.Policy{}, testImageRef, testDigest,
				nil,
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

func TestVerifyCycloneDXInTriageWithDenyPolicy(t *testing.T) {
	t.Parallel()

	bom := cycloneDXBOM(cdx.IASInTriage)
	att := wrapCycloneDXInToto(t, bom, testDigest)

	result, err := vex.Verify(
		context.Background(), att,
		&policy.Policy{
			VEX: &policy.VEXPolicy{UnderInvestigationPolicy: types.ActionDeny},
		},
		testImageRef, testDigest,
		nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Passed {
		t.Error("expected fail for in_triage with deny policy")
	}

	if result.Status != types.StatusFail {
		t.Errorf("expected fail status, got %q", result.Status)
	}
}

func TestVerifyCycloneDXEmptyVulnerabilities(t *testing.T) {
	t.Parallel()

	bom := cdx.NewBOM()
	att := wrapCycloneDXInToto(t, bom, testDigest)

	result, err := vex.Verify(
		context.Background(), att,
		&policy.Policy{}, testImageRef, testDigest,
		nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Passed {
		t.Errorf("expected pass for CycloneDX BOM without vulnerabilities, got: %s", result.Detail)
	}
}

func TestVerifyCycloneDXCheckType(t *testing.T) {
	t.Parallel()

	bom := cycloneDXBOM(cdx.IASExploitable)
	att := wrapCycloneDXInToto(t, bom, testDigest)

	result, err := vex.Verify(
		context.Background(), att,
		&policy.Policy{}, testImageRef, testDigest,
		nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Type != "vex" {
		t.Errorf("expected type vex, got %q", result.Type)
	}
}

func TestVerifyMultipleMixedFormats(t *testing.T) {
	t.Parallel()

	openVEXDoc := validVEXDoc(openvex.StatusNotAffected)
	openVEXAtt := testutil.WrapInToto(t, openVEXDoc, testDigest, testPredicateType)

	cdxBOM := cycloneDXBOM(cdx.IASNotAffected)
	cdxAtt := wrapCycloneDXInToto(t, cdxBOM, testDigest)

	attestations := [][]byte{openVEXAtt, cdxAtt}

	result, err := vex.VerifyMultiple(
		context.Background(), attestations,
		&policy.Policy{}, testImageRef, testDigest,
		nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Passed {
		t.Errorf("expected pass for mixed formats both passing, got: %s", result.Detail)
	}
}

func TestVerifyMultipleMixedFormatsWithAffected(t *testing.T) {
	t.Parallel()

	openVEXDoc := validVEXDoc(openvex.StatusNotAffected)
	openVEXAtt := testutil.WrapInToto(t, openVEXDoc, testDigest, testPredicateType)

	cdxBOM := cycloneDXBOM(cdx.IASExploitable)
	cdxAtt := wrapCycloneDXInToto(t, cdxBOM, testDigest)

	attestations := [][]byte{openVEXAtt, cdxAtt}

	result, err := vex.VerifyMultiple(
		context.Background(), attestations,
		&policy.Policy{}, testImageRef, testDigest,
		nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Passed {
		t.Error("expected fail when CycloneDX doc has exploitable status")
	}
}

func TestVerifyCancelledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := vex.Verify(ctx, nil, nil, "", "", nil)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}

	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

func TestVerifyMultipleCancelledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := vex.VerifyMultiple(ctx, [][]byte{[]byte("a")}, nil, "", "", nil)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}

	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

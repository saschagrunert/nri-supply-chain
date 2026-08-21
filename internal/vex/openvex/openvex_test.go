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

package openvex_test

import (
	"context"
	"testing"

	openvexlib "github.com/openvex/go-vex/pkg/vex"

	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/vex/openvex"
)

const (
	testDigest     = "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	testVEXContext = "https://openvex.dev/ns/v0.2.0"
)

func validDoc(status openvexlib.Status) openvexlib.VEX {
	return openvexlib.VEX{
		Context: testVEXContext,
		ID:      "https://openvex.dev/docs/example/vex-1",
		Statements: []openvexlib.Statement{
			{
				Vulnerability: openvexlib.Vulnerability{
					Name: "CVE-2024-1234",
				},
				Products: []openvexlib.Product{
					{ID: testDigest},
				},
				Status: status,
			},
		},
	}
}

func TestVerifyNotAffected(t *testing.T) {
	t.Parallel()

	doc := validDoc(openvexlib.StatusNotAffected)
	data := testutil.MustMarshal(t, doc)

	result, err := openvex.Verify(context.Background(), data, testDigest, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.AffectedNames) > 0 {
		t.Errorf("expected no affected, got %v", result.AffectedNames)
	}
}

func TestVerifyAffected(t *testing.T) {
	t.Parallel()

	doc := validDoc(openvexlib.StatusAffected)
	data := testutil.MustMarshal(t, doc)

	result, err := openvex.Verify(context.Background(), data, testDigest, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.AffectedNames) == 0 {
		t.Error("expected affected vulnerabilities")
	}

	if result.AffectedNames[0] != "CVE-2024-1234" {
		t.Errorf("expected CVE-2024-1234, got %s", result.AffectedNames[0])
	}
}

func TestVerifyUnderInvestigation(t *testing.T) {
	t.Parallel()

	doc := validDoc(openvexlib.StatusUnderInvestigation)
	data := testutil.MustMarshal(t, doc)

	result, err := openvex.Verify(context.Background(), data, testDigest, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.HasUnderInvestigation {
		t.Error("expected HasUnderInvestigation to be true")
	}
}

func TestVerifyFixed(t *testing.T) {
	t.Parallel()

	doc := validDoc(openvexlib.StatusFixed)
	data := testutil.MustMarshal(t, doc)

	result, err := openvex.Verify(context.Background(), data, testDigest, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.AffectedNames) > 0 || result.HasUnderInvestigation {
		t.Error("expected clean result for fixed status")
	}
}

func TestVerifyInvalidJSON(t *testing.T) {
	t.Parallel()

	_, err := openvex.Verify(
		context.Background(), []byte("not json"),
		testDigest, "",
	)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestVerifyEmptyStatements(t *testing.T) {
	t.Parallel()

	doc := openvexlib.VEX{
		Context:    testVEXContext,
		ID:         "https://openvex.dev/docs/example/vex-empty",
		Statements: []openvexlib.Statement{},
	}
	data := testutil.MustMarshal(t, doc)

	result, err := openvex.Verify(context.Background(), data, testDigest, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.AffectedNames) > 0 {
		t.Errorf("expected no affected, got %v", result.AffectedNames)
	}

	if result.HasUnderInvestigation {
		t.Error("expected HasUnderInvestigation to be false")
	}
}

func TestVerifyStatementWithNoProducts(t *testing.T) {
	t.Parallel()

	doc := openvexlib.VEX{
		Context: testVEXContext,
		ID:      "https://openvex.dev/docs/example/vex-no-products",
		Statements: []openvexlib.Statement{
			{
				Vulnerability: openvexlib.Vulnerability{
					Name: "CVE-2024-9999",
				},
				Products: nil,
				Status:   openvexlib.StatusAffected,
			},
		},
	}
	data := testutil.MustMarshal(t, doc)

	result, err := openvex.Verify(context.Background(), data, testDigest, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.AffectedNames) > 0 {
		t.Errorf("expected no affected (statement skipped), got %v", result.AffectedNames)
	}
}

func TestVerifyMultipleStatementsMixedStatuses(t *testing.T) {
	t.Parallel()

	doc := openvexlib.VEX{
		Context: testVEXContext,
		ID:      "https://openvex.dev/docs/example/vex-mixed",
		Statements: []openvexlib.Statement{
			{
				Vulnerability: openvexlib.Vulnerability{Name: "CVE-2024-0001"},
				Products: []openvexlib.Product{
					{ID: testDigest},
				},
				Status: openvexlib.StatusAffected,
			},
			{
				Vulnerability: openvexlib.Vulnerability{Name: "CVE-2024-0002"},
				Products: []openvexlib.Product{
					{ID: testDigest},
				},
				Status: openvexlib.StatusNotAffected,
			},
			{
				Vulnerability: openvexlib.Vulnerability{Name: "CVE-2024-0003"},
				Products: []openvexlib.Product{
					{ID: testDigest},
				},
				Status: openvexlib.StatusUnderInvestigation,
			},
			{
				Vulnerability: openvexlib.Vulnerability{Name: "CVE-2024-0004"},
				Products: []openvexlib.Product{
					{ID: testDigest},
				},
				Status: openvexlib.StatusFixed,
			},
			{
				Vulnerability: openvexlib.Vulnerability{Name: "CVE-2024-0005"},
				Products: []openvexlib.Product{
					{ID: testDigest},
				},
				Status: openvexlib.StatusAffected,
			},
		},
	}
	data := testutil.MustMarshal(t, doc)

	result, err := openvex.Verify(context.Background(), data, testDigest, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.AffectedNames) != 2 {
		t.Fatalf("expected 2 affected, got %d: %v", len(result.AffectedNames), result.AffectedNames)
	}

	if result.AffectedNames[0] != "CVE-2024-0001" {
		t.Errorf("expected first affected CVE-2024-0001, got %s", result.AffectedNames[0])
	}

	if result.AffectedNames[1] != "CVE-2024-0005" {
		t.Errorf("expected second affected CVE-2024-0005, got %s", result.AffectedNames[1])
	}

	if !result.HasUnderInvestigation {
		t.Error("expected HasUnderInvestigation to be true")
	}
}

func TestVerifyMatchByPURL(t *testing.T) {
	t.Parallel()

	testPURL := "pkg:oci/myimage@sha256:abcdef1234567890"

	doc := openvexlib.VEX{
		Context: testVEXContext,
		ID:      "https://openvex.dev/docs/example/vex-purl",
		Statements: []openvexlib.Statement{
			{
				Vulnerability: openvexlib.Vulnerability{Name: "CVE-2024-5678"},
				Products: []openvexlib.Product{
					{ID: testPURL},
				},
				Status: openvexlib.StatusAffected,
			},
		},
	}
	data := testutil.MustMarshal(t, doc)

	// Product ID does not match the image digest, but matches via purl.
	result, err := openvex.Verify(context.Background(), data, testDigest, testPURL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.AffectedNames) != 1 || result.AffectedNames[0] != "CVE-2024-5678" {
		t.Errorf("expected CVE-2024-5678 via PURL match, got %v", result.AffectedNames)
	}
}

func TestVerifyProductDoesNotMatchDigest(t *testing.T) {
	t.Parallel()

	otherDigest := "sha256:0000000000000000000000000000000000000000000000000000000000000000"

	doc := openvexlib.VEX{
		Context: testVEXContext,
		ID:      "https://openvex.dev/docs/example/vex-no-match",
		Statements: []openvexlib.Statement{
			{
				Vulnerability: openvexlib.Vulnerability{Name: "CVE-2024-7777"},
				Products: []openvexlib.Product{
					{ID: otherDigest},
				},
				Status: openvexlib.StatusAffected,
			},
		},
	}
	data := testutil.MustMarshal(t, doc)

	result, err := openvex.Verify(context.Background(), data, testDigest, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.AffectedNames) > 0 {
		t.Errorf("expected no affected (digest mismatch), got %v", result.AffectedNames)
	}
}

func TestVerifyVulnerabilityWithNoName(t *testing.T) {
	t.Parallel()

	doc := openvexlib.VEX{
		Context: testVEXContext,
		ID:      "https://openvex.dev/docs/example/vex-no-name",
		Statements: []openvexlib.Statement{
			{
				Vulnerability: openvexlib.Vulnerability{Name: ""},
				Products: []openvexlib.Product{
					{ID: testDigest},
				},
				Status: openvexlib.StatusAffected,
			},
		},
	}
	data := testutil.MustMarshal(t, doc)

	result, err := openvex.Verify(context.Background(), data, testDigest, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.AffectedNames) != 1 {
		t.Fatalf("expected 1 affected, got %d", len(result.AffectedNames))
	}

	if result.AffectedNames[0] != "unknown" {
		t.Errorf("expected 'unknown' for nameless vulnerability, got %s", result.AffectedNames[0])
	}
}

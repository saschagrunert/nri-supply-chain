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
	"strings"
	"testing"
	"time"

	openvexlib "github.com/openvex/go-vex/pkg/vex"

	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/vex/imagematch"
	"github.com/saschagrunert/nri-supply-chain/internal/vex/openvex"
)

const (
	testDigest     = "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	testImageRef   = "quay.io/myorg/myimage:v1"
	testVEXContext = "https://openvex.dev/ns/v0.2.0"
	testCVE        = "CVE-2024-4242"
	testDocID      = "doc"
)

func testImage() *imagematch.Image {
	return imagematch.New(testImageRef, testDigest, nil)
}

func statementAt(status openvexlib.Status, timestamp time.Time) openvexlib.Statement {
	return openvexlib.Statement{
		Vulnerability: openvexlib.Vulnerability{Name: testCVE},
		Products:      []openvexlib.Product{{ID: testDigest}},
		Status:        status,
		Timestamp:     &timestamp,
	}
}

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

	result, err := openvex.Verify(context.Background(), data, testImage())
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

	result, err := openvex.Verify(context.Background(), data, testImage())
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

	result, err := openvex.Verify(context.Background(), data, testImage())
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

	result, err := openvex.Verify(context.Background(), data, testImage())
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
		testImage(),
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

	result, err := openvex.Verify(context.Background(), data, testImage())
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

	result, err := openvex.Verify(context.Background(), data, testImage())
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

	result, err := openvex.Verify(context.Background(), data, testImage())
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

func TestVerifyProductIdentityMatching(t *testing.T) {
	t.Parallel()

	hexDigest := testDigest[len("sha256:"):]

	// Resolved statuses require a strict identity match; statuses that can
	// only raise severity match leniently (see
	// TestEvaluateUnresolvedStatusesMatchNamesLeniently).
	tests := []struct {
		name      string
		component openvexlib.Component
		status    openvexlib.Status
		wantMatch bool
	}{
		{
			name: "purl with percent encoded digest and spec repository_url",
			component: openvexlib.Component{
				ID: "pkg:oci/myimage@sha256%3A" + hexDigest +
					"?repository_url=quay.io/myorg/myimage&tag=v1",
			},
			status:    openvexlib.StatusNotAffected,
			wantMatch: true,
		},
		{
			name: "purl with legacy repository_url and extra qualifiers",
			component: openvexlib.Component{
				ID: "pkg:oci/myimage@" + testDigest +
					"?repository_url=quay.io%2Fmyorg&arch=amd64",
			},
			status:    openvexlib.StatusNotAffected,
			wantMatch: true,
		},
		{
			name:      "versionless purl matches by name",
			component: openvexlib.Component{ID: "pkg:oci/myimage"},
			status:    openvexlib.StatusNotAffected,
			wantMatch: true,
		},
		{
			name: "versionless purl from another repository",
			component: openvexlib.Component{
				ID: "pkg:oci/myimage?repository_url=ghcr.io/evil/myimage",
			},
			status:    openvexlib.StatusNotAffected,
			wantMatch: false,
		},
		{
			name: "purl in identifiers",
			component: openvexlib.Component{
				Identifiers: map[openvexlib.IdentifierType]string{
					openvexlib.PURL: "pkg:oci/myimage@" + testDigest,
				},
			},
			status:    openvexlib.StatusNotAffected,
			wantMatch: true,
		},
		{
			name: "hash with OpenVEX algorithm name and bare hex",
			component: openvexlib.Component{
				Hashes: map[openvexlib.Algorithm]openvexlib.Hash{
					openvexlib.SHA256: openvexlib.Hash(hexDigest),
				},
			},
			status:    openvexlib.StatusNotAffected,
			wantMatch: true,
		},
		{
			name: "image reference with digest",
			component: openvexlib.Component{
				ID: "quay.io/myorg/myimage@" + testDigest,
			},
			status:    openvexlib.StatusNotAffected,
			wantMatch: true,
		},
		{
			name: "purl of a different image digest",
			component: openvexlib.Component{
				ID: "pkg:oci/myimage@sha256:" + strings.Repeat("0", 64),
			},
			status:    openvexlib.StatusNotAffected,
			wantMatch: false,
		},
		{
			name:      "package purl applies as a component of the image",
			component: openvexlib.Component{ID: "pkg:npm/lodash@4.17.20"},
			status:    openvexlib.StatusAffected,
			wantMatch: true,
		},
		{
			name:      "tag purl of another tag",
			component: openvexlib.Component{ID: "pkg:oci/myimage@v2"},
			status:    openvexlib.StatusNotAffected,
			wantMatch: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			doc := openvexlib.VEX{
				Context: testVEXContext,
				ID:      testDocID,
				Statements: []openvexlib.Statement{{
					Vulnerability: openvexlib.Vulnerability{Name: testCVE},
					Products:      []openvexlib.Product{{Component: test.component}},
					Status:        test.status,
				}},
			}

			result, err := openvex.Verify(
				context.Background(), testutil.MustMarshal(t, doc), testImage(),
			)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got := result.MatchedStatements == 1; got != test.wantMatch {
				t.Errorf("expected match=%v, got %+v", test.wantMatch, result)
			}
		})
	}
}

func TestEvaluateStatusPrecedence(t *testing.T) {
	t.Parallel()

	older := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	newer := older.Add(24 * time.Hour)

	tests := []struct {
		name         string
		statements   []openvexlib.Statement
		wantAffected bool
		wantUI       bool
	}{
		{
			name: "later fixed overrides earlier affected",
			statements: []openvexlib.Statement{
				statementAt(openvexlib.StatusAffected, older),
				statementAt(openvexlib.StatusFixed, newer),
			},
			wantAffected: false,
			wantUI:       false,
		},
		{
			name: "later affected overrides earlier not_affected regardless of order",
			statements: []openvexlib.Statement{
				statementAt(openvexlib.StatusAffected, newer),
				statementAt(openvexlib.StatusNotAffected, older),
			},
			wantAffected: true,
			wantUI:       false,
		},
		{
			name: "equal timestamps pick the most restrictive status",
			statements: []openvexlib.Statement{
				statementAt(openvexlib.StatusAffected, older),
				statementAt(openvexlib.StatusNotAffected, older),
			},
			wantAffected: true,
			wantUI:       false,
		},
		{
			name: "later under_investigation overrides earlier affected",
			statements: []openvexlib.Statement{
				statementAt(openvexlib.StatusAffected, older),
				statementAt(openvexlib.StatusUnderInvestigation, newer),
			},
			wantAffected: false,
			wantUI:       true,
		},
		{
			name: "unknown status is treated as affected",
			statements: []openvexlib.Statement{
				statementAt("Affected", newer),
			},
			wantAffected: true,
			wantUI:       false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			doc := openvexlib.VEX{
				Context:    testVEXContext,
				ID:         testDocID,
				Statements: test.statements,
			}

			result, err := openvex.Verify(
				context.Background(), testutil.MustMarshal(t, doc), testImage(),
			)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got := len(result.AffectedNames) > 0; got != test.wantAffected {
				t.Errorf("expected affected=%v, got %+v", test.wantAffected, result)
			}

			if result.HasUnderInvestigation != test.wantUI {
				t.Errorf("expected under investigation=%v, got %+v", test.wantUI, result)
			}

			if result.MatchedStatements != 1 {
				t.Errorf("expected one effective statement, got %d", result.MatchedStatements)
			}
		})
	}
}

func TestEvaluateAcrossDocumentsUsesDocumentTimestamp(t *testing.T) {
	t.Parallel()

	older := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	newer := older.Add(time.Hour)

	build := func(status openvexlib.Status, timestamp time.Time) *openvex.Document {
		doc := openvexlib.VEX{
			Context:   testVEXContext,
			ID:        testDocID,
			Timestamp: &timestamp,
			Statements: []openvexlib.Statement{{
				Vulnerability: openvexlib.Vulnerability{Name: testCVE},
				Products: []openvexlib.Product{
					{ID: testDigest},
				},
				Status: status,
			}},
		}

		parsed, err := openvex.Parse(testutil.MustMarshal(t, doc))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}

		return parsed
	}

	result, err := openvex.Evaluate(context.Background(), []*openvex.Document{
		build(openvexlib.StatusNotAffected, newer),
		build(openvexlib.StatusAffected, older),
	}, testImage())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.AffectedNames) != 0 {
		t.Errorf("expected newer not_affected document to win, got %v", result.AffectedNames)
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

	result, err := openvex.Verify(context.Background(), data, testImage())
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

	result, err := openvex.Verify(context.Background(), data, testImage())
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

func productStatement(
	status openvexlib.Status, productID string, timestamp *time.Time,
) openvexlib.Statement {
	return openvexlib.Statement{
		Vulnerability: openvexlib.Vulnerability{Name: testCVE},
		Products:      []openvexlib.Product{{ID: productID}},
		Status:        status,
		Timestamp:     timestamp,
	}
}

func TestEvaluateMatchStrengthPrecedence(t *testing.T) {
	t.Parallel()

	older := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	newer := older.Add(24 * time.Hour)
	digestPURL := "pkg:oci/myimage@" + testDigest
	namePURL := "pkg:oci/myimage"

	tests := []struct {
		name         string
		statements   []openvexlib.Statement
		wantAffected bool
	}{
		{
			name: "newer name-only not_affected does not lower digest-bound affected",
			statements: []openvexlib.Statement{
				productStatement(openvexlib.StatusAffected, digestPURL, &older),
				productStatement(openvexlib.StatusNotAffected, namePURL, &newer),
			},
			wantAffected: true,
		},
		{
			name: "same pair in reverse document order",
			statements: []openvexlib.Statement{
				productStatement(openvexlib.StatusNotAffected, namePURL, &newer),
				productStatement(openvexlib.StatusAffected, digestPURL, &older),
			},
			wantAffected: true,
		},
		{
			name: "newer name-only affected raises digest-bound not_affected",
			statements: []openvexlib.Statement{
				productStatement(openvexlib.StatusNotAffected, digestPURL, &older),
				productStatement(openvexlib.StatusAffected, namePURL, &newer),
			},
			wantAffected: true,
		},
		{
			name: "newer digest-bound not_affected overrides older name-only affected",
			statements: []openvexlib.Statement{
				productStatement(openvexlib.StatusAffected, namePURL, &older),
				productStatement(openvexlib.StatusNotAffected, digestPURL, &newer),
			},
			wantAffected: false,
		},
		{
			name: "undated affected ties with dated not_affected",
			statements: []openvexlib.Statement{
				productStatement(openvexlib.StatusAffected, digestPURL, nil),
				productStatement(openvexlib.StatusNotAffected, digestPURL, &newer),
			},
			wantAffected: true,
		},
		{
			name: "package purl product affected applies to the image",
			statements: []openvexlib.Statement{
				productStatement(openvexlib.StatusAffected, "pkg:npm/lodash@4.17.20", &older),
			},
			wantAffected: true,
		},
		{
			name: "not_affected for one package does not resolve another package",
			statements: []openvexlib.Statement{
				productStatement(openvexlib.StatusAffected, "pkg:npm/lodash@4.17.20", &older),
				productStatement(openvexlib.StatusNotAffected, "pkg:npm/express@4.0.0", &newer),
			},
			wantAffected: true,
		},
		{
			name: "package not_affected does not lower digest-bound affected",
			statements: []openvexlib.Statement{
				productStatement(openvexlib.StatusAffected, testDigest, &older),
				productStatement(openvexlib.StatusNotAffected, "pkg:npm/lodash@4.17.20", &newer),
			},
			wantAffected: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			doc := openvexlib.VEX{
				Context:    testVEXContext,
				ID:         testDocID,
				Statements: test.statements,
			}

			result, err := openvex.Verify(
				context.Background(), testutil.MustMarshal(t, doc), testImage(),
			)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got := len(result.AffectedNames) > 0; got != test.wantAffected {
				t.Errorf("expected affected=%v, got %+v", test.wantAffected, result)
			}
		})
	}
}

func TestEvaluateUndatedDocumentTiesWithDatedDocument(t *testing.T) {
	t.Parallel()

	dated := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)

	undatedDoc := openvexlib.VEX{
		Context: testVEXContext,
		ID:      testDocID,
		Statements: []openvexlib.Statement{
			productStatement(openvexlib.StatusAffected, testDigest, nil),
		},
	}

	datedDoc := openvexlib.VEX{
		Context:   testVEXContext,
		ID:        testDocID,
		Timestamp: &dated,
		Statements: []openvexlib.Statement{
			productStatement(openvexlib.StatusNotAffected, testDigest, nil),
		},
	}

	docs := make([]*openvex.Document, 0, 2)

	for _, raw := range []openvexlib.VEX{undatedDoc, datedDoc} {
		parsed, err := openvex.Parse(testutil.MustMarshal(t, raw))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}

		docs = append(docs, parsed)
	}

	result, err := openvex.Evaluate(context.Background(), docs, testImage())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.AffectedNames) != 1 {
		t.Errorf("expected undated affected to tie and win, got %+v", result)
	}
}

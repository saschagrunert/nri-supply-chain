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

package vulnscan_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/intoto"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
	"github.com/saschagrunert/nri-supply-chain/internal/vulnscan"
)

const (
	testDigest        = "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	testDigestAlgo    = "sha256"
	testInTotoType    = "https://in-toto.io/Statement/v1"
	testSubjectName   = "test-image"
	testPredicateType = "https://in-toto.io/attestation/vulns/v0.1"
	testScannerURI    = "https://scanner.example.com/trivy"
	testCVE1          = "CVE-2024-1234"
	testCVE2          = "CVE-2024-5678"
	testCVE3          = "CVE-2024-9999"
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

type vulnScanDoc struct {
	Scanner  scannerInfo `json:"scanner"`
	Metadata *scanMeta   `json:"metadata,omitempty"`
	Result   scanResult  `json:"result"`
}

type scannerInfo struct {
	URI     string `json:"uri,omitempty"`
	Version string `json:"version,omitempty"`
}

type scanMeta struct {
	ScannedOn *string `json:"scannedOn,omitempty"`
}

type scanResult struct {
	Vulnerabilities []vuln `json:"vulnerabilities,omitempty"`
}

type vuln struct {
	ID       string   `json:"id"`
	Severity string   `json:"severity,omitempty"`
	Score    *float64 `json:"score,omitempty"`
}

const (
	testSevMedium   = "medium"
	testSevLow      = "low"
	testSevHigh     = "high"
	testSevCritical = "critical"
)

func validDoc() vulnScanDoc {
	return vulnScanDoc{ //nolint:exhaustruct // test omits Metadata
		Scanner: scannerInfo{URI: testScannerURI, Version: "0.50.0"},
		Result: scanResult{
			Vulnerabilities: []vuln{
				{ID: testCVE1, Severity: testSevMedium, Score: new(5.5)},
				{ID: testCVE2, Severity: testSevLow, Score: new(2.1)},
			},
		},
	}
}

func cleanDoc() vulnScanDoc {
	return vulnScanDoc{ //nolint:exhaustruct // test omits Metadata
		Scanner: scannerInfo{URI: testScannerURI}, //nolint:exhaustruct // test omits Version
		Result:  scanResult{Vulnerabilities: []vuln{}},
	}
}

func criticalDoc() vulnScanDoc {
	return vulnScanDoc{ //nolint:exhaustruct // test omits Metadata
		Scanner: scannerInfo{URI: testScannerURI}, //nolint:exhaustruct // test omits Version
		Result: scanResult{
			Vulnerabilities: []vuln{
				{ID: testCVE3, Severity: testSevCritical, Score: new(9.8)},
				{ID: testCVE1, Severity: testSevHigh, Score: new(7.5)},
			},
		},
	}
}

func wrapInToto(t *testing.T, doc any, digest string) []byte {
	t.Helper()

	predBytes := testutil.MustMarshal(t, doc)

	wrapper := inTotoWrapper{
		Type: testInTotoType,
		Subject: []inTotoSubj{
			{
				Name:   testSubjectName,
				Digest: map[string]string{testDigestAlgo: digest[len(testDigestAlgo)+1:]},
			},
		},
		PredicateType: testPredicateType,
		Predicate:     predBytes,
	}

	return testutil.MustMarshal(t, wrapper)
}

func TestVerify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		doc        vulnScanDoc
		pol        *policy.Policy
		wantPassed bool
		wantStatus types.CheckStatus
	}{
		{
			name:       "valid scan with no policy passes",
			doc:        validDoc(),
			pol:        &policy.Policy{},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name:       "clean scan with no policy passes",
			doc:        cleanDoc(),
			pol:        &policy.Policy{},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name: "score below threshold passes",
			doc:  validDoc(),
			pol: &policy.Policy{
				Sections: policy.Sections{
					VulnScan: &policy.VulnScanPolicy{
						MaxScore: new(7.0),
					},
				},
			},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name: "score above threshold fails",
			doc:  criticalDoc(),
			pol: &policy.Policy{
				Sections: policy.Sections{
					VulnScan: &policy.VulnScanPolicy{
						MaxScore: new(7.0),
					},
				},
			},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name: "severity below threshold passes",
			doc:  validDoc(),
			pol: &policy.Policy{
				Sections: policy.Sections{
					VulnScan: &policy.VulnScanPolicy{
						MinSeverity: "high",
					},
				},
			},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name: "severity meets threshold fails",
			doc:  criticalDoc(),
			pol: &policy.Policy{
				Sections: policy.Sections{
					VulnScan: &policy.VulnScanPolicy{
						MinSeverity: "high",
					},
				},
			},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name: "ignored CVE bypasses threshold",
			doc:  criticalDoc(),
			pol: &policy.Policy{
				Sections: policy.Sections{
					VulnScan: &policy.VulnScanPolicy{
						MaxScore:   new(7.0),
						IgnoreCVEs: []string{testCVE3, testCVE1},
					},
				},
			},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name: "clean scan with strict policy passes",
			doc:  cleanDoc(),
			pol: &policy.Policy{
				Sections: policy.Sections{
					VulnScan: &policy.VulnScanPolicy{
						MaxScore:    new(0.0),
						MinSeverity: "low",
					},
				},
			},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			att := wrapInToto(t, test.doc, testDigest)

			result, err := vulnscan.Verify(context.Background(), att, test.pol, testDigest)
			testutil.AssertNoError(t, err)

			testutil.AssertEqual(t, test.wantPassed, result.Passed)
			testutil.AssertEqual(t, test.wantStatus, result.Status)
		})
	}
}

func TestVerifyCheckType(t *testing.T) {
	t.Parallel()

	att := wrapInToto(t, validDoc(), testDigest)

	result, err := vulnscan.Verify(context.Background(), att, &policy.Policy{}, testDigest)
	testutil.AssertNoError(t, err)

	testutil.AssertEqual(t, types.CheckType("vulnscan"), result.Type)
}

func TestVerifyMetadata(t *testing.T) {
	t.Parallel()

	att := wrapInToto(t, validDoc(), testDigest)

	result, err := vulnscan.Verify(context.Background(), att, &policy.Policy{}, testDigest)
	testutil.AssertNoError(t, err)

	if result.Metadata == nil {
		t.Fatal("expected metadata on vulnscan result")
	}

	scannerURI, ok := result.Metadata["scanner"].(string)
	if !ok || scannerURI != testScannerURI {
		t.Errorf("scanner = %v, want %s", result.Metadata["scanner"], testScannerURI)
	}

	vulnCount, ok := result.Metadata["vulnCount"].(int64)
	if !ok || vulnCount != 2 {
		t.Errorf("vulnCount = %v, want 2", result.Metadata["vulnCount"])
	}

	maxScore, ok := result.Metadata["maxScore"].(float64)
	if !ok || maxScore != 5.5 {
		t.Errorf("maxScore = %v, want 5.5", result.Metadata["maxScore"])
	}

	maxSeverity, ok := result.Metadata["maxSeverity"].(string)
	if !ok || maxSeverity != "medium" {
		t.Errorf("maxSeverity = %v, want medium", result.Metadata["maxSeverity"])
	}

	criticalCount, ok := result.Metadata["criticalCount"].(int64)
	if !ok || criticalCount != 0 {
		t.Errorf("criticalCount = %v, want 0", result.Metadata["criticalCount"])
	}

	highCount, ok := result.Metadata["highCount"].(int64)
	if !ok || highCount != 0 {
		t.Errorf("highCount = %v, want 0", result.Metadata["highCount"])
	}
}

func TestVerifyMetadataCriticalDoc(t *testing.T) {
	t.Parallel()

	att := wrapInToto(t, criticalDoc(), testDigest)

	result, err := vulnscan.Verify(context.Background(), att, &policy.Policy{}, testDigest)
	testutil.AssertNoError(t, err)

	if result.Metadata == nil {
		t.Fatal("expected metadata")
	}

	criticalCount, ok := result.Metadata["criticalCount"].(int64)
	if !ok || criticalCount != 1 {
		t.Errorf("criticalCount = %v, want 1", result.Metadata["criticalCount"])
	}

	highCount, ok := result.Metadata["highCount"].(int64)
	if !ok || highCount != 1 {
		t.Errorf("highCount = %v, want 1", result.Metadata["highCount"])
	}
}

func TestVerifyMalformedPayloads(t *testing.T) {
	t.Parallel()

	t.Run("empty payload", func(t *testing.T) {
		t.Parallel()

		_, err := vulnscan.Verify(context.Background(), []byte{}, &policy.Policy{}, testDigest)
		if !errors.Is(err, vulnscan.ErrInvalidVulnScan) {
			t.Errorf("expected ErrInvalidVulnScan, got %v", err)
		}
	})

	t.Run("nil payload", func(t *testing.T) {
		t.Parallel()

		_, err := vulnscan.Verify(context.Background(), nil, &policy.Policy{}, testDigest)
		if !errors.Is(err, vulnscan.ErrInvalidVulnScan) {
			t.Errorf("expected ErrInvalidVulnScan, got %v", err)
		}
	})

	t.Run("truncated JSON", func(t *testing.T) {
		t.Parallel()

		_, err := vulnscan.Verify(
			context.Background(), []byte(`{"subject":[`), &policy.Policy{}, testDigest,
		)
		if !errors.Is(err, vulnscan.ErrInvalidVulnScan) {
			t.Errorf("expected ErrInvalidVulnScan, got %v", err)
		}
	})
}

func TestVerifySubjectEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("subject with mismatched digest", func(t *testing.T) {
		t.Parallel()

		att := wrapInToto(t, validDoc(), testDigest)

		_, err := vulnscan.Verify(context.Background(),
			att, &policy.Policy{},
			"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		)
		if !errors.Is(err, intoto.ErrSubjectMismatch) {
			t.Errorf("expected ErrSubjectMismatch, got %v", err)
		}
	})

	t.Run("empty digest with subjects rejects for binding", func(t *testing.T) {
		t.Parallel()

		att := wrapInToto(t, validDoc(), testDigest)

		_, err := vulnscan.Verify(context.Background(), att, &policy.Policy{}, "")
		if !errors.Is(err, intoto.ErrNoDigestBinding) {
			t.Errorf("expected ErrNoDigestBinding, got %v", err)
		}
	})
}

func TestVerifyThresholdDetailMessage(t *testing.T) {
	t.Parallel()

	att := wrapInToto(t, criticalDoc(), testDigest)

	result, err := vulnscan.Verify(context.Background(), att, &policy.Policy{
		Sections: policy.Sections{
			VulnScan: &policy.VulnScanPolicy{
				MaxScore: new(7.0),
			},
		},
	}, testDigest)
	testutil.AssertNoError(t, err)

	if result.Passed {
		t.Fatal("expected fail")
	}

	if !strings.Contains(result.Detail, "threshold exceeded") {
		t.Errorf("expected detail to mention threshold exceeded, got %q", result.Detail)
	}

	if !strings.Contains(result.Detail, testCVE3) {
		t.Errorf("expected detail to contain CVE ID, got %q", result.Detail)
	}
}

func TestVerifyNoVulnerabilities(t *testing.T) {
	t.Parallel()

	att := wrapInToto(t, cleanDoc(), testDigest)

	result, err := vulnscan.Verify(context.Background(), att, &policy.Policy{}, testDigest)
	testutil.AssertNoError(t, err)

	if !result.Passed {
		t.Errorf("expected pass for clean scan, got: %s", result.Detail)
	}

	vulnCount, ok := result.Metadata["vulnCount"].(int64)
	if !ok || vulnCount != 0 {
		t.Errorf("vulnCount = %v, want 0", result.Metadata["vulnCount"])
	}

	maxSeverity, ok := result.Metadata["maxSeverity"].(string)
	if !ok || maxSeverity != "none" {
		t.Errorf("maxSeverity = %v, want none", result.Metadata["maxSeverity"])
	}
}

func TestVerifyMultiple(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		docs       []vulnScanDoc
		pol        *policy.Policy
		wantPassed bool
		wantStatus types.CheckStatus
	}{
		{
			name:       "all pass",
			docs:       []vulnScanDoc{validDoc()},
			pol:        &policy.Policy{},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name: "any threshold exceeded fails",
			docs: []vulnScanDoc{criticalDoc()},
			pol: &policy.Policy{
				Sections: policy.Sections{
					VulnScan: &policy.VulnScanPolicy{
						MaxScore: new(7.0),
					},
				},
			},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name:       "empty attestation list",
			docs:       []vulnScanDoc{},
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

			result, err := vulnscan.VerifyMultiple(
				context.Background(),
				attestations,
				test.pol,
				testDigest,
			)
			testutil.AssertNoError(t, err)

			testutil.AssertEqual(t, test.wantPassed, result.Passed)
			testutil.AssertEqual(t, test.wantStatus, result.Status)
		})
	}
}

func TestVerifyMultipleMergesMetadata(t *testing.T) {
	t.Parallel()

	doc1 := vulnScanDoc{ //nolint:exhaustruct // test omits Metadata
		Scanner: scannerInfo{URI: testScannerURI}, //nolint:exhaustruct // test omits Version
		Result: scanResult{
			Vulnerabilities: []vuln{
				{ID: testCVE1, Severity: testSevMedium, Score: new(5.5)},
			},
		},
	}
	doc2 := vulnScanDoc{ //nolint:exhaustruct // test omits Metadata
		Scanner: scannerInfo{URI: testScannerURI}, //nolint:exhaustruct // test omits Version
		Result: scanResult{
			Vulnerabilities: []vuln{
				{ID: testCVE2, Severity: testSevLow, Score: new(2.1)},
			},
		},
	}

	attestations := [][]byte{
		wrapInToto(t, doc1, testDigest),
		wrapInToto(t, doc2, testDigest),
	}

	result, err := vulnscan.VerifyMultiple(
		context.Background(), attestations, &policy.Policy{}, testDigest,
	)
	testutil.AssertNoError(t, err)

	if !result.Passed {
		t.Fatalf("expected pass, got: %s", result.Detail)
	}

	if result.Metadata == nil {
		t.Fatal("expected metadata on merged result")
	}

	vulnCount, ok := result.Metadata["vulnCount"].(int64)
	if !ok || vulnCount != 2 {
		t.Errorf("vulnCount = %v, want 2", result.Metadata["vulnCount"])
	}

	maxScore, ok := result.Metadata["maxScore"].(float64)
	if !ok || maxScore != 5.5 {
		t.Errorf("maxScore = %v, want 5.5", result.Metadata["maxScore"])
	}
}

func TestVerifyMultipleEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("nil attestation slice", func(t *testing.T) {
		t.Parallel()

		result, err := vulnscan.VerifyMultiple(
			context.Background(),
			nil,
			&policy.Policy{},
			testDigest,
		)
		testutil.AssertNoError(t, err)

		if !result.Passed {
			t.Errorf("expected pass for nil attestation slice, got: %s", result.Detail)
		}
	})

	t.Run("all invalid returns fail with parse errors", func(t *testing.T) {
		t.Parallel()

		attestations := [][]byte{
			[]byte("bad json 1"),
			[]byte("bad json 2"),
		}

		result, err := vulnscan.VerifyMultiple(
			context.Background(),
			attestations,
			&policy.Policy{},
			testDigest,
		)
		testutil.AssertNoError(t, err)

		if result.Passed {
			t.Error("expected fail when all documents are invalid")
		}

		testutil.AssertEqual(t, types.StatusFail, result.Status)
	})

	t.Run("mix of valid and invalid with valid passing", func(t *testing.T) {
		t.Parallel()

		attestations := [][]byte{
			[]byte("invalid json"),
			wrapInToto(t, validDoc(), testDigest),
		}

		result, err := vulnscan.VerifyMultiple(
			context.Background(),
			attestations,
			&policy.Policy{},
			testDigest,
		)
		testutil.AssertNoError(t, err)

		if !result.Passed {
			t.Errorf("expected pass with valid doc, got: %s", result.Detail)
		}
	})
}

func TestVerifyFreshness(t *testing.T) {
	t.Parallel()

	staleTime := "2020-01-01T00:00:00Z"
	freshTime := time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339)

	tests := []struct {
		name       string
		doc        vulnScanDoc
		pol        *policy.Policy
		wantPassed bool
		wantSubstr string
	}{
		{
			name: "stale scan fails",
			doc: vulnScanDoc{
				Scanner: scannerInfo{ //nolint:exhaustruct // test omits Version
					URI: testScannerURI,
				},
				Metadata: &scanMeta{ScannedOn: &staleTime},
				Result:   scanResult{Vulnerabilities: []vuln{}},
			},
			pol: &policy.Policy{
				Sections: policy.Sections{
					VulnScan: &policy.VulnScanPolicy{
						MaxAge:         "1h",
						MaxAgeDuration: time.Hour,
					},
				},
			},
			wantPassed: false,
			wantSubstr: "stale",
		},
		{
			name: "fresh scan passes",
			doc: vulnScanDoc{
				Scanner: scannerInfo{ //nolint:exhaustruct // test omits Version
					URI: testScannerURI,
				},
				Metadata: &scanMeta{ScannedOn: &freshTime},
				Result:   scanResult{Vulnerabilities: []vuln{}},
			},
			pol: &policy.Policy{
				Sections: policy.Sections{
					VulnScan: &policy.VulnScanPolicy{
						MaxAge:         "1h",
						MaxAgeDuration: time.Hour,
					},
				},
			},
			wantPassed: true,
			wantSubstr: "",
		},
		{
			name: "no timestamp with maxAge fails",
			doc:  cleanDoc(),
			pol: &policy.Policy{
				Sections: policy.Sections{
					VulnScan: &policy.VulnScanPolicy{
						MaxAge:         "1h",
						MaxAgeDuration: time.Hour,
					},
				},
			},
			wantPassed: false,
			wantSubstr: "no scan timestamp",
		},
		{
			name:       "no timestamp without maxAge passes",
			doc:        cleanDoc(),
			pol:        &policy.Policy{},
			wantPassed: true,
			wantSubstr: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			att := wrapInToto(t, test.doc, testDigest)

			result, err := vulnscan.Verify(context.Background(), att, test.pol, testDigest)
			testutil.AssertNoError(t, err)

			testutil.AssertEqual(t, test.wantPassed, result.Passed)

			if test.wantSubstr != "" && !strings.Contains(result.Detail, test.wantSubstr) {
				t.Errorf("expected detail to contain %q, got %q", test.wantSubstr, result.Detail)
			}
		})
	}
}

func TestVerifyScoreWithoutScoreField(t *testing.T) {
	t.Parallel()

	doc := vulnScanDoc{ //nolint:exhaustruct // test omits Metadata
		Scanner: scannerInfo{URI: testScannerURI}, //nolint:exhaustruct // test omits Version
		Result: scanResult{
			Vulnerabilities: []vuln{
				{ID: testCVE1, Severity: testSevHigh}, //nolint:exhaustruct // test omits Score
			},
		},
	}
	att := wrapInToto(t, doc, testDigest)

	result, err := vulnscan.Verify(context.Background(), att, &policy.Policy{
		Sections: policy.Sections{
			VulnScan: &policy.VulnScanPolicy{
				MinSeverity: testSevCritical,
			},
		},
	}, testDigest)
	testutil.AssertNoError(t, err)

	if !result.Passed {
		t.Errorf("expected pass when severity below threshold, got: %s", result.Detail)
	}
}

func TestVerifyMultipleMergesScannerURI(t *testing.T) {
	t.Parallel()

	doc1 := vulnScanDoc{ //nolint:exhaustruct // test omits Metadata
		Scanner: scannerInfo{ //nolint:exhaustruct // test omits Version
			URI: "https://scanner1.example.com",
		},
		Result: scanResult{
			Vulnerabilities: []vuln{
				{ID: testCVE1, Severity: testSevLow, Score: new(2.0)},
			},
		},
	}
	doc2 := vulnScanDoc{ //nolint:exhaustruct // test omits Metadata
		Scanner: scannerInfo{ //nolint:exhaustruct // test omits Version
			URI: "https://scanner2.example.com",
		},
		Result: scanResult{
			Vulnerabilities: []vuln{
				{ID: testCVE2, Severity: testSevLow, Score: new(1.5)},
			},
		},
	}

	attestations := [][]byte{
		wrapInToto(t, doc1, testDigest),
		wrapInToto(t, doc2, testDigest),
	}

	result, err := vulnscan.VerifyMultiple(
		context.Background(), attestations, &policy.Policy{}, testDigest,
	)
	testutil.AssertNoError(t, err)

	if !result.Passed {
		t.Fatalf("expected pass, got: %s", result.Detail)
	}

	if result.Metadata == nil {
		t.Fatal("expected metadata on merged result")
	}

	scanner, ok := result.Metadata["scanner"].(string)
	if !ok {
		t.Fatal("scanner metadata should be a string")
	}

	if !strings.Contains(scanner, "https://scanner1.example.com") {
		t.Errorf("scanner should contain scanner1 URI, got %q", scanner)
	}

	if !strings.Contains(scanner, "https://scanner2.example.com") {
		t.Errorf("scanner should contain scanner2 URI, got %q", scanner)
	}

	if scanner != "https://scanner1.example.com,https://scanner2.example.com" {
		t.Errorf("scanner = %q, want comma-separated URIs", scanner)
	}
}

func TestVerifyMultiplePassAndFail(t *testing.T) {
	t.Parallel()

	attestations := [][]byte{
		wrapInToto(t, cleanDoc(), testDigest),
		wrapInToto(t, criticalDoc(), testDigest),
	}

	result, err := vulnscan.VerifyMultiple(
		context.Background(),
		attestations,
		&policy.Policy{
			Sections: policy.Sections{
				VulnScan: &policy.VulnScanPolicy{
					MaxScore: new(7.0),
				},
			},
		},
		testDigest,
	)
	testutil.AssertNoError(t, err)

	if result.Passed {
		t.Error("expected fail when one attestation exceeds threshold")
	}

	testutil.AssertEqual(t, types.StatusFail, result.Status)
}

func TestVerifyUnknownSeverityTreatedAsNone(t *testing.T) {
	t.Parallel()

	doc := vulnScanDoc{ //nolint:exhaustruct // test omits Metadata
		Scanner: scannerInfo{URI: testScannerURI}, //nolint:exhaustruct // test omits Version
		Result: scanResult{
			Vulnerabilities: []vuln{
				{ID: testCVE1, Severity: "moderate", Score: new(4.0)},
			},
		},
	}
	att := wrapInToto(t, doc, testDigest)

	result, err := vulnscan.Verify(context.Background(), att, &policy.Policy{
		Sections: policy.Sections{
			VulnScan: &policy.VulnScanPolicy{
				MinSeverity: testSevLow,
			},
		},
	}, testDigest)
	testutil.AssertNoError(t, err)

	if !result.Passed {
		t.Errorf(
			"expected pass: unknown severity 'moderate' should rank as none, got: %s",
			result.Detail,
		)
	}
}

func TestVerifyIgnoreCVEsWithMinSeverity(t *testing.T) {
	t.Parallel()

	att := wrapInToto(t, criticalDoc(), testDigest)

	result, err := vulnscan.Verify(context.Background(), att, &policy.Policy{
		Sections: policy.Sections{
			VulnScan: &policy.VulnScanPolicy{
				MinSeverity: testSevHigh,
				IgnoreCVEs:  []string{testCVE3, testCVE1},
			},
		},
	}, testDigest)
	testutil.AssertNoError(t, err)

	if !result.Passed {
		t.Errorf("expected pass when all CVEs are ignored, got: %s", result.Detail)
	}
}

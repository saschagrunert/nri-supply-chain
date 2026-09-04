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

package cyclonedxvex_test

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/vex/cyclonedxvex"
)

const (
	testDigest   = "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	testCompRef  = "comp-nginx"
	testCompName = "nginx"
)

func bomWithVuln(state cdx.ImpactAnalysisState, affectsRef string) *cdx.BOM {
	bom := cdx.NewBOM()
	bom.Components = &[]cdx.Component{
		{
			BOMRef:  testCompRef,
			Type:    cdx.ComponentTypeContainer,
			Name:    testCompName,
			Version: "latest",
			Hashes: &[]cdx.Hash{
				{
					Algorithm: cdx.HashAlgoSHA256,
					Value:     testDigest[len("sha256:"):],
				},
			},
		},
	}

	analysis := &cdx.VulnerabilityAnalysis{State: state}

	bom.Vulnerabilities = &[]cdx.Vulnerability{
		{
			ID:       "CVE-2024-1234",
			Analysis: analysis,
			Affects: &[]cdx.Affects{
				{Ref: affectsRef},
			},
		},
	}

	return bom
}

func TestVerifyImpactAnalysisStates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                   string
		state                  cdx.ImpactAnalysisState
		wantAffected           bool
		wantUnderInvestigation bool
	}{
		{
			name:                   "not_affected passes",
			state:                  cdx.IASNotAffected,
			wantAffected:           false,
			wantUnderInvestigation: false,
		},
		{
			name:                   "false_positive passes",
			state:                  cdx.IASFalsePositive,
			wantAffected:           false,
			wantUnderInvestigation: false,
		},
		{
			name:                   "resolved passes",
			state:                  cdx.IASResolved,
			wantAffected:           false,
			wantUnderInvestigation: false,
		},
		{
			name:                   "resolved_with_pedigree passes",
			state:                  cdx.IASResolvedWithPedigree,
			wantAffected:           false,
			wantUnderInvestigation: false,
		},
		{
			name:                   "exploitable fails",
			state:                  cdx.IASExploitable,
			wantAffected:           true,
			wantUnderInvestigation: false,
		},
		{
			name:                   "in_triage sets under investigation",
			state:                  cdx.IASInTriage,
			wantAffected:           false,
			wantUnderInvestigation: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			bom := bomWithVuln(test.state, testCompRef)
			data := testutil.MustMarshal(t, bom)

			result, err := cyclonedxvex.Verify(data, testDigest, "")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if test.wantAffected && len(result.AffectedNames) == 0 {
				t.Error("expected affected vulnerabilities, got none")
			}

			if !test.wantAffected && len(result.AffectedNames) > 0 {
				t.Errorf("expected no affected vulnerabilities, got %v", result.AffectedNames)
			}

			if result.HasUnderInvestigation != test.wantUnderInvestigation {
				t.Errorf("expected HasUnderInvestigation=%v, got %v",
					test.wantUnderInvestigation, result.HasUnderInvestigation)
			}
		})
	}
}

func TestVerifyComponentMatchByDigest(t *testing.T) {
	t.Parallel()

	bom := bomWithVuln(cdx.IASExploitable, testCompRef)
	data := testutil.MustMarshal(t, bom)

	result, err := cyclonedxvex.Verify(data, testDigest, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.AffectedNames) == 0 {
		t.Error("expected affected vulnerability via component hash match")
	}
}

func TestVerifyComponentNoMatch(t *testing.T) {
	t.Parallel()

	bom := bomWithVuln(cdx.IASExploitable, "unknown-ref")
	data := testutil.MustMarshal(t, bom)

	otherDigest := "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

	result, err := cyclonedxvex.Verify(data, otherDigest, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.AffectedNames) > 0 {
		t.Errorf("expected no match for different digest, got %v", result.AffectedNames)
	}
}

func TestVerifyDirectRefDigestMatch(t *testing.T) {
	t.Parallel()

	// Affects ref contains the digest directly (no component lookup needed).
	bom := cdx.NewBOM()
	bom.Vulnerabilities = &[]cdx.Vulnerability{
		{
			ID:       "CVE-2024-5678",
			Analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASExploitable},
			Affects: &[]cdx.Affects{
				{Ref: testDigest},
			},
		},
	}

	data := testutil.MustMarshal(t, bom)

	result, err := cyclonedxvex.Verify(data, testDigest, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.AffectedNames) == 0 {
		t.Error("expected affected vulnerability via direct digest ref match")
	}

	if result.AffectedNames[0] != "CVE-2024-5678" {
		t.Errorf("expected CVE-2024-5678, got %s", result.AffectedNames[0])
	}
}

func TestVerifyPURLMatch(t *testing.T) {
	t.Parallel()

	purl := "pkg:oci/nginx@" + testDigest + "?repository_url=index.docker.io%2Flibrary"

	bom := cdx.NewBOM()
	bom.Components = &[]cdx.Component{
		{
			BOMRef:     testCompRef,
			Type:       cdx.ComponentTypeContainer,
			Name:       testCompName,
			PackageURL: purl,
		},
	}
	bom.Vulnerabilities = &[]cdx.Vulnerability{
		{
			ID:       "CVE-2024-9999",
			Analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASExploitable},
			Affects: &[]cdx.Affects{
				{Ref: testCompRef},
			},
		},
	}

	data := testutil.MustMarshal(t, bom)

	result, err := cyclonedxvex.Verify(data, testDigest, purl)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.AffectedNames) == 0 {
		t.Error("expected affected vulnerability via PURL match")
	}
}

func TestVerifyEmptyVulnerabilities(t *testing.T) {
	t.Parallel()

	bom := cdx.NewBOM()
	data := testutil.MustMarshal(t, bom)

	result, err := cyclonedxvex.Verify(data, testDigest, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.AffectedNames) > 0 {
		t.Errorf("expected no affected for empty vulnerabilities, got %v", result.AffectedNames)
	}

	if result.HasUnderInvestigation {
		t.Error("expected no under investigation for empty vulnerabilities")
	}
}

func TestVerifyNilVulnerabilities(t *testing.T) {
	t.Parallel()

	bom := cdx.NewBOM()
	bom.Vulnerabilities = nil
	data := testutil.MustMarshal(t, bom)

	result, err := cyclonedxvex.Verify(data, testDigest, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.AffectedNames) > 0 || result.HasUnderInvestigation {
		t.Error("expected clean result for nil vulnerabilities")
	}
}

func TestVerifyMalformedJSON(t *testing.T) {
	t.Parallel()

	_, err := cyclonedxvex.Verify([]byte("not json"), testDigest, "")
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestVerifyEmptyPayload(t *testing.T) {
	t.Parallel()

	_, err := cyclonedxvex.Verify([]byte{}, testDigest, "")
	if err == nil {
		t.Fatal("expected error for empty payload")
	}
}

func TestVerifyNoAnalysis(t *testing.T) {
	t.Parallel()

	// Vulnerability with nil Analysis should be treated as affected.
	bom := cdx.NewBOM()
	bom.Components = &[]cdx.Component{
		{
			BOMRef: testCompRef,
			Type:   cdx.ComponentTypeContainer,
			Name:   testCompName,
			Hashes: &[]cdx.Hash{
				{
					Algorithm: cdx.HashAlgoSHA256,
					Value:     testDigest[len("sha256:"):],
				},
			},
		},
	}
	bom.Vulnerabilities = &[]cdx.Vulnerability{
		{
			ID: "CVE-2024-0000",
			Affects: &[]cdx.Affects{
				{Ref: testCompRef},
			},
		},
	}

	data := testutil.MustMarshal(t, bom)

	result, err := cyclonedxvex.Verify(data, testDigest, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.AffectedNames) != 1 || result.AffectedNames[0] != "CVE-2024-0000" {
		t.Errorf("expected CVE-2024-0000 to be affected when analysis is nil, got %v",
			result.AffectedNames)
	}
}

func TestVerifyEmptyAffects(t *testing.T) {
	t.Parallel()

	bom := cdx.NewBOM()
	bom.Vulnerabilities = &[]cdx.Vulnerability{
		{
			ID:       "CVE-2024-0001",
			Analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASExploitable},
		},
	}

	data := testutil.MustMarshal(t, bom)

	result, err := cyclonedxvex.Verify(data, testDigest, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.AffectedNames) > 0 {
		t.Error("expected no match when vulnerability has no affects")
	}
}

func TestVerifyUnknownVulnerabilityName(t *testing.T) {
	t.Parallel()

	bom := cdx.NewBOM()
	bom.Vulnerabilities = &[]cdx.Vulnerability{
		{
			ID:       "",
			Analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASExploitable},
			Affects: &[]cdx.Affects{
				{Ref: testDigest},
			},
		},
	}

	data := testutil.MustMarshal(t, bom)

	result, err := cyclonedxvex.Verify(data, testDigest, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.AffectedNames) == 0 {
		t.Fatal("expected affected vulnerability")
	}

	if result.AffectedNames[0] != "unknown" {
		t.Errorf("expected 'unknown' name, got %q", result.AffectedNames[0])
	}
}

func TestVerifyMultipleVulnerabilities(t *testing.T) {
	t.Parallel()

	bom := cdx.NewBOM()
	bom.Vulnerabilities = &[]cdx.Vulnerability{
		{
			ID:       "CVE-2024-1111",
			Analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASNotAffected},
			Affects: &[]cdx.Affects{
				{Ref: testDigest},
			},
		},
		{
			ID:       "CVE-2024-2222",
			Analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASExploitable},
			Affects: &[]cdx.Affects{
				{Ref: testDigest},
			},
		},
		{
			ID:       "CVE-2024-3333",
			Analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASInTriage},
			Affects: &[]cdx.Affects{
				{Ref: testDigest},
			},
		},
	}

	data := testutil.MustMarshal(t, bom)

	result, err := cyclonedxvex.Verify(data, testDigest, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.AffectedNames) != 1 || result.AffectedNames[0] != "CVE-2024-2222" {
		t.Errorf("expected [CVE-2024-2222], got %v", result.AffectedNames)
	}

	if !result.HasUnderInvestigation {
		t.Error("expected HasUnderInvestigation to be true for in_triage")
	}
}

func TestVerifyUnrecognizedStateTreatedAsAffected(t *testing.T) {
	t.Parallel()

	bom := cdx.NewBOM()
	bom.Vulnerabilities = &[]cdx.Vulnerability{
		{
			ID:       "CVE-2024-9876",
			Analysis: &cdx.VulnerabilityAnalysis{State: "some_future_state"},
			Affects: &[]cdx.Affects{
				{Ref: testDigest},
			},
		},
	}

	data := testutil.MustMarshal(t, bom)

	result, err := cyclonedxvex.Verify(data, testDigest, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.AffectedNames) != 1 || result.AffectedNames[0] != "CVE-2024-9876" {
		t.Errorf("expected unrecognized state to be treated as affected, got %v",
			result.AffectedNames)
	}
}

func TestVerifyEmptyAnalysisState(t *testing.T) {
	t.Parallel()

	// Vulnerability with Analysis set but empty State should be treated as affected.
	bom := cdx.NewBOM()
	bom.Vulnerabilities = &[]cdx.Vulnerability{
		{
			ID:       "CVE-2024-0002",
			Analysis: &cdx.VulnerabilityAnalysis{},
			Affects: &[]cdx.Affects{
				{Ref: testDigest},
			},
		},
	}

	data := testutil.MustMarshal(t, bom)

	result, err := cyclonedxvex.Verify(data, testDigest, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.AffectedNames) != 1 || result.AffectedNames[0] != "CVE-2024-0002" {
		t.Errorf("expected CVE-2024-0002 to be affected when analysis state is empty, got %v",
			result.AffectedNames)
	}
}

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
	"github.com/saschagrunert/nri-supply-chain/internal/vex/imagematch"
)

const (
	testDigest   = "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	testImageRef = "docker.io/library/nginx:latest"
	testCompRef  = "comp-nginx"
	testCompName = "nginx"
	testCVE      = "CVE-2024-4242"
	otherDigest  = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	otherName    = "other"
)

func testImage() *imagematch.Image {
	return imagematch.New(testImageRef, testDigest, nil)
}

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

			result, err := cyclonedxvex.Verify(data, testImage())
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

	result, err := cyclonedxvex.Verify(data, testImage())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.AffectedNames) == 0 {
		t.Error("expected affected vulnerability via component hash match")
	}
}

func TestVerifyComponentNoMatch(t *testing.T) {
	t.Parallel()

	bom := bomWithVuln(cdx.IASExploitable, testCompRef)
	data := testutil.MustMarshal(t, bom)

	result, err := cyclonedxvex.Verify(data, imagematch.New("", otherDigest, nil))
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

	result, err := cyclonedxvex.Verify(data, testImage())
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

	result, err := cyclonedxvex.Verify(data, testImage())
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

	result, err := cyclonedxvex.Verify(data, testImage())
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

	result, err := cyclonedxvex.Verify(data, testImage())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.AffectedNames) > 0 || result.HasUnderInvestigation {
		t.Error("expected clean result for nil vulnerabilities")
	}
}

func TestVerifyMalformedJSON(t *testing.T) {
	t.Parallel()

	_, err := cyclonedxvex.Verify([]byte("not json"), testImage())
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestVerifyEmptyPayload(t *testing.T) {
	t.Parallel()

	_, err := cyclonedxvex.Verify([]byte{}, testImage())
	if err == nil {
		t.Fatal("expected error for empty payload")
	}
}

func TestVerifyNoAnalysis(t *testing.T) {
	t.Parallel()

	// A vulnerability without analysis is a finding, not a VEX statement, so
	// it is ignored even when it affects the image.
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

	result, err := cyclonedxvex.Verify(data, testImage())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.AffectedNames) != 0 || result.MatchedVulnerabilities != 0 {
		t.Errorf("expected vulnerability without analysis to be ignored, got %+v", result)
	}
}

func TestVerifyEmptyAffectsAppliesToImage(t *testing.T) {
	t.Parallel()

	// The BOM is bound to the image, so a vulnerability without affects
	// describes the BOM subject (the image) and must not be ignored.
	bom := cdx.NewBOM()
	bom.Vulnerabilities = &[]cdx.Vulnerability{
		{
			ID:       "CVE-2024-0001",
			Analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASExploitable},
		},
	}

	data := testutil.MustMarshal(t, bom)

	result, err := cyclonedxvex.Verify(data, testImage())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.AffectedNames) != 1 || result.MatchedVulnerabilities != 1 {
		t.Errorf("expected vulnerability without affects to apply, got %+v", result)
	}
}

func vulnBOM(vulnRef string, components []cdx.Component) *cdx.BOM {
	bom := cdx.NewBOM()
	bom.Components = &components
	bom.Vulnerabilities = &[]cdx.Vulnerability{
		{
			ID:       testCVE,
			Analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASExploitable},
			Affects:  &[]cdx.Affects{{Ref: vulnRef}},
		},
	}

	return bom
}

func TestVerifyAffectsResolution(t *testing.T) {
	t.Parallel()

	hexDigest := testDigest[len("sha256:"):]

	tests := []struct {
		name      string
		bom       *cdx.BOM
		wantMatch bool
	}{
		{
			name: "trivy style package component applies to image",
			bom: vulnBOM("pkg-openssl", []cdx.Component{{
				BOMRef: "pkg-openssl", Type: cdx.ComponentTypeLibrary,
				Name: "openssl", PackageURL: "pkg:apk/alpine/openssl@3.1.0",
			}}),
			wantMatch: true,
		},
		{
			name: "nested component is indexed",
			bom: vulnBOM("nested-lib", []cdx.Component{{
				BOMRef: "app", Type: cdx.ComponentTypeApplication, Name: "app",
				Components: &[]cdx.Component{{
					BOMRef: "nested-lib", Type: cdx.ComponentTypeLibrary,
					Name: "lib", PackageURL: "pkg:npm/lib@1.0.0",
				}},
			}}),
			wantMatch: true,
		},
		{
			name: "percent encoded digest in OCI purl",
			bom: vulnBOM("pkg:oci/nginx@sha256%3A"+hexDigest+
				"?repository_url=docker.io/library/nginx&tag=latest", nil),
			wantMatch: true,
		},
		{
			name:      "BOM-Link reference applies",
			bom:       vulnBOM("urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1#pkg-x", nil),
			wantMatch: true,
		},
		{
			name: "component of a different image is ignored",
			bom: vulnBOM(otherName, []cdx.Component{{
				BOMRef: otherName, Type: cdx.ComponentTypeContainer, Name: otherName,
				PackageURL: "pkg:oci/other@" + otherDigest,
			}}),
			wantMatch: false,
		},
		{
			name: "container component with different hash is ignored",
			bom: vulnBOM(otherName, []cdx.Component{{
				BOMRef: otherName, Type: cdx.ComponentTypeContainer, Name: otherName,
				Hashes: &[]cdx.Hash{{
					Algorithm: cdx.HashAlgoSHA256,
					Value:     otherDigest[len("sha256:"):],
				}},
			}}),
			wantMatch: false,
		},
		{
			name:      "raw digest of a different image is ignored",
			bom:       vulnBOM(otherDigest, nil),
			wantMatch: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			data := testutil.MustMarshal(t, test.bom)

			result, err := cyclonedxvex.Verify(data, testImage())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got := len(result.AffectedNames) == 1; got != test.wantMatch {
				t.Errorf("expected match=%v, got %+v", test.wantMatch, result)
			}
		})
	}
}

func TestVerifyMetadataComponentIndexed(t *testing.T) {
	t.Parallel()

	bom := cdx.NewBOM()
	bom.Metadata = &cdx.Metadata{
		Component: &cdx.Component{
			BOMRef: "image", Type: cdx.ComponentTypeContainer, Name: testCompName,
			PackageURL: "pkg:oci/nginx@" + testDigest,
		},
	}
	bom.Vulnerabilities = &[]cdx.Vulnerability{{
		ID:       testCVE,
		Analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASNotAffected},
		Affects:  &[]cdx.Affects{{Ref: "image"}},
	}}

	result, err := cyclonedxvex.Verify(testutil.MustMarshal(t, bom), testImage())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.MatchedVulnerabilities != 1 || len(result.AffectedNames) != 0 {
		t.Errorf("expected metadata component match with not_affected, got %+v", result)
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

	result, err := cyclonedxvex.Verify(data, testImage())
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

	result, err := cyclonedxvex.Verify(data, testImage())
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

	result, err := cyclonedxvex.Verify(data, testImage())
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

	// A vulnerability with an empty analysis state is not a VEX statement.
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

	result, err := cyclonedxvex.Verify(data, testImage())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.AffectedNames) != 0 || result.MatchedVulnerabilities != 0 {
		t.Errorf("expected vulnerability with empty analysis state to be ignored, got %+v", result)
	}
}

func TestVerifyUnresolvedReferences(t *testing.T) {
	t.Parallel()

	retagged := func(state cdx.ImpactAnalysisState) *cdx.BOM {
		bom := cdx.NewBOM()
		bom.Metadata = &cdx.Metadata{Component: &cdx.Component{
			BOMRef: "subject", Type: cdx.ComponentTypeContainer, Name: "app-build",
			PackageURL: "pkg:oci/app-build@v2",
		}}
		bom.Vulnerabilities = &[]cdx.Vulnerability{{
			ID:       testCVE,
			Analysis: &cdx.VulnerabilityAnalysis{State: state},
			Affects:  &[]cdx.Affects{{Ref: "subject"}},
		}}

		return bom
	}

	withState := func(bom *cdx.BOM, state cdx.ImpactAnalysisState) *cdx.BOM {
		(*bom.Vulnerabilities)[0].Analysis = &cdx.VulnerabilityAnalysis{State: state}

		return bom
	}

	tests := []struct {
		name        string
		bom         *cdx.BOM
		wantMatched int
		wantAffect  bool
	}{
		{
			name:        "exploitable with bom-ref missing from the BOM applies",
			bom:         vulnBOM("ref-from-separate-sbom", nil),
			wantMatched: 1,
			wantAffect:  true,
		},
		{
			name:        "exploitable with CPE reference applies",
			bom:         vulnBOM("cpe:2.3:a:openssl:openssl:3.1.0:*:*:*:*:*:*:*", nil),
			wantMatched: 1,
			wantAffect:  true,
		},
		{
			name:        "exploitable on retagged metadata component applies",
			bom:         retagged(cdx.IASExploitable),
			wantMatched: 1,
			wantAffect:  true,
		},
		{
			name:        "in_triage with unknown reference applies",
			bom:         withState(vulnBOM("ref-from-separate-sbom", nil), cdx.IASInTriage),
			wantMatched: 1,
			wantAffect:  false,
		},
		{
			name:        "not_affected with unknown reference does not apply",
			bom:         withState(vulnBOM("ref-from-separate-sbom", nil), cdx.IASNotAffected),
			wantMatched: 0,
			wantAffect:  false,
		},
		{
			name:        "not_affected on retagged metadata component does not apply",
			bom:         retagged(cdx.IASNotAffected),
			wantMatched: 0,
			wantAffect:  false,
		},
		{
			name:        "exploitable on a different image digest is still ignored",
			bom:         vulnBOM(otherDigest, nil),
			wantMatched: 0,
			wantAffect:  false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			image := imagematch.New("ghcr.io/team/app:v1", testDigest, nil)

			result, err := cyclonedxvex.Verify(testutil.MustMarshal(t, test.bom), image)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.MatchedVulnerabilities != test.wantMatched {
				t.Errorf("matched = %d, want %d", result.MatchedVulnerabilities, test.wantMatched)
			}

			if got := len(result.AffectedNames) > 0; got != test.wantAffect {
				t.Errorf("affected = %v, want %v (%+v)", got, test.wantAffect, result)
			}
		})
	}
}

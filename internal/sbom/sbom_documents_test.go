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

package sbom_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/sbom"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	vexOnlyCycloneDX = `{"bomFormat":"CycloneDX","vulnerabilities":[` +
		`{"id":"CVE-2024-1","analysis":{"state":"not_affected"}}]}`
	emptyCycloneDX        = `{"bomFormat":"CycloneDX","components":[]}`
	twoComponentCycloneDX = `{"bomFormat":"CycloneDX","components":[` +
		`{"name":"a","purl":"pkg:npm/a@1","licenses":[{"license":{"id":"MIT"}}]},` +
		`{"name":"b","purl":"pkg:npm/b@1","licenses":[{"license":{"id":"Apache-2.0"}}]}]}`
	threeComponentCycloneDX = `{"bomFormat":"CycloneDX","components":[` +
		`{"name":"c","purl":"pkg:npm/c@1","licenses":[{"license":{"id":"MIT"}}]},` +
		`{"name":"d","purl":"pkg:npm/d@1"},{"name":"e","purl":"pkg:npm/e@1"}]}`
)

func wrapRaw(t *testing.T, predicate string) []byte {
	t.Helper()

	return testutil.WrapInToto(t, json.RawMessage(predicate), testDigest, testPredicateType)
}

func TestVerifyMultipleVEXOnlyCycloneDXIsNotAnSBOM(t *testing.T) {
	t.Parallel()

	allowList := &policy.Policy{
		SBOM: &policy.SBOMPolicy{
			Component: &policy.SBOMComponentPolicy{Allow: []string{"pkg:npm/"}},
		},
	}

	for _, predicate := range []string{vexOnlyCycloneDX, emptyCycloneDX} {
		_, err := sbom.VerifyMultipleWithBaseline(
			context.Background(), [][]byte{wrapRaw(t, predicate)}, nil, allowList, testDigest,
		)
		if !errors.Is(err, types.ErrNotApplicable) {
			t.Errorf("expected %q to be not applicable as an SBOM, got %v", predicate, err)
		}
	}
}

func TestVerifyMultipleSkipsVEXOnlyDocumentsNextToSBOMs(t *testing.T) {
	t.Parallel()

	result, err := sbom.VerifyMultiple(
		context.Background(),
		[][]byte{wrapRaw(t, vexOnlyCycloneDX), wrapRaw(t, twoComponentCycloneDX)},
		&policy.Policy{}, testDigest,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Passed {
		t.Fatalf("expected pass, got %s", result.Detail)
	}

	if got := result.Metadata["componentCount"]; got != int64(2) {
		t.Errorf("componentCount = %v, want 2", got)
	}
}

func TestVerifyMultipleAggregatesDocumentMetadata(t *testing.T) {
	t.Parallel()

	result, err := sbom.VerifyMultiple(
		context.Background(),
		[][]byte{
			wrapRaw(t, twoComponentCycloneDX),
			wrapRaw(t, threeComponentCycloneDX),
			testutil.WrapInToto(t, validSPDXDoc(), testDigest, testPredicateType),
		},
		&policy.Policy{}, testDigest,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	spdxComponents := int64(len(validSPDXDoc().Packages))

	if got := result.Metadata["componentCount"]; got != int64(5)+spdxComponents {
		t.Errorf("componentCount = %v, want %d", got, int64(5)+spdxComponents)
	}

	if got := result.Metadata["format"]; got != "cyclonedx,spdx" {
		t.Errorf("format = %v, want cyclonedx,spdx", got)
	}

	if got := result.Metadata["licenseCount"]; got != int64(2) {
		t.Errorf("licenseCount = %v, want 2 (union of MIT and Apache-2.0)", got)
	}
}

func TestVerifyMetadataPURLsKeepUppercaseUpstream(t *testing.T) {
	t.Parallel()

	predicate := `{"bomFormat":"CycloneDX","components":[` +
		`{"name":"libc6","purl":"pkg:deb/debian/libc6@2.36-9?UPSTREAM=glibc&arch=amd64"}]}`

	result, err := sbom.Verify(
		context.Background(),
		wrapRaw(t, predicate),
		&policy.Policy{},
		testDigest,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	purls, _ := result.Metadata["purls"].([]string)
	if len(purls) != 1 || purls[0] != "pkg:deb/debian/libc6@2.36-9?upstream=glibc" {
		t.Errorf("expected the upstream qualifier to be kept, got %v", result.Metadata["purls"])
	}
}

func vdrCycloneDX(state string, score float64) string {
	analysis := ""
	if state != "" {
		analysis = `,"analysis":{"state":"` + state + `"}`
	}

	scoreJSON, _ := json.Marshal(score) //nolint:errchkjson // float64 never fails

	return `{"bomFormat":"CycloneDX","vulnerabilities":[{"id":"CVE-2024-9",` +
		`"ratings":[{"score":` + string(scoreJSON) + `,"severity":"critical"}]` + analysis + `}]}`
}

func cvssPolicy(maxScore float64) *policy.Policy {
	return &policy.Policy{
		SBOM: &policy.SBOMPolicy{CVSS: &policy.SBOMCVSSPolicy{MaxScore: &maxScore}},
	}
}

func TestVerifyMultipleVulnerabilityOnlyCycloneDXIsEvaluatedForCVSS(t *testing.T) {
	t.Parallel()

	spdx := testutil.WrapInToto(t, validSPDXDoc(), testDigest, testPredicateType)

	for _, state := range []string{"", "in_triage", "exploitable"} {
		result, err := sbom.VerifyMultiple(
			context.Background(),
			[][]byte{wrapRaw(t, vdrCycloneDX(state, 9.8)), spdx},
			cvssPolicy(7), testDigest,
		)
		if err != nil {
			t.Fatalf("state %q: unexpected error: %v", state, err)
		}

		if result.Passed {
			t.Errorf(
				"state %q: expected an unresolved 9.8 vulnerability to exceed maxScore 7", state,
			)
		}
	}
}

func TestVerifyMultipleVulnerabilityOnlyAloneExceedingCVSSFails(t *testing.T) {
	t.Parallel()

	result, err := sbom.VerifyMultiple(
		context.Background(),
		[][]byte{wrapRaw(t, vdrCycloneDX("", 9.8))},
		cvssPolicy(7), testDigest,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Passed {
		t.Error("expected a vulnerability-only document exceeding maxScore to fail the check")
	}
}

func TestVerifyMultipleVulnerabilityOnlyWithinCVSSIsNotAnSBOM(t *testing.T) {
	t.Parallel()

	// Resolved findings and findings within the thresholds leave nothing to
	// fail, and a document without components is still not an SBOM.
	for _, predicate := range []string{vdrCycloneDX("", 5.0), vdrCycloneDX("not_affected", 9.8)} {
		_, err := sbom.VerifyMultiple(
			context.Background(), [][]byte{wrapRaw(t, predicate)}, cvssPolicy(7), testDigest,
		)
		if !errors.Is(err, types.ErrNotApplicable) {
			t.Errorf("expected %q to be not applicable as an SBOM, got %v", predicate, err)
		}
	}
}

func TestVerifyMultipleVulnerabilityOnlyDoesNotChangeInventoryMetadata(t *testing.T) {
	t.Parallel()

	result, err := sbom.VerifyMultiple(
		context.Background(),
		[][]byte{wrapRaw(t, vdrCycloneDX("in_triage", 5.0)), wrapRaw(t, twoComponentCycloneDX)},
		cvssPolicy(7), testDigest,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Passed {
		t.Fatalf("expected pass, got %s", result.Detail)
	}

	if got := result.Metadata["componentCount"]; got != int64(2) {
		t.Errorf("componentCount = %v, want 2", got)
	}

	if got := result.Metadata["format"]; got != "cyclonedx" {
		t.Errorf("format = %v, want cyclonedx", got)
	}

	if got := result.Metadata["cvssMax"]; got != 5.0 {
		t.Errorf("cvssMax = %v, want 5 from the vulnerability-only document", got)
	}
}

func TestVerifyEmptyBOMWithSubjectIsAnSBOM(t *testing.T) {
	t.Parallel()

	predicate := `{"bomFormat":"CycloneDX",` +
		`"metadata":{"component":{"type":"container","name":"scratch"}},"components":[]}`

	result, err := sbom.VerifyMultiple(
		context.Background(), [][]byte{wrapRaw(t, predicate)}, &policy.Policy{}, testDigest,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Passed {
		t.Errorf("expected an empty BOM with a subject to pass, got %s", result.Detail)
	}
}

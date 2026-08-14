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

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
)

func TestBuildInspectAttestations(t *testing.T) {
	t.Parallel()

	atts := []attestation.VerifiedAttestation{
		{
			PredicateType: attestation.PredicateSLSAProvenanceV1,
			SignatureType: attestation.SignatureTypeSigstore,
			Digest:        testDigestABC123,
		},
		{
			PredicateType: attestation.PredicateOpenVEX,
			SignatureType: attestation.SignatureTypeSigstore,
			Digest:        "",
		},
	}

	result := buildInspectAttestations(atts)

	if len(result) != 2 {
		t.Fatalf("got %d attestations, want 2", len(result))
	}

	if result[0].PredicateType != attestation.PredicateSLSAProvenanceV1 {
		t.Errorf("result[0].PredicateType = %q, want %q",
			result[0].PredicateType, attestation.PredicateSLSAProvenanceV1)
	}

	if result[0].Digest != testDigestABC123 {
		t.Errorf("result[0].Digest = %q, want %q", result[0].Digest, testDigestABC123)
	}

	if result[1].Digest != "" {
		t.Errorf("result[1].Digest = %q, want empty", result[1].Digest)
	}
}

func TestShortenPredicateType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  string
	}{
		{attestation.PredicateSLSAProvenanceV1, "slsa-provenance-v1"},
		{attestation.PredicateOpenVEX, "openvex"},
		{attestation.PredicateRelease, "release"},
		{attestation.PredicateRuntimeTrace, "runtime-trace"},
		{attestation.PredicateVulnScanV02, "vulns-v0.2"},
		{"https://example.com/custom/v1", "example.com/custom/v1"},
		{"custom-predicate", "custom-predicate"},
	}

	for _, test := range tests {
		got := shortenPredicateType(test.input)
		if got != test.want {
			t.Errorf("shortenPredicateType(%q) = %q, want %q", test.input, got, test.want)
		}
	}
}

func TestOutputInspectJSON(t *testing.T) {
	t.Parallel()

	out := &inspectOutput{
		Image:  testImageNginx,
		Digest: testDigestAAA,
		Attestations: []inspectAttestation{
			{
				PredicateType: attestation.PredicateSLSAProvenanceV1,
				SignatureType: string(attestation.SignatureTypeSigstore),
				Digest:        "sha256:abc",
			},
		},
	}

	var buf bytes.Buffer

	err := outputInspectJSON(&buf, out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed inspectOutput

	err = json.Unmarshal(buf.Bytes(), &parsed)
	if err != nil {
		t.Fatalf("invalid JSON: %v\nraw: %s", err, buf.String())
	}

	if parsed.Image != testImageNginx {
		t.Errorf("Image = %q, want %q", parsed.Image, testImageNginx)
	}

	if len(parsed.Attestations) != 1 {
		t.Fatalf("got %d attestations, want 1", len(parsed.Attestations))
	}
}

func TestOutputInspectTableEmpty(t *testing.T) {
	t.Parallel()

	out := &inspectOutput{
		Image:        testImageNginx,
		Digest:       testDigestAAA,
		Attestations: nil,
	}

	var buf bytes.Buffer

	err := outputInspectTable(&buf, out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := buf.String()

	if !strings.Contains(got, testImageNginx) {
		t.Errorf("output missing image ref\ngot:\n%s", got)
	}

	if !strings.Contains(got, "0") {
		t.Errorf("output missing attestation count 0\ngot:\n%s", got)
	}
}

func TestOutputInspectTableWithAttestations(t *testing.T) {
	t.Parallel()

	out := &inspectOutput{
		Image:  testImageNginx,
		Digest: testDigestAAA,
		Attestations: []inspectAttestation{
			{
				PredicateType: attestation.PredicateSLSAProvenanceV1,
				SignatureType: string(attestation.SignatureTypeSigstore),
				Digest:        "sha256:abc",
			},
		},
	}

	var buf bytes.Buffer

	err := outputInspectTable(&buf, out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := buf.String()

	for _, want := range []string{
		testImageNginx,
		"PREDICATE TYPE",
		"SIGNATURE",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q\ngot:\n%s", want, got)
		}
	}
}

func TestRunInspectInvalidOutputFormat(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	code := runInspect(&buf, testImageV1, "xml", config.DefaultConfig())
	if code != exitError {
		t.Errorf("exit code = %d, want %d", code, exitError)
	}
}

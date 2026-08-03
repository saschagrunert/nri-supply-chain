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

//nolint:testpackage // testing unexported functions
package verifier

import (
	"testing"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	celengine "github.com/saschagrunert/nri-supply-chain/internal/cel"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	celExprSLSAVerified = "slsa.verified == true"
	celMsgSLSARequired  = "SLSA must pass"
)

func TestBinAttestationsUnknownType(t *testing.T) {
	t.Parallel()

	attestations := []attestation.VerifiedAttestation{
		{
			PredicateType: "https://example.com/unknown",
			Payload:       []byte("u1"),
			Digest:        benchDigest,
		},
		{
			PredicateType: attestation.PredicateSLSAProvenanceV1,
			Payload:       []byte("slsa1"),
			Digest:        benchDigest,
		},
		{
			PredicateType: "https://example.com/other",
			Payload:       []byte("u2"),
			Digest:        benchDigest,
		},
	}

	bins := binAttestations(attestations)

	if len(bins.slsa) != 1 {
		t.Errorf("expected 1 SLSA attestation, got %d", len(bins.slsa))
	}

	if len(bins.vex) != 0 {
		t.Errorf("expected 0 VEX attestations, got %d", len(bins.vex))
	}

	if len(bins.vsa) != 0 {
		t.Errorf("expected 0 VSA attestations, got %d", len(bins.vsa))
	}

	if len(bins.notation) != 0 {
		t.Errorf("expected 0 Notation attestations, got %d", len(bins.notation))
	}
}

func TestBinAttestationsNotation(t *testing.T) {
	t.Parallel()

	attestations := []attestation.VerifiedAttestation{
		{
			PredicateType: attestation.PredicateSLSAProvenanceV1,
			Payload:       []byte("slsa1"),
			Digest:        benchDigest,
			SignatureType: attestation.SignatureTypeSigstore,
		},
		{
			PredicateType: attestation.NotationSignatureMediaType,
			Payload:       []byte("notation-ref"),
			Digest:        benchDigest,
			SignatureType: attestation.SignatureTypeNotation,
		},
		{
			PredicateType: attestation.PredicateOpenVEX,
			Payload:       []byte("vex1"),
			Digest:        benchDigest,
			SignatureType: attestation.SignatureTypeSigstore,
		},
	}

	bins := binAttestations(attestations)

	if len(bins.slsa) != 1 {
		t.Errorf("expected 1 SLSA attestation, got %d", len(bins.slsa))
	}

	if len(bins.vex) != 1 {
		t.Errorf("expected 1 VEX attestation, got %d", len(bins.vex))
	}

	if len(bins.vsa) != 0 {
		t.Errorf("expected 0 VSA attestations, got %d", len(bins.vsa))
	}

	if len(bins.notation) != 1 {
		t.Errorf("expected 1 Notation attestation, got %d", len(bins.notation))
	}

	if string(bins.notation[0].Payload) != "notation-ref" {
		t.Errorf(
			"expected notation payload %q, got %q",
			"notation-ref",
			string(bins.notation[0].Payload),
		)
	}
}

func TestBinAttestationsCycloneDX(t *testing.T) {
	t.Parallel()

	attestations := []attestation.VerifiedAttestation{
		{
			PredicateType: attestation.PredicateOpenVEX,
			Payload:       []byte("openvex1"),
			Digest:        benchDigest,
		},
		{
			PredicateType: attestation.PredicateCycloneDX,
			Payload:       []byte("cdx1"),
			Digest:        benchDigest,
		},
		{
			PredicateType: attestation.PredicateSLSAProvenanceV1,
			Payload:       []byte("slsa1"),
			Digest:        benchDigest,
		},
	}

	bins := binAttestations(attestations)

	if len(bins.vex) != 2 {
		t.Errorf("expected 2 VEX attestations (OpenVEX + CycloneDX), got %d", len(bins.vex))
	}

	if len(bins.slsa) != 1 {
		t.Errorf("expected 1 SLSA attestation, got %d", len(bins.slsa))
	}

	if len(bins.vsa) != 0 {
		t.Errorf("expected 0 VSA attestations, got %d", len(bins.vsa))
	}

	if len(bins.sbom) != 1 {
		t.Errorf(
			"expected 1 SBOM attestation (CycloneDX), got %d",
			len(bins.sbom),
		)
	}
}

func TestBinAttestationsSPDX(t *testing.T) {
	t.Parallel()

	attestations := []attestation.VerifiedAttestation{
		{
			PredicateType: attestation.PredicateSPDX,
			Payload:       []byte("spdx1"),
			Digest:        benchDigest,
		},
	}

	bins := binAttestations(attestations)

	if len(bins.sbom) != 1 {
		t.Errorf("expected 1 SBOM attestation, got %d", len(bins.sbom))
	}

	if len(bins.vex) != 0 {
		t.Errorf("expected 0 VEX attestations, got %d", len(bins.vex))
	}
}

func TestRunCELCheckNilCompiledCEL(t *testing.T) {
	t.Parallel()

	pol := &policy.Policy{}
	result := &types.Result{
		Allowed:      false,
		Reason:       "",
		CheckResults: nil,
	}

	check := runCELCheck(pol, "ghcr.io/org/img:latest", benchDigest, "default", nil, result)
	if check != nil {
		t.Errorf("expected nil for nil CompiledCEL, got %v", check)
	}
}

func TestRunCELCheckNilParsedRef(t *testing.T) {
	t.Parallel()

	compiled, err := celengine.Compile([]celengine.Rule{
		{Require: celExprSLSAVerified, Message: celMsgSLSARequired},
	})
	if err != nil {
		t.Fatalf("compiling CEL rules: %v", err)
	}

	pol := &policy.Policy{}
	pol.CompiledCEL = compiled

	result := &types.Result{
		Allowed: false,
		Reason:  "",
		CheckResults: []types.CheckResult{
			*types.PassResult(types.CheckTypeSLSA, "verified"),
		},
	}

	check := runCELCheck(pol, "ghcr.io/org/img:latest", benchDigest, "default", nil, result)
	if check == nil {
		t.Fatal("expected non-nil CEL check result with nil parsedRef")
	}

	if !check.Passed {
		t.Errorf(
			"expected CEL check to pass with nil parsedRef, got status=%s detail=%s",
			check.Status, check.Detail,
		)
	}
}

func TestRunCELCheckRequirePass(t *testing.T) {
	t.Parallel()

	compiled, err := celengine.Compile([]celengine.Rule{
		{Require: celExprSLSAVerified, Message: celMsgSLSARequired},
	})
	if err != nil {
		t.Fatalf("compiling CEL rules: %v", err)
	}

	pol := &policy.Policy{}
	pol.CompiledCEL = compiled

	result := &types.Result{
		Allowed: false,
		Reason:  "",
		CheckResults: []types.CheckResult{
			*types.PassResult(types.CheckTypeSLSA, "verified"),
		},
	}

	ref, _ := name.ParseReference("ghcr.io/org/img:latest")

	check := runCELCheck(pol, "ghcr.io/org/img:latest", benchDigest, "default", ref, result)
	if check == nil {
		t.Fatal("expected non-nil CEL check result")
	}

	if !check.Passed {
		t.Errorf("expected CEL check to pass, got status=%s detail=%s", check.Status, check.Detail)
	}
}

func TestRunCELCheckRequireFail(t *testing.T) {
	t.Parallel()

	compiled, err := celengine.Compile([]celengine.Rule{
		{Require: celExprSLSAVerified, Message: celMsgSLSARequired},
	})
	if err != nil {
		t.Fatalf("compiling CEL rules: %v", err)
	}

	pol := &policy.Policy{}
	pol.CompiledCEL = compiled

	result := &types.Result{
		Allowed: false,
		Reason:  "",
		CheckResults: []types.CheckResult{
			*types.FailResult(types.CheckTypeSLSA, "no provenance found", nil),
		},
	}

	ref, _ := name.ParseReference("ghcr.io/org/img:latest")

	check := runCELCheck(pol, "ghcr.io/org/img:latest", benchDigest, "default", ref, result)
	if check == nil {
		t.Fatal("expected non-nil CEL check result")
	}

	if check.Passed {
		t.Error("expected CEL check to fail when SLSA is not verified")
	}
}

func TestRunCELCheckMatchFilter(t *testing.T) {
	t.Parallel()

	compiled, err := celengine.Compile([]celengine.Rule{
		{
			Match:   "image.registry == 'docker.io'",
			Require: celExprSLSAVerified,
			Message: "Docker Hub images require SLSA",
		},
	})
	if err != nil {
		t.Fatalf("compiling CEL rules: %v", err)
	}

	pol := &policy.Policy{}
	pol.CompiledCEL = compiled

	result := &types.Result{
		Allowed: false,
		Reason:  "",
		CheckResults: []types.CheckResult{
			*types.FailResult(types.CheckTypeSLSA, "no provenance", nil),
		},
	}

	ref, _ := name.ParseReference("ghcr.io/org/img:latest")

	check := runCELCheck(pol, "ghcr.io/org/img:latest", benchDigest, "default", ref, result)
	if check == nil {
		t.Fatal("expected non-nil CEL check result")
	}

	if !check.Passed {
		t.Error("expected CEL check to pass when match filter excludes the image")
	}
}

func TestRunCELCheckMultipleCheckTypes(t *testing.T) {
	t.Parallel()

	compiled, err := celengine.Compile([]celengine.Rule{
		{Require: celExprSLSAVerified + " && vex.verified == true"},
	})
	if err != nil {
		t.Fatalf("compiling CEL rules: %v", err)
	}

	pol := &policy.Policy{}
	pol.CompiledCEL = compiled

	result := &types.Result{
		Allowed: false,
		Reason:  "",
		CheckResults: []types.CheckResult{
			*types.PassResult(types.CheckTypeSLSA, "verified"),
			*types.PassResult(types.CheckTypeVEX, "no vulnerabilities"),
		},
	}

	ref, _ := name.ParseReference("ghcr.io/org/img:latest")

	check := runCELCheck(pol, "ghcr.io/org/img:latest", benchDigest, "default", ref, result)
	if check == nil {
		t.Fatal("expected non-nil CEL check result")
	}

	if !check.Passed {
		t.Errorf("expected CEL check to pass with both SLSA and VEX passing")
	}
}

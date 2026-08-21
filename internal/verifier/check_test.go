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
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	celengine "github.com/saschagrunert/nri-supply-chain/internal/cel"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	celExprSLSAVerified = "slsa.verified == true"
	celMsgSLSARequired  = "SLSA must pass"
)

var errBadRef = errors.New("bad ref")

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

	bins := binAttestations(context.Background(), attestations, "")

	if len(bins[types.CheckTypeSLSA]) != 1 {
		t.Errorf("expected 1 SLSA attestation, got %d", len(bins[types.CheckTypeSLSA]))
	}

	if len(bins[types.CheckTypeVEX]) != 0 {
		t.Errorf("expected 0 VEX attestations, got %d", len(bins[types.CheckTypeVEX]))
	}

	if len(bins[types.CheckTypeVSA]) != 0 {
		t.Errorf("expected 0 VSA attestations, got %d", len(bins[types.CheckTypeVSA]))
	}

	if len(bins[types.CheckTypeNotation]) != 0 {
		t.Errorf("expected 0 Notation attestations, got %d", len(bins[types.CheckTypeNotation]))
	}
}

//nolint:paralleltest // mutates slog.SetDefault
func TestBinAttestationsUnknownTypeWarning(t *testing.T) {
	var buf bytes.Buffer

	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	prev := slog.Default()

	slog.SetDefault(slog.New(handler))

	t.Cleanup(func() { slog.SetDefault(prev) })

	const imageRef = "ghcr.io/org/img:latest"

	attestations := []attestation.VerifiedAttestation{
		{
			PredicateType: "https://example.com/unknown",
			Payload:       []byte("u1"),
			Digest:        benchDigest,
		},
	}

	_ = binAttestations(context.Background(), attestations, imageRef)

	output := buf.String()

	if !strings.Contains(output, "Skipping attestation with unrecognized predicate type") {
		t.Errorf("expected warning about unrecognized predicate type, got: %s", output)
	}

	if !strings.Contains(output, "https://example.com/unknown") {
		t.Errorf("expected predicate type in warning, got: %s", output)
	}

	if !strings.Contains(output, imageRef) {
		t.Errorf("expected image reference in warning, got: %s", output)
	}
}

//nolint:paralleltest // mutates slog.SetDefault
func TestBinAttestationsCosignSignatureSilent(t *testing.T) {
	var buf bytes.Buffer

	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	prev := slog.Default()

	slog.SetDefault(slog.New(handler))

	t.Cleanup(func() { slog.SetDefault(prev) })

	attestations := []attestation.VerifiedAttestation{
		{
			PredicateType: attestation.PredicateCosignSignature,
			Payload:       []byte("sig"),
			Digest:        benchDigest,
		},
	}

	bins := binAttestations(context.Background(), attestations, "ghcr.io/org/img:latest")

	if len(bins[types.CheckTypeSLSA]) != 0 ||
		len(bins[types.CheckTypeVEX]) != 0 ||
		len(bins[types.CheckTypeVSA]) != 0 ||
		len(bins[types.CheckTypeSBOM]) != 0 {
		t.Error("cosign signature should not be binned")
	}

	if buf.Len() != 0 {
		t.Errorf("cosign signature should not produce warn-level output, got: %s", buf.String())
	}
}

func TestBinAttestationsSLSAV02(t *testing.T) {
	t.Parallel()

	attestations := []attestation.VerifiedAttestation{
		{
			PredicateType: attestation.PredicateSLSAProvenanceV02,
			Payload:       []byte("slsa02"),
			Digest:        benchDigest,
		},
	}

	bins := binAttestations(context.Background(), attestations, "")

	if len(bins[types.CheckTypeSLSA]) != 1 {
		t.Errorf("expected 1 SLSA attestation for v0.2, got %d", len(bins[types.CheckTypeSLSA]))
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

	bins := binAttestations(context.Background(), attestations, "")

	if len(bins[types.CheckTypeSLSA]) != 1 {
		t.Errorf("expected 1 SLSA attestation, got %d", len(bins[types.CheckTypeSLSA]))
	}

	if len(bins[types.CheckTypeVEX]) != 1 {
		t.Errorf("expected 1 VEX attestation, got %d", len(bins[types.CheckTypeVEX]))
	}

	if len(bins[types.CheckTypeVSA]) != 0 {
		t.Errorf("expected 0 VSA attestations, got %d", len(bins[types.CheckTypeVSA]))
	}

	if len(bins[types.CheckTypeNotation]) != 1 {
		t.Errorf("expected 1 Notation attestation, got %d", len(bins[types.CheckTypeNotation]))
	}

	if string(bins[types.CheckTypeNotation][0].Payload) != "notation-ref" {
		t.Errorf(
			"expected notation payload %q, got %q",
			"notation-ref",
			string(bins[types.CheckTypeNotation][0].Payload),
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

	bins := binAttestations(context.Background(), attestations, "")

	if len(bins[types.CheckTypeVEX]) != 2 {
		t.Errorf(
			"expected 2 VEX attestations (OpenVEX + CycloneDX), got %d",
			len(bins[types.CheckTypeVEX]),
		)
	}

	if len(bins[types.CheckTypeSLSA]) != 1 {
		t.Errorf("expected 1 SLSA attestation, got %d", len(bins[types.CheckTypeSLSA]))
	}

	if len(bins[types.CheckTypeVSA]) != 0 {
		t.Errorf("expected 0 VSA attestations, got %d", len(bins[types.CheckTypeVSA]))
	}

	if len(bins[types.CheckTypeSBOM]) != 1 {
		t.Errorf(
			"expected 1 SBOM attestation (CycloneDX), got %d",
			len(bins[types.CheckTypeSBOM]),
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

	bins := binAttestations(context.Background(), attestations, "")

	if len(bins[types.CheckTypeSBOM]) != 1 {
		t.Errorf("expected 1 SBOM attestation, got %d", len(bins[types.CheckTypeSBOM]))
	}

	if len(bins[types.CheckTypeVEX]) != 0 {
		t.Errorf("expected 0 VEX attestations, got %d", len(bins[types.CheckTypeVEX]))
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

	check := runCELCheck(
		pol, metrics.New(), "ghcr.io/org/img:latest", benchDigest, "default", nil, result,
	)
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

	check := runCELCheck(
		pol, metrics.New(), "ghcr.io/org/img:latest", benchDigest, "default", nil, result,
	)
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

	check := runCELCheck(
		pol, metrics.New(), "ghcr.io/org/img:latest", benchDigest, "default", ref, result,
	)
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

	check := runCELCheck(
		pol, metrics.New(), "ghcr.io/org/img:latest", benchDigest, "default", ref, result,
	)
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

	check := runCELCheck(
		pol, metrics.New(), "ghcr.io/org/img:latest", benchDigest, "default", ref, result,
	)
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

	check := runCELCheck(
		pol, metrics.New(), "ghcr.io/org/img:latest", benchDigest, "default", ref, result,
	)
	if check == nil {
		t.Fatal("expected non-nil CEL check result")
	}

	if !check.Passed {
		t.Errorf("expected CEL check to pass with both SLSA and VEX passing")
	}
}

func TestRunParallelCheckPanicRecovery(t *testing.T) {
	t.Parallel()

	var (
		waitGroup sync.WaitGroup
		result    *types.CheckResult
	)

	waitGroup.Add(1)

	runParallelCheck(
		context.Background(),
		&waitGroup,
		&result,
		types.CheckTypeSLSA,
		time.Minute,
		func(_ context.Context) *types.CheckResult {
			panic("test panic in check function")
		},
	)

	waitGroup.Wait()

	if result == nil {
		t.Fatal("expected non-nil result after panic recovery")
	}

	if result.Passed {
		t.Error("expected result to not pass after panic")
	}

	if result.Status != types.StatusFail {
		t.Errorf("expected status %q, got %q", types.StatusFail, result.Status)
	}

	if result.Type != types.CheckTypeSLSA {
		t.Errorf("expected check type %q, got %q", types.CheckTypeSLSA, result.Type)
	}

	expectedDetail := "internal error during slsa check"
	if result.Detail != expectedDetail {
		t.Errorf("expected detail %q, got %q", expectedDetail, result.Detail)
	}
}

func TestAcquireHostSemSameHost(t *testing.T) {
	t.Parallel()

	hsm := &hostSemMap{ //nolint:exhaustruct_v5 // test data
		m:     sync.Map{},
		count: atomic.Int64{},
	}

	sem1 := acquireHostSem(hsm, "registry.example.com")
	sem2 := acquireHostSem(hsm, "registry.example.com")

	if sem1 != sem2 {
		t.Error("expected same semaphore for the same host")
	}

	if hsm.count.Load() != 1 {
		t.Errorf("expected count 1, got %d", hsm.count.Load())
	}
}

func TestAcquireHostSemOverflow(t *testing.T) {
	t.Parallel()

	hsm := &hostSemMap{ //nolint:exhaustruct_v5 // test data
		m:     sync.Map{},
		count: atomic.Int64{},
	}

	// Fill the map to maxHostSemEntries.
	for i := range maxHostSemEntries {
		host := fmt.Sprintf("host-%d.example.com", i)
		acquireHostSem(hsm, host)
	}

	if hsm.count.Load() != maxHostSemEntries {
		t.Fatalf("expected count %d after filling, got %d", maxHostSemEntries, hsm.count.Load())
	}

	// The next host should trigger the overflow path.
	overflowHost := "overflow.example.com"
	sem := acquireHostSem(hsm, overflowHost)

	if sem == nil {
		t.Fatal("expected non-nil semaphore from overflow path")
	}

	if hsm.count.Load() != maxHostSemEntries {
		t.Errorf("expected count to remain %d after overflow, got %d",
			maxHostSemEntries, hsm.count.Load())
	}

	// The overflow host should not be stored in the map.
	if _, ok := hsm.m.Load(overflowHost); ok {
		t.Error("expected overflow host to be deleted from the map")
	}

	// Previously stored hosts should still be accessible.
	existing := acquireHostSem(hsm, "host-0.example.com")
	if existing == nil {
		t.Error("expected non-nil semaphore for previously stored host")
	}
}

func TestBuildFetchOptsPropagatesTimeBounds(t *testing.T) {
	t.Parallel()

	nb := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	na := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	pol := &policy.Policy{
		Trust: &policy.TrustPolicy{
			Verifiers: []policy.TrustedVerifier{
				{
					ID:            "https://example.com/v",
					Keys:          []string{"/key/a.pub", "/key/b.pub"},
					NotBeforeTime: nb,
					NotAfterTime:  na,
				},
				{
					ID:   "https://example.com/v2",
					Keys: []string{"/key/c.pub"},
				},
			},
		},
	}

	opts := buildFetchOpts(pol, "sha256:abc", 0, nil)

	if len(opts.TrustedKeys) != 3 {
		t.Fatalf("expected 3 trusted keys, got %d", len(opts.TrustedKeys))
	}

	// Keys from verifier 0 carry time bounds.
	for _, idx := range []int{0, 1} {
		if !opts.TrustedKeys[idx].NotBefore.Equal(nb) {
			t.Errorf(
				"key[%d] NotBefore: expected %v, got %v",
				idx, nb, opts.TrustedKeys[idx].NotBefore,
			)
		}

		if !opts.TrustedKeys[idx].NotAfter.Equal(na) {
			t.Errorf(
				"key[%d] NotAfter: expected %v, got %v",
				idx, na, opts.TrustedKeys[idx].NotAfter,
			)
		}
	}

	// Key from verifier 1 has zero time bounds.
	if !opts.TrustedKeys[2].NotBefore.IsZero() {
		t.Errorf("key[2] NotBefore: expected zero, got %v", opts.TrustedKeys[2].NotBefore)
	}

	if !opts.TrustedKeys[2].NotAfter.IsZero() {
		t.Errorf("key[2] NotAfter: expected zero, got %v", opts.TrustedKeys[2].NotAfter)
	}
}

func TestRegistryHost(t *testing.T) {
	t.Parallel()

	t.Run("successful parse", func(t *testing.T) {
		t.Parallel()

		ref, err := name.ParseReference("ghcr.io/org/img:latest")
		if err != nil {
			t.Fatalf("unexpected parse error: %v", err)
		}

		got := registryHost(ref, nil, "ghcr.io/org/img:latest")
		if got != "ghcr.io" {
			t.Errorf("got %q, want %q", got, "ghcr.io")
		}
	})

	t.Run("parse error short ref", func(t *testing.T) {
		t.Parallel()

		got := registryHost(nil, errBadRef, "not-a-valid-ref")
		if got != "not-a-valid-ref" {
			t.Errorf("got %q, want %q", got, "not-a-valid-ref")
		}
	})

	t.Run("parse error long ref truncated", func(t *testing.T) {
		t.Parallel()

		longRef := strings.Repeat("x", 500)
		got := registryHost(nil, errBadRef, longRef)

		if len(got) != maxRegistryHostLen {
			t.Errorf("len = %d, want %d", len(got), maxRegistryHostLen)
		}

		if got != longRef[:maxRegistryHostLen] {
			t.Error("truncated value does not match prefix of input")
		}
	})
}

func TestBuildFetchOptsNilTrustHasNoKeys(t *testing.T) {
	t.Parallel()

	pol := &policy.Policy{}

	opts := buildFetchOpts(pol, "sha256:abc", 0, nil)

	if len(opts.TrustedKeys) != 0 {
		t.Fatalf("expected 0 trusted keys, got %d", len(opts.TrustedKeys))
	}
}

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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	internaltypes "github.com/saschagrunert/nri-supply-chain/internal/types"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

const (
	testArchAmd64  = "amd64"
	testArchArm64  = "arm64"
	testArchS390x  = "s390x"
	testOSLinux    = "linux"
	testOSZos      = "zos"
	testImageNginx = "nginx:latest"
)

func TestOutputVerifyResultAllowed(t *testing.T) {
	t.Parallel()

	checks := []internaltypes.CheckResult{
		{
			Type: internaltypes.CheckTypeSLSA, Passed: true,
			Status: internaltypes.StatusPass, Detail: "verified", Err: nil,
		},
	}

	const testDigest = "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4" +
		"e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

	out := captureVerifyOutput(
		t, testImageNginx, testDigest,
		verifier.DefaultPolicyLabel, true, "verified", checks,
	)

	if out.Image != testImageNginx {
		t.Errorf("Image = %q, want %q", out.Image, testImageNginx)
	}

	if out.Digest != testDigest {
		t.Errorf("Digest = %q, want %q", out.Digest, testDigest)
	}

	if out.Namespace != verifier.DefaultPolicyLabel {
		t.Errorf("Namespace = %q, want %q", out.Namespace, verifier.DefaultPolicyLabel)
	}

	if !out.Allowed {
		t.Error("expected Allowed = true")
	}

	if out.Reason != "verified" {
		t.Errorf("Reason = %q, want %q", out.Reason, "verified")
	}

	if len(out.CheckResults) != 1 {
		t.Fatalf("CheckResults length = %d, want 1", len(out.CheckResults))
	}

	if out.CheckResults[0].Type != internaltypes.CheckTypeSLSA {
		t.Errorf(
			"CheckResults[0].Type = %q, want %q",
			out.CheckResults[0].Type,
			internaltypes.CheckTypeSLSA,
		)
	}
}

func TestOutputVerifyResultDenied(t *testing.T) {
	t.Parallel()

	const deniedDigest = "sha256:ffffffffffffffffffffffffffffffff" +
		"ffffffffffffffffffffffffffffffff"

	out := captureVerifyOutput(
		t, "evil:latest", deniedDigest,
		testNamespaceProd, false, "failed checks", nil,
	)

	if out.Allowed {
		t.Error("expected Allowed = false")
	}

	if out.Reason != "failed checks" {
		t.Errorf("Reason = %q, want %q", out.Reason, "failed checks")
	}

	if out.CheckResults != nil {
		t.Errorf("expected nil CheckResults, got %v", out.CheckResults)
	}
}

func captureVerifyOutput(
	t *testing.T,
	imageRef, digest, namespace string,
	allowed bool, reason string, checks []internaltypes.CheckResult,
) verifyOutput {
	t.Helper()

	var buf bytes.Buffer

	input := &verifyOutput{
		Image: imageRef, Digest: digest, Namespace: namespace,
		PolicyFile: "", Mode: "",
		Allowed: allowed, Reason: reason, CheckResults: checks,
	}

	err := outputVerifyResult(&buf, outputFormatJSON, input)
	if err != nil {
		t.Fatalf("outputVerifyResult failed: %v", err)
	}

	var parsed verifyOutput

	err = json.Unmarshal(buf.Bytes(), &parsed)
	if err != nil {
		t.Fatalf("invalid JSON output: %v\nraw: %s", err, buf.String())
	}

	return parsed
}

func TestResolveDigestInvalidRef(t *testing.T) {
	t.Parallel()

	_, err := resolveDigest(context.Background(), ":::invalid", 30*time.Second)
	if err == nil {
		t.Fatal("expected error for invalid image reference")
	}

	if !strings.Contains(err.Error(), "parsing image reference") {
		t.Errorf("error = %q, expected to contain 'parsing image reference'", err)
	}
}

func TestResolveDigestNetworkError(t *testing.T) {
	t.Parallel()

	// Use a closed server so connection is refused immediately.
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	addr := server.Listener.Addr().String()
	server.Close()

	_, err := resolveDigest(context.Background(), addr+"/test:latest", 30*time.Second)
	if err == nil {
		t.Fatal("expected error for unreachable registry")
	}

	if !strings.Contains(err.Error(), "resolving image digest") {
		t.Errorf("error = %q, expected to contain 'resolving image digest'", err)
	}
}

func TestResolveDigestSuccess(t *testing.T) {
	t.Parallel()

	regHandler := registry.New()
	server := httptest.NewServer(regHandler)

	t.Cleanup(server.Close)

	addr := strings.TrimPrefix(server.URL, "http://")
	imgRef := addr + "/test:latest"

	img, err := mutate.ConfigFile(empty.Image, nil)
	if err != nil {
		t.Fatalf("creating test image: %v", err)
	}

	err = crane.Push(img, imgRef, crane.Insecure)
	if err != nil {
		t.Fatalf("pushing test image: %v", err)
	}

	resolved, err := resolveDigest(context.Background(), imgRef, 30*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.HasPrefix(resolved.digest, "sha256:") {
		t.Errorf("digest = %q, expected sha256: prefix", resolved.digest)
	}

	if resolved.indexDigest != "" {
		t.Errorf("indexDigest = %q, expected empty for single manifest", resolved.indexDigest)
	}
}

func TestResolveDigestManifestList(t *testing.T) {
	t.Parallel()

	regHandler := registry.New()
	server := httptest.NewServer(regHandler)

	t.Cleanup(server.Close)

	addr := strings.TrimPrefix(server.URL, "http://")
	imgRef := addr + "/multiarch:latest"

	// Create two platform-specific images.
	amdImg, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{
		Architecture: testArchAmd64,
		OS:           testOSLinux,
	})
	if err != nil {
		t.Fatalf("creating amd64 image: %v", err)
	}

	armImg, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{
		Architecture: testArchArm64,
		OS:           testOSLinux,
	})
	if err != nil {
		t.Fatalf("creating arm64 image: %v", err)
	}

	// Build an image index (manifest list) containing both images.
	idx := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{
			Add: amdImg,
			Descriptor: v1.Descriptor{
				Platform: &v1.Platform{
					Architecture: testArchAmd64,
					OS:           testOSLinux,
				},
			},
		},
		mutate.IndexAddendum{
			Add: armImg,
			Descriptor: v1.Descriptor{
				Platform: &v1.Platform{
					Architecture: testArchArm64,
					OS:           testOSLinux,
				},
			},
		},
	)

	ref, err := name.ParseReference(imgRef)
	if err != nil {
		t.Fatalf("parsing reference: %v", err)
	}

	err = remote.WriteIndex(ref, idx, remote.WithTransport(server.Client().Transport))
	if err != nil {
		t.Fatalf("pushing index: %v", err)
	}

	// resolveDigest should return a platform-specific image digest, not the
	// index digest.
	resolved, err := resolveDigest(context.Background(), imgRef, 30*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.HasPrefix(resolved.digest, "sha256:") {
		t.Errorf("digest = %q, expected sha256: prefix", resolved.digest)
	}

	// Verify it resolved to an actual image digest, not the index digest.
	idxDigest, err := idx.Digest()
	if err != nil {
		t.Fatalf("getting index digest: %v", err)
	}

	if resolved.digest == idxDigest.String() {
		t.Errorf(
			"digest should be a platform image digest, not the index digest %s",
			resolved.digest,
		)
	}

	// The index digest should be populated for manifest lists.
	if resolved.indexDigest != idxDigest.String() {
		t.Errorf("indexDigest = %q, expected %q", resolved.indexDigest, idxDigest.String())
	}
}

func TestResolveDigestManifestListDockerMediaType(t *testing.T) {
	t.Parallel()

	regHandler := registry.New()
	server := httptest.NewServer(regHandler)

	t.Cleanup(server.Close)

	addr := strings.TrimPrefix(server.URL, "http://")
	imgRef := addr + "/docker-multiarch:latest"

	img, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{
		Architecture: testArchAmd64,
		OS:           testOSLinux,
	})
	if err != nil {
		t.Fatalf("creating image: %v", err)
	}

	// Use Docker manifest list media type.
	idx := mutate.IndexMediaType(
		mutate.AppendManifests(empty.Index,
			mutate.IndexAddendum{
				Add: img,
				Descriptor: v1.Descriptor{
					Platform: &v1.Platform{
						Architecture: testArchAmd64,
						OS:           testOSLinux,
					},
				},
			},
		),
		types.DockerManifestList,
	)

	ref, err := name.ParseReference(imgRef)
	if err != nil {
		t.Fatalf("parsing reference: %v", err)
	}

	err = remote.WriteIndex(ref, idx, remote.WithTransport(server.Client().Transport))
	if err != nil {
		t.Fatalf("pushing index: %v", err)
	}

	resolved, err := resolveDigest(context.Background(), imgRef, 30*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.HasPrefix(resolved.digest, "sha256:") {
		t.Errorf("digest = %q, expected sha256: prefix", resolved.digest)
	}

	if resolved.indexDigest == "" {
		t.Error("indexDigest should be set for manifest list")
	}
}

func TestResolveDigestManifestListNoPlatformMatch(t *testing.T) {
	t.Parallel()

	regHandler := registry.New()
	server := httptest.NewServer(regHandler)

	t.Cleanup(server.Close)

	addr := strings.TrimPrefix(server.URL, "http://")
	imgRef := addr + "/no-match:latest"

	img, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{
		Architecture: testArchS390x,
		OS:           testOSLinux,
	})
	if err != nil {
		t.Fatalf("creating image: %v", err)
	}

	// Create an index with only a platform that won't match the test host.
	idx := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{
			Add: img,
			Descriptor: v1.Descriptor{
				Platform: &v1.Platform{
					Architecture: testArchS390x,
					OS:           testOSZos,
				},
			},
		},
	)

	ref, err := name.ParseReference(imgRef)
	if err != nil {
		t.Fatalf("parsing reference: %v", err)
	}

	err = remote.WriteIndex(ref, idx, remote.WithTransport(server.Client().Transport))
	if err != nil {
		t.Fatalf("pushing index: %v", err)
	}

	_, err = resolveDigest(context.Background(), imgRef, 30*time.Second)
	if err == nil {
		t.Fatal("expected error for no matching platform")
	}

	if !strings.Contains(err.Error(), "no matching platform") {
		t.Errorf("error = %q, expected to contain 'no matching platform'", err)
	}
}

func TestResolvePolicyFile(t *testing.T) {
	t.Parallel()

	policyDir := t.TempDir()

	writeValidationPolicy(t, policyDir, "default.json", `{}`)
	writeValidationPolicy(t, policyDir, "production.json", `{}`)

	t.Run("namespace file exists", func(t *testing.T) {
		t.Parallel()

		got := resolvePolicyFile(policyDir, testNamespaceProduction)
		want := filepath.Join(policyDir, "production.json")

		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("falls back to default", func(t *testing.T) {
		t.Parallel()

		got := resolvePolicyFile(policyDir, "nonexistent")
		want := filepath.Join(policyDir, "default.json")

		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("empty dir falls back to default", func(t *testing.T) {
		t.Parallel()

		emptyDir := t.TempDir()
		got := resolvePolicyFile(emptyDir, testNamespaceProduction)
		want := filepath.Join(emptyDir, "default.json")

		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})
}

func TestRunVerifyInvalidOutputFormat(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()

	opts := &options{ //nolint:exhaustruct // test only sets relevant fields
		verifyImage:     "img:v1",
		verifyNamespace: verifier.DefaultPolicyLabel,
		outputFormat:    "xml",
	}

	if code := runVerify(opts, cfg); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
}

func TestRunVerifyResolveDigestFails(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	err := os.WriteFile(filepath.Join(dir, "default.json"), []byte(`{}`), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir

	opts := &options{ //nolint:exhaustruct // test only sets relevant fields
		verifyImage:     ":::invalid-ref",
		verifyNamespace: verifier.DefaultPolicyLabel,
		outputFormat:    outputFormatJSON,
	}

	code := runVerify(opts, cfg)
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
}

func TestRunVerifyDisabledErrors(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	opts := &options{ //nolint:exhaustruct // test only sets relevant fields
		verifyImage:     "example.com/test:latest",
		verifyNamespace: verifier.DefaultPolicyLabel,
		outputFormat:    outputFormatJSON,
	}

	code := runVerify(opts, cfg)
	if code != 1 {
		t.Errorf("expected exit code 1 for disabled verification, got %d", code)
	}
}

func TestRunVerifyEnforceDenied(t *testing.T) {
	t.Parallel()
	// Push image to in-memory registry, then verify with enforce mode.
	regHandler := registry.New()
	server := httptest.NewServer(regHandler)

	t.Cleanup(server.Close)

	addr := strings.TrimPrefix(server.URL, "http://")
	imgRef := addr + "/deny-test:latest"

	img, err := mutate.ConfigFile(empty.Image, nil)
	if err != nil {
		t.Fatalf("creating test image: %v", err)
	}

	err = crane.Push(img, imgRef, crane.Insecure)
	if err != nil {
		t.Fatalf("pushing test image: %v", err)
	}

	policyDir := t.TempDir()
	writeValidationPolicy(t, policyDir, "default.json",
		`{"slsa": {"missingPolicy": "deny"}}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.PolicyDir = policyDir

	opts := &options{ //nolint:exhaustruct // test only sets relevant fields
		verifyImage:     imgRef,
		verifyNamespace: verifier.DefaultPolicyLabel,
		outputFormat:    outputFormatJSON,
	}

	out := captureRunVerify(t, opts, cfg)

	if out.Allowed {
		t.Error("expected Allowed = false for enforce mode with deny policy")
	}
}

func TestRunVerifyVerifierNewError(t *testing.T) {
	t.Parallel()

	// Create a policy dir with an invalid policy file so that
	// verifier.New fails when loading policies.
	policyDir := t.TempDir()
	writeValidationPolicy(t, policyDir, "bad.json", `{invalid json}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = policyDir

	opts := &options{ //nolint:exhaustruct // test only sets relevant fields
		verifyImage:     "test:latest",
		verifyNamespace: verifier.DefaultPolicyLabel,
		outputFormat:    outputFormatJSON,
	}

	code := runVerify(opts, cfg)
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
}

func TestRunVerifyWarnModeWithChecks(t *testing.T) {
	t.Parallel()
	// In warn mode with a deny policy, the verifier returns check results
	// but allows the image. This exercises the CheckResults loop body.
	regHandler := registry.New()
	server := httptest.NewServer(regHandler)

	t.Cleanup(server.Close)

	addr := strings.TrimPrefix(server.URL, "http://")
	imgRef := addr + "/warn-test:latest"

	img, err := mutate.ConfigFile(empty.Image, nil)
	if err != nil {
		t.Fatalf("creating test image: %v", err)
	}

	err = crane.Push(img, imgRef, crane.Insecure)
	if err != nil {
		t.Fatalf("pushing test image: %v", err)
	}

	policyDir := t.TempDir()
	writeValidationPolicy(t, policyDir, "default.json",
		`{"slsa": {"missingPolicy": "deny"}}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = policyDir

	opts := &options{ //nolint:exhaustruct // test only sets relevant fields
		verifyImage:     imgRef,
		verifyNamespace: verifier.DefaultPolicyLabel,
		outputFormat:    outputFormatJSON,
	}

	out := captureRunVerify(t, opts, cfg)

	if !out.Allowed {
		t.Error("expected Allowed = true for warn mode")
	}

	if len(out.CheckResults) == 0 {
		t.Error("expected non-empty CheckResults for warn mode with deny policy")
	}
}

func captureRunVerify(t *testing.T, opts *options, cfg *config.Config) verifyOutput {
	t.Helper()

	var buf bytes.Buffer

	_ = runVerifyTo(&buf, opts, cfg)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	lastJSON := findLastJSON(lines)

	if lastJSON == "" {
		t.Fatalf("no JSON found in output: %s", buf.String())
	}

	var out verifyOutput

	err := json.Unmarshal([]byte(lastJSON), &out)
	if err != nil {
		t.Fatalf("invalid JSON: %v\nraw: %s", err, lastJSON)
	}

	return out
}

func findLastJSON(lines []string) string {
	// outputVerifyResult writes a multi-line JSON object.
	// Collect lines starting from last '{' to matching '}'.
	// Tracks brace depth while ignoring braces inside JSON strings.
	var jsonLines []string

	depth := 0

	for _, line := range slices.Backward(lines) {
		inString := false
		escaped := false

		for _, ch := range line {
			if escaped {
				escaped = false

				continue
			}

			if ch == '\\' && inString {
				escaped = true

				continue
			}

			if ch == '"' {
				inString = !inString

				continue
			}

			if !inString {
				switch ch {
				case '}':
					depth++
				case '{':
					depth--
				}
			}
		}

		jsonLines = append([]string{line}, jsonLines...)

		if depth == 0 && strings.Contains(line, "{") {
			break
		}
	}

	return strings.Join(jsonLines, "\n")
}

func TestOutputVerifyResultTableAllowed(t *testing.T) {
	t.Parallel()

	checks := []internaltypes.CheckResult{
		{
			Type: internaltypes.CheckTypeSLSA, Passed: true,
			Status: internaltypes.StatusPass, Detail: "SLSA level 3", Err: nil,
		},
		{
			Type: internaltypes.CheckTypeVEX, Passed: true,
			Status: internaltypes.StatusWarn, Detail: "advisory found", Err: nil,
		},
	}

	var buf bytes.Buffer

	input := &verifyOutput{
		Image: testImageNginx, Digest: "sha256:abc123", Namespace: testNamespaceProd,
		PolicyFile: "/policies/prod.json", Mode: string(config.ModeWarn), Allowed: true,
		Reason: "", CheckResults: checks,
	}

	err := outputVerifyResult(&buf, outputFormatTable, input)
	if err != nil {
		t.Fatalf("outputVerifyResult failed: %v", err)
	}

	got := buf.String()

	for _, want := range []string{
		testImageNginx,
		"sha256:abc123",
		testNamespaceProd,
		"/policies/prod.json",
		"ALLOWED",
		"TYPE",
		"STATUS",
		"DETAIL",
		"SLSA",
		"SLSA level 3",
		"VEX",
		"advisory found",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("table output missing %q\ngot:\n%s", want, got)
		}
	}

	if strings.Contains(got, "Reason") {
		t.Errorf("should not contain Reason when reason is empty\ngot:\n%s", got)
	}
}

func TestOutputVerifyResultTableDenied(t *testing.T) {
	t.Parallel()

	checks := []internaltypes.CheckResult{
		{
			Type: internaltypes.CheckTypeSLSA, Passed: false,
			Status: internaltypes.StatusFail, Detail: "no attestation", Err: nil,
		},
	}

	var buf bytes.Buffer

	input := &verifyOutput{
		Image: "evil:latest", Digest: "sha256:fff", Namespace: "default",
		PolicyFile: "/policies/default.json", Mode: string(config.ModeEnforce), Allowed: false,
		Reason: "verification failed", CheckResults: checks,
	}

	err := outputVerifyResult(&buf, outputFormatTable, input)
	if err != nil {
		t.Fatalf("outputVerifyResult failed: %v", err)
	}

	got := buf.String()

	for _, want := range []string{
		"DENIED",
		"verification failed",
		"SLSA",
		"no attestation",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("table output missing %q\ngot:\n%s", want, got)
		}
	}
}

func TestOutputVerifyResultTableNoChecks(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	input := &verifyOutput{
		Image: "img:v1", Digest: "sha256:aaa", Namespace: "ns",
		PolicyFile: "/policies/ns.json", Mode: string(config.ModeWarn), Allowed: true,
		Reason: "", CheckResults: nil,
	}

	err := outputVerifyResult(&buf, outputFormatTable, input)
	if err != nil {
		t.Fatalf("outputVerifyResult failed: %v", err)
	}

	got := buf.String()

	if strings.Contains(got, "TYPE") {
		t.Errorf("should not contain table header when no checks\ngot:\n%s", got)
	}
}

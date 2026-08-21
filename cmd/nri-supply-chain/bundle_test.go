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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/bundle"
)

const (
	testBundleImageRef   = "registry.example.com/app:v1"
	testBundleSLSAPred   = "https://slsa.dev/provenance/v1"
	testBundleSigType    = "sigstore"
	testBundleImageDigst = "sha256:testimage123"
	testRevTypeCRL       = "crl"
	testRevTypeTSA       = "tsa"
)

func TestIsConcreteImageRef(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pattern string
		want    bool
	}{
		{"concrete ref", testBundleImageRef, true},
		{"with digest", "registry.example.com/app@sha256:abc", true},
		{"wildcard star", "registry.example.com/*", false},
		{"wildcard question", "registry.example.com/?", false},
		{"wildcard bracket", "registry.example.com/[a-z]", false},
		{"empty string", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := isConcreteImageRef(tc.pattern)
			if got != tc.want {
				t.Errorf("isConcreteImageRef(%q) = %v, want %v",
					tc.pattern, got, tc.want)
			}
		})
	}
}

func TestRevocationTypeFromPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
		want string
	}{
		{"pem file", "/path/to/revocation.pem", testRevTypeCRL},
		{"crl file", "/path/to/ca.crl", testRevTypeCRL},
		{"json file", "/path/to/tsa.json", testRevTypeTSA},
		{"no extension", "/path/to/data", testRevTypeTSA},
		{"pem in middle", "/path/to/pem/data.json", testRevTypeTSA},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := revocationTypeFromPath(tc.path)
			if got != tc.want {
				t.Errorf("revocationTypeFromPath(%q) = %q, want %q",
					tc.path, got, tc.want)
			}
		})
	}
}

func TestImagesFromPolicy(t *testing.T) {
	t.Parallel()

	t.Run("extracts concrete refs from include and rules", func(t *testing.T) {
		t.Parallel()

		policyJSON := `{
			"include": [
				"registry.example.com/app:v1",
				"registry.example.com/app:v2",
				"registry.example.com/*"
			],
			"rules": [
				{
					"images": [
						"registry.example.com/other:v3",
						"gcr.io/project/*"
					]
				}
			]
		}`

		policyPath := writeTempPolicy(t, policyJSON)

		refs, err := imagesFromPolicy(policyPath)
		if err != nil {
			t.Fatalf("imagesFromPolicy() error: %v", err)
		}

		if len(refs) != 3 {
			t.Fatalf("got %d refs, want 3: %v", len(refs), refs)
		}

		expected := []string{
			testBundleImageRef,
			"registry.example.com/app:v2",
			"registry.example.com/other:v3",
		}
		for i, want := range expected {
			if refs[i] != want {
				t.Errorf("refs[%d] = %q, want %q", i, refs[i], want)
			}
		}
	})

	t.Run("deduplicates across include and rules", func(t *testing.T) {
		t.Parallel()

		policyJSON := `{
			"include": ["registry.example.com/app:v1"],
			"rules": [{"images": ["registry.example.com/app:v1"]}]
		}`

		policyPath := writeTempPolicy(t, policyJSON)

		refs, err := imagesFromPolicy(policyPath)
		if err != nil {
			t.Fatalf("imagesFromPolicy() error: %v", err)
		}

		if len(refs) != 1 {
			t.Errorf("got %d refs, want 1 (should deduplicate): %v",
				len(refs), refs)
		}
	})

	t.Run("returns empty for all-glob policy", func(t *testing.T) {
		t.Parallel()

		policyJSON := `{
			"include": ["registry.example.com/*"],
			"rules": [{"images": ["gcr.io/*"]}]
		}`

		policyPath := writeTempPolicy(t, policyJSON)

		refs, err := imagesFromPolicy(policyPath)
		if err != nil {
			t.Fatalf("imagesFromPolicy() error: %v", err)
		}

		if len(refs) != 0 {
			t.Errorf("got %d refs, want 0 (all globs): %v",
				len(refs), refs)
		}
	})

	t.Run("returns error for missing file", func(t *testing.T) {
		t.Parallel()

		_, err := imagesFromPolicy("/nonexistent/policy.json")
		if err == nil {
			t.Error("expected error for missing file, got nil")
		}
	})
}

func TestExtractOCIFetcher(t *testing.T) {
	t.Parallel()

	t.Run("nil fetcher", func(t *testing.T) {
		t.Parallel()

		result := extractOCIFetcher(nil)
		if result != nil {
			t.Error("expected nil for nil fetcher")
		}
	})

	t.Run("non-OCI fetcher returns nil", func(t *testing.T) {
		t.Parallel()

		mockFetcher := &mockAttestationFetcher{}
		result := extractOCIFetcher(mockFetcher)

		if result != nil {
			t.Error("expected nil for non-OCI fetcher")
		}
	})

	t.Run("FallbackFetcher wrapping OCIFetcher", func(t *testing.T) {
		t.Parallel()

		ociFetcher := &attestation.OCIFetcher{} //nolint:exhaustruct // test stub
		fallback := bundle.NewFallbackFetcher(
			&mockAttestationFetcher{},
			ociFetcher,
		)

		result := extractOCIFetcher(fallback)
		if result != ociFetcher {
			t.Error("expected unwrapped OCIFetcher from FallbackFetcher")
		}
	})

	t.Run("FallbackFetcher without OCIFetcher", func(t *testing.T) {
		t.Parallel()

		fallback := bundle.NewFallbackFetcher(
			&mockAttestationFetcher{},
			&mockAttestationFetcher{},
		)

		result := extractOCIFetcher(fallback)
		if result != nil {
			t.Error("expected nil when FallbackFetcher has no OCIFetcher")
		}
	})
}

func TestVerifySignature(t *testing.T) {
	t.Parallel()

	t.Run("empty key path passes", func(t *testing.T) {
		t.Parallel()

		manifest := testBundleManifest(time.Now().UTC())

		code := verifySignature(manifest, "")
		if code != exitSuccess {
			t.Errorf("expected exitSuccess, got %d", code)
		}
	})

	t.Run("key provided but unsigned manifest", func(t *testing.T) {
		t.Parallel()

		manifest := testBundleManifest(time.Now().UTC())

		code := verifySignature(manifest, "/some/key.pem")
		if code != exitError {
			t.Errorf("expected exitError for unsigned manifest, got %d", code)
		}
	})
}

func TestVerifyExpiry(t *testing.T) {
	t.Parallel()

	t.Run("no max age passes", func(t *testing.T) {
		t.Parallel()

		manifest := testBundleManifest(time.Now().UTC().Add(-48 * time.Hour))

		code := verifyExpiry(manifest, "")
		if code != exitSuccess {
			t.Errorf("expected exitSuccess with no max age, got %d", code)
		}
	})

	t.Run("fresh bundle passes", func(t *testing.T) {
		t.Parallel()

		manifest := testBundleManifest(time.Now().UTC())

		code := verifyExpiry(manifest, "24h")
		if code != exitSuccess {
			t.Errorf("expected exitSuccess for fresh bundle, got %d", code)
		}
	})

	t.Run("expired bundle fails", func(t *testing.T) {
		t.Parallel()

		manifest := testBundleManifest(time.Now().UTC().Add(-48 * time.Hour))

		code := verifyExpiry(manifest, "24h")
		if code != exitError {
			t.Errorf("expected exitError for expired bundle, got %d", code)
		}
	})

	t.Run("invalid duration fails", func(t *testing.T) {
		t.Parallel()

		manifest := testBundleManifest(time.Now().UTC())

		code := verifyExpiry(manifest, "not-a-duration")
		if code != exitError {
			t.Errorf("expected exitError for invalid duration, got %d", code)
		}
	})
}

func TestRunBundleInspect(t *testing.T) {
	t.Parallel()

	t.Run("nonexistent store returns error", func(t *testing.T) {
		t.Parallel()

		var buf bytes.Buffer

		code := runBundleInspect(&buf, "/nonexistent/store", outputFormatTable)
		if code != exitError {
			t.Errorf("expected exitError, got %d", code)
		}
	})

	t.Run("table format", func(t *testing.T) {
		t.Parallel()

		storePath := createBundleTestStore(t)

		var buf bytes.Buffer

		code := runBundleInspect(&buf, storePath, outputFormatTable)
		if code != exitSuccess {
			t.Errorf("expected exitSuccess, got %d", code)
		}

		output := buf.String()
		if !strings.Contains(output, "VERSION") {
			t.Error("table output missing header")
		}

		if !strings.Contains(output, "sha256:") {
			t.Error("table output missing image digest")
		}
	})

	t.Run("json format", func(t *testing.T) {
		t.Parallel()

		storePath := createBundleTestStore(t)

		var buf bytes.Buffer

		code := runBundleInspect(&buf, storePath, outputFormatJSON)
		if code != exitSuccess {
			t.Errorf("expected exitSuccess, got %d", code)
		}

		var result map[string]any

		decodeErr := json.Unmarshal(buf.Bytes(), &result)
		if decodeErr != nil {
			t.Errorf("output is not valid JSON: %v", decodeErr)
		}

		if _, ok := result["version"]; !ok {
			t.Error("JSON output missing 'version' field")
		}

		ageStr, ok := result["age"].(string)
		if !ok {
			t.Error("age should be a string (HumanDuration), not a number")
		}

		if !strings.Contains(ageStr, "s") {
			t.Errorf("age %q doesn't look like a duration string", ageStr)
		}
	})
}

func TestLoadBundleRevocationData(t *testing.T) {
	t.Parallel()

	t.Run("no paths returns nil", func(t *testing.T) {
		t.Parallel()

		result, err := loadBundleRevocationData(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result != nil {
			t.Error("expected nil for empty paths")
		}
	})

	t.Run("loads files with correct types", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		crlPath := filepath.Join(dir, "ca.crl")
		tsaPath := filepath.Join(dir, "tsa.json")

		writeErr := os.WriteFile(crlPath, []byte("crl-data"), 0o600)
		if writeErr != nil {
			t.Fatal(writeErr)
		}

		writeErr = os.WriteFile(tsaPath, []byte("tsa-data"), 0o600)
		if writeErr != nil {
			t.Fatal(writeErr)
		}

		result, err := loadBundleRevocationData([]string{crlPath, tsaPath})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(result) != 2 {
			t.Fatalf("got %d entries, want 2", len(result))
		}

		if result[0].Type != testRevTypeCRL {
			t.Errorf("first entry type = %q, want %s", result[0].Type, testRevTypeCRL)
		}

		if result[1].Type != testRevTypeTSA {
			t.Errorf("second entry type = %q, want %s", result[1].Type, testRevTypeTSA)
		}
	})

	t.Run("missing file returns error", func(t *testing.T) {
		t.Parallel()

		_, err := loadBundleRevocationData([]string{"/nonexistent/file.pem"})
		if err == nil {
			t.Error("expected error for missing file")
		}
	})
}

func TestRunBundleVerify(t *testing.T) {
	t.Parallel()

	t.Run("nonexistent store fails", func(t *testing.T) {
		t.Parallel()

		code := runBundleVerify("/nonexistent/store", "", "")
		if code != exitError {
			t.Errorf("expected exitError, got %d", code)
		}
	})

	t.Run("valid store no checks", func(t *testing.T) {
		t.Parallel()

		storePath := createBundleTestStore(t)
		code := runBundleVerify(storePath, "", "")

		if code != exitSuccess {
			t.Errorf("expected exitSuccess, got %d", code)
		}
	})

	t.Run("valid store with passing max-age", func(t *testing.T) {
		t.Parallel()

		storePath := createBundleTestStore(t)
		code := runBundleVerify(storePath, "", "720h")

		if code != exitSuccess {
			t.Errorf("expected exitSuccess with generous max-age, got %d", code)
		}
	})

	t.Run("key provided but unsigned", func(t *testing.T) {
		t.Parallel()

		storePath := createBundleTestStore(t)
		code := runBundleVerify(storePath, "/some/key.pem", "")

		if code != exitError {
			t.Errorf("expected exitError for unsigned bundle with key, got %d",
				code)
		}
	})
}

func testBundleManifest(createdAt time.Time) *bundle.Manifest {
	return &bundle.Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: createdAt,
		Images:    map[string]*bundle.ImageEntry{},
	}
}

func writeTempPolicy(t *testing.T, policyJSON string) string {
	t.Helper()

	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")

	writeErr := os.WriteFile(policyPath, []byte(policyJSON), 0o600)
	if writeErr != nil {
		t.Fatal(writeErr)
	}

	return policyPath
}

func createBundleTestStore(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()

	payload := []byte(`{"payloadType":"application/vnd.in-toto+json"}`)
	hash := sha256.Sum256(payload)
	digest := "sha256:" + hex.EncodeToString(hash[:])

	manifest := &bundle.Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Images: map[string]*bundle.ImageEntry{
			testBundleImageDigst: { //nolint:exhaustruct_v5 // test data
				Refs: []string{testBundleImageRef},
				Attestations: []bundle.AttestationEntry{{
					PredicateType: testBundleSLSAPred,
					BlobDigest:    digest,
					Size:          int64(len(payload)),
					SignatureType: testBundleSigType,
				}},
			},
		},
	}

	writeBundleTestFile(t, filepath.Join(dir, "oci-layout"),
		[]byte(`{"imageLayoutVersion":"1.0.0"}`))
	writeBundleTestFile(t, filepath.Join(dir, "index.json"),
		[]byte(`{"schemaVersion":2,"manifests":[]}`))

	blobsDir := filepath.Join(dir, "blobs", "sha256")

	mkdirErr := os.MkdirAll(blobsDir, 0o750)
	if mkdirErr != nil {
		t.Fatal(mkdirErr)
	}

	writeBundleTestFile(t, filepath.Join(blobsDir, hex.EncodeToString(hash[:])), payload)

	manifestData, marshalErr := json.MarshalIndent(manifest, "", "  ")
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}

	writeBundleTestFile(t, filepath.Join(dir, "bundle-manifest.json"), manifestData)

	return dir
}

func writeBundleTestFile(t *testing.T, path string, data []byte) {
	t.Helper()

	err := os.WriteFile(path, data, 0o600)
	if err != nil {
		t.Fatal(err)
	}
}

func TestFetchOptsFromPolicy(t *testing.T) {
	t.Parallel()

	t.Run("empty policy dir", func(t *testing.T) {
		t.Parallel()

		opts, err := fetchOptsFromPolicy("")
		if err != nil {
			t.Fatal(err)
		}

		if len(opts.TrustedKeys) != 0 {
			t.Errorf("expected no keys, got %d", len(opts.TrustedKeys))
		}
	})

	t.Run("missing default policy file", func(t *testing.T) {
		t.Parallel()

		opts, err := fetchOptsFromPolicy(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}

		if len(opts.TrustedKeys) != 0 {
			t.Errorf("expected no keys, got %d", len(opts.TrustedKeys))
		}
	})

	t.Run("policy with trust keys", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		policyJSON := `{
			"trust": {
				"verifiers": [
					{"id": "v1", "keys": ["/key1.pub", "/key2.pub"]},
					{"id": "v2", "keys": ["/key3.pub"]}
				],
				"issuers": ["https://issuer.example.com"],
				"sanPatterns": ["*.example.com"]
			},
			"slsa": {"missingPolicy": "allow"},
			"vex": {"missingPolicy": "allow"}
		}`
		writeBundleTestFile(t, filepath.Join(dir, "default.json"), []byte(policyJSON))

		opts, err := fetchOptsFromPolicy(dir)
		if err != nil {
			t.Fatal(err)
		}

		if len(opts.TrustedKeys) != 3 {
			t.Fatalf("expected 3 keys, got %d", len(opts.TrustedKeys))
		}

		if opts.TrustedKeys[0].Path != "/key1.pub" {
			t.Errorf("expected /key1.pub, got %s", opts.TrustedKeys[0].Path)
		}

		if len(opts.TrustedIssuers) != 1 || opts.TrustedIssuers[0] != "https://issuer.example.com" {
			t.Errorf("unexpected issuers: %v", opts.TrustedIssuers)
		}

		if len(opts.SANPatterns) != 1 || opts.SANPatterns[0] != "*.example.com" {
			t.Errorf("unexpected SAN patterns: %v", opts.SANPatterns)
		}
	})

	t.Run("policy without trust section", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		policyJSON := `{
			"slsa": {"missingPolicy": "allow"},
			"vex": {"missingPolicy": "allow"}
		}`
		writeBundleTestFile(t, filepath.Join(dir, "default.json"), []byte(policyJSON))

		opts, err := fetchOptsFromPolicy(dir)
		if err != nil {
			t.Fatal(err)
		}

		if len(opts.TrustedKeys) != 0 {
			t.Errorf("expected no keys, got %d", len(opts.TrustedKeys))
		}
	})

	t.Run("invalid policy file", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		writeBundleTestFile(t, filepath.Join(dir, "default.json"), []byte("not json"))

		_, err := fetchOptsFromPolicy(dir)
		if err == nil {
			t.Fatal("expected error for invalid policy file")
		}
	})
}

type mockAttestationFetcher struct{}

func (m *mockAttestationFetcher) Fetch(
	_ context.Context, _ string, _ *attestation.FetchOptions,
) ([]attestation.VerifiedAttestation, error) {
	return nil, nil
}

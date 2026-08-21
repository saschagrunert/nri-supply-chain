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

package bundle //nolint:testpackage // tests use internal test helpers

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const (
	testImageDigest   = "sha256:img1"
	testPredicateType = "test"
	testDigestABC     = "sha256:abc"
	testSigType       = "sigstore"
	testSLSAPredicate = "https://slsa.dev/provenance/v1"
	testFromFallback  = "from-fallback"
	testExampleRef    = "registry.example.com/app:v1"
	testOCILayout     = "oci-layout"
	testIndexJSON     = "index.json"
	testRevTypeCRL    = "crl"
)

func createTestStore(
	t *testing.T, manifest *Manifest, blobs map[string][]byte,
) string {
	t.Helper()

	dir := t.TempDir()

	writeTestFile(t, filepath.Join(dir, testOCILayout),
		[]byte(`{"imageLayoutVersion":"1.0.0"}`))
	writeTestFile(t, filepath.Join(dir, testIndexJSON),
		[]byte(`{"schemaVersion":2,"manifests":[]}`))

	blobsDir := filepath.Join(dir, "blobs", "sha256")

	mkdirErr := os.MkdirAll(blobsDir, 0o750)
	if mkdirErr != nil {
		t.Fatal(mkdirErr)
	}

	for digest, data := range blobs {
		hash := digest
		if len(digest) > 7 && digest[:7] == "sha256:" {
			hash = digest[7:]
		}

		writeTestFile(t, filepath.Join(blobsDir, hash), data)
	}

	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	writeTestFile(t, filepath.Join(dir, manifestFileName), manifestData)

	return dir
}

func blobDigest(data []byte) string {
	h := sha256.Sum256(data)

	return fmt.Sprintf("sha256:%x", h)
}

func TestOpenStore(t *testing.T) {
	t.Parallel()

	attestationData := []byte(`{"payloadType":"application/vnd.in-toto+json"}`)
	digest := blobDigest(attestationData)

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Images: map[string]*ImageEntry{
			"sha256:imageabc": {
				Refs: []string{testExampleRef},
				Attestations: []AttestationEntry{{
					PredicateType: testSLSAPredicate,
					BlobDigest:    digest,
					Size:          int64(len(attestationData)),
					SignatureType: testSigType,
				}},
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	dir := createTestStore(t, manifest, map[string][]byte{
		digest: attestationData,
	})

	store, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore() error: %v", err)
	}

	m := store.Manifest()
	if m.Version != 1 {
		t.Errorf("Manifest().Version = %d, want 1", m.Version)
	}

	if len(m.Images) != 1 {
		t.Errorf("Manifest().Images count = %d, want 1", len(m.Images))
	}
}

func TestOpenStoreNotFound(t *testing.T) {
	t.Parallel()

	_, err := OpenStore("/nonexistent/path")
	if !errors.Is(err, ErrBundleNotFound) {
		t.Fatalf("OpenStore() error = %v, want %v", err, ErrBundleNotFound)
	}
}

func TestOpenStoreNoManifest(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	writeTestFile(t, filepath.Join(dir, testOCILayout),
		[]byte(`{"imageLayoutVersion":"1.0.0"}`))
	writeTestFile(t, filepath.Join(dir, testIndexJSON),
		[]byte(`{"schemaVersion":2,"manifests":[]}`))

	_, err := OpenStore(dir)
	if !errors.Is(err, ErrManifestNotFound) {
		t.Fatalf("OpenStore() error = %v, want %v", err, ErrManifestNotFound)
	}
}

func TestStoreAttestationsFor(t *testing.T) {
	t.Parallel()

	payload := []byte(`{"test":"attestation"}`)
	digest := blobDigest(payload)

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Images: map[string]*ImageEntry{
			testImageDigest: { //nolint:exhaustruct_v5 // test data
				Attestations: []AttestationEntry{
					{
						PredicateType: testSLSAPredicate,
						BlobDigest:    digest,
						Size:          int64(len(payload)),
						SignatureType: testSigType,
					},
				},
			},
		},
	}

	dir := createTestStore(t, manifest, map[string][]byte{digest: payload})

	store, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore() error: %v", err)
	}

	atts, err := store.AttestationsFor(testImageDigest)
	if err != nil {
		t.Fatalf("AttestationsFor() error: %v", err)
	}

	if len(atts) != 1 {
		t.Fatalf("AttestationsFor() count = %d, want 1", len(atts))
	}

	if atts[0].PredicateType != testSLSAPredicate {
		t.Errorf("PredicateType = %q, want %q", atts[0].PredicateType, testSLSAPredicate)
	}

	if !bytes.Equal(atts[0].BundleBytes, payload) {
		t.Errorf("BundleBytes = %q, want %q", atts[0].BundleBytes, payload)
	}
}

func TestStoreAttestationsForNotFound(t *testing.T) {
	t.Parallel()

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Images:    map[string]*ImageEntry{},
	}

	dir := createTestStore(t, manifest, nil)

	store, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore() error: %v", err)
	}

	_, err = store.AttestationsFor("sha256:nonexistent")
	if !errors.Is(err, ErrNoAttestationsForDigest) {
		t.Fatalf("AttestationsFor() error = %v, want %v", err, ErrNoAttestationsForDigest)
	}
}

func TestStoreBlobSizeMismatch(t *testing.T) {
	t.Parallel()

	payload := []byte(`{"test":"data"}`)
	digest := blobDigest(payload)

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Images: map[string]*ImageEntry{
			testImageDigest: { //nolint:exhaustruct_v5 // test data
				Attestations: []AttestationEntry{{
					PredicateType: testPredicateType,
					BlobDigest:    digest,
					Size:          9999,
					SignatureType: testSigType,
				}},
			},
		},
	}

	dir := createTestStore(t, manifest, map[string][]byte{digest: payload})

	store, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore() error: %v", err)
	}

	_, err = store.AttestationsFor(testImageDigest)
	if !errors.Is(err, ErrBlobSizeMismatch) {
		t.Fatalf("AttestationsFor() error = %v, want %v", err, ErrBlobSizeMismatch)
	}
}

func TestStoreTrustedRootMissing(t *testing.T) {
	t.Parallel()

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Images:    map[string]*ImageEntry{},
	}

	dir := createTestStore(t, manifest, nil)

	store, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore() error: %v", err)
	}

	_, err = store.TrustedRoot()
	if !errors.Is(err, ErrTrustedRootMissing) {
		t.Fatalf("TrustedRoot() error = %v, want %v", err, ErrTrustedRootMissing)
	}
}

func TestStoreRevocationData(t *testing.T) {
	t.Parallel()

	crlData := []byte(`-----BEGIN X509 CRL-----\ntest\n-----END X509 CRL-----`)
	tsaData := []byte(`{"timestamp":"2024-01-01T00:00:00Z"}`)

	crlDigest := blobDigest(crlData)
	tsaDigest := blobDigest(tsaData)

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Images:    map[string]*ImageEntry{},
		Revocation: []RevocationEntry{
			{BlobDigest: crlDigest, Size: int64(len(crlData)), Type: testRevTypeCRL},
			{BlobDigest: tsaDigest, Size: int64(len(tsaData)), Type: "tsa"},
		},
	}

	dir := createTestStore(t, manifest, map[string][]byte{
		crlDigest: crlData,
		tsaDigest: tsaData,
	})

	store, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore() error: %v", err)
	}

	snapshots, err := store.RevocationData()
	if err != nil {
		t.Fatalf("RevocationData() error: %v", err)
	}

	if len(snapshots) != 2 {
		t.Fatalf("RevocationData() count = %d, want 2", len(snapshots))
	}

	if snapshots[0].Type != testRevTypeCRL {
		t.Errorf("snapshots[0].Type = %q, want %q", snapshots[0].Type, testRevTypeCRL)
	}

	if !bytes.Equal(snapshots[0].Data, crlData) {
		t.Errorf("snapshots[0].Data mismatch")
	}

	if snapshots[1].Type != "tsa" {
		t.Errorf("snapshots[1].Type = %q, want %q", snapshots[1].Type, "tsa")
	}
}

func TestStoreRevocationDataEmpty(t *testing.T) {
	t.Parallel()

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Images:    map[string]*ImageEntry{},
	}

	dir := createTestStore(t, manifest, nil)

	store, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore() error: %v", err)
	}

	snapshots, err := store.RevocationData()
	if err != nil {
		t.Fatalf("RevocationData() error: %v", err)
	}

	if snapshots != nil {
		t.Errorf("RevocationData() = %v, want nil", snapshots)
	}
}

func TestOpenStoreManifestTooLarge(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	writeTestFile(t, filepath.Join(dir, testOCILayout),
		[]byte(`{"imageLayoutVersion":"1.0.0"}`))
	writeTestFile(t, filepath.Join(dir, testIndexJSON),
		[]byte(`{"schemaVersion":2,"manifests":[]}`))

	oversizedData := make([]byte, maxManifestReadSize+1)
	for i := range oversizedData {
		oversizedData[i] = ' '
	}

	writeTestFile(t, filepath.Join(dir, manifestFileName), oversizedData)

	_, err := OpenStore(dir)
	if !errors.Is(err, ErrManifestCorrupt) {
		t.Fatalf("OpenStore() error = %v, want %v", err, ErrManifestCorrupt)
	}
}

func TestOpenStoreNotADirectory(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	filePath := filepath.Join(dir, "not-a-dir")

	writeTestFile(t, filePath, []byte("data"))

	_, err := OpenStore(filePath)
	if !errors.Is(err, ErrBundleNotFound) {
		t.Fatalf("OpenStore() error = %v, want %v", err, ErrBundleNotFound)
	}
}

func TestBlobReadLimitZeroExpected(t *testing.T) {
	t.Parallel()

	limit, err := blobReadLimit(0)
	if err != nil {
		t.Fatalf("blobReadLimit(0) error: %v", err)
	}

	if limit != int64(maxBlobReadSize) {
		t.Errorf("blobReadLimit(0) = %d, want %d", limit, maxBlobReadSize)
	}
}

func TestBlobReadLimitPositive(t *testing.T) {
	t.Parallel()

	limit, err := blobReadLimit(1024)
	if err != nil {
		t.Fatalf("blobReadLimit(1024) error: %v", err)
	}

	if limit != 1025 {
		t.Errorf("blobReadLimit(1024) = %d, want 1025", limit)
	}
}

func TestBlobReadLimitTooLarge(t *testing.T) {
	t.Parallel()

	_, err := blobReadLimit(maxBlobReadSize + 1)
	if !errors.Is(err, ErrBlobTooLarge) {
		t.Fatalf("blobReadLimit() error = %v, want %v", err, ErrBlobTooLarge)
	}
}

func TestStoreBlobMissingDigest(t *testing.T) {
	t.Parallel()

	payload := []byte(`{"test":"data"}`)
	digest := blobDigest(payload)

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Images: map[string]*ImageEntry{
			testImageDigest: { //nolint:exhaustruct_v5 // test data
				Attestations: []AttestationEntry{{
					PredicateType: testPredicateType,
					BlobDigest:    digest,
					Size:          int64(len(payload)),
					SignatureType: testSigType,
				}},
			},
		},
	}

	// Create store without the blob file
	dir := createTestStore(t, manifest, nil)

	store, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore() error: %v", err)
	}

	_, err = store.AttestationsFor(testImageDigest)
	if !errors.Is(err, ErrBlobMissing) {
		t.Fatalf("AttestationsFor() error = %v, want %v", err, ErrBlobMissing)
	}
}

func TestStoreBlobDeclaredTooLarge(t *testing.T) {
	t.Parallel()

	payload := []byte(`{"test":"data"}`)
	digest := blobDigest(payload)

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Images: map[string]*ImageEntry{
			testImageDigest: { //nolint:exhaustruct_v5 // test data
				Attestations: []AttestationEntry{{
					PredicateType: testPredicateType,
					BlobDigest:    digest,
					Size:          maxBlobReadSize + 1,
					SignatureType: testSigType,
				}},
			},
		},
	}

	dir := createTestStore(t, manifest, map[string][]byte{digest: payload})

	store, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore() error: %v", err)
	}

	_, err = store.AttestationsFor(testImageDigest)
	if !errors.Is(err, ErrBlobTooLarge) {
		t.Fatalf("AttestationsFor() error = %v, want %v", err, ErrBlobTooLarge)
	}
}

func TestStoreRevocationDataBlobMissing(t *testing.T) {
	t.Parallel()

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Images:    map[string]*ImageEntry{},
		Revocation: []RevocationEntry{{
			BlobDigest: "sha256:nonexistent",
			Size:       100,
			Type:       testRevTypeCRL,
		}},
	}

	dir := createTestStore(t, manifest, nil)

	store, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore() error: %v", err)
	}

	_, err = store.RevocationData()
	if !errors.Is(err, ErrBlobMissing) {
		t.Fatalf("RevocationData() error = %v, want %v", err, ErrBlobMissing)
	}
}

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()

	err := os.WriteFile(path, data, 0o600)
	if err != nil {
		t.Fatal(err)
	}
}

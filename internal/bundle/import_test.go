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
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func createTestTarGz(t *testing.T, entries map[string][]byte) string {
	t.Helper()

	dir := t.TempDir()
	tarPath := filepath.Join(dir, "bundle.tar.gz")

	outFile, err := os.Create(tarPath) //nolint:gosec // test helper with temp paths
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = outFile.Close() }()

	gzWriter := gzip.NewWriter(outFile)
	defer func() { _ = gzWriter.Close() }()

	tarWriter := tar.NewWriter(gzWriter)
	defer func() { _ = tarWriter.Close() }()

	for name, data := range entries {
		header := &tar.Header{ //nolint:exhaustruct_v5 // test data
			Name: name,
			Mode: 0o600,
			Size: int64(len(data)),
		}

		writeErr := tarWriter.WriteHeader(header)
		if writeErr != nil {
			t.Fatal(writeErr)
		}

		_, writeErr = tarWriter.Write(data)
		if writeErr != nil {
			t.Fatal(writeErr)
		}
	}

	return tarPath
}

func createTraversalTarGz(t *testing.T, entryName string) string {
	t.Helper()

	dir := t.TempDir()
	tarPath := filepath.Join(dir, "traversal.tar.gz")

	outFile, err := os.Create(tarPath) //nolint:gosec // test helper with temp paths
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = outFile.Close() }()

	gzWriter := gzip.NewWriter(outFile)
	defer func() { _ = gzWriter.Close() }()

	tarWriter := tar.NewWriter(gzWriter)
	defer func() { _ = tarWriter.Close() }()

	header := &tar.Header{ //nolint:exhaustruct_v5 // test data
		Name: entryName,
		Mode: 0o600,
		Size: 5,
	}

	writeErr := tarWriter.WriteHeader(header)
	if writeErr != nil {
		t.Fatal(writeErr)
	}

	_, writeErr = tarWriter.Write([]byte("evil!"))
	if writeErr != nil {
		t.Fatal(writeErr)
	}

	return tarPath
}

func createOversizeTarGz(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	tarPath := filepath.Join(dir, "oversize.tar.gz")

	outFile, err := os.Create(tarPath) //nolint:gosec // test helper with temp paths
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = outFile.Close() }()

	gzWriter := gzip.NewWriter(outFile)
	defer func() { _ = gzWriter.Close() }()

	tarWriter := tar.NewWriter(gzWriter)
	defer func() { _ = tarWriter.Close() }()

	header := &tar.Header{ //nolint:exhaustruct_v5 // test data
		Name: "huge-file",
		Mode: 0o600,
		Size: maxBundleTarSize + 1,
	}

	writeErr := tarWriter.WriteHeader(header)
	if writeErr != nil {
		t.Fatal(writeErr)
	}

	// Write minimal data; the size check triggers on the header size accumulator.
	_, writeErr = tarWriter.Write([]byte("x"))
	if writeErr != nil {
		t.Fatal(writeErr)
	}

	return tarPath
}

func createValidBundleTarGz(t *testing.T) string {
	t.Helper()

	payload := []byte(`{"payloadType":"application/vnd.in-toto+json"}`)
	digest := blobDigest(payload)

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Images: map[string]*ImageEntry{
			testImageDigest: {
				Refs: []string{testExampleRef},
				Attestations: []AttestationEntry{{
					PredicateType: testSLSAPredicate,
					BlobDigest:    digest,
					Size:          int64(len(payload)),
					SignatureType: testSigType,
				}},
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	hashStr := digest[7:]

	entries := map[string][]byte{
		testOCILayout:             []byte(`{"imageLayoutVersion":"1.0.0"}`),
		testIndexJSON:             []byte(`{"schemaVersion":2,"manifests":[]}`),
		manifestFileName:          manifestData,
		"blobs/sha256/" + hashStr: payload,
	}

	return createTestTarGz(t, entries)
}

func TestImportRoundTrip(t *testing.T) {
	t.Parallel()

	tarPath := createValidBundleTarGz(t)
	storePath := filepath.Join(t.TempDir(), "imported-store")

	err := Import(tarPath, storePath, "")
	if err != nil {
		t.Fatalf("Import() error: %v", err)
	}

	store, err := OpenStore(storePath)
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

	entry, ok := m.Images[testImageDigest]
	if !ok {
		t.Fatal("expected image entry not found in manifest")
	}

	if len(entry.Attestations) != 1 {
		t.Errorf("attestation count = %d, want 1", len(entry.Attestations))
	}

	if entry.Attestations[0].PredicateType != testSLSAPredicate {
		t.Errorf(
			"PredicateType = %q, want %q",
			entry.Attestations[0].PredicateType, testSLSAPredicate,
		)
	}
}

func TestImportPathTraversal(t *testing.T) {
	t.Parallel()

	tarPath := createTraversalTarGz(t, "../../etc/evil")
	storePath := filepath.Join(t.TempDir(), "store")

	err := Import(tarPath, storePath, "")
	if !errors.Is(err, ErrPathTraversal) {
		t.Fatalf("Import() error = %v, want %v", err, ErrPathTraversal)
	}
}

func TestImportPathTraversalPrefixCollision(t *testing.T) {
	t.Parallel()

	parentDir := t.TempDir()
	storePath := filepath.Join(parentDir, "store")

	tarPath := createTraversalTarGz(t, "../store-evil/file")

	err := Import(tarPath, storePath, "")
	if !errors.Is(err, ErrPathTraversal) {
		t.Fatalf(
			"Import() error = %v, want %v (prefix collision case)",
			err, ErrPathTraversal,
		)
	}
}

func TestImportEntryCountLimit(t *testing.T) {
	t.Parallel()

	tarPath := createManyEntriesTarGz(t, maxBundleTarEntries+1)
	storePath := filepath.Join(t.TempDir(), "store")

	err := Import(tarPath, storePath, "")
	if !errors.Is(err, ErrBundleTooManyEntries) {
		t.Fatalf("Import() error = %v, want %v", err, ErrBundleTooManyEntries)
	}
}

func createManyEntriesTarGz(t *testing.T, count int) string {
	t.Helper()

	dir := t.TempDir()
	tarPath := filepath.Join(dir, "many-entries.tar.gz")

	outFile, err := os.Create(tarPath) //nolint:gosec // test helper with temp paths
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = outFile.Close() }()

	gzWriter := gzip.NewWriter(outFile)
	defer func() { _ = gzWriter.Close() }()

	tarWriter := tar.NewWriter(gzWriter)
	defer func() { _ = tarWriter.Close() }()

	for i := range count {
		header := &tar.Header{ //nolint:exhaustruct_v5 // test data
			Name: fmt.Sprintf("entry-%d", i),
			Mode: 0o600,
			Size: 0,
		}

		writeErr := tarWriter.WriteHeader(header)
		if writeErr != nil {
			t.Fatal(writeErr)
		}
	}

	return tarPath
}

func TestImportSizeLimit(t *testing.T) {
	t.Parallel()

	tarPath := createOversizeTarGz(t)
	storePath := filepath.Join(t.TempDir(), "store")

	err := Import(tarPath, storePath, "")
	if !errors.Is(err, ErrBundleTooLarge) {
		t.Fatalf("Import() error = %v, want %v", err, ErrBundleTooLarge)
	}
}

func TestImportInvalidBundle(t *testing.T) {
	t.Parallel()

	tarPath := createTestTarGz(t, map[string][]byte{
		"random.txt": []byte("not a bundle"),
	})
	storePath := filepath.Join(t.TempDir(), "store")

	err := Import(tarPath, storePath, "")
	if err == nil {
		t.Fatal("Import() should fail for invalid bundle contents")
	}
}

func TestImportWithSignatureVerification(t *testing.T) {
	t.Parallel()

	payload := []byte(`{"payloadType":"application/vnd.in-toto+json"}`)
	digest := blobDigest(payload)

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Images: map[string]*ImageEntry{
			testImageDigest: {
				Refs: []string{testExampleRef},
				Attestations: []AttestationEntry{{
					PredicateType: testSLSAPredicate,
					BlobDigest:    digest,
					Size:          int64(len(payload)),
					SignatureType: testSigType,
				}},
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	privPath, pubPath := generateTestKeyPair(t)

	signErr := SignManifest(manifest, privPath)
	if signErr != nil {
		t.Fatalf("SignManifest() error: %v", signErr)
	}

	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	hashStr := digest[7:]

	entries := map[string][]byte{
		testOCILayout:             []byte(`{"imageLayoutVersion":"1.0.0"}`),
		testIndexJSON:             []byte(`{"schemaVersion":2,"manifests":[]}`),
		manifestFileName:          manifestData,
		"blobs/sha256/" + hashStr: payload,
	}

	tarPath := createTestTarGz(t, entries)
	storePath := filepath.Join(t.TempDir(), "signed-store")

	importErr := Import(tarPath, storePath, pubPath)
	if importErr != nil {
		t.Fatalf("Import() with valid signature error: %v", importErr)
	}

	store, openErr := OpenStore(storePath)
	if openErr != nil {
		t.Fatalf("OpenStore() error: %v", openErr)
	}

	if store.Manifest().Version != 1 {
		t.Errorf("Manifest().Version = %d, want 1", store.Manifest().Version)
	}
}

func TestImportWithWrongSignatureKey(t *testing.T) {
	t.Parallel()

	payload := []byte(`{"payloadType":"application/vnd.in-toto+json"}`)
	digest := blobDigest(payload)

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Images: map[string]*ImageEntry{
			testImageDigest: {
				Refs: []string{testExampleRef},
				Attestations: []AttestationEntry{{
					PredicateType: testSLSAPredicate,
					BlobDigest:    digest,
					Size:          int64(len(payload)),
					SignatureType: testSigType,
				}},
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	privPath, _ := generateTestKeyPair(t)
	_, wrongPubPath := generateTestKeyPair(t)

	signErr := SignManifest(manifest, privPath)
	if signErr != nil {
		t.Fatalf("SignManifest() error: %v", signErr)
	}

	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	hashStr := digest[7:]

	entries := map[string][]byte{
		testOCILayout:             []byte(`{"imageLayoutVersion":"1.0.0"}`),
		testIndexJSON:             []byte(`{"schemaVersion":2,"manifests":[]}`),
		manifestFileName:          manifestData,
		"blobs/sha256/" + hashStr: payload,
	}

	tarPath := createTestTarGz(t, entries)
	storePath := filepath.Join(t.TempDir(), "wrong-key-store")

	importErr := Import(tarPath, storePath, wrongPubPath)
	if !errors.Is(importErr, ErrBundleSignatureInvalid) {
		t.Fatalf("Import() error = %v, want %v", importErr, ErrBundleSignatureInvalid)
	}
}

func TestImportAtomicSwapPreservesExisting(t *testing.T) {
	t.Parallel()

	storePath := filepath.Join(t.TempDir(), "existing-store")

	// First import to create the store
	tarPath1 := createValidBundleTarGz(t)

	err := Import(tarPath1, storePath, "")
	if err != nil {
		t.Fatalf("first Import() error: %v", err)
	}

	// Second import to verify atomic swap works
	tarPath2 := createValidBundleTarGz(t)

	err = Import(tarPath2, storePath, "")
	if err != nil {
		t.Fatalf("second Import() error: %v", err)
	}

	// Verify the store is still valid
	store, err := OpenStore(storePath)
	if err != nil {
		t.Fatalf("OpenStore() error: %v", err)
	}

	if store.Manifest().Version != 1 {
		t.Errorf("Manifest().Version = %d, want 1", store.Manifest().Version)
	}
}

func TestImportBundleNotFoundPath(t *testing.T) {
	t.Parallel()

	storePath := filepath.Join(t.TempDir(), "store")

	err := Import("/nonexistent/bundle.tar.gz", storePath, "")
	if err == nil {
		t.Fatal("Import() should fail with nonexistent bundle path")
	}
}

func TestImportNotGzip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	notGzip := filepath.Join(dir, "not-gzip.tar.gz")

	writeErr := os.WriteFile(notGzip, []byte("not gzip content"), 0o600)
	if writeErr != nil {
		t.Fatal(writeErr)
	}

	storePath := filepath.Join(dir, "store")

	err := Import(notGzip, storePath, "")
	if err == nil {
		t.Fatal("Import() should fail with non-gzip file")
	}
}

func TestImportDirectoryCreation(t *testing.T) {
	t.Parallel()

	tarPath := createValidBundleTarGz(t)

	storePath := filepath.Join(t.TempDir(), "nested", "deep", "store")

	err := Import(tarPath, storePath, "")
	if err != nil {
		t.Fatalf("Import() error: %v", err)
	}

	info, statErr := os.Stat(storePath)
	if statErr != nil {
		t.Fatalf("store directory was not created: %v", statErr)
	}

	if !info.IsDir() {
		t.Fatal("store path is not a directory")
	}
}

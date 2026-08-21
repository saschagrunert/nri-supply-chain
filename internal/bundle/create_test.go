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

package bundle //nolint:testpackage // tests use internal helpers

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
)

type createTestFetcher struct {
	attestations []attestation.VerifiedAttestation
	err          error
}

func (m *createTestFetcher) Fetch(
	_ context.Context, _ string, _ *attestation.FetchOptions,
) ([]attestation.VerifiedAttestation, error) {
	return m.attestations, m.err
}

func TestCreateBasic(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outputPath := filepath.Join(dir, "bundle.tar.gz")
	storePath := filepath.Join(dir, "store")

	payload := []byte(`{"predicateType":"test","predicate":{}}`)

	//nolint:exhaustruct_v5 // test data
	opts := &CreateOptions{
		Images:     []string{testImageDigest},
		OutputPath: outputPath,
		//nolint:exhaustruct_v5 // test data
		Fetcher: &createTestFetcher{
			attestations: []attestation.VerifiedAttestation{{
				PredicateType: testSLSAPredicate,
				Payload:       payload,
				Digest:        testImageDigest,
				SignatureType: attestation.SignatureTypeSigstore,
			}},
		},
		//nolint:exhaustruct_v5 // test data
		FetchOptions: &attestation.FetchOptions{},
	}

	err := Create(context.Background(), opts)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	importErr := Import(outputPath, storePath, "")
	if importErr != nil {
		t.Fatalf("Import() error: %v", importErr)
	}

	store, openErr := OpenStore(storePath)
	if openErr != nil {
		t.Fatalf("OpenStore() error: %v", openErr)
	}

	manifest := store.Manifest()
	if len(manifest.Images) != 1 {
		t.Errorf("image count = %d, want 1", len(manifest.Images))
	}

	entry, ok := manifest.Images[testImageDigest]
	if !ok {
		t.Fatal("image not found in manifest")
	}

	if len(entry.Attestations) != 1 {
		t.Errorf(
			"attestation count = %d, want 1",
			len(entry.Attestations),
		)
	}
}

func TestCreateDuplicateDigest(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outputPath := filepath.Join(dir, "bundle.tar.gz")
	storePath := filepath.Join(dir, "store")

	resolvedDigest := "sha256:resolvedabc123"
	payload := []byte(`{"predicateType":"test","predicate":{}}`)

	//nolint:exhaustruct_v5 // test data
	opts := &CreateOptions{
		Images:     []string{"app:v1", "app:latest"},
		OutputPath: outputPath,
		//nolint:exhaustruct_v5 // test data
		Fetcher: &createTestFetcher{
			attestations: []attestation.VerifiedAttestation{{
				PredicateType: testSLSAPredicate,
				Payload:       payload,
				Digest:        resolvedDigest,
				SignatureType: attestation.SignatureTypeSigstore,
			}},
		},
		//nolint:exhaustruct_v5 // test data
		FetchOptions: &attestation.FetchOptions{},
		ResolveDigest: func(
			_ context.Context, _ string,
		) (string, string, error) {
			return resolvedDigest, "", nil
		},
	}

	err := Create(context.Background(), opts)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	importErr := Import(outputPath, storePath, "")
	if importErr != nil {
		t.Fatalf("Import() error: %v", importErr)
	}

	store, openErr := OpenStore(storePath)
	if openErr != nil {
		t.Fatalf("OpenStore() error: %v", openErr)
	}

	manifest := store.Manifest()
	if len(manifest.Images) != 1 {
		t.Fatalf("image count = %d, want 1", len(manifest.Images))
	}

	entry, ok := manifest.Images[resolvedDigest]
	if !ok {
		t.Fatalf("image %s not found in manifest", resolvedDigest)
	}

	if len(entry.Refs) != 2 {
		t.Errorf("refs count = %d, want 2", len(entry.Refs))
	}
}

func TestCreateWithSigning(t *testing.T) {
	t.Parallel()

	privPath, _ := generateTestKeyPair(t)
	dir := t.TempDir()
	outputPath := filepath.Join(dir, "bundle.tar.gz")
	storePath := filepath.Join(dir, "store")

	payload := []byte(`{"predicateType":"test","predicate":{}}`)

	//nolint:exhaustruct_v5 // test data
	opts := &CreateOptions{
		Images:     []string{testImageDigest},
		OutputPath: outputPath,
		//nolint:exhaustruct_v5 // test data
		Fetcher: &createTestFetcher{
			attestations: []attestation.VerifiedAttestation{{
				PredicateType: testSLSAPredicate,
				Payload:       payload,
				Digest:        testImageDigest,
				SignatureType: attestation.SignatureTypeSigstore,
			}},
		},
		//nolint:exhaustruct_v5 // test data
		FetchOptions:   &attestation.FetchOptions{},
		SigningKeyPath: privPath,
	}

	err := Create(context.Background(), opts)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	importErr := Import(outputPath, storePath, "")
	if importErr != nil {
		t.Fatalf("Import() error: %v", importErr)
	}

	store, openErr := OpenStore(storePath)
	if openErr != nil {
		t.Fatalf("OpenStore() error: %v", openErr)
	}

	manifest := store.Manifest()
	if manifest.Signature == nil {
		t.Fatal("Signature should not be nil after signing")
	}

	if manifest.Signature.Value == "" {
		t.Error("Signature.Value should not be empty")
	}
}

func TestCreateNoImages(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outputPath := filepath.Join(dir, "bundle.tar.gz")

	//nolint:exhaustruct_v5 // test data
	opts := &CreateOptions{
		Images:     []string{},
		OutputPath: outputPath,
		//nolint:exhaustruct_v5 // test data
		Fetcher: &createTestFetcher{},
		//nolint:exhaustruct_v5 // test data
		FetchOptions: &attestation.FetchOptions{},
	}

	err := Create(context.Background(), opts)
	if err != nil {
		t.Fatalf("Create() with no images should succeed: %v", err)
	}

	storePath := filepath.Join(dir, "store")

	importErr := Import(outputPath, storePath, "")
	if importErr != nil {
		t.Fatalf("Import() error: %v", importErr)
	}

	store, openErr := OpenStore(storePath)
	if openErr != nil {
		t.Fatalf("OpenStore() error: %v", openErr)
	}

	manifest := store.Manifest()
	if len(manifest.Images) != 0 {
		t.Errorf("image count = %d, want 0", len(manifest.Images))
	}
}

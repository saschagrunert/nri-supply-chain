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
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
)

const testResolvedDigest = "sha256:" +
	"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// TestCreateRequiresImageDigest checks that an image whose digest cannot be
// determined fails bundle creation instead of producing a bundle keyed by
// the image reference, which could not be opened or imported.
func TestCreateRequiresImageDigest(t *testing.T) {
	t.Parallel()

	emptyResolver := func(context.Context, string) (string, string, error) {
		return "", "", nil
	}
	tagResolver := func(context.Context, string) (string, string, error) {
		return testExampleRef, "", nil
	}

	tests := []struct {
		name     string
		image    string
		resolver DigestResolver
	}{
		{"tag without resolver", testExampleRef, nil},
		{"tag with empty resolved digest", testExampleRef, emptyResolver},
		{"resolver returning no digest", testExampleRef, tagResolver},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			outputPath := filepath.Join(t.TempDir(), "bundle.tar.gz")

			//nolint:exhaustruct_v5 // test data
			err := Create(context.Background(), &CreateOptions{
				Images:        []string{test.image},
				OutputPath:    outputPath,
				Fetcher:       &createTestFetcher{attestations: nil, err: nil},
				FetchOptions:  &attestation.FetchOptions{},
				ResolveDigest: test.resolver,
			})
			if !errors.Is(err, ErrDigestUnresolved) {
				t.Fatalf("Create() error = %v, want %v", err, ErrDigestUnresolved)
			}

			_, statErr := os.Stat(outputPath)
			if !errors.Is(statErr, os.ErrNotExist) {
				t.Errorf("expected no bundle to be written, stat error: %v", statErr)
			}
		})
	}
}

// TestCreateDigestReferenceWithoutResolver checks that a digest reference is
// bundled under its digest, so the bundle can be imported and opened.
func TestCreateDigestReferenceWithoutResolver(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outputPath := filepath.Join(dir, "bundle.tar.gz")
	storePath := filepath.Join(dir, "store")
	imageRef := "registry.example.com/app@" + testResolvedDigest

	//nolint:exhaustruct_v5 // test data
	err := Create(context.Background(), &CreateOptions{
		Images:       []string{imageRef},
		OutputPath:   outputPath,
		Fetcher:      &createTestFetcher{attestations: nil, err: nil},
		FetchOptions: &attestation.FetchOptions{},
	})
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	err = Import(outputPath, storePath, "")
	if err != nil {
		t.Fatalf("Import() error: %v", err)
	}

	store, err := OpenStore(storePath)
	if err != nil {
		t.Fatalf("OpenStore() error: %v", err)
	}

	t.Cleanup(func() { _ = store.Close() })

	entry, ok := store.Manifest().Images[testResolvedDigest]
	if !ok {
		t.Fatalf("manifest images = %v, want an entry for %s",
			store.Manifest().Images, testResolvedDigest)
	}

	if len(entry.Refs) != 1 || entry.Refs[0] != imageRef {
		t.Errorf("refs = %v, want [%s]", entry.Refs, imageRef)
	}
}

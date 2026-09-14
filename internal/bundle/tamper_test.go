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

package bundle //nolint:testpackage // tests access internal store helpers

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
)

// TestFetcherTamperedBlobIsVerificationFailure checks that bundled blobs that
// were modified, truncated or removed after import are denied instead of
// being handled with the fetch failure policy.
func TestFetcherTamperedBlobIsVerificationFailure(t *testing.T) {
	t.Parallel()

	payload := []byte(`{"predicateType":"` + testSLSAPredicate + `","predicate":{}}`)
	digest := blobDigest(payload)
	blobPath := func(dir string) string {
		return filepath.Join(dir, "blobs", "sha256", digest[len(sha256Prefix):])
	}

	tests := []struct {
		name   string
		tamper func(t *testing.T, dir string)
		want   error
	}{
		{
			name: "content replaced",
			tamper: func(t *testing.T, dir string) {
				t.Helper()

				swapped := []byte(
					`{"predicateType":"` + testSLSAPredicate + `","predicate":{"x":1}}`,
				)
				writeTestFile(t, blobPath(dir), swapped[:len(payload)])
			},
			want: ErrBlobDigestMismatch,
		},
		{
			name: "size changed",
			tamper: func(t *testing.T, dir string) {
				t.Helper()

				writeTestFile(t, blobPath(dir), append(payload, ' '))
			},
			want: ErrBlobSizeMismatch,
		},
		{
			name: "blob removed",
			tamper: func(t *testing.T, dir string) {
				t.Helper()

				err := os.Remove(blobPath(dir))
				if err != nil {
					t.Fatalf("removing blob: %v", err)
				}
			},
			want: ErrBlobMissing,
		},
		{
			name: "blob replaced by a directory",
			tamper: func(t *testing.T, dir string) {
				t.Helper()

				replaceBlob(t, blobPath(dir), func(path string) error {
					return os.Mkdir(path, 0o750)
				})
			},
			want: ErrBlobNotRegular,
		},
		{
			name: "blob replaced by a FIFO",
			tamper: func(t *testing.T, dir string) {
				t.Helper()

				replaceBlob(t, blobPath(dir), func(path string) error {
					return syscall.Mkfifo(path, 0o600)
				})
			},
			want: ErrBlobNotRegular,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
				Version:   1,
				CreatedAt: time.Now().UTC(),
				Images: map[string]*ImageEntry{
					testImageDigest: { //nolint:exhaustruct_v5 // test data
						Attestations: []AttestationEntry{{
							PredicateType: testSLSAPredicate,
							BlobDigest:    digest,
							Size:          int64(len(payload)),
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

			tt.tamper(t, dir)

			ctx, cancel := context.WithTimeout(context.Background(), tamperFetchTimeout)
			defer cancel()

			done := make(chan error, 1)

			go func() {
				_, fetchErr := NewFetcher(store, passthroughVerifier).Fetch(
					ctx, "registry.example.com/app:v1",
					&attestation.FetchOptions{Digest: testImageDigest},
				)
				done <- fetchErr
			}()

			select {
			case err = <-done:
			case <-ctx.Done():
				t.Fatal("Fetch() blocked on the tampered blob")
			}

			if !errors.Is(err, attestation.ErrVerificationFailed) {
				t.Fatalf("Fetch() error = %v, want %v", err, attestation.ErrVerificationFailed)
			}

			// Tampering must deny instead of counting as absent attestations.
			if !errors.Is(err, attestation.ErrIncompleteAttestationSet) {
				t.Fatalf(
					"Fetch() error = %v, want %v",
					err,
					attestation.ErrIncompleteAttestationSet,
				)
			}

			if !errors.Is(err, tt.want) {
				t.Errorf("Fetch() error = %v, want %v", err, tt.want)
			}
		})
	}
}

const tamperFetchTimeout = 10 * time.Second

// replaceBlob removes the blob at path and creates a replacement with create.
func replaceBlob(t *testing.T, path string, create func(path string) error) {
	t.Helper()

	err := os.Remove(path)
	if err != nil {
		t.Fatalf("removing blob: %v", err)
	}

	err = create(path)
	if err != nil {
		t.Fatalf("replacing blob: %v", err)
	}
}

// TestFetcherUnreadableBlobIsNotVerificationFailure checks that a blob the
// plugin cannot read for local reasons (permissions, file descriptor limits)
// is an availability problem rather than tampering.
func TestFetcherUnreadableBlobIsNotVerificationFailure(t *testing.T) {
	t.Parallel()

	if os.Geteuid() == 0 {
		t.Skip("file permissions do not restrict root")
	}

	payload := []byte(`{"predicateType":"` + testSLSAPredicate + `","predicate":{}}`)
	digest := blobDigest(payload)

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Images: map[string]*ImageEntry{
			testImageDigest: { //nolint:exhaustruct_v5 // test data
				Attestations: []AttestationEntry{{
					PredicateType: testSLSAPredicate,
					BlobDigest:    digest,
					Size:          int64(len(payload)),
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

	blob := filepath.Join(dir, "blobs", "sha256", digest[len(sha256Prefix):])

	err = os.Chmod(blob, 0)
	if err != nil {
		t.Fatalf("chmod blob: %v", err)
	}

	_, err = NewFetcher(store, passthroughVerifier).Fetch(
		context.Background(), "registry.example.com/app:v1",
		&attestation.FetchOptions{Digest: testImageDigest},
	)
	if err == nil {
		t.Fatal("expected an error for an unreadable blob")
	}

	if errors.Is(err, attestation.ErrVerificationFailed) {
		t.Errorf("an unreadable blob must not be a verification failure: %v", err)
	}
}

// TestFetcherTrustMaterialUnavailable checks that bundled attestations that
// cannot be verified because trust material is unavailable are reported as
// such instead of as verification failures.
func TestFetcherTrustMaterialUnavailable(t *testing.T) {
	t.Parallel()

	payload := []byte(`{"predicateType":"` + testSLSAPredicate + `","predicate":{}}`)
	digest := blobDigest(payload)

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Images: map[string]*ImageEntry{
			testImageDigest: { //nolint:exhaustruct_v5 // test data
				Attestations: []AttestationEntry{{
					PredicateType: testSLSAPredicate,
					BlobDigest:    digest,
					Size:          int64(len(payload)),
					SignatureType: testSigType,
				}},
			},
		},
	}

	store, err := OpenStore(createTestStore(t, manifest, map[string][]byte{digest: payload}))
	if err != nil {
		t.Fatalf("OpenStore() error: %v", err)
	}

	unavailable := func(
		context.Context, []byte, *attestation.FetchOptions,
	) (*attestation.VerifiedBundle, error) {
		return nil, fmt.Errorf("%w: key file unreadable", attestation.ErrTrustMaterialUnavailable)
	}

	_, err = NewFetcher(store, unavailable).Fetch(
		context.Background(), "registry.example.com/app:v1",
		&attestation.FetchOptions{Digest: testImageDigest},
	)
	if !errors.Is(err, attestation.ErrTrustMaterialUnavailable) {
		t.Fatalf("Fetch() error = %v, want %v", err, attestation.ErrTrustMaterialUnavailable)
	}

	if errors.Is(err, attestation.ErrVerificationFailed) {
		t.Errorf("unavailable trust material must not be a verification failure: %v", err)
	}
}

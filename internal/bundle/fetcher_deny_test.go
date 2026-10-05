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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
)

// assertDenied checks that err makes the attestation set incomplete, which
// denies regardless of the fetch failure policy.
func assertDenied(t *testing.T, err, target error) {
	t.Helper()

	if !errors.Is(err, target) {
		t.Fatalf("Fetch() error = %v, want %v", err, target)
	}

	if !errors.Is(err, attestation.ErrVerificationFailed) ||
		!errors.Is(err, attestation.ErrIncompleteAttestationSet) {
		t.Fatalf("Fetch() error = %v, want an incomplete attestation set", err)
	}
}

func signedTestManifest(t *testing.T, payload []byte) (manifest *Manifest, pubPath string) {
	t.Helper()

	digest := blobDigest(payload)

	manifest = &Manifest{ //nolint:exhaustruct_v5 // test data
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

	privPath, pubPath := generateTestKeyPair(t)

	signErr := SignManifest(manifest, privPath)
	if signErr != nil {
		t.Fatalf("SignManifest() error: %v", signErr)
	}

	return manifest, pubPath
}

func openTestFetcher(
	t *testing.T, manifest *Manifest, blobs map[string][]byte, opts ...FetcherOption,
) *Fetcher {
	t.Helper()

	store, err := OpenStore(createTestStore(t, manifest, blobs))
	if err != nil {
		t.Fatalf("OpenStore() error: %v", err)
	}

	fetcher := NewFetcher(store, passthroughVerifier, opts...)

	t.Cleanup(func() { _ = fetcher.Close() })

	return fetcher
}

// TestFetcherExpiredBundleDenies checks that a bundle rejected by the expiry
// policy denies instead of following the fetch failure policy.
func TestFetcherExpiredBundleDenies(t *testing.T) {
	t.Parallel()

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: time.Now().UTC().Add(-48 * time.Hour),
		Images: map[string]*ImageEntry{
			testImageDigest: { //nolint:exhaustruct_v5 // test data
				Attestations: []AttestationEntry{},
			},
		},
	}

	fetcher := openTestFetcher(t, manifest, nil,
		WithMaxAge(24*time.Hour), WithExpiryPolicy(ExpiryDeny),
	)

	_, err := fetcher.Fetch(
		context.Background(), "ref", &attestation.FetchOptions{Digest: testImageDigest},
	)
	assertDenied(t, err, ErrBundleExpired)
}

// TestFetcherTamperedManifestDenies checks that a manifest modified after it
// was signed, or stripped of its signature, denies instead of following the
// fetch failure policy.
func TestFetcherTamperedManifestDenies(t *testing.T) {
	t.Parallel()

	payload := []byte(`{"predicateType":"test","test":"data"}`)

	t.Run("modified", func(t *testing.T) {
		t.Parallel()

		manifest, pubPath := signedTestManifest(t, payload)
		manifest.Images[testImageDigest].Attestations = nil

		fetcher := openTestFetcher(t, manifest, map[string][]byte{blobDigest(payload): payload},
			WithBundleSignatureKey(pubPath),
		)

		_, err := fetcher.Fetch(
			context.Background(), "ref", &attestation.FetchOptions{Digest: testImageDigest},
		)
		assertDenied(t, err, ErrBundleSignatureInvalid)
	})

	t.Run("stripped", func(t *testing.T) {
		t.Parallel()

		manifest, pubPath := signedTestManifest(t, payload)
		manifest.Signature = nil

		fetcher := openTestFetcher(t, manifest, map[string][]byte{blobDigest(payload): payload},
			WithBundleSignatureKey(pubPath),
		)

		_, err := fetcher.Fetch(
			context.Background(), "ref", &attestation.FetchOptions{Digest: testImageDigest},
		)
		assertDenied(t, err, ErrBundleSignatureRequired)
	})
}

// TestFetcherUnreadableSignatureKeyIsRetried checks that a bundle signature
// key that cannot be read follows the fetch failure policy and is read again
// on the next fetch instead of failing until the fetcher is replaced.
func TestFetcherUnreadableSignatureKeyIsRetried(t *testing.T) {
	t.Parallel()

	payload := []byte(`{"predicateType":"test","test":"data"}`)
	manifest, pubPath := signedTestManifest(t, payload)

	movedPath := pubPath + ".moved"

	moveErr := os.Rename(pubPath, movedPath)
	if moveErr != nil {
		t.Fatal(moveErr)
	}

	fetcher := openTestFetcher(t, manifest, map[string][]byte{blobDigest(payload): payload},
		WithBundleSignatureKey(pubPath),
	)
	opts := &attestation.FetchOptions{Digest: testImageDigest}

	_, err := fetcher.Fetch(context.Background(), "ref", opts)
	if !errors.Is(err, attestation.ErrTrustMaterialUnavailable) ||
		errors.Is(err, attestation.ErrVerificationFailed) {
		t.Fatalf("Fetch() error = %v, want unavailable trust material", err)
	}

	restoreErr := os.Rename(movedPath, pubPath)
	if restoreErr != nil {
		t.Fatal(restoreErr)
	}

	result, err := fetcher.Fetch(context.Background(), "ref", opts)
	if err != nil || len(result) != 1 {
		t.Fatalf("Fetch() = %d attestations, error %v; want 1 attestation", len(result), err)
	}
}

// TestFetcherUnreadableBlobEntryDenies checks that a manifest entry whose blob
// cannot be evaluated because of the store content denies.
func TestFetcherUnreadableBlobEntryDenies(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		entry  AttestationEntry
		target error
	}{
		{
			name: "oversized",
			entry: AttestationEntry{
				PredicateType: testPredicateType,
				BlobDigest:    blobDigest([]byte("data")),
				Size:          maxBlobReadSize + 1,
				SignatureType: testSigType,
			},
			target: ErrBlobTooLarge,
		},
		{
			name: "unsupported digest algorithm",
			entry: AttestationEntry{
				PredicateType: testPredicateType,
				BlobDigest:    "sha512:" + blobDigest([]byte("data"))[len(sha256Prefix):],
				Size:          4,
				SignatureType: testSigType,
			},
			target: ErrUnsupportedDigestAlgorithm,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
				Version:   1,
				CreatedAt: time.Now().UTC(),
				Images: map[string]*ImageEntry{
					testImageDigest: { //nolint:exhaustruct_v5 // test data
						Attestations: []AttestationEntry{test.entry},
					},
				},
			}

			fetcher := openTestFetcher(t, manifest, map[string][]byte{
				blobDigest([]byte("data")): []byte("data"),
			})

			_, err := fetcher.Fetch(
				context.Background(), "ref", &attestation.FetchOptions{Digest: testImageDigest},
			)
			assertDenied(t, err, test.target)
		})
	}
}

const (
	testKindVerified        = "verified"
	testKindKeyUnavailable  = "key-unavailable"
	testKindRootUnavailable = "root-unavailable"
	testKindRejected        = "rejected"
)

var errTestBundleRejected = errors.New("bundle rejected")

// kindVerifier fails or verifies a test payload depending on its kind.
func kindVerifier(
	ctx context.Context, data []byte, opts *attestation.FetchOptions,
) (*attestation.VerifiedBundle, error) {
	var statement struct {
		Kind string `json:"kind"`
	}

	unmarshalErr := json.Unmarshal(data, &statement)
	if unmarshalErr != nil {
		return nil, fmt.Errorf("decoding test payload: %w", unmarshalErr)
	}

	switch statement.Kind {
	case testKindKeyUnavailable:
		return nil, fmt.Errorf(
			"%w: %w: loading public key",
			attestation.ErrTrustMaterialUnavailable, attestation.ErrTrustedKeyUnavailable,
		)
	case testKindRootUnavailable:
		return nil, fmt.Errorf(
			"%w: fetching sigstore trusted root", attestation.ErrTrustMaterialUnavailable,
		)
	case testKindRejected:
		return nil, errTestBundleRejected
	default:
		return passthroughVerifier(ctx, data, opts)
	}
}

// kindStoreFetcher opens a store with one attestation per kind and a fetcher
// verifying it with kindVerifier.
func kindStoreFetcher(t *testing.T, kinds []string) *Fetcher {
	t.Helper()

	entries := make([]AttestationEntry, 0, len(kinds))
	blobs := make(map[string][]byte, len(kinds))

	for _, kind := range kinds {
		payload := []byte(`{"predicateType":"` + testPredicateType + `","kind":"` + kind + `"}`)
		entries = append(entries, AttestationEntry{
			PredicateType: testPredicateType,
			BlobDigest:    blobDigest(payload),
			Size:          int64(len(payload)),
			SignatureType: testSigType,
		})
		blobs[blobDigest(payload)] = payload
	}

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Images: map[string]*ImageEntry{
			testImageDigest: { //nolint:exhaustruct_v5 // test data
				Attestations: entries,
			},
		},
	}

	store, err := OpenStore(createTestStore(t, manifest, blobs))
	if err != nil {
		t.Fatalf("OpenStore() error: %v", err)
	}

	fetcher := NewFetcher(store, kindVerifier)

	t.Cleanup(func() { _ = fetcher.Close() })

	return fetcher
}

// TestFetcherUnreadableKeyDoesNotHideVerifiedAttestation checks that a stored
// attestation that cannot be checked because a trusted key file is unreadable
// is ignored like a failed verification when another stored attestation
// verified, and only fails the fetch when nothing verified. Other unavailable
// trust material always fails the fetch.
func TestFetcherUnreadableKeyDoesNotHideVerifiedAttestation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		kinds   []string
		wantErr error
	}{
		{
			name:    "unreadable key first",
			kinds:   []string{testKindKeyUnavailable, testKindVerified},
			wantErr: nil,
		},
		{
			name:    "unreadable key last",
			kinds:   []string{testKindVerified, testKindKeyUnavailable},
			wantErr: nil,
		},
		{
			name:    "only unreadable key",
			kinds:   []string{testKindKeyUnavailable},
			wantErr: attestation.ErrTrustedKeyUnavailable,
		},
		{
			name:    "unreadable key and rejected",
			kinds:   []string{testKindRejected, testKindKeyUnavailable},
			wantErr: attestation.ErrTrustedKeyUnavailable,
		},
		{
			name:    "unavailable root",
			kinds:   []string{testKindVerified, testKindRootUnavailable},
			wantErr: attestation.ErrTrustMaterialUnavailable,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			result, err := kindStoreFetcher(t, test.kinds).Fetch(
				context.Background(), "ref", &attestation.FetchOptions{Digest: testImageDigest},
			)

			if test.wantErr == nil {
				if err != nil || len(result) != 1 {
					t.Fatalf("Fetch() = %d attestations, error %v; want 1 attestation",
						len(result), err)
				}

				return
			}

			if !errors.Is(err, test.wantErr) ||
				!errors.Is(err, attestation.ErrTrustMaterialUnavailable) ||
				errors.Is(err, attestation.ErrVerificationFailed) {
				t.Fatalf("Fetch() error = %v, want unavailable trust material: %v",
					err, test.wantErr)
			}
		})
	}
}

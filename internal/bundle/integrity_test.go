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
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestVerifyBlobIntegrityValid(t *testing.T) {
	t.Parallel()

	payload := []byte(`{"predicateType":"test"}`)
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

	dir := createTestStore(t, manifest, map[string][]byte{digest: payload})

	store, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore() error: %v", err)
	}

	integrityErr := VerifyBlobIntegrity(store)
	if integrityErr != nil {
		t.Fatalf("VerifyBlobIntegrity() error: %v", integrityErr)
	}
}

func TestVerifyBlobIntegrityCorrupt(t *testing.T) {
	t.Parallel()

	payload := []byte(`{"predicateType":"test"}`)
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

	dir := createTestStore(t, manifest, map[string][]byte{digest: payload})

	hashStr := digest[7:]
	blobPath := filepath.Join(dir, "blobs", "sha256", hashStr)

	corrupted := make([]byte, len(payload))
	copy(corrupted, payload)
	corrupted[0] = 'X'

	writeErr := os.WriteFile(blobPath, corrupted, 0o600)
	if writeErr != nil {
		t.Fatal(writeErr)
	}

	store, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore() error: %v", err)
	}

	integrityErr := VerifyBlobIntegrity(store)
	if !errors.Is(integrityErr, ErrBlobDigestMismatch) {
		t.Fatalf(
			"VerifyBlobIntegrity() error = %v, want %v",
			integrityErr, ErrBlobDigestMismatch,
		)
	}
}

func TestVerifyBlobIntegrityUnsupportedAlgorithm(t *testing.T) {
	t.Parallel()

	payload := []byte(`{"predicateType":"test"}`)

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Images: map[string]*ImageEntry{
			testImageDigest: { //nolint:exhaustruct_v5 // test data
				Attestations: []AttestationEntry{{
					PredicateType: testPredicateType,
					BlobDigest:    "sha512:abcdef1234567890",
					Size:          int64(len(payload)),
					SignatureType: testSigType,
				}},
			},
		},
	}

	dir := createTestStore(t, manifest, map[string][]byte{
		blobDigest(payload): payload,
	})

	store, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore() error: %v", err)
	}

	integrityErr := VerifyBlobIntegrity(store)
	if !errors.Is(integrityErr, ErrUnsupportedDigestAlgorithm) {
		t.Fatalf(
			"VerifyBlobIntegrity() error = %v, want %v",
			integrityErr, ErrUnsupportedDigestAlgorithm,
		)
	}
}

func TestVerifyBlobIntegritySizeMismatch(t *testing.T) {
	t.Parallel()

	payload := []byte(`{"predicateType":"test"}`)
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

	integrityErr := VerifyBlobIntegrity(store)
	if !errors.Is(integrityErr, ErrBlobSizeMismatch) {
		t.Fatalf(
			"VerifyBlobIntegrity() error = %v, want %v",
			integrityErr, ErrBlobSizeMismatch,
		)
	}
}

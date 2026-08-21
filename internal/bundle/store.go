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

package bundle

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	ociV1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
)

const (
	maxBlobReadSize     = 100 << 20 // 100 MiB
	maxManifestReadSize = 10 << 20  // 10 MiB
)

// StoredAttestation holds an attestation blob loaded from the bundle store.
type StoredAttestation struct {
	PredicateType string
	BundleBytes   []byte
	Digest        string
	SignatureType attestation.SignatureType
}

// Store provides read access to an on-disk attestation bundle backed by an OCI layout.
type Store struct {
	layoutPath layout.Path
	manifest   *Manifest
	mu         sync.RWMutex
}

// OpenStore opens an existing bundle store rooted at dir, validates the OCI
// layout, and loads the bundle manifest.
func OpenStore(dir string) (*Store, error) {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBundleNotFound, err)
	}

	info, statErr := os.Stat(absDir)
	if statErr != nil || !info.IsDir() {
		return nil, fmt.Errorf("%w: %s", ErrBundleNotFound, absDir)
	}

	ociLayout, err := layout.FromPath(absDir)
	if err != nil {
		return nil, fmt.Errorf("opening OCI layout at %s: %w", absDir, err)
	}

	manifest, err := readAndParseManifest(absDir)
	if err != nil {
		return nil, err
	}

	return &Store{
		layoutPath: ociLayout,
		manifest:   manifest,
		mu:         sync.RWMutex{},
	}, nil
}

// Manifest returns the parsed bundle manifest.
func (s *Store) Manifest() *Manifest {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.manifest
}

// AttestationsFor returns all stored attestations for the given image digest.
func (s *Store) AttestationsFor(digest string) ([]StoredAttestation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, ok := s.manifest.Images[digest]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNoAttestationsForDigest, digest)
	}

	result := make([]StoredAttestation, 0, len(entry.Attestations))

	for _, att := range entry.Attestations {
		data, err := s.readBlob(att.BlobDigest, att.Size)
		if err != nil {
			return nil, err
		}

		result = append(result, StoredAttestation{
			PredicateType: att.PredicateType,
			BundleBytes:   data,
			Digest:        digest,
			SignatureType: attestation.SignatureType(att.SignatureType),
		})
	}

	return result, nil
}

// TrustedRoot loads and parses the trusted root from the bundle.
func (s *Store) TrustedRoot() (*root.TrustedRoot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.manifest.TrustedRoot == nil {
		return nil, ErrTrustedRootMissing
	}

	data, err := s.readBlob(
		s.manifest.TrustedRoot.BlobDigest,
		s.manifest.TrustedRoot.Size,
	)
	if err != nil {
		return nil, fmt.Errorf("reading trusted root blob: %w", err)
	}

	tr, err := root.NewTrustedRootFromJSON(data)
	if err != nil {
		return nil, fmt.Errorf("parsing trusted root: %w", err)
	}

	return tr, nil
}

// RevocationData returns all revocation snapshots embedded in the bundle.
func (s *Store) RevocationData() ([]RevocationSnapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.manifest.Revocation) == 0 {
		return nil, nil
	}

	snapshots := make([]RevocationSnapshot, 0, len(s.manifest.Revocation))

	for _, rev := range s.manifest.Revocation {
		data, err := s.readBlob(rev.BlobDigest, rev.Size)
		if err != nil {
			return nil, fmt.Errorf("reading revocation blob: %w", err)
		}

		snapshots = append(snapshots, RevocationSnapshot{
			Type: rev.Type,
			Data: data,
		})
	}

	return snapshots, nil
}

// RevocationSnapshot holds a loaded revocation data snapshot from the bundle.
type RevocationSnapshot struct {
	Type string
	Data []byte
}

func readAndParseManifest(storeDir string) (*Manifest, error) {
	manifestPath := filepath.Join(storeDir, manifestFileName)

	manifestFile, err := os.Open(manifestPath) //nolint:gosec // validated store path
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrManifestNotFound, err)
	}
	defer func() { _ = manifestFile.Close() }()

	data, err := io.ReadAll(io.LimitReader(manifestFile, maxManifestReadSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading manifest: %w", err)
	}

	if int64(len(data)) > maxManifestReadSize {
		return nil, fmt.Errorf(
			"%w: manifest exceeds %d byte limit", ErrManifestCorrupt, maxManifestReadSize,
		)
	}

	return ParseManifest(data)
}

func (s *Store) readBlob(digestStr string, expectedSize int64) ([]byte, error) {
	readLimit, limitErr := blobReadLimit(expectedSize)
	if limitErr != nil {
		return nil, fmt.Errorf("%s: %w", digestStr, limitErr)
	}

	hash, err := ociV1.NewHash(digestStr)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid digest %q: %w", ErrBlobMissing, digestStr, err)
	}

	blobReader, err := s.layoutPath.Blob(hash)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrBlobMissing, digestStr, err)
	}
	defer func() { _ = blobReader.Close() }()

	data, err := io.ReadAll(io.LimitReader(blobReader, readLimit))
	if err != nil {
		return nil, fmt.Errorf("reading blob %s: %w", digestStr, err)
	}

	if int64(len(data)) == readLimit && expectedSize == 0 {
		return nil, fmt.Errorf(
			"%w: %s exceeds %d byte read limit",
			ErrBlobTooLarge, digestStr, maxBlobReadSize,
		)
	}

	if expectedSize > 0 && int64(len(data)) != expectedSize {
		return nil, fmt.Errorf(
			"%w: %s (expected %d, got %d)",
			ErrBlobSizeMismatch, digestStr, expectedSize, len(data),
		)
	}

	return data, nil
}

func blobReadLimit(expectedSize int64) (int64, error) {
	if expectedSize > maxBlobReadSize {
		return 0, fmt.Errorf(
			"%w: declared %d bytes, limit %d",
			ErrBlobTooLarge, expectedSize, maxBlobReadSize,
		)
	}

	if expectedSize > 0 {
		return expectedSize + 1, nil
	}

	return int64(maxBlobReadSize), nil
}

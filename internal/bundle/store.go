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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

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

// Store provides read access to an on-disk attestation bundle backed by an OCI
// layout. The store directory is pinned when the store is opened, so blobs are
// always read from the directory the manifest was loaded from, even after a
// bundle import replaced the directory at the store path. A Store is
// immutable and safe for concurrent use.
type Store struct {
	dir      string
	root     *os.Root
	manifest *Manifest
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

	_, err = layout.FromPath(absDir)
	if err != nil {
		return nil, fmt.Errorf("opening OCI layout at %s: %w", absDir, err)
	}

	storeRoot, err := os.OpenRoot(absDir)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBundleNotFound, err)
	}

	manifest, err := readAndParseManifest(storeRoot)
	if err != nil {
		_ = storeRoot.Close()

		return nil, err
	}

	return &Store{dir: absDir, root: storeRoot, manifest: manifest}, nil
}

// Close releases the pinned store directory. The store must not be used
// afterwards.
func (s *Store) Close() error {
	err := s.root.Close()
	if err != nil {
		return fmt.Errorf("closing bundle store: %w", err)
	}

	return nil
}

// Manifest returns the parsed bundle manifest.
func (s *Store) Manifest() *Manifest {
	return s.manifest
}

// AttestationsFor returns all stored attestations for the given image digest.
func (s *Store) AttestationsFor(digest string) ([]StoredAttestation, error) {
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

// TrustedRoots loads and parses every trusted root embedded in the bundle,
// with the name of the Sigstore root source each came from. Roots written by
// older releases have no name.
func (s *Store) TrustedRoots() ([]TrustedRootSource, error) {
	entries := s.manifest.allTrustedRoots()
	if len(entries) == 0 {
		return nil, ErrTrustedRootMissing
	}

	roots := make([]TrustedRootSource, 0, len(entries))

	for idx := range entries {
		data, err := s.readBlob(entries[idx].BlobDigest, entries[idx].Size)
		if err != nil {
			return nil, fmt.Errorf("reading trusted root blob %q: %w", entries[idx].Name, err)
		}

		trustedRoot, err := root.NewTrustedRootFromJSON(data)
		if err != nil {
			return nil, fmt.Errorf("parsing trusted root %q: %w", entries[idx].Name, err)
		}

		roots = append(roots, TrustedRootSource{
			Name:    entries[idx].Name,
			Issuers: entries[idx].Issuers,
			Root:    trustedRoot,
		})
	}

	return roots, nil
}

// RevocationData returns all revocation snapshots embedded in the bundle.
func (s *Store) RevocationData() ([]RevocationSnapshot, error) {
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

func readAndParseManifest(storeRoot *os.Root) (*Manifest, error) {
	manifestFile, err := storeRoot.Open(manifestFileName)
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

// readBlob reads a blob and verifies both its declared size and its content
// digest, so blobs swapped on disk after import are detected on every read.
func (s *Store) readBlob(digestStr string, expectedSize int64) ([]byte, error) {
	if !strings.HasPrefix(digestStr, sha256Prefix) {
		return nil, fmt.Errorf(
			"%w: expected %q prefix, got %q",
			ErrUnsupportedDigestAlgorithm, sha256Prefix, digestStr,
		)
	}

	data, err := s.readBlobData(digestStr, expectedSize)
	if err != nil {
		return nil, err
	}

	actualHash := sha256.Sum256(data)
	if hex.EncodeToString(actualHash[:]) != digestStr[len(sha256Prefix):] {
		return nil, fmt.Errorf("%w: %s", ErrBlobDigestMismatch, digestStr)
	}

	return data, nil
}

// readBlobData reads a blob from the pinned OCI layout directory. A blob that
// is absent, not a regular file, or cannot be resolved inside the store (a
// directory, FIFO, regular file or escaping symbolic link swapped in for the
// blob or one of its parent directories after import) is an integrity
// failure, and so is a blob that is gone because the store directory was
// removed. Only local availability problems, such as missing permissions or
// file descriptor exhaustion, are reported as plain errors. The blob is
// opened without blocking, so a FIFO cannot stall verification.
func (s *Store) readBlobData(digestStr string, expectedSize int64) ([]byte, error) {
	readLimit, limitErr := blobReadLimit(expectedSize)
	if limitErr != nil {
		return nil, fmt.Errorf("%s: %w", digestStr, limitErr)
	}

	hash, err := ociV1.NewHash(digestStr)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid digest %q: %w", ErrBlobMissing, digestStr, err)
	}

	blobPath := path.Join("blobs", hash.Algorithm, hash.Hex)

	blobFile, err := s.root.OpenFile(blobPath, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, s.blobOpenError(digestStr, err)
	}

	defer func() { _ = blobFile.Close() }()

	info, err := blobFile.Stat()
	if err != nil {
		return nil, fmt.Errorf("reading blob %s: %w", digestStr, err)
	}

	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s: mode %s", ErrBlobNotRegular, digestStr, info.Mode().Type())
	}

	// The limit allows one byte more than declared so a grown blob is
	// reported as a size mismatch.
	data, err := io.ReadAll(io.LimitReader(blobFile, readLimit+1))
	if err != nil {
		return nil, fmt.Errorf("reading blob %s: %w", digestStr, err)
	}

	return data, checkBlobSize(digestStr, int64(len(data)), readLimit, expectedSize)
}

// checkBlobSize checks the number of bytes read from a blob against its read
// limit and declared size.
func checkBlobSize(digestStr string, size, readLimit, expectedSize int64) error {
	switch {
	case size > readLimit && expectedSize > 0:
		return fmt.Errorf(
			"%w: %s (expected %d, got more)", ErrBlobSizeMismatch, digestStr, expectedSize,
		)
	case size > readLimit:
		return fmt.Errorf(
			"%w: %s exceeds %d byte read limit", ErrBlobTooLarge, digestStr, maxBlobReadSize,
		)
	case expectedSize > 0 && size != expectedSize:
		return fmt.Errorf(
			"%w: %s (expected %d, got %d)", ErrBlobSizeMismatch, digestStr, expectedSize, size,
		)
	default:
		return nil
	}
}

// blobOpenError classifies an error opening a blob file.
func (s *Store) blobOpenError(digestStr string, err error) error {
	switch {
	case errors.Is(err, os.ErrNotExist) && s.replaced():
		return fmt.Errorf("%w: %s: %w", ErrStoreReplaced, digestStr, err)
	case errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("%w: %s: %w", ErrBlobMissing, digestStr, err)
	case isLocalReadError(err):
		return fmt.Errorf("reading blob %s: %w", digestStr, err)
	default:
		// The blob path exists but cannot be opened inside the store
		// directory: a symbolic link escaping the store, a symbolic link
		// loop or a file in place of a parent directory was swapped in.
		return fmt.Errorf(
			"%w: %s: cannot be opened inside the store: %w", ErrBlobNotRegular, digestStr, err,
		)
	}
}

// isLocalReadError reports whether err is a local availability problem
// rather than a change to the store's content.
func isLocalReadError(err error) bool {
	return errors.Is(err, os.ErrPermission) ||
		errors.Is(err, syscall.EMFILE) ||
		errors.Is(err, syscall.ENFILE) ||
		errors.Is(err, syscall.ENOMEM)
}

// replaced reports whether the store path no longer refers to the directory
// pinned when the store was opened, which happens when a bundle import swaps
// in a new store.
func (s *Store) replaced() bool {
	pinned, err := s.root.Stat(".")
	if err != nil {
		return true
	}

	current, err := os.Stat(s.dir)

	return err != nil || !os.SameFile(pinned, current)
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

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
	"errors"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
)

var (
	// ErrBundleNotFound indicates the bundle store directory does not exist.
	ErrBundleNotFound = errors.New("bundle store not found")

	// ErrManifestNotFound indicates bundle-manifest.json is missing from the store.
	ErrManifestNotFound = errors.New("bundle-manifest.json not found in store")

	// ErrManifestCorrupt indicates the bundle manifest could not be parsed.
	ErrManifestCorrupt = errors.New("bundle manifest is corrupt")

	// ErrManifestVersionUnsupported indicates the manifest version is not supported.
	ErrManifestVersionUnsupported = errors.New("bundle manifest version is not supported")

	// ErrBlobMissing indicates a blob referenced by the manifest is missing from the OCI layout.
	ErrBlobMissing = errors.New("referenced blob missing from OCI layout")

	// ErrStoreReplaced indicates a blob could not be read because the store
	// directory was replaced and the directory pinned when the store was
	// opened was removed. A bundle import keeps the previous store as a
	// backup, so this only happens when that backup was removed as well (by
	// a second import, or by hand). The attestation set cannot be evaluated,
	// so it denies like tampering until the store is reopened.
	ErrStoreReplaced = errors.New("bundle store was replaced, reopen it")

	// ErrBlobNotRegular indicates a blob path in the OCI layout is not a regular
	// file (for example a directory or FIFO swapped in after import).
	ErrBlobNotRegular = errors.New("blob is not a regular file")

	// ErrBlobSizeMismatch indicates a blob's actual size does not match the manifest entry.
	ErrBlobSizeMismatch = errors.New("blob size does not match manifest")

	// ErrBundleExpired indicates the bundle exceeds the configured maximum age.
	ErrBundleExpired = errors.New("bundle exceeds maximum age")

	// ErrBundleSignatureInvalid indicates the bundle's cryptographic signature is invalid.
	ErrBundleSignatureInvalid = errors.New("bundle signature verification failed")

	// ErrBundleSignatureRequired indicates a bundle signature is required but not present.
	ErrBundleSignatureRequired = errors.New("bundle signature required but not present")

	// ErrBundleSignatureKeyRequired indicates a bundle signature is required
	// but no key to verify it is configured.
	ErrBundleSignatureKeyRequired = errors.New(
		"bundle signature required but no verification key configured",
	)

	// ErrNoAttestationsForDigest indicates no attestations were found for the given image digest.
	ErrNoAttestationsForDigest = errors.New("no attestations found for image digest")

	// ErrTrustedRootMissing indicates the bundle has no embedded trusted root.
	ErrTrustedRootMissing = errors.New("no trusted root in bundle")

	// ErrDigestRequired indicates Digest must be set in FetchOptions.
	ErrDigestRequired = errors.New("digest is required in fetch options")

	// ErrFetchOptionsRequired indicates FetchOptions must not be nil.
	ErrFetchOptionsRequired = errors.New("fetch options must not be nil")

	// ErrInvalidPEMBlock indicates the public key file contains no valid PEM block.
	ErrInvalidPEMBlock = attestation.ErrNoPEMBlock

	// ErrPathTraversal indicates a tar entry attempts to escape the target directory.
	ErrPathTraversal = errors.New("tar entry escapes target directory")

	// ErrBundleTooLarge indicates the bundle tar exceeds the maximum allowed size.
	ErrBundleTooLarge = errors.New("bundle exceeds maximum allowed size")

	// ErrBlobDigestMismatch indicates a blob's content hash does not match the declared digest.
	ErrBlobDigestMismatch = errors.New("blob content hash does not match declared digest")

	// ErrBlobTooLarge indicates a blob exceeds the maximum read size.
	ErrBlobTooLarge = errors.New("blob exceeds maximum read size")

	// ErrUnsupportedKeyType indicates the private key type is not supported for signing.
	ErrUnsupportedKeyType = errors.New("private key does not implement crypto.Signer")

	// ErrBundleTooManyEntries indicates the bundle tar contains too many entries.
	ErrBundleTooManyEntries = errors.New("bundle exceeds maximum entry count")

	// ErrUnsupportedDigestAlgorithm indicates a digest uses an unsupported hash algorithm.
	ErrUnsupportedDigestAlgorithm = errors.New("unsupported digest algorithm")

	// ErrFetcherClosed indicates a fetch on a bundle fetcher whose store was
	// released because a reload replaced it.
	ErrFetcherClosed = errors.New("bundle fetcher is closed")

	// ErrDigestUnresolved indicates the digest of an image to bundle could not
	// be determined.
	ErrDigestUnresolved = errors.New("image digest could not be resolved")

	errUnsupportedSignatureType = errors.New("signature type is not supported in offline bundles")
	errMissingPredicateType     = errors.New("verified statement has no predicate type")
)

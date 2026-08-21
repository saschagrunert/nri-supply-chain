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
	"strings"
)

// VerifyBlobIntegrity checks that all blobs referenced by the manifest exist
// in the OCI layout and match their declared digest and size.
func VerifyBlobIntegrity(store *Store) error {
	store.mu.RLock()
	defer store.mu.RUnlock()

	var errs []error

	for digest, entry := range store.manifest.Images {
		for _, att := range entry.Attestations {
			blobErr := verifyBlob(store, att.BlobDigest, att.Size)
			if blobErr != nil {
				errs = append(errs, fmt.Errorf(
					"image %s attestation %s: %w",
					digest, att.PredicateType, blobErr,
				))
			}
		}
	}

	if store.manifest.TrustedRoot != nil {
		rootErr := verifyBlob(
			store,
			store.manifest.TrustedRoot.BlobDigest,
			store.manifest.TrustedRoot.Size,
		)
		if rootErr != nil {
			errs = append(errs, fmt.Errorf("trusted root: %w", rootErr))
		}
	}

	for i, rev := range store.manifest.Revocation {
		revErr := verifyBlob(store, rev.BlobDigest, rev.Size)
		if revErr != nil {
			errs = append(errs, fmt.Errorf(
				"revocation[%d] (%s): %w", i, rev.Type, revErr,
			))
		}
	}

	return errors.Join(errs...)
}

const sha256Prefix = "sha256:"

func verifyBlob(store *Store, digestStr string, expectedSize int64) error {
	if !strings.HasPrefix(digestStr, sha256Prefix) {
		return fmt.Errorf(
			"%w: expected %q prefix, got %q",
			ErrUnsupportedDigestAlgorithm,
			sha256Prefix,
			digestStr,
		)
	}

	data, err := store.readBlob(digestStr, expectedSize)
	if err != nil {
		return err
	}

	actualHash := sha256.Sum256(data)
	expectedHash := digestStr[len(sha256Prefix):]

	actualHex := hex.EncodeToString(actualHash[:])
	if actualHex != expectedHash {
		return fmt.Errorf(
			"%w: %s", ErrBlobDigestMismatch, digestStr,
		)
	}

	return nil
}

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
	"fmt"
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

	for _, entry := range store.manifest.allTrustedRoots() {
		rootErr := verifyBlob(store, entry.BlobDigest, entry.Size)
		if rootErr != nil {
			errs = append(errs, fmt.Errorf("trusted root %q: %w", entry.Name, rootErr))
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

// verifyBlob checks a blob's presence, size, and content digest. readBlob
// performs the digest and size checks on every read.
func verifyBlob(store *Store, digestStr string, expectedSize int64) error {
	_, err := store.readBlob(digestStr, expectedSize)

	return err
}

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
	"encoding/json"
	"fmt"
	"time"
)

const (
	manifestFileName = "bundle-manifest.json"

	currentManifestVersion = 1
)

// Manifest is the authoritative index persisted as bundle-manifest.json
// at the root of an attestation bundle store.
type Manifest struct {
	Version     int                    `json:"version"`
	CreatedAt   time.Time              `json:"createdAt"`
	Images      map[string]*ImageEntry `json:"images"`
	TrustedRoot *TrustedRootEntry      `json:"trustedRoot,omitempty"`
	Revocation  []RevocationEntry      `json:"revocation,omitempty"`
	Signature   *ManifestSignature     `json:"signature,omitempty"`
}

// ImageEntry describes the attestations bundled for a single container image.
type ImageEntry struct {
	Refs         []string           `json:"refs,omitempty"`
	Attestations []AttestationEntry `json:"attestations"`
	CreatedAt    time.Time          `json:"createdAt"`
}

// AttestationEntry describes a single attestation blob stored in the OCI layout.
type AttestationEntry struct {
	PredicateType string `json:"predicateType"`
	BlobDigest    string `json:"blobDigest"`
	Size          int64  `json:"size"`
	SignatureType string `json:"signatureType"`
}

// TrustedRootEntry describes the trusted root blob stored in the OCI layout.
type TrustedRootEntry struct {
	BlobDigest string `json:"blobDigest"`
	Size       int64  `json:"size"`
}

// RevocationEntry describes a certificate revocation snapshot embedded in the bundle.
type RevocationEntry struct {
	BlobDigest string `json:"blobDigest"`
	Size       int64  `json:"size"`
	Type       string `json:"type"`
}

// ManifestSignature holds a cryptographic signature over the manifest contents.
type ManifestSignature struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
	KeyHint   string `json:"keyHint"`
}

// ParseManifest parses a Manifest from JSON bytes.
func ParseManifest(data []byte) (*Manifest, error) {
	var manifest Manifest

	unmarshalErr := json.Unmarshal(data, &manifest)
	if unmarshalErr != nil {
		return nil, fmt.Errorf("%w: %w", ErrManifestCorrupt, unmarshalErr)
	}

	if manifest.Version < 1 || manifest.Version > currentManifestVersion {
		return nil, fmt.Errorf(
			"%w: got %d, supported up to %d",
			ErrManifestVersionUnsupported, manifest.Version, currentManifestVersion,
		)
	}

	if manifest.Images == nil {
		manifest.Images = make(map[string]*ImageEntry)
	}

	return &manifest, nil
}

// MarshalManifest serializes a Manifest to JSON.
func MarshalManifest(manifest *Manifest) ([]byte, error) {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling manifest: %w", err)
	}

	return data, nil
}

// MarshalManifestForSigning serializes the manifest with the Signature field
// cleared, producing the canonical bytes that are signed/verified.
func MarshalManifestForSigning(manifest *Manifest) ([]byte, error) {
	withoutSig := *manifest
	withoutSig.Signature = nil

	data, err := json.Marshal(&withoutSig)
	if err != nil {
		return nil, fmt.Errorf("marshaling manifest for signing: %w", err)
	}

	return data, nil
}

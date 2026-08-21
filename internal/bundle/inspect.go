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
	"sort"
	"time"
)

// InspectResult holds the inspection output for a bundle.
type InspectResult struct {
	Version          int            `json:"version"`
	CreatedAt        time.Time      `json:"createdAt"`
	Age              HumanDuration  `json:"age"`
	ImageCount       int            `json:"imageCount"`
	AttestationCount int            `json:"attestationCount"`
	Images           []InspectImage `json:"images"`
	TrustedRoot      bool           `json:"trustedRoot"`
	RevocationCount  int            `json:"revocationCount"`
	Signed           bool           `json:"signed"`
	SignatureKeyHint string         `json:"signatureKeyHint,omitempty"`
}

// HumanDuration wraps time.Duration to serialize as a human-readable string
// in JSON (e.g. "1h30m0s") instead of nanoseconds.
type HumanDuration time.Duration

// MarshalJSON serializes the duration as a quoted string.
func (d HumanDuration) MarshalJSON() ([]byte, error) {
	return []byte(`"` + time.Duration(d).Round(time.Second).String() + `"`), nil
}

// Duration returns the underlying time.Duration.
func (d HumanDuration) Duration() time.Duration {
	return time.Duration(d)
}

// InspectImage holds per-image inspection details.
type InspectImage struct {
	Digest           string               `json:"digest"`
	Refs             []string             `json:"refs,omitempty"`
	AttestationCount int                  `json:"attestationCount"`
	Attestations     []InspectAttestation `json:"attestations"`
}

// InspectAttestation holds per-attestation details.
type InspectAttestation struct {
	PredicateType string `json:"predicateType"`
	Size          int64  `json:"size"`
	SignatureType string `json:"signatureType"`
}

// Inspect examines a bundle store directory and returns summary information.
func Inspect(storePath string) (*InspectResult, error) {
	store, err := OpenStore(storePath)
	if err != nil {
		return nil, fmt.Errorf("opening bundle: %w", err)
	}

	manifest := store.Manifest()

	result := &InspectResult{
		Version:          manifest.Version,
		CreatedAt:        manifest.CreatedAt,
		Age:              HumanDuration(time.Since(manifest.CreatedAt)),
		ImageCount:       len(manifest.Images),
		AttestationCount: 0,
		Images:           nil,
		TrustedRoot:      manifest.TrustedRoot != nil,
		RevocationCount:  len(manifest.Revocation),
		Signed:           manifest.Signature != nil,
		SignatureKeyHint: "",
	}

	if manifest.Signature != nil {
		result.SignatureKeyHint = manifest.Signature.KeyHint
	}

	totalAtts := 0

	digests := make([]string, 0, len(manifest.Images))
	for digest := range manifest.Images {
		digests = append(digests, digest)
	}

	sort.Strings(digests)

	for _, digest := range digests {
		entry := manifest.Images[digest]
		img := InspectImage{
			Digest:           digest,
			Refs:             entry.Refs,
			AttestationCount: len(entry.Attestations),
			Attestations:     make([]InspectAttestation, 0, len(entry.Attestations)),
		}

		for _, att := range entry.Attestations {
			img.Attestations = append(img.Attestations, InspectAttestation{
				PredicateType: att.PredicateType,
				Size:          att.Size,
				SignatureType: att.SignatureType,
			})
		}

		totalAtts += len(entry.Attestations)

		result.Images = append(result.Images, img)
	}

	result.AttestationCount = totalAtts

	return result, nil
}

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

package bundle_test

import (
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/bundle"
)

func benchManifestJSON() []byte {
	return []byte(`{
  "version": 1,
  "createdAt": "2024-01-01T00:00:00Z",
  "images": {
    "sha256:aabbccdd": {
      "refs": ["ghcr.io/example/app:v1.0"],
      "attestations": [
        {
          "predicateType": "https://slsa.dev/provenance/v1",
          "blobDigest": "sha256:1111",
          "size": 4096,
          "signatureType": "cosign"
        },
        {
          "predicateType": "https://spdx.dev/Document",
          "blobDigest": "sha256:2222",
          "size": 8192,
          "signatureType": "cosign"
        }
      ],
      "createdAt": "2024-01-01T00:00:00Z"
    }
  },
  "trustedRoot": {"blobDigest": "sha256:3333", "size": 2048},
  "signature": {
    "algorithm": "ECDSA_P256_SHA256",
    "value": "MEUCIQD...",
    "keyHint": "bundle-signing-key"
  }
}`)
}

func BenchmarkParseManifest(b *testing.B) {
	data := benchManifestJSON()

	for range b.N {
		_, _ = bundle.ParseManifest(data)
	}
}

func BenchmarkMarshalManifest(b *testing.B) {
	manifest := &bundle.Manifest{ //nolint:exhaustruct_v5 // benchmark only needs core fields
		Version:   1,
		CreatedAt: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		Images: map[string]*bundle.ImageEntry{
			"sha256:aabbccdd": {
				Refs: []string{"ghcr.io/example/app:v1.0"},
				Attestations: []bundle.AttestationEntry{
					{
						PredicateType: "https://slsa.dev/provenance/v1",
						BlobDigest:    "sha256:1111",
						Size:          4096,
						SignatureType: "cosign",
					},
				},
				CreatedAt: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			},
		},
	}

	for range b.N {
		_, _ = bundle.MarshalManifest(manifest)
	}
}

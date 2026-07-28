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

package attestation_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	ociV1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
)

func TestFetchCorruptedBundleJSON(t *testing.T) {
	t.Parallel()

	corruptPayloads := []struct {
		name    string
		payload string
	}{
		{name: "empty string", payload: ""},
		{name: "malformed JSON", payload: "{not json at all"},
		{name: "truncated JSON", payload: `{"predicateType": "https://slsa.dev/provenance/v`},
		{name: "null payload", payload: "null"},
		{name: "just whitespace", payload: "   \n\t  "},
		{name: "binary garbage", payload: "\x00\x01\x02\x03\xff\xfe"},
		{name: "array instead of object", payload: `[1,2,3]`},
	}

	for _, tc := range corruptPayloads {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			fetcher := attestation.NewTestOCIFetcherFull(
				func(_ context.Context, _ []byte, _ *attestation.FetchOptions) ([]byte, error) {
					return nil, errSignatureMismatch
				},
				func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
					layer := static.NewLayer([]byte(tc.payload), types.OCIUncompressedLayer)

					img, imgErr := mutate.AppendLayers(empty.Image, layer)
					if imgErr != nil {
						t.Fatalf("building test image: %v", imgErr)
					}

					return img, nil
				},
				func(_ name.Digest, _ ...remote.Option) (ociV1.ImageIndex, error) {
					return &fakeImageIndex{
						manifests: []ociV1.Descriptor{
							{
								ArtifactType: "application/vnd.dev.sigstore.bundle.v0.3+json",
								Digest: ociV1.Hash{
									Algorithm: testHashAlgorithm,
									Hex:       testHashHex,
								},
								Annotations: map[string]string{
									"dev.sigstore.bundle.predicateType": attestation.PredicateSLSAProvenanceV1,
								},
							},
						},
						err: nil,
					}, nil
				},
			)

			opts := &attestation.FetchOptions{
				TrustedIssuers: []string{testIssuerGoogle},
				SANPatterns:    []string{testSANUser},
				Timeout:        5 * time.Second,
				Digest:         testFetchDigest,
			}

			_, err := fetcher.Fetch(context.Background(), testFetchImageRef, opts)

			testutil.AssertError(t, err)
		})
	}
}

func TestFetchOversizedAttestation(t *testing.T) {
	t.Parallel()

	oversized := strings.Repeat("A", 10<<20+1)

	fetcher := attestation.NewTestOCIFetcherFull(
		func(_ context.Context, _ []byte, _ *attestation.FetchOptions) ([]byte, error) {
			t.Fatal("verifyBundle should not be called for oversized attestations")

			return nil, nil
		},
		func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
			layer := static.NewLayer([]byte(oversized), types.OCIUncompressedLayer)

			img, imgErr := mutate.AppendLayers(empty.Image, layer)
			if imgErr != nil {
				t.Fatalf("building test image: %v", imgErr)
			}

			return img, nil
		},
		func(_ name.Digest, _ ...remote.Option) (ociV1.ImageIndex, error) {
			return &fakeImageIndex{
				manifests: []ociV1.Descriptor{
					{
						ArtifactType: "application/vnd.dev.sigstore.bundle.v0.3+json",
						Digest: ociV1.Hash{
							Algorithm: testHashAlgorithm,
							Hex:       testHashHex,
						},
						Annotations: map[string]string{
							"dev.sigstore.bundle.predicateType": attestation.PredicateSLSAProvenanceV1,
						},
					},
				},
				err: nil,
			}, nil
		},
	)

	opts := &attestation.FetchOptions{
		TrustedIssuers: []string{testIssuerGoogle},
		SANPatterns:    []string{testSANUser},
		Timeout:        5 * time.Second,
		Digest:         testFetchDigest,
	}

	result, err := fetcher.Fetch(context.Background(), testFetchImageRef, opts)
	if err != nil {
		return
	}

	if len(result) != 0 {
		t.Error("expected no attestations for oversized payload")
	}
}

func TestExtractPredicateTypeCorrupted(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		payload  string
		wantType string
	}{
		{
			name:     "valid",
			payload:  `{"predicateType":"` + attestation.PredicateSLSAProvenanceV1 + `"}`,
			wantType: attestation.PredicateSLSAProvenanceV1,
		},
		{name: "missing field", payload: `{"other":"value"}`, wantType: ""},
		{name: "empty JSON", payload: `{}`, wantType: ""},
		{name: "malformed", payload: `{bad`, wantType: ""},
		{name: "null JSON", payload: `null`, wantType: ""},
		{name: "empty", payload: ``, wantType: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := attestation.ExportExtractPredicateType([]byte(tc.payload))
			testutil.AssertEqual(t, tc.wantType, got)
		})
	}
}

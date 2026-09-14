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
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"
	ociV1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
)

// foreignLayerRegistry starts a registry and a server standing in for an
// attacker-controlled host that counts the requests it receives.
func foreignLayerRegistry(t *testing.T) (registryHost, foreignURL string, hits *atomic.Int64) {
	t.Helper()

	registryServer := httptest.NewServer(ggcrregistry.New())
	t.Cleanup(registryServer.Close)

	hits = &atomic.Int64{}

	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(foreign.Close)

	// A host name instead of an IP literal passes go-containerregistry's
	// private address check for foreign layer URLs.
	foreignURL = strings.Replace(foreign.URL, "127.0.0.1", "localhost", 1) + "/blob"

	return strings.TrimPrefix(registryServer.URL, "http://"), foreignURL, hits
}

// pushForeignLayerManifest pushes a manifest whose only layer is missing from
// the registry and lists a foreign URL, and returns its descriptor.
func pushForeignLayerManifest(
	t *testing.T,
	ref name.Reference,
	foreignURL string,
) ociV1.Descriptor {
	t.Helper()

	missing := ociV1.Hash{Algorithm: testHashAlgorithm, Hex: strings.Repeat("ab", 32)}
	manifest := ociV1.Manifest{
		SchemaVersion: 2,
		MediaType:     types.OCIManifestSchema1,
		Config: ociV1.Descriptor{
			MediaType: types.OCIConfigJSON,
			Size:      2,
			Digest:    ociV1.Hash{Algorithm: testHashAlgorithm, Hex: strings.Repeat("cd", 32)},
		},
		Layers: []ociV1.Descriptor{{
			MediaType: types.MediaType(attestation.ExportBundleMediaType),
			Size:      128,
			Digest:    missing,
			URLs:      []string{foreignURL},
		}},
	}

	raw, err := json.Marshal(&manifest)
	if err != nil {
		t.Fatalf("marshaling manifest: %v", err)
	}

	digest, _, err := ociV1.SHA256(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("hashing manifest: %v", err)
	}

	putURL := "http://" + ref.Context().RegistryStr() + "/v2/" +
		ref.Context().RepositoryStr() + "/manifests/" + ref.Identifier()

	req, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodPut,
		putURL,
		bytes.NewReader(raw),
	)
	if err != nil {
		t.Fatalf("building manifest request: %v", err)
	}

	req.Header.Set("Content-Type", string(types.OCIManifestSchema1))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("pushing manifest: %v", err)
	}

	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("pushing manifest: unexpected status %d", resp.StatusCode)
	}

	return ociV1.Descriptor{
		MediaType:    types.OCIManifestSchema1,
		ArtifactType: attestation.ExportBundleMediaType,
		Size:         int64(len(raw)),
		Digest:       digest,
	}
}

func TestFetchNeverContactsForeignLayerURLs(t *testing.T) {
	t.Parallel()

	t.Run("referrer", func(t *testing.T) {
		t.Parallel()

		registryHost, foreignURL, hits := foreignLayerRegistry(t)
		imageRef := registryHost + "/app@" + signerTestDigest

		referrerRef, err := name.ParseReference(registryHost + "/app:foreign")
		testutil.AssertNoError(t, err)

		desc := pushForeignLayerManifest(t, referrerRef, foreignURL)

		fetcher := attestation.NewTestOCIFetcherSigned(
			func(ctx context.Context, data []byte, opts *attestation.FetchOptions) (*attestation.VerifiedBundle, error) {
				return attestation.ExportVerifyBundle(ctx, data, opts, nil)
			},
			remote.Image,
			func(_ name.Digest, _ ...remote.Option) (ociV1.ImageIndex, error) {
				return &fakeImageIndex{manifests: []ociV1.Descriptor{desc}, err: nil}, nil
			},
		)

		_, err = fetcher.Fetch(t.Context(), imageRef, &attestation.FetchOptions{
			Digest: signerTestDigest,
		})
		testutil.AssertErrorIs(t, err, attestation.ErrVerificationFailed)
		testutil.AssertEqual(t, int64(0), hits.Load())
	})

	t.Run("cosign tag", func(t *testing.T) {
		t.Parallel()

		registryHost, foreignURL, hits := foreignLayerRegistry(t)
		imageRef := registryHost + "/app@" + signerTestDigest

		tagRef, err := name.ParseReference(
			registryHost + "/app:" + cosignAttestationTagFor(signerTestDigest),
		)
		testutil.AssertNoError(t, err)

		pushForeignLayerManifest(t, tagRef, foreignURL)

		fetcher := attestation.NewTestOCIFetcherSigned(
			func(ctx context.Context, data []byte, opts *attestation.FetchOptions) (*attestation.VerifiedBundle, error) {
				return attestation.ExportVerifyBundle(ctx, data, opts, nil)
			},
			remote.Image,
			func(_ name.Digest, _ ...remote.Option) (ociV1.ImageIndex, error) {
				return &fakeImageIndex{manifests: nil, err: nil}, nil
			},
		)

		_, err = fetcher.Fetch(t.Context(), imageRef, &attestation.FetchOptions{
			Digest: signerTestDigest,
		})
		testutil.AssertErrorIs(t, err, attestation.ErrVerificationFailed)
		testutil.AssertEqual(t, int64(0), hits.Load())
	})
}

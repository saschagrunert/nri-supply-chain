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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	ociV1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
)

var errUntrustedBundle = errors.New("untrusted bundle")

// testPaddingAnnotation inflates manifests and listings beyond size limits.
const testPaddingAnnotation = "padding"

func notationDescriptor(seed string) ociV1.Descriptor {
	sum := sha256.Sum256([]byte(seed))

	return ociV1.Descriptor{
		ArtifactType: attestation.ExportNotationSignatureMediaType,
		Digest:       ociV1.Hash{Algorithm: testHashAlgorithm, Hex: hex.EncodeToString(sum[:])},
	}
}

func junkNotationImage() ociV1.Image {
	return fakeNotationImage([]byte("junk"), types.MediaType(testNotationLayerMediaType), nil)
}

// TestJunkNotationReferrersDoNotHideFailedBundles checks that unverified
// Notation signatures do not count as verified attestations, so a bundle
// referrer that failed verification still denies the image.
func TestJunkNotationReferrersDoNotHideFailedBundles(t *testing.T) {
	t.Parallel()

	bundleDesc := bundleDescriptor(attestation.PredicateSLSAProvenanceV1)
	notationDesc := notationDescriptor("junk")

	fetcher := attestation.NewTestOCIFetcherFull(
		func(context.Context, []byte, *attestation.FetchOptions) ([]byte, error) {
			return nil, errUntrustedBundle
		},
		func(ref name.Reference, _ ...remote.Option) (ociV1.Image, error) {
			if ref.Identifier() == notationDesc.Digest.String() {
				return junkNotationImage(), nil
			}

			return fakeImageWithPayload([]byte(sigstoreBundleJSON)), nil
		},
		func(name.Digest, ...remote.Option) (ociV1.ImageIndex, error) {
			return &fakeImageIndex{
				manifests: []ociV1.Descriptor{bundleDesc, notationDesc},
				err:       nil,
			}, nil
		},
	)

	atts, err := fetcher.Fetch(
		context.Background(), testFetchImageRef, &attestation.FetchOptions{Digest: testFetchDigest},
	)
	if !errors.Is(err, attestation.ErrVerificationFailed) {
		t.Fatalf("Fetch() error = %v, want %v", err, attestation.ErrVerificationFailed)
	}

	if errors.Is(err, attestation.ErrIncompleteAttestationSet) {
		t.Fatalf("Fetch() error = %v, want a complete set", err)
	}

	// The Notation signature is returned with the error, so the Notation
	// check still evaluates it instead of treating it as missing.
	if len(atts) != 1 || atts[0].SignatureType != attestation.SignatureTypeNotation ||
		atts[0].Digest != testFetchDigest {
		t.Fatalf("Fetch() attestations = %+v, want the Notation signature", atts)
	}
}

// TestJunkNotationReferrersDoNotSuppressCosignTagFallback checks that the
// cosign attestation tag is still consulted when the referrers only hold
// (unverified) Notation signatures.
func TestJunkNotationReferrersDoNotSuppressCosignTagFallback(t *testing.T) {
	t.Parallel()

	var tagFetched atomic.Bool

	notationDesc := notationDescriptor("junk")

	fetcher := attestation.NewTestOCIFetcherFull(
		func(context.Context, []byte, *attestation.FetchOptions) ([]byte, error) {
			return []byte(slsaStatementJSON), nil
		},
		func(ref name.Reference, _ ...remote.Option) (ociV1.Image, error) {
			if strings.HasSuffix(ref.Identifier(), ".att") {
				tagFetched.Store(true)

				return fakeImageWithPayload([]byte(sigstoreBundleJSON)), nil
			}

			return junkNotationImage(), nil
		},
		func(name.Digest, ...remote.Option) (ociV1.ImageIndex, error) {
			return &fakeImageIndex{manifests: []ociV1.Descriptor{notationDesc}, err: nil}, nil
		},
	)

	atts, err := fetcher.Fetch(
		context.Background(), testFetchImageRef, &attestation.FetchOptions{Digest: testFetchDigest},
	)
	if err != nil {
		t.Fatalf("Fetch() error: %v", err)
	}

	if !tagFetched.Load() {
		t.Fatal("cosign attestation tag was not consulted")
	}

	predicateTypes := make([]string, 0, len(atts))
	for idx := range atts {
		predicateTypes = append(predicateTypes, atts[idx].PredicateType)
	}

	want := attestation.PredicateSLSAProvenanceV1 + "," + attestation.NotationSignatureMediaType
	if got := strings.Join(predicateTypes, ","); got != want {
		t.Errorf("attestations = %s, want %s", got, want)
	}
}

// registryStub serves a referrers listing and manifests for a fixed
// repository, the way a registry pushed to by an attacker would.
type registryStub struct {
	listing   []byte
	manifests map[string][]byte
	blobs     map[string][]byte
}

func (s *registryStub) ServeHTTP(writer http.ResponseWriter, req *http.Request) {
	path := req.URL.Path

	switch {
	case path == "/v2/":
		writer.WriteHeader(http.StatusOK)
	case strings.HasPrefix(path, "/v2/app/referrers/"):
		writer.Header().Set("Content-Type", string(types.OCIImageIndex))
		_, _ = writer.Write(s.listing)
	case strings.HasPrefix(path, "/v2/app/manifests/"):
		body, ok := s.manifests[strings.TrimPrefix(path, "/v2/app/manifests/")]
		if !ok {
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusNotFound)
			_, _ = writer.Write(
				[]byte(`{"errors":[{"code":"MANIFEST_UNKNOWN","message":"unknown"}]}`),
			)

			return
		}

		writer.Header().Set("Content-Type", string(types.OCIManifestSchema1))
		_, _ = writer.Write(body)
	case strings.HasPrefix(path, "/v2/app/blobs/"):
		body, ok := s.blobs[strings.TrimPrefix(path, "/v2/app/blobs/")]
		if !ok {
			writer.WriteHeader(http.StatusNotFound)

			return
		}

		_, _ = writer.Write(body)
	default:
		writer.WriteHeader(http.StatusNotFound)
	}
}

func digestOf(data []byte) ociV1.Hash {
	sum := sha256.Sum256(data)

	return ociV1.Hash{Algorithm: testHashAlgorithm, Hex: hex.EncodeToString(sum[:])}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()

	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}

	return data
}

// TestManifestDownloadChargesActualBytes checks that a referrer manifest is
// charged to the download budget with the bytes actually read, not with the
// size declared by the referrers listing, which whoever pushed it chooses.
func TestManifestDownloadChargesActualBytes(t *testing.T) {
	t.Parallel()

	layer := []byte(sigstoreBundleJSON)
	layerDigest := digestOf(layer)

	manifest := mustJSON(t, &ociV1.Manifest{
		SchemaVersion: 2,
		MediaType:     types.OCIManifestSchema1,
		ArtifactType:  attestation.ExportBundleMediaType,
		Config: ociV1.Descriptor{
			MediaType: types.MediaType(attestation.ExportOCIEmptyMediaType),
			Digest:    digestOf([]byte("{}")),
			Size:      2,
		},
		Layers: []ociV1.Descriptor{{
			MediaType: types.MediaType(attestation.ExportBundleMediaType),
			Digest:    layerDigest,
			Size:      int64(len(layer)),
		}},
		Annotations: map[string]string{testPaddingAnnotation: strings.Repeat("x", 64<<10)},
	})
	manifestDigest := digestOf(manifest)

	listing := mustJSON(t, &ociV1.IndexManifest{
		SchemaVersion: 2,
		MediaType:     types.OCIImageIndex,
		Manifests: []ociV1.Descriptor{{
			MediaType:    types.OCIManifestSchema1,
			ArtifactType: attestation.ExportBundleMediaType,
			Digest:       manifestDigest,
			// Far below the actual manifest size.
			Size: 100,
		}},
	})

	server := httptest.NewServer(&registryStub{
		listing:   listing,
		manifests: map[string][]byte{manifestDigest.String(): manifest},
		blobs:     map[string][]byte{layerDigest.String(): layer},
	})
	t.Cleanup(server.Close)

	fetcher := attestation.NewOCIFetcherWithVerifier(
		func(context.Context, []byte, *attestation.FetchOptions) ([]byte, error) {
			return []byte(slsaStatementJSON), nil
		},
	)
	imageRef := strings.TrimPrefix(server.URL, "http://") + "/app:v1"

	// With the default budget the referrer verifies.
	atts, err := fetcher.Fetch(
		context.Background(), imageRef, &attestation.FetchOptions{Digest: testFetchDigest},
	)
	if err != nil || len(atts) != 1 {
		t.Fatalf("Fetch() = %d attestations, error %v; want 1 attestation", len(atts), err)
	}

	// A budget that fits the declared but not the actual size denies.
	fetcher.ExportSetDownloadLimit(16 << 10)

	_, err = fetcher.Fetch(
		context.Background(), imageRef, &attestation.FetchOptions{Digest: testFetchDigest},
	)
	if !errors.Is(err, attestation.ErrVerificationFailed) ||
		!errors.Is(err, attestation.ErrIncompleteAttestationSet) {
		t.Fatalf("Fetch() error = %v, want an incomplete attestation set", err)
	}
}

// TestOversizedReferrersListingIsDenied checks that the referrers listing is
// bounded by the bytes read, instead of go-containerregistry's 100 MiB limit,
// and that an oversized listing makes the attestation set incomplete instead
// of a verification failure that is ignored like absent attestations.
func TestOversizedReferrersListingIsDenied(t *testing.T) {
	t.Parallel()

	listing := mustJSON(t, &ociV1.IndexManifest{
		SchemaVersion: 2,
		MediaType:     types.OCIImageIndex,
		Manifests:     []ociV1.Descriptor{},
		Annotations:   map[string]string{testPaddingAnnotation: strings.Repeat("x", 5<<20)},
	})

	server := httptest.NewServer(&registryStub{
		listing:   listing,
		manifests: map[string][]byte{},
		blobs:     map[string][]byte{},
	})
	t.Cleanup(server.Close)

	fetcher := attestation.NewOCIFetcherWithVerifier(
		func(context.Context, []byte, *attestation.FetchOptions) ([]byte, error) {
			return []byte(slsaStatementJSON), nil
		},
	)

	_, err := fetcher.Fetch(
		context.Background(),
		strings.TrimPrefix(server.URL, "http://")+"/app:v1",
		&attestation.FetchOptions{Digest: testFetchDigest},
	)
	if !errors.Is(err, attestation.ErrVerificationFailed) ||
		!errors.Is(err, attestation.ErrIncompleteAttestationSet) {
		t.Fatalf("Fetch() error = %v, want an incomplete attestation set", err)
	}
}

// TestOversizedCosignTagManifestIsDenied checks that a cosign attestation tag
// whose manifest exceeds the response size limit makes the attestation set
// incomplete.
func TestOversizedCosignTagManifestIsDenied(t *testing.T) {
	t.Parallel()

	manifest := mustJSON(t, &ociV1.Manifest{
		SchemaVersion: 2,
		MediaType:     types.OCIManifestSchema1,
		Config: ociV1.Descriptor{
			MediaType: types.MediaType(attestation.ExportOCIEmptyMediaType),
			Digest:    digestOf([]byte("{}")),
			Size:      2,
		},
		Layers:      []ociV1.Descriptor{},
		Annotations: map[string]string{testPaddingAnnotation: strings.Repeat("x", 5<<20)},
	})

	listing := mustJSON(t, &ociV1.IndexManifest{
		SchemaVersion: 2,
		MediaType:     types.OCIImageIndex,
		Manifests:     []ociV1.Descriptor{},
	})

	server := httptest.NewServer(&registryStub{
		listing:   listing,
		manifests: map[string][]byte{cosignAttestationTagFor(testFetchDigest): manifest},
		blobs:     map[string][]byte{},
	})
	t.Cleanup(server.Close)

	fetcher := attestation.NewOCIFetcherWithVerifier(
		func(context.Context, []byte, *attestation.FetchOptions) ([]byte, error) {
			return []byte(slsaStatementJSON), nil
		},
	)

	_, err := fetcher.Fetch(
		context.Background(),
		strings.TrimPrefix(server.URL, "http://")+"/app:v1",
		&attestation.FetchOptions{Digest: testFetchDigest},
	)
	if !errors.Is(err, attestation.ErrVerificationFailed) ||
		!errors.Is(err, attestation.ErrIncompleteAttestationSet) {
		t.Fatalf("Fetch() error = %v, want an incomplete attestation set", err)
	}
}

// TestNotationSignaturesSurviveFailedCosignTag checks that Notation
// signatures are returned with the error when the cosign attestation tag
// fails verification, so an untrusted Notation signature is still evaluated
// instead of being treated as missing.
func TestNotationSignaturesSurviveFailedCosignTag(t *testing.T) {
	t.Parallel()

	notationDesc := notationDescriptor("signature")

	fetcher := attestation.NewTestOCIFetcherFull(
		func(context.Context, []byte, *attestation.FetchOptions) ([]byte, error) {
			return nil, errUntrustedBundle
		},
		func(ref name.Reference, _ ...remote.Option) (ociV1.Image, error) {
			if strings.HasSuffix(ref.Identifier(), ".att") {
				return fakeImageWithPayload([]byte(sigstoreBundleJSON)), nil
			}

			return junkNotationImage(), nil
		},
		func(name.Digest, ...remote.Option) (ociV1.ImageIndex, error) {
			return &fakeImageIndex{manifests: []ociV1.Descriptor{notationDesc}, err: nil}, nil
		},
	)

	atts, err := fetcher.Fetch(
		context.Background(), testFetchImageRef, &attestation.FetchOptions{Digest: testFetchDigest},
	)
	if !errors.Is(err, attestation.ErrVerificationFailed) ||
		errors.Is(err, attestation.ErrIncompleteAttestationSet) {
		t.Fatalf("Fetch() error = %v, want a complete set that failed verification", err)
	}

	if len(atts) != 1 || atts[0].SignatureType != attestation.SignatureTypeNotation {
		t.Fatalf("Fetch() attestations = %+v, want the Notation signature", atts)
	}
}

// TestIsManifestPathMatchesEndpointOnly checks that only manifest and
// referrers endpoints are bounded as such, also for repositories whose names
// contain "manifests" or "referrers", whose blobs must not get the manifest
// size limit or be charged twice.
func TestIsManifestPathMatchesEndpointOnly(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path string
		want bool
	}{
		{"/v2/app/manifests/v1", true},
		{"/v2/app/manifests/" + testFetchDigest, true},
		{"/v2/app/referrers/" + testFetchDigest, true},
		{"/v2/org/referrers/app/manifests/" + testFetchDigest, true},
		{"/v2/org/manifests/app/referrers/" + testFetchDigest, true},
		{"/v2/org/referrers/app/blobs/" + testFetchDigest, false},
		{"/v2/org/manifests/app/blobs/" + testFetchDigest, false},
		{"/v2/referrers/blobs/" + testFetchDigest, false},
		{"/v2/manifests/blobs/uploads/", false},
		{"/v2/app/blobs/" + testFetchDigest, false},
		{"/v2/manifests/" + testFetchDigest, false},
		{"/v2/app/manifests/", false},
		{"/v2//manifests/" + testFetchDigest, false},
		{"/v2/", false},
		{"/token", false},
		{"/other/app/manifests/v1", false},
	}

	for _, test := range tests {
		if got := attestation.ExportIsManifestPath(test.path); got != test.want {
			t.Errorf("isManifestPath(%q) = %v, want %v", test.path, got, test.want)
		}
	}
}

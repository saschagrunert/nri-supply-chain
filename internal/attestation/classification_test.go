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
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	ociV1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
)

var errNoChildWithPlatform = errors.New("no child with platform linux/amd64 in index")

// referrerFetcher serves referrer images by digest and returns errs for the
// digests listed there.
func referrerFetcher(
	images map[string]ociV1.Image, errs map[string]error, manifests []ociV1.Descriptor,
) *attestation.OCIFetcher {
	return attestation.NewTestOCIFetcherSigned(
		func(ctx context.Context, data []byte, opts *attestation.FetchOptions) (*attestation.VerifiedBundle, error) {
			return attestation.ExportVerifyBundle(ctx, data, opts, nil)
		},
		func(ref name.Reference, _ ...remote.Option) (ociV1.Image, error) {
			key := ref.Identifier()
			if err, ok := errs[key]; ok {
				return nil, err
			}

			if img, ok := images[key]; ok {
				return img, nil
			}

			return nil, &transport.Error{StatusCode: http.StatusNotFound}
		},
		func(_ name.Digest, _ ...remote.Option) (ociV1.ImageIndex, error) {
			return &fakeImageIndex{manifests: manifests, err: nil}, nil
		},
	)
}

func bundleReferrer(idx int) ociV1.Descriptor {
	return ociV1.Descriptor{
		ArtifactType: attestation.ExportBundleMediaType,
		Digest:       referrerDigest(idx),
	}
}

func TestFetchMalformedReferrerKeepsVerificationFailure(t *testing.T) {
	t.Parallel()

	trusted := testutil.NewKeySigner(t)
	attacker := testutil.NewKeySigner(t)
	forged := bundleReferrer(1)
	indexReferrer := bundleReferrer(2)

	fetcher := referrerFetcher(
		map[string]ociV1.Image{
			forged.Digest.String(): fakeImageWithPayload(
				attacker.SignBundle(t, signerStatement(t)),
			),
		},
		map[string]error{indexReferrer.Digest.String(): errNoChildWithPlatform},
		[]ociV1.Descriptor{forged, indexReferrer},
	)

	_, err := fetcher.Fetch(t.Context(), signerImageRef, &attestation.FetchOptions{
		TrustedKeys: []attestation.TrustedKeyRef{{Path: trusted.PublicKeyPath}},
		Digest:      signerTestDigest,
	})
	testutil.AssertErrorIs(t, err, attestation.ErrVerificationFailed)
}

func TestFetchTransportErrorWinsOverVerificationFailure(t *testing.T) {
	t.Parallel()

	trusted := testutil.NewKeySigner(t)
	attacker := testutil.NewKeySigner(t)
	forged := bundleReferrer(1)
	unreachable := bundleReferrer(2)

	fetcher := referrerFetcher(
		map[string]ociV1.Image{
			forged.Digest.String(): fakeImageWithPayload(
				attacker.SignBundle(t, signerStatement(t)),
			),
		},
		map[string]error{
			unreachable.Digest.String(): &transport.Error{
				StatusCode: http.StatusServiceUnavailable,
			},
		},
		[]ociV1.Descriptor{forged, unreachable},
	)

	// The unreachable referrer might be the trusted attestation, so the
	// attestation set is unknown and must not be evaluated as unverified.
	_, err := fetcher.Fetch(t.Context(), signerImageRef, &attestation.FetchOptions{
		TrustedKeys: []attestation.TrustedKeyRef{{Path: trusted.PublicKeyPath}},
		Digest:      signerTestDigest,
	})
	testutil.AssertError(t, err)

	if errors.Is(err, attestation.ErrVerificationFailed) {
		t.Fatalf("a transport error must fail the fetch: %v", err)
	}

	if _, ok := errors.AsType[*transport.Error](err); !ok {
		t.Errorf("expected the transport error, got: %v", err)
	}
}

func TestFetchContentErrorWithoutSignedMaterialIsVerificationFailure(t *testing.T) {
	t.Parallel()

	indexReferrer := bundleReferrer(1)

	fetcher := referrerFetcher(
		nil,
		map[string]error{indexReferrer.Digest.String(): errNoChildWithPlatform},
		[]ociV1.Descriptor{indexReferrer},
	)

	_, err := fetcher.Fetch(t.Context(), signerImageRef, &attestation.FetchOptions{
		Digest: signerTestDigest,
	})
	testutil.AssertErrorIs(t, err, attestation.ErrVerificationFailed)
}

func TestFetchCorruptCosignTagIsVerificationFailure(t *testing.T) {
	t.Parallel()

	tag := strings.Replace(signerTestDigest, ":", "-", 1) + ".att"

	fetcher := referrerFetcher(nil, map[string]error{tag: errNoChildWithPlatform}, nil)

	_, err := fetcher.Fetch(t.Context(), signerImageRef, &attestation.FetchOptions{
		Digest: signerTestDigest,
	})
	testutil.AssertErrorIs(t, err, attestation.ErrVerificationFailed)
}

func TestFetchCosignTagTransportErrorIsNotVerificationFailure(t *testing.T) {
	t.Parallel()

	tag := strings.Replace(signerTestDigest, ":", "-", 1) + ".att"

	fetcher := referrerFetcher(
		nil,
		map[string]error{tag: &transport.Error{StatusCode: http.StatusServiceUnavailable}},
		nil,
	)

	_, err := fetcher.Fetch(t.Context(), signerImageRef, &attestation.FetchOptions{
		Digest: signerTestDigest,
	})
	testutil.AssertError(t, err)

	if errors.Is(err, attestation.ErrVerificationFailed) {
		t.Fatalf("transport error must not wrap ErrVerificationFailed: %v", err)
	}
}

func TestFetchReferrerBudgetExceededDenies(t *testing.T) {
	t.Parallel()

	signer := testutil.NewKeySigner(t)
	bundleJSON := signer.SignBundle(t, signerStatement(t))
	images := make(map[string]ociV1.Image)
	manifests := make([]ociV1.Descriptor, 0, attestation.ExportMaxReferrers()+1)

	// Distinct manifests that all carry the same, validly signed bundle.
	for idx := range attestation.ExportMaxReferrers() + 1 {
		desc := bundleReferrer(idx + 1)
		images[desc.Digest.String()] = fakeImageWithPayload(bundleJSON)
		manifests = append(manifests, desc)
	}

	fetcher := referrerFetcher(images, nil, manifests)

	atts, err := fetcher.Fetch(t.Context(), signerImageRef, &attestation.FetchOptions{
		TrustedKeys: []attestation.TrustedKeyRef{{Path: signer.PublicKeyPath}},
		Digest:      signerTestDigest,
	})
	testutil.AssertErrorIs(t, err, attestation.ErrVerificationFailed)
	testutil.AssertErrorIs(t, err, attestation.ErrIncompleteAttestationSet)
	testutil.AssertEqual(t, 0, len(atts))
}

func TestFetchDuplicateReferrersAreDeduplicated(t *testing.T) {
	t.Parallel()

	signer := testutil.NewKeySigner(t)
	bundleJSON := signer.SignBundle(t, signerStatement(t))
	desc := bundleReferrer(1)
	otherManifest := bundleReferrer(2)
	manifests := make([]ociV1.Descriptor, 0, attestation.ExportMaxReferrers()+2)

	// The same referrer listed more often than the budget allows.
	for range attestation.ExportMaxReferrers() + 1 {
		manifests = append(manifests, desc)
	}

	// A second manifest carrying an identical bundle blob.
	manifests = append(manifests, otherManifest)

	fetcher := referrerFetcher(
		map[string]ociV1.Image{
			desc.Digest.String():          fakeImageWithPayload(bundleJSON),
			otherManifest.Digest.String(): fakeImageWithPayload(bytes.Clone(bundleJSON)),
		},
		nil,
		manifests,
	)

	atts, err := fetcher.Fetch(t.Context(), signerImageRef, &attestation.FetchOptions{
		TrustedKeys: []attestation.TrustedKeyRef{{Path: signer.PublicKeyPath}},
		Digest:      signerTestDigest,
	})
	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, 1, len(atts))
}

func TestFetchOversizedAttestationDenies(t *testing.T) {
	t.Parallel()

	signer := testutil.NewKeySigner(t)
	valid := bundleReferrer(1)
	oversized := bundleReferrer(2)

	fetcher := referrerFetcher(
		map[string]ociV1.Image{
			valid.Digest.String(): fakeImageWithPayload(signer.SignBundle(t, signerStatement(t))),
			oversized.Digest.String(): fakeImageWithPayload(
				bytes.Repeat([]byte("x"), 2048),
			),
		},
		nil,
		[]ociV1.Descriptor{valid, oversized},
	)
	fetcher.SetMaxAttestationSize(1024)

	_, err := fetcher.Fetch(t.Context(), signerImageRef, &attestation.FetchOptions{
		TrustedKeys: []attestation.TrustedKeyRef{{Path: signer.PublicKeyPath}},
		Digest:      signerTestDigest,
	})
	testutil.AssertErrorIs(t, err, attestation.ErrVerificationFailed)
	testutil.AssertErrorIs(t, err, attestation.ErrIncompleteAttestationSet)
}

func TestFetchOversizedUnrelatedReferrerIsIgnored(t *testing.T) {
	t.Parallel()

	signer := testutil.NewKeySigner(t)
	valid := bundleReferrer(1)
	unrelated := ociV1.Descriptor{
		ArtifactType: "application/vnd.example.unrelated",
		Digest:       referrerDigest(2),
		Size:         attestation.ExportMaxReferrerManifestSize + 1,
	}

	fetcher := referrerFetcher(
		map[string]ociV1.Image{
			valid.Digest.String(): fakeImageWithPayload(signer.SignBundle(t, signerStatement(t))),
		},
		nil,
		[]ociV1.Descriptor{valid, unrelated},
	)

	atts, err := fetcher.Fetch(t.Context(), signerImageRef, &attestation.FetchOptions{
		TrustedKeys: []attestation.TrustedKeyRef{{Path: signer.PublicKeyPath}},
		Digest:      signerTestDigest,
	})
	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, 1, len(atts))
}

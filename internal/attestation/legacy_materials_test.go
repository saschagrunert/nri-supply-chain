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
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	ociV1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
)

func TestLegacyLayerWithoutVerificationMaterial(t *testing.T) {
	t.Parallel()

	signer := testutil.NewKeySigner(t)
	layerData, annotations := testutil.LegacyCosignLayer(
		t,
		signer.SignBundle(t, signerStatement(t)),
	)

	converted, err := attestation.ExportLegacyLayerToBundles(layerData, annotations, nil)
	testutil.AssertErrorIs(t, err, attestation.ErrNoLegacyVerificationMaterial)
	testutil.AssertEqual(t, 0, len(converted))
}

//nolint:paralleltest // mutates slog.SetDefault
func TestCosignTagWithoutVerificationMaterialLogsReason(t *testing.T) {
	var buf bytes.Buffer

	prev := slog.Default()

	slog.SetDefault(
		slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})),
	)
	t.Cleanup(func() { slog.SetDefault(prev) })

	signer := testutil.NewKeySigner(t)
	ref, err := name.NewDigest(signerLegacyTagRef + "@" + signerTestDigest)
	testutil.AssertNoError(t, err)

	img := legacyCosignImage(t, signer.SignBundle(t, signerStatement(t)))
	fetcher := signedFetcher(map[string]ociV1.Image{
		strings.Replace(signerTestDigest, ":", "-", 1) + ".att": img,
	}, nil)

	_, err = fetcher.CosignTagFallback(
		t.Context(),
		ref,
		signerTestDigest,
		nil,
		&attestation.FetchOptions{Digest: signerTestDigest},
	)
	testutil.AssertErrorIs(t, err, attestation.ErrVerificationFailed)

	output := buf.String()

	if strings.Contains(output, "error=<nil>") {
		t.Errorf("expected every verification failure log to carry an error, got: %s", output)
	}

	if !strings.Contains(output, "no certificate annotation and no trusted keys") {
		t.Errorf("expected the missing verification material to be logged, got: %s", output)
	}
}

// TestCosignTagLegacyKeySignedLayerWithUnreadableKey checks that a legacy
// key-signed layer whose trusted keys cannot be loaded is reported as
// unavailable trust material, so the fetch failure policy applies, instead of
// a verification failure that is ignored like absent attestations.
func TestCosignTagLegacyKeySignedLayerWithUnreadableKey(t *testing.T) {
	t.Parallel()

	signer := testutil.NewKeySigner(t)

	img := legacyCosignImage(t, signer.SignBundle(t, signerStatement(t)))
	fetcher := signedFetcher(map[string]ociV1.Image{
		strings.Replace(signerTestDigest, ":", "-", 1) + ".att": img,
	}, nil)

	_, err := fetcher.Fetch(t.Context(), signerImageRef, &attestation.FetchOptions{
		TrustedKeys: []attestation.TrustedKeyRef{{Path: signer.PublicKeyPath + "-missing"}},
		Digest:      signerTestDigest,
	})
	testutil.AssertErrorIs(t, err, attestation.ErrTrustMaterialUnavailable)

	if errors.Is(err, attestation.ErrVerificationFailed) {
		t.Fatalf("unreadable key must not wrap ErrVerificationFailed: %v", err)
	}
}

// TestCosignTagUnreadableKeyDoesNotHideVerifiedLayer checks that a legacy
// layer without a certificate, which cannot be checked while no trusted key
// file loads, does not hide a verified layer of the same tag behind the fetch
// failure policy: anyone with push access can add such a layer.
func TestCosignTagUnreadableKeyDoesNotHideVerifiedLayer(t *testing.T) {
	t.Parallel()

	virtual := testutil.NewVirtualSigstore(t)
	trustedRoot := testutil.VirtualTrustedRoot(t, virtual)
	keylessData, keylessAnnotations := testutil.LegacyCosignLayer(t, testutil.KeylessBundle(
		t, virtual, signerIdentity, signerIssuer, signerStatement(t),
	))

	signer := testutil.NewKeySigner(t)
	keyData, keyAnnotations := testutil.LegacyCosignLayer(
		t, signer.SignBundle(t, signerStatement(t)),
	)

	ref, err := name.NewDigest(signerLegacyTagRef + "@" + signerTestDigest)
	testutil.AssertNoError(t, err)

	missingKey := attestation.TrustedKeyRef{Path: signer.PublicKeyPath + "-missing"}
	loadableKey := attestation.TrustedKeyRef{Path: signer.PublicKeyPath}

	for _, tc := range []struct {
		name     string
		layers   []legacyLayer
		keys     []attestation.TrustedKeyRef
		verified bool
	}{
		{
			name: "key-signed layer first",
			layers: []legacyLayer{
				{keyData, keyAnnotations}, {keylessData, keylessAnnotations},
			},
			keys:     []attestation.TrustedKeyRef{missingKey},
			verified: true,
		},
		{
			name: "key-signed layer last",
			layers: []legacyLayer{
				{keylessData, keylessAnnotations}, {keyData, keyAnnotations},
			},
			keys:     []attestation.TrustedKeyRef{missingKey},
			verified: true,
		},
		{
			// One key loads, so the layer is tried against it, but the
			// key material cannot be built while another key is missing.
			name: "one of two keys unreadable",
			layers: []legacyLayer{
				{keyData, keyAnnotations}, {keylessData, keylessAnnotations},
			},
			keys:     []attestation.TrustedKeyRef{loadableKey, missingKey},
			verified: true,
		},
		{
			name:     "only key-signed layer",
			layers:   []legacyLayer{{keyData, keyAnnotations}},
			keys:     []attestation.TrustedKeyRef{missingKey},
			verified: false,
		},
		{
			name:     "only key-signed layer, one of two keys unreadable",
			layers:   []legacyLayer{{keyData, keyAnnotations}},
			keys:     []attestation.TrustedKeyRef{loadableKey, missingKey},
			verified: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			img := legacyCosignLayersImage(t, tc.layers)
			fetcher := attestation.NewTestOCIFetcherSigned(
				func(
					ctx context.Context, data []byte, fetchOpts *attestation.FetchOptions,
				) (*attestation.VerifiedBundle, error) {
					return attestation.ExportVerifyBundleWithRoots(
						ctx, data, fetchOpts, []*root.TrustedRoot{trustedRoot}, nil, true,
					)
				},
				func(ref name.Reference, _ ...remote.Option) (ociV1.Image, error) {
					if ref.Identifier() == strings.Replace(signerTestDigest, ":", "-", 1)+".att" {
						return img, nil
					}

					return nil, &transport.Error{StatusCode: http.StatusNotFound}
				},
				nil,
			)

			opts := &attestation.FetchOptions{
				TrustedKeys:    tc.keys,
				TrustedIssuers: []string{signerIssuer},
				SANPatterns:    []string{signerIdentity},
				Digest:         signerTestDigest,
			}

			atts, err := fetcher.CosignTagFallback(t.Context(), ref, signerTestDigest, nil, opts)

			if !tc.verified {
				// Nothing verified: the trust material to decide is
				// missing, so the fetch failure policy applies.
				testutil.AssertErrorIs(t, err, attestation.ErrTrustMaterialUnavailable)

				if errors.Is(err, attestation.ErrVerificationFailed) {
					t.Fatalf("unreadable key must not wrap ErrVerificationFailed: %v", err)
				}

				return
			}

			testutil.AssertNoError(t, err)
			testutil.AssertEqual(t, 1, len(atts))
			testutil.AssertEqual(t, signerIdentity, atts[0].Signer.SAN)
		})
	}
}

type legacyLayer struct {
	data        []byte
	annotations map[string]string
}

func legacyCosignLayersImage(t *testing.T, layers []legacyLayer) ociV1.Image {
	t.Helper()

	img := empty.Image

	for _, layer := range layers {
		var err error

		img, err = mutate.Append(img, mutate.Addendum{
			Layer: static.NewLayer(
				layer.data, types.MediaType("application/vnd.dsse.envelope.v1+json"),
			),
			History:     ociV1.History{},
			Annotations: layer.annotations,
			URLs:        nil,
			MediaType:   "",
		})
		if err != nil {
			t.Fatalf("building legacy cosign image: %v", err)
		}
	}

	return img
}

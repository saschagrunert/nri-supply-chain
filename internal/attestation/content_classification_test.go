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
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	ociV1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/registry"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
)

const (
	slowReferrerDelay = 500 * time.Millisecond
	junkLayerSize     = 4096
)

func cosignAttestationTagFor(digest string) string {
	return strings.Replace(digest, ":", "-", 1) + ".att"
}

func TestFetchTruncatedGzipCosignLayerIsVerificationFailure(t *testing.T) {
	t.Parallel()

	// Two bytes of gzip magic: registries store any layer content, so anyone
	// with push access can publish this.
	fetcher := referrerFetcher(
		map[string]ociV1.Image{
			cosignAttestationTagFor(signerTestDigest): fakeImageWithPayload([]byte{0x1f, 0x8b}),
		},
		nil,
		nil,
	)

	_, err := fetcher.Fetch(t.Context(), signerImageRef, &attestation.FetchOptions{
		Digest: signerTestDigest,
	})
	testutil.AssertErrorIs(t, err, attestation.ErrVerificationFailed)

	if registry.IsConnectionError(err) {
		t.Fatalf("truncated layer content must not look like a connection error: %v", err)
	}
}

func TestFetchTruncatedGzipReferrerLayerIsVerificationFailure(t *testing.T) {
	t.Parallel()

	junk := bundleReferrer(1)

	fetcher := referrerFetcher(
		map[string]ociV1.Image{junk.Digest.String(): fakeImageWithPayload([]byte{0x1f, 0x8b})},
		nil,
		[]ociV1.Descriptor{junk},
	)

	_, err := fetcher.Fetch(t.Context(), signerImageRef, &attestation.FetchOptions{
		Digest: signerTestDigest,
	})
	testutil.AssertErrorIs(t, err, attestation.ErrVerificationFailed)

	if registry.IsConnectionError(err) {
		t.Fatalf("truncated layer content must not look like a connection error: %v", err)
	}
}

func TestFetchTruncatedManifestIsVerificationFailure(t *testing.T) {
	t.Parallel()

	junk := bundleReferrer(1)

	// json.Decoder reports a truncated manifest as io.ErrUnexpectedEOF.
	_, parseErr := ociV1.ParseManifest(bytes.NewReader([]byte(`{"schemaVersion": 2, "layers": [`)))
	if parseErr == nil {
		t.Fatal("expected a parse error for the truncated manifest")
	}

	fetcher := referrerFetcher(
		nil,
		map[string]error{junk.Digest.String(): parseErr},
		[]ociV1.Descriptor{junk},
	)

	_, err := fetcher.Fetch(t.Context(), signerImageRef, &attestation.FetchOptions{
		Digest: signerTestDigest,
	})
	testutil.AssertErrorIs(t, err, attestation.ErrVerificationFailed)
}

func TestFetchReferrerAuthErrorsAfterListingAreVerificationFailures(t *testing.T) {
	t.Parallel()

	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()

			blocked := bundleReferrer(1)

			fetcher := referrerFetcher(
				nil,
				map[string]error{blocked.Digest.String(): &transport.Error{StatusCode: status}},
				[]ociV1.Descriptor{blocked},
			)

			_, err := fetcher.Fetch(t.Context(), signerImageRef, &attestation.FetchOptions{
				Digest: signerTestDigest,
			})
			testutil.AssertErrorIs(t, err, attestation.ErrVerificationFailed)
		})
	}
}

func TestFetchReferrersListingAuthErrorIsTransportFailure(t *testing.T) {
	t.Parallel()

	fetcher := attestation.NewTestOCIFetcherSigned(
		func(ctx context.Context, data []byte, opts *attestation.FetchOptions) (*attestation.VerifiedBundle, error) {
			return attestation.ExportVerifyBundle(ctx, data, opts, nil)
		},
		func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
			return nil, &transport.Error{StatusCode: http.StatusNotFound}
		},
		func(_ name.Digest, _ ...remote.Option) (ociV1.ImageIndex, error) {
			return nil, &transport.Error{StatusCode: http.StatusUnauthorized}
		},
	)

	_, err := fetcher.Fetch(t.Context(), signerImageRef, &attestation.FetchOptions{
		Digest: signerTestDigest,
	})
	testutil.AssertError(t, err)

	if errors.Is(err, attestation.ErrVerificationFailed) {
		t.Fatalf("an unauthorized referrers listing must stay a fetch failure: %v", err)
	}
}

func TestFetchInterruptionWinsOverVerificationFailure(t *testing.T) {
	t.Parallel()

	trusted := testutil.NewKeySigner(t)
	attacker := testutil.NewKeySigner(t)
	forged := bundleReferrer(1)
	slow := bundleReferrer(2)
	forgedImage := fakeImageWithPayload(attacker.SignBundle(t, signerStatement(t)))

	fetcher := attestation.NewTestOCIFetcherSigned(
		func(ctx context.Context, data []byte, opts *attestation.FetchOptions) (*attestation.VerifiedBundle, error) {
			return attestation.ExportVerifyBundle(ctx, data, opts, nil)
		},
		func(ref name.Reference, _ ...remote.Option) (ociV1.Image, error) {
			if ref.Identifier() == forged.Digest.String() {
				return forgedImage, nil
			}

			// The slow referrer only answers after the fetch deadline.
			time.Sleep(slowReferrerDelay)

			return nil, context.DeadlineExceeded
		},
		func(_ name.Digest, _ ...remote.Option) (ociV1.ImageIndex, error) {
			return &fakeImageIndex{manifests: []ociV1.Descriptor{forged, slow}, err: nil}, nil
		},
	)

	_, err := fetcher.Fetch(t.Context(), signerImageRef, &attestation.FetchOptions{
		TrustedKeys: []attestation.TrustedKeyRef{{Path: trusted.PublicKeyPath}},
		Digest:      signerTestDigest,
		Timeout:     200 * time.Millisecond,
	})
	testutil.AssertErrorIs(t, err, context.DeadlineExceeded)

	if errors.Is(err, attestation.ErrVerificationFailed) {
		t.Fatalf("an interrupted fetch must not be a verification failure: %v", err)
	}
}

func TestFetchJunkDownloadsCountTowardsDownloadLimit(t *testing.T) {
	t.Parallel()

	signer := testutil.NewKeySigner(t)
	bundleJSON := signer.SignBundle(t, signerStatement(t))
	valid := bundleReferrer(1)
	junkFirst := bundleReferrer(2)
	junkSecond := bundleReferrer(3)

	fetcher := referrerFetcher(
		map[string]ociV1.Image{
			valid.Digest.String(): fakeImageWithPayload(bundleJSON),
			junkFirst.Digest.String(): fakeImageWithPayload(
				bytes.Repeat([]byte("j"), junkLayerSize),
			),
			junkSecond.Digest.String(): fakeImageWithPayload(
				bytes.Repeat([]byte("k"), junkLayerSize),
			),
		},
		nil,
		[]ociV1.Descriptor{valid, junkFirst, junkSecond},
	)
	fetcher.ExportSetDownloadLimit(int64(len(bundleJSON)) + junkLayerSize)

	atts, err := fetcher.Fetch(t.Context(), signerImageRef, &attestation.FetchOptions{
		TrustedKeys: []attestation.TrustedKeyRef{{Path: signer.PublicKeyPath}},
		Digest:      signerTestDigest,
	})
	testutil.AssertErrorIs(t, err, attestation.ErrVerificationFailed)
	testutil.AssertEqual(t, 0, len(atts))
}

func TestFetchWithinDownloadLimitSucceeds(t *testing.T) {
	t.Parallel()

	signer := testutil.NewKeySigner(t)
	bundleJSON := signer.SignBundle(t, signerStatement(t))
	valid := bundleReferrer(1)

	fetcher := referrerFetcher(
		map[string]ociV1.Image{valid.Digest.String(): fakeImageWithPayload(bundleJSON)},
		nil,
		[]ociV1.Descriptor{valid},
	)
	fetcher.ExportSetDownloadLimit(int64(len(bundleJSON)))

	atts, err := fetcher.Fetch(t.Context(), signerImageRef, &attestation.FetchOptions{
		TrustedKeys: []attestation.TrustedKeyRef{{Path: signer.PublicKeyPath}},
		Digest:      signerTestDigest,
	})
	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, 1, len(atts))
}

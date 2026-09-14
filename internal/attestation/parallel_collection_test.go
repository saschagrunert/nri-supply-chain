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
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	ociV1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
)

const (
	collectBarrierTimeout = 2 * time.Second
	// collectReferrerKinds is the number of referrer kinds in the fixture:
	// one Sigstore bundle, one Notation signature, and one baseline SBOM.
	collectReferrerKinds int32 = 3
)

// collectionFixture is a referrer set with one Sigstore bundle, one Notation
// signature, and one baseline SBOM, served by an image fetch function that
// can be wrapped to observe or delay fetches.
type collectionFixture struct {
	signer    *testutil.KeySigner
	manifests []ociV1.Descriptor
	images    map[string]ociV1.Image
}

func newCollectionFixture(t *testing.T) *collectionFixture {
	t.Helper()

	signer := testutil.NewKeySigner(t)
	bundleDesc := ociV1.Descriptor{
		ArtifactType: attestation.ExportBundleMediaType,
		Digest:       referrerDigest(1),
	}
	notationDesc := ociV1.Descriptor{
		ArtifactType: attestation.NotationSignatureMediaType,
		Digest:       referrerDigest(2),
	}
	baselineDesc := ociV1.Descriptor{
		ArtifactType: attestation.BaselineSBOMArtifactType,
		Digest:       referrerDigest(3),
	}

	baseline := signer.SignBundle(t, testutil.Statement(
		t, signerTestDigest, attestation.PredicateBaselineSBOM,
		map[string]any{"spdxVersion": "SPDX-2.3", "packages": []any{}},
	))

	return &collectionFixture{
		signer:    signer,
		manifests: []ociV1.Descriptor{bundleDesc, notationDesc, baselineDesc},
		images: map[string]ociV1.Image{
			bundleDesc.Digest.String(): fakeImageWithPayload(
				signer.SignBundle(t, signerStatement(t)),
			),
			notationDesc.Digest.String(): fakeNotationImage(
				[]byte(`{"signature":"valid"}`), types.MediaType(testNotationLayerMediaType), nil,
			),
			baselineDesc.Digest.String(): fakeImageWithPayload(baseline),
		},
	}
}

func (c *collectionFixture) fetcher(fetch attestation.ImageFetchFunc) *attestation.OCIFetcher {
	return attestation.NewTestOCIFetcherSigned(
		func(ctx context.Context, data []byte, opts *attestation.FetchOptions) (*attestation.VerifiedBundle, error) {
			return attestation.ExportVerifyBundle(ctx, data, opts, nil)
		},
		fetch,
		func(_ name.Digest, _ ...remote.Option) (ociV1.ImageIndex, error) {
			return &fakeImageIndex{manifests: c.manifests, err: nil}, nil
		},
	)
}

func (c *collectionFixture) serve(ref name.Reference, _ ...remote.Option) (ociV1.Image, error) {
	if img, ok := c.images[ref.Identifier()]; ok {
		return img, nil
	}

	return nil, &transport.Error{StatusCode: http.StatusNotFound}
}

func (c *collectionFixture) options() *attestation.FetchOptions {
	return &attestation.FetchOptions{
		TrustedKeys: []attestation.TrustedKeyRef{{Path: c.signer.PublicKeyPath}},
		Digest:      signerTestDigest,
	}
}

func TestFetchCollectsReferrerKindsConcurrently(t *testing.T) {
	t.Parallel()

	fixture := newCollectionFixture(t)

	var (
		inFlight    atomic.Int32
		maxInFlight atomic.Int32
		allStarted  = make(chan struct{})
		startedOnce sync.Once
	)

	// Every referrer fetch waits until the fetches of all three referrer
	// kinds are in flight at the same time. Collected one kind after
	// another, each fetch would wait for the barrier timeout instead.
	fetcher := fixture.fetcher(
		func(ref name.Reference, opts ...remote.Option) (ociV1.Image, error) {
			current := inFlight.Add(1)
			defer inFlight.Add(-1)

			for {
				seen := maxInFlight.Load()
				if current <= seen || maxInFlight.CompareAndSwap(seen, current) {
					break
				}
			}

			if current == collectReferrerKinds {
				startedOnce.Do(func() { close(allStarted) })
			}

			select {
			case <-allStarted:
			case <-time.After(collectBarrierTimeout):
			}

			return fixture.serve(ref, opts...)
		},
	)

	start := time.Now()

	atts, err := fetcher.Fetch(t.Context(), signerImageRef, fixture.options())
	testutil.AssertNoError(t, err)

	if got := maxInFlight.Load(); got != collectReferrerKinds {
		t.Errorf("at most %d referrer fetches ran at once (after %s), want %d",
			got, time.Since(start), collectReferrerKinds)
	}

	predicateTypes := make([]string, 0, len(atts))
	for idx := range atts {
		predicateTypes = append(predicateTypes, atts[idx].PredicateType)
	}

	want := []string{
		attestation.PredicateSLSAProvenanceV1,
		attestation.NotationSignatureMediaType,
		attestation.PredicateBaselineSBOM,
	}

	if strings.Join(predicateTypes, ",") != strings.Join(want, ",") {
		t.Errorf("attestation order = %v, want %v", predicateTypes, want)
	}
}

func TestConcurrentCollectionMatchesSerialClassification(t *testing.T) {
	t.Parallel()

	ref, err := name.NewDigest(signerImageRef)
	testutil.AssertNoError(t, err)

	attacker := testutil.NewKeySigner(t)

	tests := []struct {
		name   string
		mutate func(t *testing.T, fixture *collectionFixture) attestation.ImageFetchFunc
		want   collectionClass
	}{
		{
			name: "all verify",
			mutate: func(_ *testing.T, fixture *collectionFixture) attestation.ImageFetchFunc {
				return fixture.serve
			},
			want: collectionClass{verificationFailed: false, incomplete: false, transport: false},
		},
		{
			name: "untrusted bundle and baseline with notation transport failure",
			mutate: func(t *testing.T, fixture *collectionFixture) attestation.ImageFetchFunc {
				t.Helper()

				untrusted := fakeImageWithPayload(attacker.SignBundle(t, signerStatement(t)))
				fixture.images[referrerDigest(1).String()] = untrusted
				fixture.images[referrerDigest(3).String()] = untrusted

				return failing(fixture, referrerDigest(2), http.StatusNotImplemented)
			},
			want: collectionClass{verificationFailed: false, incomplete: false, transport: true},
		},
		{
			name: "verified bundle with notation transport failure",
			mutate: func(_ *testing.T, fixture *collectionFixture) attestation.ImageFetchFunc {
				return failing(fixture, referrerDigest(2), http.StatusNotImplemented)
			},
			want: collectionClass{verificationFailed: false, incomplete: false, transport: true},
		},
		{
			name: "untrusted bundle with verified notation",
			mutate: func(t *testing.T, fixture *collectionFixture) attestation.ImageFetchFunc {
				t.Helper()

				fixture.images[referrerDigest(1).String()] = fakeImageWithPayload(
					attacker.SignBundle(t, signerStatement(t)),
				)

				return fixture.serve
			},
			want: collectionClass{verificationFailed: false, incomplete: false, transport: false},
		},
		{
			name: "oversized notation envelope",
			mutate: func(_ *testing.T, fixture *collectionFixture) attestation.ImageFetchFunc {
				fixture.images[referrerDigest(2).String()] = fakeNotationImage(
					[]byte(`{"signature":"`+strings.Repeat("x", 4096)+`"}`),
					types.MediaType(testNotationLayerMediaType), nil,
				)

				return fixture.serve
			},
			want: collectionClass{verificationFailed: true, incomplete: true, transport: false},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fixture := newCollectionFixture(t)
			fetcher := fixture.fetcher(test.mutate(t, fixture))
			fetcher.SetMaxAttestationSize(2048)

			serialAtts, serialErr := fetcher.CollectSelectionSerial(
				t.Context(), fixture.manifests, ref, signerTestDigest, fixture.options(),
			)
			parallelAtts, parallelErr := fetcher.CollectSelectionParallel(
				t.Context(), fixture.manifests, ref, signerTestDigest, fixture.options(),
			)

			assertSameClassification(t, serialErr, parallelErr)

			if got := classify(parallelErr); got != test.want {
				t.Errorf("classification = %+v (%v), want %+v", got, parallelErr, test.want)
			}

			testutil.AssertEqual(t, len(serialAtts), len(parallelAtts))

			for idx := range serialAtts {
				testutil.AssertEqual(
					t,
					serialAtts[idx].PredicateType,
					parallelAtts[idx].PredicateType,
				)
			}
		})
	}
}

// failing serves the fixture but fails the fetch of digest with status.
func failing(
	fixture *collectionFixture, digest ociV1.Hash, status int,
) attestation.ImageFetchFunc {
	return func(ref name.Reference, opts ...remote.Option) (ociV1.Image, error) {
		if ref.Identifier() == digest.String() {
			return nil, &transport.Error{StatusCode: status}
		}

		return fixture.serve(ref, opts...)
	}
}

type collectionClass struct {
	verificationFailed bool
	incomplete         bool
	transport          bool
}

func classify(err error) collectionClass {
	var transportErr *transport.Error

	return collectionClass{
		verificationFailed: errors.Is(err, attestation.ErrVerificationFailed),
		incomplete:         errors.Is(err, attestation.ErrIncompleteAttestationSet),
		transport:          errors.As(err, &transportErr),
	}
}

func assertSameClassification(t *testing.T, serial, parallel error) {
	t.Helper()

	if (serial == nil) != (parallel == nil) {
		t.Fatalf("serial error %v, concurrent error %v", serial, parallel)
	}

	for _, sentinel := range []error{
		attestation.ErrVerificationFailed,
		attestation.ErrIncompleteAttestationSet,
		attestation.ErrTrustMaterialUnavailable,
	} {
		if errors.Is(serial, sentinel) != errors.Is(parallel, sentinel) {
			t.Errorf("classification differs for %v: serial %v, concurrent %v",
				sentinel, serial, parallel)
		}
	}

	var serialTransport, parallelTransport *transport.Error

	if errors.As(serial, &serialTransport) != errors.As(parallel, &parallelTransport) {
		t.Errorf("transport classification differs: serial %v, concurrent %v", serial, parallel)
	}
}

// TestConcurrentCollectionLatency compares collecting the referrer kinds one
// after another with collecting them concurrently against a registry that
// answers each referrer fetch after a fixed delay.
func TestConcurrentCollectionLatency(t *testing.T) {
	t.Parallel()

	const registryDelay = 50 * time.Millisecond

	fixture := newCollectionFixture(t)

	ref, err := name.NewDigest(signerImageRef)
	testutil.AssertNoError(t, err)

	fetcher := fixture.fetcher(
		func(imgRef name.Reference, opts ...remote.Option) (ociV1.Image, error) {
			time.Sleep(registryDelay)

			return fixture.serve(imgRef, opts...)
		},
	)

	start := time.Now()

	_, err = fetcher.CollectSelectionSerial(
		t.Context(), fixture.manifests, ref, signerTestDigest, fixture.options(),
	)
	testutil.AssertNoError(t, err)

	serial := time.Since(start)
	start = time.Now()

	_, err = fetcher.CollectSelectionParallel(
		t.Context(), fixture.manifests, ref, signerTestDigest, fixture.options(),
	)
	testutil.AssertNoError(t, err)

	concurrent := time.Since(start)

	t.Logf("serial collection %s, concurrent collection %s", serial, concurrent)

	if concurrent >= serial {
		t.Errorf("concurrent collection took %s, not faster than serial %s", concurrent, serial)
	}
}

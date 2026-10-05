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

package bundle //nolint:testpackage // tests use internal helpers

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
)

const closeTestTimeout = 10 * time.Second

func singleAttestationStore(t *testing.T) string {
	t.Helper()

	payload := []byte(`{"predicateType":"` + testSLSAPredicate + `","predicate":{}}`)
	digest := blobDigest(payload)

	return createTestStore(t, &Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Images: map[string]*ImageEntry{
			testImageDigest: { //nolint:exhaustruct_v5 // test data
				Attestations: []AttestationEntry{{
					PredicateType: testSLSAPredicate,
					BlobDigest:    digest,
					Size:          int64(len(payload)),
					SignatureType: testSigType,
				}},
			},
		},
	}, map[string][]byte{digest: payload})
}

// TestFetcherCloseWaitsForRunningFetches checks that closing a fetcher
// releases its store only after running fetches finished, and that fetches
// afterwards fail instead of reading a released store.
func TestFetcherCloseWaitsForRunningFetches(t *testing.T) {
	t.Parallel()

	store, err := OpenStore(singleAttestationStore(t))
	if err != nil {
		t.Fatalf("OpenStore() error: %v", err)
	}

	entered := make(chan struct{})
	release := make(chan struct{})

	fetcher := NewFetcher(store, func(
		ctx context.Context, bundleBytes []byte, opts *attestation.FetchOptions,
	) (*attestation.VerifiedBundle, error) {
		close(entered)
		<-release

		return passthroughVerifier(ctx, bundleBytes, opts)
	})

	fetchDone := make(chan error, 1)

	go func() {
		_, fetchErr := fetcher.Fetch(context.Background(), testExampleRef,
			&attestation.FetchOptions{Digest: testImageDigest})
		fetchDone <- fetchErr
	}()

	<-entered

	closeDone := make(chan error, 1)

	go func() { closeDone <- fetcher.Close() }()

	select {
	case <-closeDone:
		t.Fatal("Close() returned while a fetch was running")
	case <-time.After(50 * time.Millisecond):
	}

	close(release)

	select {
	case fetchErr := <-fetchDone:
		if fetchErr != nil {
			t.Fatalf("running Fetch() error: %v", fetchErr)
		}
	case <-time.After(closeTestTimeout):
		t.Fatal("Fetch() did not finish")
	}

	select {
	case closeErr := <-closeDone:
		if closeErr != nil {
			t.Fatalf("Close() error: %v", closeErr)
		}
	case <-time.After(closeTestTimeout):
		t.Fatal("Close() did not finish")
	}

	_, err = fetcher.Fetch(context.Background(), testExampleRef,
		&attestation.FetchOptions{Digest: testImageDigest})
	if !errors.Is(err, ErrFetcherClosed) {
		t.Errorf("Fetch() after Close() error = %v, want %v", err, ErrFetcherClosed)
	}

	err = fetcher.Close()
	if err != nil {
		t.Errorf("second Close() error: %v", err)
	}
}

// TestFallbackFetcherCloseClosesPrimary checks that closing a fallback
// fetcher releases the bundle store of its primary fetcher.
func TestFallbackFetcherCloseClosesPrimary(t *testing.T) {
	t.Parallel()

	store, err := OpenStore(singleAttestationStore(t))
	if err != nil {
		t.Fatalf("OpenStore() error: %v", err)
	}

	primary := NewFetcher(store, passthroughVerifier)
	fallback := NewFallbackFetcher(primary, &createTestFetcher{attestations: nil, err: nil})

	err = fallback.Close()
	if err != nil {
		t.Fatalf("Close() error: %v", err)
	}

	_, err = primary.Fetch(context.Background(), testExampleRef,
		&attestation.FetchOptions{Digest: testImageDigest})
	if !errors.Is(err, ErrFetcherClosed) {
		t.Errorf("Fetch() error = %v, want %v", err, ErrFetcherClosed)
	}
}

// TestFallbackFetcherKeepsPartialResult checks that the material a fallback
// fetcher returns with a verification failure is passed on.
func TestFallbackFetcherKeepsPartialResult(t *testing.T) {
	t.Parallel()

	notationSig := attestation.VerifiedAttestation{
		SignatureType: attestation.SignatureTypeNotation,
		Digest:        testImageDigest,
	}
	verifyErr := fmt.Errorf("%w: untrusted", attestation.ErrVerificationFailed)

	fallback := NewFallbackFetcher(
		&createTestFetcher{attestations: nil, err: ErrNoAttestationsForDigest},
		&createTestFetcher{
			attestations: []attestation.VerifiedAttestation{notationSig},
			err:          verifyErr,
		},
	)

	atts, err := fallback.Fetch(context.Background(), testExampleRef,
		&attestation.FetchOptions{Digest: testImageDigest})
	if !errors.Is(err, attestation.ErrVerificationFailed) {
		t.Fatalf("Fetch() error = %v, want %v", err, attestation.ErrVerificationFailed)
	}

	if len(atts) != 1 || atts[0].SignatureType != attestation.SignatureTypeNotation {
		t.Errorf("Fetch() attestations = %+v, want the Notation signature", atts)
	}
}

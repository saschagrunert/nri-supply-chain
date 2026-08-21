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

package bundle //nolint:testpackage // tests access internal store helpers

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
)

var errNetworkTimeout = errors.New("network timeout")

type mockFetcher struct {
	attestations []attestation.VerifiedAttestation
	err          error
	called       bool
}

func (m *mockFetcher) Fetch(
	_ context.Context, _ string, _ *attestation.FetchOptions,
) ([]attestation.VerifiedAttestation, error) {
	m.called = true

	return m.attestations, m.err
}

func TestFallbackFetcherPrimaryHit(t *testing.T) {
	t.Parallel()

	primary := &mockFetcher{ //nolint:exhaustruct_v5 // test mock
		attestations: []attestation.VerifiedAttestation{{
			PredicateType: testPredicateType,
			Digest:        testDigestABC,
		}},
	}
	fallback := &mockFetcher{} //nolint:exhaustruct_v5 // test mock

	f := NewFallbackFetcher(primary, fallback)

	result, err := f.Fetch(
		context.Background(), "ref", &attestation.FetchOptions{Digest: testDigestABC},
	)
	if err != nil {
		t.Fatalf("Fetch() error: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("Fetch() count = %d, want 1", len(result))
	}

	if fallback.called {
		t.Error("fallback should not be called when primary succeeds")
	}
}

func TestFallbackFetcherPrimaryMiss(t *testing.T) {
	t.Parallel()

	primary := &mockFetcher{ //nolint:exhaustruct_v5 // test mock
		err: fmt.Errorf("wrapped: %w", ErrNoAttestationsForDigest),
	}
	fallback := &mockFetcher{ //nolint:exhaustruct_v5 // test mock
		attestations: []attestation.VerifiedAttestation{{
			PredicateType: testFromFallback,
			Digest:        testDigestABC,
		}},
	}

	f := NewFallbackFetcher(primary, fallback)

	result, err := f.Fetch(
		context.Background(), "ref", &attestation.FetchOptions{Digest: testDigestABC},
	)
	if err != nil {
		t.Fatalf("Fetch() error: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("Fetch() count = %d, want 1", len(result))
	}

	if result[0].PredicateType != testFromFallback {
		t.Errorf("PredicateType = %q, want %q", result[0].PredicateType, testFromFallback)
	}

	if !fallback.called {
		t.Error("fallback should be called when primary returns ErrNoAttestationsForDigest")
	}
}

func TestFallbackFetcherBundleNotFound(t *testing.T) {
	t.Parallel()

	primary := &mockFetcher{ //nolint:exhaustruct_v5 // test mock
		err: fmt.Errorf("wrapped: %w", ErrBundleNotFound),
	}
	fallback := &mockFetcher{ //nolint:exhaustruct_v5 // test mock
		attestations: []attestation.VerifiedAttestation{{
			PredicateType: testFromFallback,
		}},
	}

	f := NewFallbackFetcher(primary, fallback)

	result, err := f.Fetch(
		context.Background(), "ref", &attestation.FetchOptions{Digest: testDigestABC},
	)
	if err != nil {
		t.Fatalf("Fetch() error: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("Fetch() count = %d, want 1", len(result))
	}

	if !fallback.called {
		t.Error("fallback should be called when primary returns ErrBundleNotFound")
	}
}

func TestFallbackFetcherManifestNotFound(t *testing.T) {
	t.Parallel()

	primary := &mockFetcher{ //nolint:exhaustruct_v5 // test mock
		err: fmt.Errorf("wrapped: %w", ErrManifestNotFound),
	}
	fallback := &mockFetcher{ //nolint:exhaustruct_v5 // test mock
		attestations: []attestation.VerifiedAttestation{{
			PredicateType: testFromFallback,
		}},
	}

	f := NewFallbackFetcher(primary, fallback)

	result, err := f.Fetch(
		context.Background(), "ref", &attestation.FetchOptions{Digest: testDigestABC},
	)
	if err != nil {
		t.Fatalf("Fetch() error: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("Fetch() count = %d, want 1", len(result))
	}
}

func TestFallbackFetcherNonRecoverableError(t *testing.T) {
	t.Parallel()

	primaryErr := errNetworkTimeout
	primary := &mockFetcher{ //nolint:exhaustruct_v5 // test mock
		err: primaryErr,
	}
	fallback := &mockFetcher{} //nolint:exhaustruct_v5 // test mock

	f := NewFallbackFetcher(primary, fallback)

	_, err := f.Fetch(
		context.Background(), "ref", &attestation.FetchOptions{Digest: testDigestABC},
	)
	if !errors.Is(err, primaryErr) {
		t.Fatalf("Fetch() error = %v, want %v", err, primaryErr)
	}

	if fallback.called {
		t.Error("fallback should not be called for non-recoverable errors")
	}
}

func TestFallbackFetcherEmptyResultFallsBack(t *testing.T) {
	t.Parallel()

	primary := &mockFetcher{ //nolint:exhaustruct_v5 // test mock
		attestations: []attestation.VerifiedAttestation{},
	}
	fallback := &mockFetcher{ //nolint:exhaustruct_v5 // test mock
		attestations: []attestation.VerifiedAttestation{{
			PredicateType: testFromFallback,
			Digest:        testDigestABC,
		}},
	}

	f := NewFallbackFetcher(primary, fallback)

	result, err := f.Fetch(
		context.Background(), "ref", &attestation.FetchOptions{Digest: testDigestABC},
	)
	if err != nil {
		t.Fatalf("Fetch() error: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("Fetch() count = %d, want 1", len(result))
	}

	if result[0].PredicateType != testFromFallback {
		t.Errorf("PredicateType = %q, want %q", result[0].PredicateType, testFromFallback)
	}

	if !fallback.called {
		t.Error("fallback should be called when primary returns empty results")
	}
}

func TestFallbackFetcherBothFail(t *testing.T) {
	t.Parallel()

	primaryErr := fmt.Errorf("wrapped: %w", ErrNoAttestationsForDigest)
	fallbackErr := errNetworkTimeout

	primary := &mockFetcher{ //nolint:exhaustruct_v5 // test mock
		err: primaryErr,
	}
	fallback := &mockFetcher{ //nolint:exhaustruct_v5 // test mock
		err: fallbackErr,
	}

	f := NewFallbackFetcher(primary, fallback)

	_, err := f.Fetch(
		context.Background(), "ref", &attestation.FetchOptions{Digest: testDigestABC},
	)
	if err == nil {
		t.Fatal("Fetch() expected error when both fetchers fail")
	}

	if !errors.Is(err, fallbackErr) {
		t.Errorf("error chain should contain fallback error: got %v", err)
	}

	if !fallback.called {
		t.Error("fallback should be called when primary returns recoverable error")
	}
}

func TestFallbackFetcherOCIFetcher(t *testing.T) {
	t.Parallel()

	primary := &mockFetcher{}  //nolint:exhaustruct_v5 // test mock
	fallback := &mockFetcher{} //nolint:exhaustruct_v5 // test mock

	f := NewFallbackFetcher(primary, fallback)

	if f.OCIFetcher() != nil {
		t.Error("OCIFetcher() should return nil for non-OCIFetcher fallback")
	}
}

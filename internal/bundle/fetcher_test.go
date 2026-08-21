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
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
)

func passthroughVerifier(
	_ context.Context, bundleBytes []byte, _ *attestation.FetchOptions,
) ([]byte, error) {
	return bundleBytes, nil
}

var errVerificationFailed = errors.New("verification failed")

func failingVerifier(_ context.Context, _ []byte, _ *attestation.FetchOptions) ([]byte, error) {
	return nil, errVerificationFailed
}

func TestFetcherFetch(t *testing.T) {
	t.Parallel()

	payload := []byte(`{"predicateType":"test","predicate":{}}`)
	digest := blobDigest(payload)
	imageDigest := testImageDigest

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Images: map[string]*ImageEntry{
			imageDigest: { //nolint:exhaustruct_v5 // test data
				Attestations: []AttestationEntry{{
					PredicateType: testSLSAPredicate,
					BlobDigest:    digest,
					Size:          int64(len(payload)),
					SignatureType: testSigType,
				}},
			},
		},
	}

	dir := createTestStore(t, manifest, map[string][]byte{digest: payload})

	store, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore() error: %v", err)
	}

	fetcher := NewFetcher(store, passthroughVerifier)

	fetchOpts := &attestation.FetchOptions{
		Digest: imageDigest,
	}

	result, err := fetcher.Fetch(
		context.Background(), "registry.example.com/app:v1", fetchOpts,
	)
	if err != nil {
		t.Fatalf("Fetch() error: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("Fetch() count = %d, want 1", len(result))
	}

	if result[0].PredicateType != testSLSAPredicate {
		t.Errorf("PredicateType = %q, want %q", result[0].PredicateType, testSLSAPredicate)
	}

	if result[0].Digest != imageDigest {
		t.Errorf("Digest = %q, want %q", result[0].Digest, imageDigest)
	}

	if result[0].SignatureType != attestation.SignatureTypeSigstore {
		t.Errorf("SignatureType = %q, want %q",
			result[0].SignatureType, attestation.SignatureTypeSigstore)
	}
}

func TestFetcherNilOptions(t *testing.T) {
	t.Parallel()

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Images:    map[string]*ImageEntry{},
	}

	dir := createTestStore(t, manifest, nil)

	store, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore() error: %v", err)
	}

	fetcher := NewFetcher(store, passthroughVerifier)

	_, err = fetcher.Fetch(context.Background(), "ref", nil)
	if !errors.Is(err, ErrFetchOptionsRequired) {
		t.Fatalf("Fetch() error = %v, want %v", err, ErrFetchOptionsRequired)
	}
}

func TestFetcherEmptyDigest(t *testing.T) {
	t.Parallel()

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Images:    map[string]*ImageEntry{},
	}

	dir := createTestStore(t, manifest, nil)

	store, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore() error: %v", err)
	}

	fetcher := NewFetcher(store, passthroughVerifier)

	_, err = fetcher.Fetch(context.Background(), "ref", &attestation.FetchOptions{})
	if !errors.Is(err, ErrDigestRequired) {
		t.Fatalf("Fetch() error = %v, want %v", err, ErrDigestRequired)
	}
}

func TestFetcherVerificationFailure(t *testing.T) {
	t.Parallel()

	payload := []byte(`{"test":"data"}`)
	digest := blobDigest(payload)

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Images: map[string]*ImageEntry{
			testImageDigest: { //nolint:exhaustruct_v5 // test data
				Attestations: []AttestationEntry{{
					PredicateType: testPredicateType,
					BlobDigest:    digest,
					Size:          int64(len(payload)),
					SignatureType: testSigType,
				}},
			},
		},
	}

	dir := createTestStore(t, manifest, map[string][]byte{digest: payload})

	store, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore() error: %v", err)
	}

	fetcher := NewFetcher(store, failingVerifier)

	result, err := fetcher.Fetch(context.Background(), "ref", &attestation.FetchOptions{
		Digest: testImageDigest,
	})
	if err != nil {
		t.Fatalf("Fetch() unexpected error: %v", err)
	}

	if len(result) != 0 {
		t.Errorf("Fetch() should return empty result when verification fails, got %d", len(result))
	}
}

func TestFetcherExpiryDeny(t *testing.T) {
	t.Parallel()

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: time.Now().UTC().Add(-48 * time.Hour),
		Images: map[string]*ImageEntry{
			testImageDigest: { //nolint:exhaustruct_v5 // test data
				Attestations: []AttestationEntry{},
			},
		},
	}

	dir := createTestStore(t, manifest, nil)

	store, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore() error: %v", err)
	}

	fetcher := NewFetcher(store, passthroughVerifier,
		WithMaxAge(24*time.Hour),
		WithExpiryPolicy(ExpiryDeny),
	)

	_, err = fetcher.Fetch(context.Background(), "ref", &attestation.FetchOptions{
		Digest: testImageDigest,
	})
	if !errors.Is(err, ErrBundleExpired) {
		t.Fatalf("Fetch() error = %v, want %v", err, ErrBundleExpired)
	}
}

func TestFetcherExpiryAllowAndWarn(t *testing.T) {
	t.Parallel()

	for _, policy := range []ExpiryPolicy{ExpiryAllow, ExpiryWarn} {
		t.Run(string(policy), func(t *testing.T) {
			t.Parallel()

			payload := []byte(`{"test":"data"}`)
			digest := blobDigest(payload)

			manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
				Version:   1,
				CreatedAt: time.Now().UTC().Add(-48 * time.Hour),
				Images: map[string]*ImageEntry{
					testImageDigest: { //nolint:exhaustruct_v5 // test data
						Attestations: []AttestationEntry{{
							PredicateType: testPredicateType,
							BlobDigest:    digest,
							Size:          int64(len(payload)),
							SignatureType: testSigType,
						}},
					},
				},
			}

			dir := createTestStore(t, manifest, map[string][]byte{digest: payload})

			store, err := OpenStore(dir)
			if err != nil {
				t.Fatalf("OpenStore() error: %v", err)
			}

			fetcher := NewFetcher(store, passthroughVerifier,
				WithMaxAge(24*time.Hour),
				WithExpiryPolicy(policy),
			)

			result, err := fetcher.Fetch(
				context.Background(), "ref", &attestation.FetchOptions{
					Digest: testImageDigest,
				},
			)
			if err != nil {
				t.Fatalf("Fetch() unexpected error: %v", err)
			}

			if len(result) != 1 {
				t.Errorf("Fetch() count = %d, want 1", len(result))
			}
		})
	}
}

func TestFetcherNoMaxAge(t *testing.T) {
	t.Parallel()

	payload := []byte(`{"test":"data"}`)
	digest := blobDigest(payload)

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: time.Now().UTC().Add(-365 * 24 * time.Hour),
		Images: map[string]*ImageEntry{
			testImageDigest: { //nolint:exhaustruct_v5 // test data
				Attestations: []AttestationEntry{{
					PredicateType: testPredicateType,
					BlobDigest:    digest,
					Size:          int64(len(payload)),
					SignatureType: testSigType,
				}},
			},
		},
	}

	dir := createTestStore(t, manifest, map[string][]byte{digest: payload})

	store, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore() error: %v", err)
	}

	fetcher := NewFetcher(store, passthroughVerifier)

	result, err := fetcher.Fetch(context.Background(), "ref", &attestation.FetchOptions{
		Digest: testImageDigest,
	})
	if err != nil {
		t.Fatalf("Fetch() unexpected error: %v", err)
	}

	if len(result) != 1 {
		t.Errorf("Fetch() count = %d, want 1", len(result))
	}
}

func TestFetcherContextCanceled(t *testing.T) {
	t.Parallel()

	payload := []byte(`{"test":"data"}`)
	digest := blobDigest(payload)

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Images: map[string]*ImageEntry{
			testImageDigest: { //nolint:exhaustruct_v5 // test data
				Attestations: []AttestationEntry{{
					PredicateType: testPredicateType,
					BlobDigest:    digest,
					Size:          int64(len(payload)),
					SignatureType: testSigType,
				}},
			},
		},
	}

	dir := createTestStore(t, manifest, map[string][]byte{digest: payload})

	store, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore() error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	fetcher := NewFetcher(store, passthroughVerifier)

	_, err = fetcher.Fetch(ctx, "ref", &attestation.FetchOptions{
		Digest: testImageDigest,
	})
	if err == nil {
		t.Fatal("Fetch() should fail with canceled context")
	}
}

func TestFetcherRequireSignatureMissing(t *testing.T) {
	t.Parallel()

	payload := []byte(`{"test":"data"}`)
	digest := blobDigest(payload)

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Images: map[string]*ImageEntry{
			testImageDigest: { //nolint:exhaustruct_v5 // test data
				Attestations: []AttestationEntry{{
					PredicateType: testPredicateType,
					BlobDigest:    digest,
					Size:          int64(len(payload)),
					SignatureType: testSigType,
				}},
			},
		},
	}

	dir := createTestStore(t, manifest, map[string][]byte{digest: payload})

	store, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore() error: %v", err)
	}

	fetcher := NewFetcher(store, passthroughVerifier,
		WithRequireBundleSignature(true),
	)

	_, err = fetcher.Fetch(
		context.Background(), "ref", &attestation.FetchOptions{
			Digest: testImageDigest,
		},
	)
	if !errors.Is(err, ErrBundleSignatureRequired) {
		t.Fatalf(
			"Fetch() error = %v, want %v",
			err, ErrBundleSignatureRequired,
		)
	}
}

func TestFetcherSignatureKeyConfiguredButUnsigned(t *testing.T) {
	t.Parallel()

	payload := []byte(`{"test":"data"}`)
	digest := blobDigest(payload)

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Images: map[string]*ImageEntry{
			testImageDigest: { //nolint:exhaustruct_v5 // test data
				Attestations: []AttestationEntry{{
					PredicateType: testPredicateType,
					BlobDigest:    digest,
					Size:          int64(len(payload)),
					SignatureType: testSigType,
				}},
			},
		},
	}

	dir := createTestStore(t, manifest, map[string][]byte{digest: payload})

	store, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore() error: %v", err)
	}

	_, pubPath := generateTestKeyPair(t)

	fetcher := NewFetcher(store, passthroughVerifier,
		WithBundleSignatureKey(pubPath),
	)

	result, err := fetcher.Fetch(
		context.Background(), "ref", &attestation.FetchOptions{
			Digest: testImageDigest,
		},
	)
	if err != nil {
		t.Fatalf("Fetch() should succeed with key configured but unsigned bundle: %v", err)
	}

	if len(result) != 1 {
		t.Errorf("Fetch() count = %d, want 1", len(result))
	}
}

func TestFetcherMetricsCallbacks(t *testing.T) {
	t.Parallel()

	payload := []byte(`{"test":"data"}`)
	digest := blobDigest(payload)

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: time.Now().UTC().Add(-48 * time.Hour),
		Images: map[string]*ImageEntry{
			testImageDigest: { //nolint:exhaustruct_v5 // test data
				Attestations: []AttestationEntry{{
					PredicateType: testPredicateType,
					BlobDigest:    digest,
					Size:          int64(len(payload)),
					SignatureType: testSigType,
				}},
			},
		},
	}

	dir := createTestStore(t, manifest, map[string][]byte{digest: payload})

	store, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore() error: %v", err)
	}

	var (
		stalenessPolicy string
		verificationRes string
		ageSeconds      float64
		imageCountVal   float64
	)

	met := &Metrics{
		OnStaleness:    func(policy string) { stalenessPolicy = policy },
		OnVerification: func(result string) { verificationRes = result },
		SetAge:         func(seconds float64) { ageSeconds = seconds },
		SetImageCount:  func(count float64) { imageCountVal = count },
	}

	fetcher := NewFetcher(store, passthroughVerifier,
		WithMaxAge(24*time.Hour),
		WithExpiryPolicy(ExpiryWarn),
		WithMetrics(met),
	)

	result, err := fetcher.Fetch(
		context.Background(), "ref", &attestation.FetchOptions{
			Digest: testImageDigest,
		},
	)
	if err != nil {
		t.Fatalf("Fetch() error: %v", err)
	}

	if len(result) != 1 {
		t.Errorf("Fetch() count = %d, want 1", len(result))
	}

	if stalenessPolicy != string(ExpiryWarn) {
		t.Errorf("OnStaleness called with %q, want %q", stalenessPolicy, ExpiryWarn)
	}

	if verificationRes != "success" {
		t.Errorf("OnVerification called with %q, want %q", verificationRes, "success")
	}

	if ageSeconds <= 0 {
		t.Errorf("SetAge called with %f, want > 0", ageSeconds)
	}

	if imageCountVal != 1 {
		t.Errorf("SetImageCount called with %f, want 1", imageCountVal)
	}
}

func TestFetcherStoreCreatedAt(t *testing.T) {
	t.Parallel()

	createdAt := time.Now().UTC().Add(-24 * time.Hour).Truncate(time.Second)

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: createdAt,
		Images:    map[string]*ImageEntry{},
	}

	dir := createTestStore(t, manifest, nil)

	store, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore() error: %v", err)
	}

	fetcher := NewFetcher(store, passthroughVerifier)

	if !fetcher.StoreCreatedAt().Equal(createdAt) {
		t.Errorf("StoreCreatedAt() = %v, want %v", fetcher.StoreCreatedAt(), createdAt)
	}
}

func TestFetcherSignatureVerification(t *testing.T) {
	t.Parallel()

	payload := []byte(`{"test":"data"}`)
	digest := blobDigest(payload)

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Images: map[string]*ImageEntry{
			testImageDigest: { //nolint:exhaustruct_v5 // test data
				Attestations: []AttestationEntry{{
					PredicateType: testPredicateType,
					BlobDigest:    digest,
					Size:          int64(len(payload)),
					SignatureType: testSigType,
				}},
			},
		},
	}

	privPath, pubPath := generateTestKeyPair(t)

	signErr := SignManifest(manifest, privPath)
	if signErr != nil {
		t.Fatalf("SignManifest() error: %v", signErr)
	}

	dir := createTestStore(t, manifest, map[string][]byte{digest: payload})

	store, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore() error: %v", err)
	}

	fetcher := NewFetcher(store, passthroughVerifier,
		WithBundleSignatureKey(pubPath),
	)

	result, err := fetcher.Fetch(
		context.Background(), "ref", &attestation.FetchOptions{
			Digest: testImageDigest,
		},
	)
	if err != nil {
		t.Fatalf("Fetch() unexpected error: %v", err)
	}

	if len(result) != 1 {
		t.Errorf("Fetch() count = %d, want 1", len(result))
	}
}

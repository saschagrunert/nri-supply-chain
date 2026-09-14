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

package bundle

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
)

// ExpiryPolicy controls how expired bundles are handled.
type ExpiryPolicy string

// Expiry policy constants.
const (
	ExpiryAllow ExpiryPolicy = "allow"
	ExpiryWarn  ExpiryPolicy = "warn"
	ExpiryDeny  ExpiryPolicy = "deny"
)

// Metrics allows the Fetcher to report metrics without importing
// the metrics package directly.
type Metrics struct {
	OnStaleness    func(policy string)
	OnVerification func(result string)
	SetAge         func(seconds float64)
	SetImageCount  func(count float64)
}

// Fetcher implements attestation.Fetcher by reading attestations from a
// local on-disk bundle store, enabling fully offline verification.
type Fetcher struct {
	store                  *Store
	verifyBundle           attestation.SignedBundleVerifyFunc
	maxAge                 time.Duration
	expiryPolicy           ExpiryPolicy
	requireBundleSignature bool
	bundleSignatureKey     string
	metrics                *Metrics
	signatureOnce          sync.Once
	signatureErr           error
}

// FetcherOption configures a Fetcher.
type FetcherOption func(*Fetcher)

// NewFetcher creates a Fetcher backed by the given store.
func NewFetcher(
	store *Store,
	verifyBundle attestation.SignedBundleVerifyFunc,
	opts ...FetcherOption,
) *Fetcher {
	fetcher := &Fetcher{
		store:                  store,
		verifyBundle:           verifyBundle,
		maxAge:                 0,
		expiryPolicy:           ExpiryWarn,
		requireBundleSignature: false,
		bundleSignatureKey:     "",
		metrics:                nil,
		signatureOnce:          sync.Once{},
		signatureErr:           nil,
	}

	for _, opt := range opts {
		opt(fetcher)
	}

	return fetcher
}

// SetMetrics sets the metrics callbacks after construction.
func (f *Fetcher) SetMetrics(met *Metrics) {
	f.metrics = met
}

// StoreCreatedAt returns the CreatedAt timestamp from the bundle manifest
// held in memory. This can be compared with the on-disk manifest to detect
// whether the store has been updated (e.g. via bundle import).
func (f *Fetcher) StoreCreatedAt() time.Time {
	return f.store.Manifest().CreatedAt
}

// WithMaxAge sets the maximum age for the bundle before staleness checks apply.
func WithMaxAge(d time.Duration) FetcherOption {
	return func(f *Fetcher) {
		f.maxAge = d
	}
}

// WithExpiryPolicy sets the behavior when a bundle exceeds max age.
func WithExpiryPolicy(p ExpiryPolicy) FetcherOption {
	return func(f *Fetcher) {
		f.expiryPolicy = p
	}
}

// WithRequireBundleSignature requires bundles to have a valid signature.
func WithRequireBundleSignature(required bool) FetcherOption {
	return func(f *Fetcher) {
		f.requireBundleSignature = required
	}
}

// WithBundleSignatureKey sets the public key path for bundle signature verification.
func WithBundleSignatureKey(keyPath string) FetcherOption {
	return func(f *Fetcher) {
		f.bundleSignatureKey = keyPath
	}
}

// WithMetrics sets the metrics callbacks for the Fetcher.
func WithMetrics(met *Metrics) FetcherOption {
	return func(f *Fetcher) {
		f.metrics = met
	}
}

// Fetch retrieves and verifies attestations for the given image from the local
// bundle store.
func (f *Fetcher) Fetch(
	ctx context.Context,
	_ string,
	opts *attestation.FetchOptions,
) ([]attestation.VerifiedAttestation, error) {
	if opts == nil {
		return nil, ErrFetchOptionsRequired
	}

	if opts.Digest == "" {
		return nil, ErrDigestRequired
	}

	stalenessErr := f.checkStaleness()
	if stalenessErr != nil {
		return nil, stalenessErr
	}

	signatureErr := f.checkSignature()
	if signatureErr != nil {
		return nil, signatureErr
	}

	f.reportBundleState()

	stored, err := f.store.AttestationsFor(opts.Digest)
	if err != nil {
		f.recordVerification("error")

		// A blob listed in the bundle manifest that was modified, truncated or
		// removed after import is tampering, so it must be denied instead of
		// being handled with the fetch failure policy.
		if isBlobIntegrityError(err) {
			return nil, fmt.Errorf(
				"%w: %w: %w",
				attestation.ErrVerificationFailed, attestation.ErrIncompleteAttestationSet, err,
			)
		}

		return nil, err
	}

	result, err := f.verifyStoredAttestations(ctx, stored, opts)
	if err != nil {
		return nil, err
	}

	f.recordVerification("success")

	return result, nil
}

func (f *Fetcher) verifyStoredAttestations(
	ctx context.Context,
	stored []StoredAttestation,
	opts *attestation.FetchOptions,
) ([]attestation.VerifiedAttestation, error) {
	result := make([]attestation.VerifiedAttestation, 0, len(stored))

	var failures int

	for idx := range stored {
		ctxErr := ctx.Err()
		if ctxErr != nil {
			return nil, fmt.Errorf(
				"context canceled during bundle verification: %w", ctxErr,
			)
		}

		att, err := f.verifyStoredAttestation(ctx, &stored[idx], opts)
		if err != nil {
			slog.WarnContext(ctx,
				"Skipping attestation that failed verification",
				"digest", stored[idx].Digest,
				"predicateType", stored[idx].PredicateType,
				"error", err,
			)

			// Without its trust material the attestation set cannot be
			// evaluated completely; report that instead of a verification
			// failure so the fetch failure policy applies.
			if errors.Is(err, attestation.ErrTrustMaterialUnavailable) {
				f.recordVerification("error")

				return nil, err
			}

			if !errors.Is(err, errUnsupportedSignatureType) {
				failures++
			}

			continue
		}

		result = append(result, *att)
	}

	if len(result) == 0 && failures > 0 {
		f.recordVerification("error")

		return nil, fmt.Errorf(
			"%w: all %d bundled attestations failed verification "+
				"(bundles created by older releases must be recreated)",
			attestation.ErrVerificationFailed, failures,
		)
	}

	return result, nil
}

// verifyStoredAttestation cryptographically verifies one bundled attestation.
// The predicate type is always taken from the verified statement, never from
// the unsigned bundle manifest.
func (f *Fetcher) verifyStoredAttestation(
	ctx context.Context,
	stored *StoredAttestation,
	opts *attestation.FetchOptions,
) (*attestation.VerifiedAttestation, error) {
	if stored.SignatureType != "" && stored.SignatureType != attestation.SignatureTypeSigstore {
		return nil, fmt.Errorf("%w: %q", errUnsupportedSignatureType, stored.SignatureType)
	}

	verified, err := f.verifyBundle(ctx, stored.BundleBytes, opts)
	if err != nil {
		return nil, err
	}

	if verified.PredicateType == "" {
		return nil, errMissingPredicateType
	}

	if stored.PredicateType != "" && stored.PredicateType != verified.PredicateType {
		slog.WarnContext(ctx, "Bundle manifest predicate type differs from signed statement",
			"manifest", stored.PredicateType,
			"statement", verified.PredicateType,
		)
	}

	payload := verified.Payload

	if verified.PredicateType == attestation.PredicateBaselineSBOM {
		payload, err = attestation.BaselineSBOMDocument(payload, stored.Digest)
		if err != nil {
			return nil, fmt.Errorf("verifying baseline SBOM: %w", err)
		}
	}

	return &attestation.VerifiedAttestation{
		PredicateType: verified.PredicateType,
		Payload:       payload,
		Digest:        stored.Digest,
		SignatureType: attestation.SignatureTypeSigstore,
		Signer:        verified.Signer,
		Bundle:        stored.BundleBytes,
	}, nil
}

func (f *Fetcher) checkStaleness() error {
	result := CheckStaleness(f.store.Manifest(), f.maxAge, f.expiryPolicy)
	if !result.Stale {
		return nil
	}

	f.recordStaleness(string(f.expiryPolicy))

	if !result.Allowed {
		return fmt.Errorf(
			"%w: age %s exceeds maximum %s",
			ErrBundleExpired, result.Age.Round(time.Second), result.MaxAge,
		)
	}

	if f.expiryPolicy == ExpiryWarn {
		slog.Warn(
			"Bundle is stale",
			"age", result.Age.Round(time.Second),
			"maxAge", result.MaxAge,
		)
	}

	return nil
}

func (f *Fetcher) recordStaleness(policy string) {
	if f.metrics != nil && f.metrics.OnStaleness != nil {
		f.metrics.OnStaleness(policy)
	}
}

func (f *Fetcher) recordVerification(result string) {
	if f.metrics != nil && f.metrics.OnVerification != nil {
		f.metrics.OnVerification(result)
	}
}

func (f *Fetcher) reportBundleState() {
	if f.metrics == nil {
		return
	}

	manifest := f.store.Manifest()

	if f.metrics.SetAge != nil {
		f.metrics.SetAge(time.Since(manifest.CreatedAt).Seconds())
	}

	if f.metrics.SetImageCount != nil {
		f.metrics.SetImageCount(float64(len(manifest.Images)))
	}
}

func (f *Fetcher) checkSignature() error {
	f.signatureOnce.Do(func() {
		f.signatureErr = f.verifySignature()
	})

	return f.signatureErr
}

func (f *Fetcher) verifySignature() error {
	manifest := f.store.Manifest()

	if f.requireBundleSignature && manifest.Signature == nil {
		return ErrBundleSignatureRequired
	}

	if f.bundleSignatureKey != "" {
		// A configured key always requires a valid signature: accepting an
		// unsigned (or stripped) manifest would let whoever writes the bundle
		// choose the embedded trusted root and staleness timestamp.
		if manifest.Signature == nil {
			return fmt.Errorf(
				"%w: bundle_signature_key is configured", ErrBundleSignatureRequired,
			)
		}

		return VerifyManifestSignature(manifest, f.bundleSignatureKey)
	}

	return nil
}

func isBlobIntegrityError(err error) bool {
	return errors.Is(err, ErrBlobDigestMismatch) ||
		errors.Is(err, ErrBlobSizeMismatch) ||
		errors.Is(err, ErrBlobMissing) ||
		errors.Is(err, ErrBlobNotRegular)
}

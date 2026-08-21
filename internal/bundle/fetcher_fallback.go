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

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
)

// FallbackFetcher tries a primary fetcher (typically a Fetcher) and falls
// back to a secondary fetcher (typically an OCIFetcher) when the primary cannot
// serve the request.
type FallbackFetcher struct {
	primary  attestation.Fetcher
	fallback attestation.Fetcher
}

// NewFallbackFetcher creates a FallbackFetcher that tries primary first, then
// falls back to fallback when the primary returns ErrNoAttestationsForDigest or
// ErrBundleNotFound.
func NewFallbackFetcher(primary, fallback attestation.Fetcher) *FallbackFetcher {
	return &FallbackFetcher{
		primary:  primary,
		fallback: fallback,
	}
}

// Primary returns the primary (bundle) fetcher.
func (f *FallbackFetcher) Primary() attestation.Fetcher { //nolint:ireturn // accessor
	return f.primary
}

// Fallback returns the secondary (registry) fetcher.
func (f *FallbackFetcher) Fallback() attestation.Fetcher { //nolint:ireturn // accessor
	return f.fallback
}

// Fetch tries the primary fetcher first. If the primary returns a recoverable
// error (no attestations found or bundle not found), the fallback fetcher is
// tried instead.
func (f *FallbackFetcher) Fetch(
	ctx context.Context,
	imageRef string,
	opts *attestation.FetchOptions,
) ([]attestation.VerifiedAttestation, error) {
	result, err := f.primary.Fetch(ctx, imageRef, opts)
	if err == nil && len(result) > 0 {
		return result, nil
	}

	if err != nil && !isRecoverableError(err) {
		return nil, fmt.Errorf("primary fetcher: %w", err)
	}

	reason := "no verified attestations in bundle"
	if err != nil {
		reason = err.Error()
	}

	slog.InfoContext(ctx,
		"Bundle fetcher did not find attestations, falling back to registry",
		"imageRef", imageRef,
		"reason", reason,
	)

	fallbackResult, fallbackErr := f.fallback.Fetch(ctx, imageRef, opts)
	if fallbackErr != nil {
		return nil, fmt.Errorf("fallback fetcher: %w", fallbackErr)
	}

	return fallbackResult, nil
}

// OCIFetcher returns the inner OCIFetcher if the fallback is one, or nil.
func (f *FallbackFetcher) OCIFetcher() *attestation.OCIFetcher {
	if ociFetcher, ok := f.fallback.(*attestation.OCIFetcher); ok {
		return ociFetcher
	}

	return nil
}

func isRecoverableError(err error) bool {
	return errors.Is(err, ErrNoAttestationsForDigest) ||
		errors.Is(err, ErrBundleNotFound) ||
		errors.Is(err, ErrManifestNotFound)
}

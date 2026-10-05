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

package attestation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/google/go-containerregistry/pkg/name"
	ociV1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"golang.org/x/sync/errgroup"

	"github.com/saschagrunert/nri-supply-chain/internal/intoto"
)

// collectBaselineSBOMs fetches baseline SBOM referrers. Baselines must be
// signed Sigstore bundles like any other attestation; unsigned baselines are
// rejected because they would let anyone with push access steer drift
// detection.
func (f *OCIFetcher) collectBaselineSBOMs(
	ctx context.Context,
	candidates []*ociV1.Descriptor, ref name.Digest, digest string,
	remoteOpts []remote.Option, fetchOpts *FetchOptions,
) ([]VerifiedAttestation, *collectStats) {
	atts, stats := f.collectBundles(ctx, candidates, ref, digest, remoteOpts, fetchOpts)

	baselines := make([]VerifiedAttestation, 0, len(atts))

	for idx := range atts {
		if atts[idx].PredicateType != PredicateBaselineSBOM {
			slog.WarnContext(ctx, "Baseline SBOM referrer has unexpected predicate type, skipping",
				"predicateType", atts[idx].PredicateType,
			)

			stats.record(outcomeVerifyFailed, nil)

			continue
		}

		baselines = append(baselines, atts[idx])
	}

	return baselines, stats
}

// collectNotationSignatures fetches Notation signature referrers. They are
// verified later by the Notation check and are collected unverified.
func (f *OCIFetcher) collectNotationSignatures(
	ctx context.Context,
	candidates []*ociV1.Descriptor, ref name.Digest, digest string,
	remoteOpts []remote.Option,
) ([]VerifiedAttestation, *collectStats) {
	return collectConcurrently(
		ctx,
		"Notation signature",
		candidates,
		func(ctx context.Context, desc *ociV1.Descriptor) (VerifiedAttestation, referrerOutcome, error) {
			return f.fetchNotationSignature(ctx, desc, ref, digest, remoteOpts)
		},
	)
}

func (f *OCIFetcher) fetchNotationSignature(
	ctx context.Context,
	desc *ociV1.Descriptor,
	ref name.Digest, digest string,
	remoteOpts []remote.Option,
) (VerifiedAttestation, referrerOutcome, error) {
	sigRef := ref.Context().Digest(desc.Digest.String())

	img, err := f.fetchImage(sigRef, remoteOpts...)
	if err != nil {
		return VerifiedAttestation{}, classifyReferrerError(
			ctx, "Notation signature image", desc, err,
		), err
	}

	manifest, err := img.Manifest()
	if err != nil {
		return VerifiedAttestation{}, classifyReferrerError(
			ctx, "Notation signature manifest", desc, err,
		), err
	}

	if manifest == nil {
		slog.WarnContext(ctx, "Notation signature referrer has no manifest",
			"digest", desc.Digest.String(),
		)

		return VerifiedAttestation{}, outcomeVerifyFailed, nil
	}

	envelope, err := f.readFirstLayer(ctx, img)
	if err != nil {
		return VerifiedAttestation{}, classifyReferrerError(
			ctx, "Notation signature envelope", desc, err,
		), err
	}

	return notationAttestation(manifest, envelope, digest), outcomeUnverified, nil
}

func notationAttestation(
	manifest *ociV1.Manifest,
	envelope []byte,
	digest string,
) VerifiedAttestation {
	att := VerifiedAttestation{
		PredicateType: NotationSignatureMediaType,
		Payload:       envelope,
		Digest:        digest,
		SignatureType: SignatureTypeNotation,
		Signer:        SignerIdentity{KeyPath: "", KeyPaths: nil, Issuer: "", SAN: ""},
		Bundle:        nil,
	}

	if manifest.Subject != nil {
		att.NotationSubjectDigest = manifest.Subject.Digest.String()
		att.NotationSubjectSize = manifest.Subject.Size
		att.NotationSubjectMediaType = string(manifest.Subject.MediaType)
	}

	if len(manifest.Layers) > 0 {
		att.NotationMediaType = string(manifest.Layers[0].MediaType)
	}

	return att
}

// collectBundles fetches and verifies Sigstore bundle referrers.
func (f *OCIFetcher) collectBundles(
	ctx context.Context, candidates []*ociV1.Descriptor,
	ref name.Digest, digest string, remoteOpts []remote.Option,
	fetchOpts *FetchOptions,
) ([]VerifiedAttestation, *collectStats) {
	var seen blobSet

	return collectConcurrently(
		ctx,
		"attestation",
		candidates,
		func(ctx context.Context, desc *ociV1.Descriptor) (VerifiedAttestation, referrerOutcome, error) {
			return f.processDescriptor(ctx, desc, ref, digest, remoteOpts, fetchOpts, &seen)
		},
	)
}

// referrerFetchFunc fetches one referrer and reports its outcome.
type referrerFetchFunc func(
	ctx context.Context, desc *ociV1.Descriptor,
) (VerifiedAttestation, referrerOutcome, error)

// collectConcurrently runs fetch for every candidate with bounded
// concurrency and returns the collected attestations in candidate order, so
// the result does not depend on scheduling. Their aggregate payload size is
// limited to maxTotalAttestationSize: exceeding it records a limit violation
// and cancels the remaining fetches. A fetch that has not started when the
// collection is interrupted records the interruption as a fetch failure.
func collectConcurrently(
	ctx context.Context, kind string, candidates []*ociV1.Descriptor, fetch referrerFetchFunc,
) ([]VerifiedAttestation, *collectStats) {
	var (
		totalSize atomic.Int64
		stats     collectStats
	)

	slots := make([]*VerifiedAttestation, len(candidates))

	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(maxConcurrentCollectFetch)

	for idx, desc := range candidates {
		group.Go(func() error {
			if groupCtx.Err() != nil {
				if !errors.Is(context.Cause(groupCtx), errAggregateSizeExceeded) {
					stats.record(outcomeFetchFailed, groupCtx.Err())
				}

				return nil
			}

			att, outcome, err := fetch(groupCtx, desc)
			stats.record(outcome, err)

			if outcome != outcomeVerified && outcome != outcomeUnverified {
				return nil
			}

			newTotal := totalSize.Add(int64(len(att.Payload)))
			if newTotal > maxTotalAttestationSize {
				slog.WarnContext(groupCtx,
					"Aggregate referrer size exceeds limit, attestation set is incomplete",
					"kind", kind,
					"totalSize", newTotal,
					"limit", maxTotalAttestationSize,
				)

				stats.record(outcomeLimitExceeded, errAggregateSizeExceeded)

				return errAggregateSizeExceeded
			}

			slots[idx] = &att

			return nil
		})
	}

	// errAggregateSizeExceeded cancels the group context; log unexpected errors.
	err := group.Wait()
	if err != nil && !errors.Is(err, errAggregateSizeExceeded) {
		slog.WarnContext(ctx, "Unexpected error during referrer collection",
			"kind", kind,
			"error", err,
		)
	}

	return compactSlots(slots), &stats
}

// compactSlots returns the collected attestations in candidate order. Each
// collector goroutine fills only its own slot, so no lock is needed.
func compactSlots(slots []*VerifiedAttestation) []VerifiedAttestation {
	atts := make([]VerifiedAttestation, 0, len(slots))

	for _, att := range slots {
		if att != nil {
			atts = append(atts, *att)
		}
	}

	return atts
}

// blobSet records the content hashes of referrer blobs already processed, so
// identical bundles attached through different manifests are verified and
// counted only once.
type blobSet struct {
	mu     sync.Mutex
	hashes map[[sha256.Size]byte]struct{}
}

// add reports whether data was not seen before.
func (b *blobSet) add(data []byte) bool {
	sum := sha256.Sum256(data)

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.hashes == nil {
		b.hashes = make(map[[sha256.Size]byte]struct{})
	}

	if _, ok := b.hashes[sum]; ok {
		return false
	}

	b.hashes[sum] = struct{}{}

	return true
}

// processDescriptor fetches one Sigstore bundle referrer and verifies it. The
// predicate type always comes from the signed statement; unsigned referrer
// annotations are never trusted.
func (f *OCIFetcher) processDescriptor(
	ctx context.Context, desc *ociV1.Descriptor,
	ref name.Digest, digest string, remoteOpts []remote.Option,
	fetchOpts *FetchOptions, seen *blobSet,
) (VerifiedAttestation, referrerOutcome, error) {
	attestRef := ref.Context().Digest(desc.Digest.String())

	img, err := f.fetchImage(attestRef, remoteOpts...)
	if err != nil {
		return VerifiedAttestation{}, classifyReferrerError(
			ctx,
			"attestation image",
			desc,
			err,
		), err
	}

	bundleBytes, err := f.readFirstLayer(ctx, img)
	if err != nil {
		return VerifiedAttestation{}, classifyReferrerError(
			ctx,
			"attestation layer",
			desc,
			err,
		), err
	}

	if !seen.add(bundleBytes) {
		slog.DebugContext(ctx, "Skipping duplicate attestation referrer blob",
			"digest", desc.Digest.String(),
		)

		return VerifiedAttestation{}, outcomeSkipped, nil
	}

	verified, err := f.verifyBundle(ctx, bundleBytes, fetchOpts)
	if err != nil {
		slog.WarnContext(ctx, "Attestation referrer failed verification",
			"digest", desc.Digest.String(),
			"error", err,
		)

		if errors.Is(err, ErrTrustMaterialUnavailable) {
			return VerifiedAttestation{}, trustMaterialOutcome(err), err
		}

		return VerifiedAttestation{}, outcomeVerifyFailed, nil
	}

	att, ok := f.attestationFromVerified(ctx, verified, bundleBytes, digest)
	if !ok {
		return VerifiedAttestation{}, outcomeVerifyFailed, nil
	}

	return att, outcomeVerified, nil
}

// attestationFromVerified builds a VerifiedAttestation from a verified bundle.
// Baseline SBOM statements are checked against the image digest and reduced
// to their predicate (the SBOM document) for drift detection.
func (f *OCIFetcher) attestationFromVerified(
	ctx context.Context, verified *VerifiedBundle, bundleBytes []byte, digest string,
) (VerifiedAttestation, bool) {
	predicateType := verified.PredicateType
	if predicateType == "" {
		predicateType = extractPredicateType(verified.Payload)
	}

	if predicateType == "" {
		slog.WarnContext(ctx, "Verified attestation has no predicate type in its statement")

		return VerifiedAttestation{}, false
	}

	payload := verified.Payload

	if predicateType == PredicateBaselineSBOM {
		predicate, err := BaselineSBOMDocument(payload, digest)
		if err != nil {
			slog.WarnContext(ctx, "Invalid baseline SBOM statement", "error", err)

			return VerifiedAttestation{}, false
		}

		payload = predicate
	}

	return VerifiedAttestation{
		PredicateType: predicateType,
		Payload:       payload,
		Digest:        digest,
		SignatureType: SignatureTypeSigstore,
		Signer:        verified.Signer,
		Bundle:        bundleBytes,
	}, true
}

// BaselineSBOMDocument verifies that a baseline SBOM in-toto statement is
// bound to the image digest and returns the SBOM document it carries.
func BaselineSBOMDocument(statement []byte, digest string) ([]byte, error) {
	predicate, err := intoto.VerifySubjectAndExtractPredicate(statement, digest)
	if err != nil {
		return nil, fmt.Errorf("baseline SBOM statement: %w", err)
	}

	if bytes.Equal(predicate, statement) {
		return nil, fmt.Errorf(
			"%w: baseline SBOM statement has no predicate",
			intoto.ErrInvalidStatement,
		)
	}

	return predicate, nil
}

func parseDigestRef(imageRef, digest string, parsed name.Reference) (name.Digest, error) {
	if parsed != nil {
		return parsed.Context().Digest(digest), nil
	}

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return name.Digest{}, fmt.Errorf("parsing reference %q: %w", imageRef, err)
	}

	return ref.Context().Digest(digest), nil
}

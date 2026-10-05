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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	ociV1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

func (f *OCIFetcher) cosignTagFallback(
	ctx context.Context, ref name.Digest, digest string,
	remoteOpts []remote.Option,
	fetchOpts *FetchOptions,
) ([]VerifiedAttestation, error) {
	tagAtts, stats, tagErr := f.fetchCosignTagAttestations(
		ctx, ref, digest, remoteOpts, fetchOpts,
	)
	if tagErr != nil {
		return nil, fmt.Errorf("cosign tag-based discovery: %w", tagErr)
	}

	err := evaluateCollection(len(tagAtts), stats)
	if errors.Is(err, ErrVerificationFailed) {
		return nil, fmt.Errorf("cosign tag-based discovery: %w", err)
	}

	ctxErr := ctx.Err()
	if ctxErr != nil {
		return nil, fmt.Errorf("cosign tag-based discovery interrupted: %w", ctxErr)
	}

	if err != nil {
		return nil, fmt.Errorf("cosign tag-based discovery: %w", err)
	}

	if len(tagAtts) > 0 {
		slog.DebugContext(ctx, "Discovered attestations via cosign tag scheme",
			"count", len(tagAtts),
			"digest", digest,
		)
	}

	return tagAtts, nil
}

func cosignAttestationTag(ref name.Digest) name.Tag {
	return ref.Context().Tag(
		strings.Replace(ref.DigestStr(), ":", "-", 1) + cosignAttestationTagSuffix,
	)
}

// fetchCosignTagAttestations discovers attestations stored with the legacy
// cosign tag scheme (sha256-<digest>.att). A missing tag means there are no
// attestations. Registry transport failures are returned as fetch errors,
// while a tag that does not hold a readable attestation image counts as a
// verification failure.
func (f *OCIFetcher) fetchCosignTagAttestations(
	ctx context.Context, ref name.Digest, digest string,
	remoteOpts []remote.Option,
	fetchOpts *FetchOptions,
) ([]VerifiedAttestation, *collectStats, error) {
	var stats collectStats

	attTag := cosignAttestationTag(ref)

	slog.DebugContext(ctx, "Trying cosign tag-based attestation discovery",
		"tag", attTag.String(),
	)

	img, fetchErr := f.fetchImage(attTag, remoteOpts...)
	if fetchErr != nil {
		if isRegistryNotFound(fetchErr) {
			return nil, &stats, nil
		}

		return nil, &stats, tagContentError(
			fmt.Errorf("fetching cosign attestation tag %q: %w", attTag.String(), fetchErr),
		)
	}

	manifest, err := img.Manifest()
	if err != nil {
		return nil, &stats, tagContentError(
			fmt.Errorf("reading cosign attestation manifest: %w", err),
		)
	}

	layers, layerErr := img.Layers()
	if layerErr != nil {
		return nil, &stats, tagContentError(
			fmt.Errorf("reading cosign attestation layers: %w", layerErr),
		)
	}

	var descriptors []ociV1.Descriptor

	if manifest != nil {
		descriptors = manifest.Layers
	}

	return f.verifyCosignLayers(ctx, layers, descriptors, digest, fetchOpts)
}

// exceededCosignLayerLimit records a limit violation when the cosign
// attestation image has more layers than can be processed.
func exceededCosignLayerLimit(ctx context.Context, stats *collectStats, layers int) bool {
	if layers <= maxReferrers {
		return false
	}

	slog.WarnContext(ctx, "Cosign attestation layer count exceeds limit",
		"limit", maxReferrers,
		"total", layers,
	)

	stats.record(outcomeLimitExceeded, fmt.Errorf(
		"%w: %d cosign attestation layers, limit %d",
		errReferrerLimitExceeded, layers, maxReferrers,
	))

	return true
}

func (f *OCIFetcher) verifyCosignLayers(
	ctx context.Context, layers []ociV1.Layer, descriptors []ociV1.Descriptor,
	digest string, fetchOpts *FetchOptions,
) ([]VerifiedAttestation, *collectStats, error) {
	var (
		stats        collectStats
		attestations []VerifiedAttestation
		totalSize    int64
	)

	if exceededCosignLayerLimit(ctx, &stats, len(layers)) {
		return nil, &stats, nil
	}

	keys := loadLegacyKeys(ctx, fetchOpts)

	for idx, layer := range layers {
		// Stop at an interruption but keep the outcomes recorded so far, so
		// verification failures still decide over the interruption.
		ctxErr := ctx.Err()
		if ctxErr != nil {
			stats.record(
				outcomeFetchFailed,
				fmt.Errorf("cosign tag discovery interrupted: %w", ctxErr),
			)

			break
		}

		var desc *ociV1.Descriptor
		if idx < len(descriptors) {
			desc = &descriptors[idx]
		}

		att, outcome, err := f.processCosignLayer(ctx, layer, desc, digest, &keys, fetchOpts)
		stats.record(outcome, err)

		if outcome != outcomeVerified {
			continue
		}

		totalSize += int64(len(att.Payload))
		if exceededTotalAttestationSize(ctx, totalSize) {
			stats.record(outcomeLimitExceeded, errAggregateSizeExceeded)

			break
		}

		attestations = append(attestations, att)
	}

	return attestations, &stats, nil
}

// processCosignLayer reads and verifies one cosign attestation layer. desc is
// the layer's manifest descriptor, or nil when the manifest lists fewer
// layers; foreign layers are rejected before anything is downloaded.
func (f *OCIFetcher) processCosignLayer(
	ctx context.Context, layer ociV1.Layer, desc *ociV1.Descriptor,
	digest string, keys *legacyKeys, fetchOpts *FetchOptions,
) (VerifiedAttestation, referrerOutcome, error) {
	var annotations map[string]string

	if desc != nil {
		foreignErr := rejectForeignLayer(desc)
		if foreignErr != nil {
			slog.WarnContext(ctx, "Cosign attestation layer references external URLs, skipping",
				"error", foreignErr,
			)

			return VerifiedAttestation{}, outcomeVerifyFailed, nil
		}

		annotations = desc.Annotations
	}

	data, err := f.readLayer(ctx, layer)
	if err != nil {
		slog.WarnContext(ctx, "Failed to read cosign attestation layer", "error", err)

		outcome, outcomeErr := classifyCosignLayerError(err)

		return VerifiedAttestation{}, outcome, outcomeErr
	}

	candidates := [][]byte{data}

	// Legacy cosign layers are bare DSSE envelopes with the signing material
	// in layer annotations; convert them into verifiable Sigstore bundles.
	if !isSigstoreBundleJSON(data) {
		converted, convErr := legacyLayerToBundles(data, annotations, keys.hints)
		if convErr != nil {
			slog.WarnContext(ctx, "Cosign attestation layer is not a verifiable bundle",
				"error", convErr,
			)

			// Without any loadable trusted key a key-signed layer cannot be
			// checked, which is unavailable trust material rather than a
			// verification failure; see evaluateCollection.
			if errors.Is(convErr, errNoLegacyVerificationMaterial) && keys.err != nil {
				return VerifiedAttestation{}, outcomeKeyUnavailable, keys.err
			}

			return VerifiedAttestation{}, outcomeVerifyFailed, nil
		}

		candidates = converted
	}

	return f.verifyCosignCandidates(ctx, candidates, digest, fetchOpts)
}

// verifyCosignCandidates verifies the bundles derived from one cosign layer
// and returns the first that verifies.
func (f *OCIFetcher) verifyCosignCandidates(
	ctx context.Context, candidates [][]byte, digest string, fetchOpts *FetchOptions,
) (VerifiedAttestation, referrerOutcome, error) {
	if len(candidates) == 0 {
		slog.WarnContext(ctx, "Cosign tag attestation failed verification",
			"error", errNoCosignCandidates,
		)

		return VerifiedAttestation{}, outcomeVerifyFailed, nil
	}

	var verifyErrs []error

	for _, bundleBytes := range candidates {
		verified, verifyErr := f.verifyBundle(ctx, bundleBytes, fetchOpts)
		if verifyErr != nil {
			verifyErrs = append(verifyErrs, verifyErr)

			continue
		}

		att, ok := f.attestationFromVerified(ctx, verified, bundleBytes, digest)
		if !ok {
			return VerifiedAttestation{}, outcomeVerifyFailed, nil
		}

		return att, outcomeVerified, nil
	}

	joined := errors.Join(verifyErrs...)

	slog.WarnContext(ctx, "Cosign tag attestation failed verification", "error", joined)

	if errors.Is(joined, ErrTrustMaterialUnavailable) {
		return VerifiedAttestation{}, trustMaterialOutcome(joined), joined
	}

	return VerifiedAttestation{}, outcomeVerifyFailed, nil
}

func isSigstoreBundleJSON(data []byte) bool {
	var probe struct {
		MediaType string `json:"mediaType"`
	}

	err := json.Unmarshal(data, &probe)

	return err == nil && strings.HasPrefix(probe.MediaType, "application/vnd.dev.sigstore.bundle")
}

// legacyKeys holds the key hints of the trusted keys that legacy key-signed
// cosign layers are tried against, and why any trusted key could not be
// loaded.
type legacyKeys struct {
	hints []string
	// err wraps ErrTrustMaterialUnavailable when a trusted key file could
	// not be loaded.
	err error
}

func loadLegacyKeys(ctx context.Context, opts *FetchOptions) legacyKeys {
	keys := legacyKeys{hints: make([]string, 0, len(opts.TrustedKeys)), err: nil}

	var loadErrs []error

	for idx := range opts.TrustedKeys {
		pub, err := LoadPublicKey(opts.TrustedKeys[idx].Path)
		if err != nil {
			slog.WarnContext(ctx, "Failed to load trusted key for cosign tag discovery",
				"key", opts.TrustedKeys[idx].Path,
				"error", err,
			)

			loadErrs = append(loadErrs, fmt.Errorf(
				"%w: %w: loading public key %q: %w",
				ErrTrustMaterialUnavailable, ErrTrustedKeyUnavailable,
				opts.TrustedKeys[idx].Path, err,
			))

			continue
		}

		hint, err := computeKeyHint(pub)
		if err != nil {
			continue
		}

		keys.hints = append(keys.hints, hint)
	}

	keys.err = errors.Join(loadErrs...)

	return keys
}

func exceededTotalAttestationSize(ctx context.Context, totalSize int64) bool {
	if totalSize <= maxTotalAttestationSize {
		return false
	}

	slog.WarnContext(ctx,
		"Aggregate attestation size exceeds limit, skipping remaining",
		"totalSize", totalSize,
		"limit", maxTotalAttestationSize,
	)

	return true
}

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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/google/go-containerregistry/pkg/name"
	ociV1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"golang.org/x/sync/errgroup"
)

func isNotationCandidate(artifactType string) bool {
	return artifactType == NotationSignatureMediaType
}

func isBaselineSBOM(artifactType string) bool {
	return artifactType == BaselineSBOMArtifactType
}

//nolint:dupl // intentionally similar to collectNotationSignatures
func (f *OCIFetcher) collectBaselineSBOMs(
	ctx context.Context,
	manifests []ociV1.Descriptor, ref name.Digest, digest string,
	remoteOpts []remote.Option,
) []VerifiedAttestation {
	var (
		attsMu    sync.Mutex
		atts      []VerifiedAttestation
		totalSize atomic.Int64
	)

	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(maxConcurrentCollectFetch)

	for idx := range manifests {
		if !isBaselineSBOM(manifests[idx].ArtifactType) {
			continue
		}

		desc := &manifests[idx]

		group.Go(func() error {
			att, ok := f.fetchBaselineSBOM(groupCtx, desc, ref, digest, remoteOpts)
			if !ok {
				return nil
			}

			if totalSize.Add(int64(len(att.Payload))) > maxTotalAttestationSize {
				slog.WarnContext(groupCtx, "Aggregate baseline SBOM size exceeds limit",
					"limit", maxTotalAttestationSize,
				)

				return errAggregateSizeExceeded
			}

			appendAttestation(&attsMu, &atts, &att)

			return nil
		})
	}

	err := group.Wait()
	if err != nil && !errors.Is(err, errAggregateSizeExceeded) {
		slog.WarnContext(ctx, "Unexpected error during baseline SBOM collection", "error", err)
	}

	return atts
}

func (f *OCIFetcher) fetchBaselineSBOM( //nolint:funlen // mirrors fetchNotationSignature
	ctx context.Context,
	desc *ociV1.Descriptor,
	ref name.Digest, digest string,
	remoteOpts []remote.Option,
) (VerifiedAttestation, bool) {
	baseRef := ref.Context().Digest(desc.Digest.String())

	img, err := f.fetchImage(baseRef, remoteOpts...)
	if err != nil {
		slog.WarnContext(ctx, "Failed to fetch baseline SBOM image",
			"digest", desc.Digest.String(),
			"error", err,
		)

		return VerifiedAttestation{}, false
	}

	layers, err := img.Layers()
	if err != nil || len(layers) == 0 {
		slog.WarnContext(ctx, "Baseline SBOM has no layers",
			"digest", desc.Digest.String(),
			"error", err,
		)

		return VerifiedAttestation{}, false
	}

	reader, err := layers[0].Uncompressed()
	if err != nil {
		slog.WarnContext(ctx, "Failed to read baseline SBOM layer",
			"digest", desc.Digest.String(),
			"error", err,
		)

		return VerifiedAttestation{}, false
	}

	defer func() {
		closeErr := reader.Close()
		if closeErr != nil {
			slog.WarnContext(ctx, "Failed to close baseline SBOM layer reader",
				"error", closeErr,
			)
		}
	}()

	maxSize := f.maxAttestationSize.Load()

	data, err := io.ReadAll(io.LimitReader(reader, maxSize+1))
	if err != nil {
		slog.WarnContext(ctx, "Failed to read baseline SBOM data",
			"digest", desc.Digest.String(),
			"error", err,
		)

		return VerifiedAttestation{}, false
	}

	if int64(len(data)) > maxSize {
		slog.WarnContext(ctx, "Baseline SBOM exceeds size limit",
			"size", len(data),
			"limit", maxSize,
		)

		return VerifiedAttestation{}, false
	}

	slog.WarnContext(ctx, "Collected baseline SBOM without bundle verification",
		"digest", desc.Digest.String(),
		"size", len(data),
	)

	return VerifiedAttestation{
		PredicateType: PredicateBaselineSBOM,
		Payload:       data,
		Digest:        digest,
	}, true
}

//nolint:dupl // intentionally similar to collectBaselineSBOMs
func (f *OCIFetcher) collectNotationSignatures(
	ctx context.Context,
	manifests []ociV1.Descriptor, ref name.Digest, digest string,
	remoteOpts []remote.Option,
) []VerifiedAttestation {
	var (
		sigsMu    sync.Mutex
		sigs      []VerifiedAttestation
		totalSize atomic.Int64
	)

	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(maxConcurrentCollectFetch)

	for idx := range manifests {
		if !isNotationCandidate(manifests[idx].ArtifactType) {
			continue
		}

		desc := &manifests[idx]

		group.Go(func() error {
			att, ok := f.fetchNotationSignature(groupCtx, desc, ref, digest, remoteOpts)
			if !ok {
				return nil
			}

			if totalSize.Add(int64(len(att.Payload))) > maxTotalAttestationSize {
				slog.WarnContext(groupCtx, "Aggregate Notation signature size exceeds limit",
					"limit", maxTotalAttestationSize,
				)

				return errAggregateSizeExceeded
			}

			appendAttestation(&sigsMu, &sigs, &att)

			return nil
		})
	}

	err := group.Wait()
	if err != nil && !errors.Is(err, errAggregateSizeExceeded) {
		slog.WarnContext(ctx, "Unexpected error during Notation signature collection", "error", err)
	}

	return sigs
}

func (f *OCIFetcher) fetchNotationSignature(
	ctx context.Context,
	desc *ociV1.Descriptor,
	ref name.Digest, digest string,
	remoteOpts []remote.Option,
) (VerifiedAttestation, bool) {
	sigRef := ref.Context().Digest(desc.Digest.String())

	img, err := f.fetchImage(sigRef, remoteOpts...)
	if err != nil {
		slog.WarnContext(ctx, "Failed to fetch Notation signature image",
			"digest", desc.Digest.String(),
			"error", err,
		)

		return VerifiedAttestation{}, false
	}

	manifest, err := img.Manifest()
	if err != nil || manifest == nil {
		slog.WarnContext(ctx, "Failed to read Notation signature manifest",
			"digest", desc.Digest.String(),
			"error", err,
		)

		return VerifiedAttestation{}, false
	}

	envelope, ok := f.readNotationEnvelope(ctx, img, desc.Digest.String())
	if !ok {
		return VerifiedAttestation{}, false
	}

	att := VerifiedAttestation{
		PredicateType: NotationSignatureMediaType,
		Payload:       envelope,
		Digest:        digest,
		SignatureType: SignatureTypeNotation,
	}

	if manifest.Subject != nil {
		att.NotationSubjectDigest = manifest.Subject.Digest.String()
		att.NotationSubjectSize = manifest.Subject.Size
		att.NotationSubjectMediaType = string(manifest.Subject.MediaType)
	}

	if len(manifest.Layers) > 0 {
		att.NotationMediaType = string(manifest.Layers[0].MediaType)
	}

	return att, true
}

func (f *OCIFetcher) readNotationEnvelope(
	ctx context.Context, img ociV1.Image, descDigest string,
) ([]byte, bool) {
	layers, err := img.Layers()
	if err != nil || len(layers) == 0 {
		slog.WarnContext(ctx, "Notation signature has no layers",
			"digest", descDigest,
			"error", err,
		)

		return nil, false
	}

	reader, err := layers[0].Uncompressed()
	if err != nil {
		slog.WarnContext(ctx, "Failed to read Notation signature layer",
			"digest", descDigest,
			"error", err,
		)

		return nil, false
	}

	defer func() {
		closeErr := reader.Close()
		if closeErr != nil {
			slog.WarnContext(ctx, "Failed to close Notation signature layer reader",
				"error", closeErr,
			)
		}
	}()

	maxSize := f.maxAttestationSize.Load()

	envelope, err := io.ReadAll(io.LimitReader(reader, maxSize+1))
	if err != nil {
		slog.WarnContext(ctx, "Failed to read Notation signature envelope",
			"digest", descDigest,
			"error", err,
		)

		return nil, false
	}

	if int64(len(envelope)) > maxSize {
		slog.WarnContext(ctx, "Notation signature envelope exceeds size limit",
			"size", len(envelope),
			"limit", maxSize,
		)

		return nil, false
	}

	return envelope, true
}

func logReferrers(
	ctx context.Context, ref name.Digest, digest string,
	manifests []ociV1.Descriptor,
) {
	slog.DebugContext(ctx, "Referrers lookup result",
		"ref", ref.String(),
		"digest", digest,
		"manifests_count", len(manifests),
	)

	for i := range manifests {
		slog.DebugContext(ctx, "Referrer manifest",
			"index", i,
			"artifact_type", manifests[i].ArtifactType,
			"digest", manifests[i].Digest.String(),
			"annotations", manifests[i].Annotations,
		)
	}
}

func (f *OCIFetcher) cosignTagFallback(
	ctx context.Context, ref name.Digest, digest string,
	remoteOpts []remote.Option,
	fetchOpts *FetchOptions,
) ([]VerifiedAttestation, error) {
	tagAtts, tagErr := f.fetchCosignTagAttestations(
		ctx, ref, digest, remoteOpts, fetchOpts,
	)
	if tagErr != nil {
		if isAuthError(tagErr) {
			slog.WarnContext(ctx, "Cosign tag-based discovery failed with auth error",
				"error", tagErr,
			)
		} else {
			slog.DebugContext(ctx, "Cosign tag-based discovery failed",
				"error", tagErr,
			)
		}

		return nil, nil
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

func (f *OCIFetcher) fetchCosignTagAttestations(
	ctx context.Context, ref name.Digest, digest string,
	remoteOpts []remote.Option,
	fetchOpts *FetchOptions,
) ([]VerifiedAttestation, error) {
	attTag := cosignAttestationTag(ref)

	slog.DebugContext(ctx, "Trying cosign tag-based attestation discovery",
		"tag", attTag.String(),
	)

	img, fetchErr := f.fetchImage(attTag, remoteOpts...)
	if fetchErr != nil {
		if isRegistryNotFound(fetchErr) {
			return nil, nil
		}

		return nil, fmt.Errorf(
			"fetching cosign attestation tag %q: %w", attTag.String(), fetchErr,
		)
	}

	layers, layerErr := img.Layers()
	if layerErr != nil {
		return nil, fmt.Errorf("reading cosign attestation layers: %w", layerErr)
	}

	var (
		attestations []VerifiedAttestation
		totalSize    int64
	)

	for idx, layer := range layers {
		ctxErr := ctx.Err()
		if ctxErr != nil {
			return nil, fmt.Errorf("cosign tag discovery interrupted: %w", ctxErr)
		}

		if idx >= maxReferrers {
			slog.WarnContext(ctx, "Cosign attestation layer count exceeds limit",
				"limit", maxReferrers,
				"total", len(layers),
			)

			break
		}

		att, ok := f.processCosignLayer(ctx, layer, digest, fetchOpts)
		if ok {
			totalSize += int64(len(att.Payload))
			if exceededTotalAttestationSize(ctx, totalSize) {
				break
			}

			attestations = append(attestations, att)
		}
	}

	return attestations, nil
}

func (f *OCIFetcher) processCosignLayer(
	ctx context.Context, layer ociV1.Layer, digest string,
	fetchOpts *FetchOptions,
) (VerifiedAttestation, bool) {
	reader, readErr := layer.Uncompressed()
	if readErr != nil {
		slog.WarnContext(ctx, "Failed to read cosign attestation layer",
			"error", readErr,
		)

		return VerifiedAttestation{}, false
	}

	defer func() {
		closeErr := reader.Close()
		if closeErr != nil {
			slog.WarnContext(ctx, "Failed to close cosign layer reader",
				"error", closeErr,
			)
		}
	}()

	maxSize := f.maxAttestationSize.Load()

	data, dataErr := io.ReadAll(io.LimitReader(reader, maxSize+1))
	if dataErr != nil {
		slog.WarnContext(ctx, "Failed to read cosign attestation data",
			"error", dataErr,
		)

		return VerifiedAttestation{}, false
	}

	if int64(len(data)) > maxSize {
		slog.WarnContext(ctx, "Cosign attestation exceeds size limit",
			"size", len(data),
			"limit", maxSize,
		)

		return VerifiedAttestation{}, false
	}

	payload, verifyErr := f.verifyBundle(ctx, data, fetchOpts)
	if verifyErr != nil {
		slog.DebugContext(ctx, "Cosign tag layer is not a valid sigstore bundle",
			"error", verifyErr,
		)

		return VerifiedAttestation{}, false
	}

	predicateType := extractPredicateType(payload)

	return VerifiedAttestation{
		PredicateType: predicateType,
		Payload:       payload,
		Digest:        digest,
		SignatureType: SignatureTypeSigstore,
	}, true
}

func extractPredicateType(payload []byte) string {
	dec := json.NewDecoder(bytes.NewReader(payload))

	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return ""
	}

	for dec.More() {
		key, keyErr := dec.Token()
		if keyErr != nil {
			return ""
		}

		if key == "predicateType" {
			var val string

			valErr := dec.Decode(&val)
			if valErr != nil {
				return ""
			}

			return val
		}

		var skip json.RawMessage

		skipErr := dec.Decode(&skip)
		if skipErr != nil {
			return ""
		}
	}

	return ""
}

func (f *OCIFetcher) collectAttestations(
	ctx context.Context, manifests []ociV1.Descriptor,
	ref name.Digest, digest string, remoteOpts []remote.Option,
	fetchOpts *FetchOptions,
) ([]VerifiedAttestation, bool) {
	candidates := filterBundleCandidates(ctx, manifests)
	if len(candidates) == 0 {
		return nil, false
	}

	var (
		attsMu       sync.Mutex
		attestations []VerifiedAttestation
		totalSize    atomic.Int64
	)

	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(maxConcurrentCollectFetch)

	for _, desc := range candidates {
		group.Go(func() error {
			if groupCtx.Err() != nil {
				return nil //nolint:nilerr // context cancelled, skip remaining
			}

			predicateType := desc.Annotations[annotationPredicateType]

			att, valid := f.processDescriptor(
				groupCtx, desc, ref, digest,
				predicateType, remoteOpts, fetchOpts,
			)
			if !valid {
				return nil
			}

			newTotal := totalSize.Add(int64(len(att.Payload)))
			if newTotal > maxTotalAttestationSize {
				slog.WarnContext(groupCtx,
					"Aggregate attestation size exceeds limit, skipping remaining",
					"totalSize", newTotal,
					"limit", maxTotalAttestationSize,
				)

				return errAggregateSizeExceeded
			}

			appendAttestation(&attsMu, &attestations, &att)

			return nil
		})
	}

	// errAggregateSizeExceeded cancels the group context; log unexpected errors.
	err := group.Wait()
	if err != nil && !errors.Is(err, errAggregateSizeExceeded) {
		slog.WarnContext(ctx, "Unexpected error during attestation collection", "error", err)
	}

	return attestations, true
}

func filterBundleCandidates(
	ctx context.Context, manifests []ociV1.Descriptor,
) []*ociV1.Descriptor {
	var candidates []*ociV1.Descriptor

	for idx := range manifests {
		if !isBundleCandidate(manifests[idx].ArtifactType) {
			continue
		}

		if len(candidates) >= maxReferrers {
			slog.WarnContext(ctx, "Referrer count exceeds limit, skipping remaining",
				"limit", maxReferrers,
				"totalManifests", len(manifests),
			)

			break
		}

		candidates = append(candidates, &manifests[idx])
	}

	return candidates
}

func isBundleCandidate(artifactType string) bool {
	switch artifactType {
	case bundleMediaType, ociEmptyMediaType, "":
		return true
	default:
		return false
	}
}

func appendAttestation(mu *sync.Mutex, dst *[]VerifiedAttestation, att *VerifiedAttestation) {
	mu.Lock()
	defer mu.Unlock()

	*dst = append(*dst, *att)
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

func isRegistryNotFound(err error) bool {
	var transportErr *transport.Error

	return errors.As(err, &transportErr) &&
		transportErr.StatusCode == http.StatusNotFound
}

func isAuthError(err error) bool {
	var transportErr *transport.Error

	return errors.As(err, &transportErr) &&
		(transportErr.StatusCode == http.StatusUnauthorized ||
			transportErr.StatusCode == http.StatusForbidden)
}

func (f *OCIFetcher) processDescriptor(
	ctx context.Context, desc *ociV1.Descriptor,
	ref name.Digest, digest, predicateType string, remoteOpts []remote.Option,
	fetchOpts *FetchOptions,
) (VerifiedAttestation, bool) {
	attestRef := ref.Context().Digest(desc.Digest.String())

	img, err := f.fetchImage(attestRef, remoteOpts...)
	if err != nil {
		slog.WarnContext(ctx, "Failed to fetch attestation image",
			"digest", desc.Digest.String(),
			"error", err,
		)

		return VerifiedAttestation{}, false
	}

	if predicateType == "" {
		predicateType = resolvePredicateFromManifest(ctx, img, desc.Digest.String())
	}

	if predicateType == "" {
		slog.DebugContext(ctx, "Skipping referrer without predicate type",
			"digest", desc.Digest.String(),
		)

		return VerifiedAttestation{}, false
	}

	payload, extractErr := f.extractPayloadFromImage(ctx, img, fetchOpts)
	if extractErr != nil {
		slog.WarnContext(ctx, "Failed to extract attestation payload",
			"digest", desc.Digest.String(),
			"error", extractErr,
		)

		return VerifiedAttestation{}, false
	}

	if payloadPredType := extractPredicateType(payload); payloadPredType != "" {
		predicateType = payloadPredType
	}

	return VerifiedAttestation{
		PredicateType: predicateType,
		Payload:       payload,
		Digest:        digest,
		SignatureType: SignatureTypeSigstore,
	}, true
}

func resolvePredicateFromManifest(ctx context.Context, img ociV1.Image, descDigest string) string {
	manifest, err := img.Manifest()
	if err != nil {
		slog.DebugContext(ctx, "Failed to read manifest for predicate type resolution",
			"digest", descDigest,
			"error", err,
		)

		return ""
	}

	if manifest == nil {
		return ""
	}

	return manifest.Annotations[annotationPredicateType]
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

func (f *OCIFetcher) extractPayloadFromImage(
	ctx context.Context,
	img ociV1.Image,
	fetchOpts *FetchOptions,
) ([]byte, error) {
	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("reading attestation layers: %w", err)
	}

	if len(layers) == 0 {
		return nil, fmt.Errorf("attestation has no layers: %w", errEmptyAttestation)
	}

	reader, err := layers[0].Uncompressed()
	if err != nil {
		return nil, fmt.Errorf("reading attestation layer: %w", err)
	}

	defer func() {
		closeErr := reader.Close()
		if closeErr != nil {
			slog.WarnContext(ctx, "Failed to close attestation layer reader",
				"error", closeErr,
			)
		}
	}()

	maxSize := f.maxAttestationSize.Load()
	limited := io.LimitReader(reader, maxSize+1)

	bundleBytes, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("reading attestation bundle: %w", err)
	}

	if int64(len(bundleBytes)) > maxSize {
		return nil, fmt.Errorf(
			"attestation size %d exceeds limit of %d bytes: %w",
			len(bundleBytes), maxSize, errAttestationTooLarge,
		)
	}

	return f.verifyBundle(ctx, bundleBytes, fetchOpts)
}

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
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/google/go-containerregistry/pkg/name"
	ociV1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"golang.org/x/sync/errgroup"

	"github.com/saschagrunert/nri-supply-chain/internal/intoto"
)

//nolint:gochecknoglobals // immutable magic byte prefixes
var (
	gzipMagic = []byte{0x1f, 0x8b}
	zstdMagic = []byte{0x28, 0xb5, 0x2f, 0xfd}
)

// referrerOutcome classifies what happened to a single referrer candidate.
type referrerOutcome int

const (
	// outcomeVerified means the referrer produced a verified attestation.
	outcomeVerified referrerOutcome = iota
	// outcomeSkipped means the referrer is not relevant (for example gone).
	outcomeSkipped
	// outcomeVerifyFailed means signed material or referrer content was found
	// but did not verify or could not be parsed.
	outcomeVerifyFailed
	// outcomeFetchFailed means the registry could not serve the referrer or
	// the trust material to verify it was unavailable.
	outcomeFetchFailed
	// outcomeLimitExceeded means the referrer was dropped because a size or
	// count limit was exceeded, so the attestation set is incomplete.
	outcomeLimitExceeded
)

// collectStats aggregates referrer outcomes of one collection pass.
type collectStats struct {
	mu             sync.Mutex
	verifyFailures int
	fetchErr       error
	limitErr       error
}

func (s *collectStats) record(outcome referrerOutcome, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch outcome {
	case outcomeVerifyFailed:
		s.verifyFailures++
	case outcomeFetchFailed:
		if s.fetchErr == nil {
			s.fetchErr = err
		}
	case outcomeLimitExceeded:
		if s.limitErr == nil {
			s.limitErr = err
		}
	case outcomeVerified, outcomeSkipped:
	}
}

func (s *collectStats) merge(other *collectStats) {
	s.verifyFailures += other.verifyFailures

	if s.fetchErr == nil {
		s.fetchErr = other.fetchErr
	}

	if s.limitErr == nil {
		s.limitErr = other.limitErr
	}
}

// referrerSelection is the budgeted set of referrers considered for an image.
type referrerSelection struct {
	bundles   []*ociV1.Descriptor
	notation  []*ociV1.Descriptor
	baselines []*ociV1.Descriptor
	// dropped counts relevant referrers left out because a budget was
	// exhausted or their manifest was oversized.
	dropped int
}

// referrerKind classifies a referrer descriptor for budgeting.
type referrerKind int

const (
	referrerIgnored referrerKind = iota
	referrerBundle
	referrerGenericBundle
	referrerNotation
	referrerBaseline
)

func classifyReferrer(desc *ociV1.Descriptor) referrerKind {
	switch {
	case desc.ArtifactType == bundleMediaType:
		return bundleKind(desc, referrerBundle)
	case isGenericBundleCandidate(desc.ArtifactType):
		return bundleKind(desc, referrerGenericBundle)
	case isNotationCandidate(desc.ArtifactType):
		return referrerNotation
	case isBaselineSBOM(desc.ArtifactType):
		return referrerBaseline
	default:
		return referrerIgnored
	}
}

// bundleKind skips cosign signature bundles, which are not attestations.
func bundleKind(desc *ociV1.Descriptor, kind referrerKind) referrerKind {
	if desc.Annotations[annotationPredicateType] == PredicateCosignSignature {
		return referrerIgnored
	}

	return kind
}

// add places desc into its budgeted bucket and reports whether the referrer
// was dropped because the budget is exhausted or the manifest is oversized.
func (s *referrerSelection) add(kind referrerKind, desc *ociV1.Descriptor) (dropped bool) {
	if kind != referrerIgnored && desc.Size > maxReferrerManifestSize {
		return true
	}

	switch kind {
	case referrerBundle, referrerGenericBundle:
		return !appendBudgeted(&s.bundles, desc, maxReferrers)
	case referrerNotation:
		return !appendBudgeted(&s.notation, desc, maxNotationReferrers)
	case referrerBaseline:
		return !appendBudgeted(&s.baselines, desc, maxBaselineReferrers)
	case referrerIgnored:
		return false
	default:
		return false
	}
}

// appendBudgeted appends desc when the bucket has room and reports whether it
// was added.
func appendBudgeted(bucket *[]*ociV1.Descriptor, desc *ociV1.Descriptor, limit int) bool {
	if len(*bucket) >= limit {
		return false
	}

	*bucket = append(*bucket, desc)

	return true
}

// selectReferrers applies the referrer budget to the distinct referrer
// manifests of an image. Exact Sigstore bundle media types are preferred over
// generic artifact types. Cosign signature bundles (not attestations) and
// unrelated artifact types are skipped before any blob is fetched. Relevant
// referrers that do not fit the budget or whose manifest is oversized are
// counted as dropped; the caller must not evaluate such an incomplete set.
func selectReferrers(ctx context.Context, manifests []ociV1.Descriptor) referrerSelection {
	var (
		selection referrerSelection
		generic   []*ociV1.Descriptor
	)

	seen := make(map[ociV1.Hash]struct{}, len(manifests))

	for idx := range manifests {
		desc := &manifests[idx]

		if _, duplicate := seen[desc.Digest]; duplicate {
			continue
		}

		seen[desc.Digest] = struct{}{}

		kind := classifyReferrer(desc)

		// Generic candidates only get the budget left after exact matches.
		if kind == referrerGenericBundle {
			generic = append(generic, desc)

			continue
		}

		if selection.add(kind, desc) {
			selection.dropped++
		}
	}

	for _, desc := range generic {
		if selection.add(referrerGenericBundle, desc) {
			selection.dropped++
		}
	}

	if selection.dropped > 0 {
		slog.WarnContext(ctx, "Referrer limits exceeded, attestation set is incomplete",
			"dropped", selection.dropped,
			"totalManifests", len(manifests),
			"maxBundles", maxReferrers,
			"maxNotation", maxNotationReferrers,
			"maxBaselines", maxBaselineReferrers,
			"maxManifestSize", maxReferrerManifestSize,
		)
	}

	return selection
}

func isNotationCandidate(artifactType string) bool {
	return artifactType == NotationSignatureMediaType
}

func isBaselineSBOM(artifactType string) bool {
	return artifactType == BaselineSBOMArtifactType
}

func isGenericBundleCandidate(artifactType string) bool {
	return artifactType == ociEmptyMediaType || artifactType == ""
}

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

func (f *OCIFetcher) collectNotationSignatures(
	ctx context.Context,
	candidates []*ociV1.Descriptor, ref name.Digest, digest string,
	remoteOpts []remote.Option,
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
			att, outcome, err := f.fetchNotationSignature(groupCtx, desc, ref, digest, remoteOpts)
			stats.record(outcome, err)

			if outcome != outcomeVerified {
				return nil
			}

			if totalSize.Add(int64(len(att.Payload))) > maxTotalAttestationSize {
				slog.WarnContext(groupCtx, "Aggregate Notation signature size exceeds limit",
					"limit", maxTotalAttestationSize,
				)

				stats.record(outcomeLimitExceeded, errAggregateSizeExceeded)

				return errAggregateSizeExceeded
			}

			slots[idx] = &att

			return nil
		})
	}

	err := group.Wait()
	if err != nil && !errors.Is(err, errAggregateSizeExceeded) {
		slog.WarnContext(ctx, "Unexpected error during Notation signature collection", "error", err)
	}

	return compactSlots(slots), &stats
}

func (f *OCIFetcher) fetchNotationSignature(
	ctx context.Context,
	desc *ociV1.Descriptor,
	ref name.Digest, digest string,
	remoteOpts []remote.Option,
) (VerifiedAttestation, referrerOutcome, error) {
	sigRef := ref.Context().Digest(desc.Digest.String())

	err := chargeManifestDownload(ctx, desc)
	if err != nil {
		return VerifiedAttestation{}, outcomeLimitExceeded, err
	}

	img, err := f.fetchImage(sigRef, remoteOpts...)
	if err != nil {
		return VerifiedAttestation{}, classifyFetchError(
			ctx,
			"Notation signature image",
			desc,
			err,
		), err
	}

	manifest, err := img.Manifest()
	if err != nil {
		return VerifiedAttestation{}, classifyFetchError(
			ctx,
			"Notation signature manifest",
			desc,
			err,
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
		return VerifiedAttestation{}, classifyReadError(
			ctx,
			"Notation signature envelope",
			desc,
			err,
		), err
	}

	return notationAttestation(manifest, envelope, digest), outcomeVerified, nil
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

// readFirstLayer reads the first layer of an artifact image, bounded by the
// configured attestation size limit. Content problems (no layers, undecodable
// data) wrap errInvalidReferrer or errEmptyAttestation and oversized layers
// wrap errAttestationTooLarge; other errors come from the registry.
func (f *OCIFetcher) readFirstLayer(ctx context.Context, img ociV1.Image) ([]byte, error) {
	manifest, err := img.Manifest()
	if err != nil {
		return nil, fmt.Errorf("reading attestation manifest: %w", err)
	}

	if manifest != nil && len(manifest.Layers) > 0 {
		err = rejectForeignLayer(&manifest.Layers[0])
		if err != nil {
			return nil, err
		}
	}

	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("reading attestation layers: %w", err)
	}

	if len(layers) == 0 {
		return nil, fmt.Errorf("attestation has no layers: %w", errEmptyAttestation)
	}

	return f.readLayer(ctx, layers[0])
}

// rejectForeignLayer refuses layer descriptors that list external URLs.
// go-containerregistry falls back to those URLs when the registry does not
// serve the blob, so a manifest pushed by anyone with push access could make
// the plugin contact arbitrary hosts and turn their responses into transport
// failures. Attestation layers are always served by the registry itself.
func rejectForeignLayer(desc *ociV1.Descriptor) error {
	if len(desc.URLs) == 0 {
		return nil
	}

	return fmt.Errorf("%w: %w: %d URLs", errInvalidReferrer, errForeignLayer, len(desc.URLs))
}

// readLayer downloads the stored (compressed) layer blob first and decodes it
// in memory afterwards. Errors while downloading come from the registry, so
// a network problem is never mistaken for bad content; errors while decoding
// are content errors, so malformed data pushed to a registry is never
// mistaken for a network problem.
func (f *OCIFetcher) readLayer(ctx context.Context, layer ociV1.Layer) ([]byte, error) {
	maxSize := f.maxAttestationSize.Load()

	// Check the declared size first so oversized blobs are never downloaded.
	declared, sizeErr := layer.Size()
	if sizeErr == nil && declared > maxSize {
		return nil, fmt.Errorf(
			"attestation size %d exceeds limit of %d bytes: %w",
			declared, maxSize, errAttestationTooLarge,
		)
	}

	if sizeErr == nil {
		err := reserveDownload(ctx, declared)
		if err != nil {
			return nil, err
		}
	}

	stored, err := readBounded(ctx, layer.Compressed, maxSize)
	if err != nil {
		return nil, err
	}

	err = chargeDownload(ctx, int64(len(stored)))
	if err != nil {
		return nil, err
	}

	return decodeLayer(stored, maxSize)
}

// chargeManifestDownload charges the declared size of a referrer manifest
// against the download budget before the manifest is fetched.
func chargeManifestDownload(ctx context.Context, desc *ociV1.Descriptor) error {
	return chargeDownload(ctx, max(desc.Size, 0))
}

func readBounded(
	ctx context.Context, open func() (io.ReadCloser, error), maxSize int64,
) ([]byte, error) {
	reader, err := open()
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

	data, err := io.ReadAll(io.LimitReader(reader, maxSize+1))
	if err != nil {
		// A body that ends early while downloading is a truncated registry
		// response. It is tagged here, where the bytes come off the wire,
		// because decoding errors of the same kind are content problems.
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, fmt.Errorf("reading attestation layer: %w: %w", errTruncatedResponse, err)
		}

		return nil, fmt.Errorf("reading attestation layer: %w", err)
	}

	if int64(len(data)) > maxSize {
		return nil, fmt.Errorf(
			"attestation size %d exceeds limit of %d bytes: %w",
			len(data), maxSize, errAttestationTooLarge,
		)
	}

	return data, nil
}

// decodeLayer decompresses gzip layer data in memory. Attestation layers are
// normally stored uncompressed and returned unchanged.
func decodeLayer(data []byte, maxSize int64) ([]byte, error) {
	if bytes.HasPrefix(data, zstdMagic) {
		return nil, fmt.Errorf("%w: %w: zstd", errInvalidReferrer, errUnsupportedLayerCodec)
	}

	if !bytes.HasPrefix(data, gzipMagic) {
		return data, nil
	}

	gzipReader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("%w: decompressing attestation layer: %w", errInvalidReferrer, err)
	}

	defer func() { _ = gzipReader.Close() }()

	decoded, err := io.ReadAll(io.LimitReader(gzipReader, maxSize+1))
	if err != nil {
		return nil, fmt.Errorf("%w: decompressing attestation layer: %w", errInvalidReferrer, err)
	}

	if int64(len(decoded)) > maxSize {
		return nil, fmt.Errorf(
			"decompressed attestation size exceeds limit of %d bytes: %w",
			maxSize, errAttestationTooLarge,
		)
	}

	return decoded, nil
}

func isContentError(err error) bool {
	return errors.Is(err, errEmptyAttestation) || errors.Is(err, errInvalidReferrer)
}

// isTransportFailure reports whether err means that the registry could not
// be reached or refused to serve a request, as opposed to serving content
// that is malformed. Only transport failures may be handled with the fetch
// failure policy. Everything else counts as a verification failure, so junk
// pushed to a registry (an index where an attestation manifest is expected,
// undecodable layers, broken manifests) can never turn a deny into a lenient
// fetch failure.
func isTransportFailure(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}

	if transportErr, ok := errors.AsType[*transport.Error](err); ok {
		switch transportErr.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden,
			http.StatusRequestTimeout, http.StatusTooManyRequests:
			return true
		default:
			return transportErr.StatusCode >= http.StatusInternalServerError
		}
	}

	if _, ok := errors.AsType[net.Error](err); ok {
		return true
	}

	// Only a body that ended early while it was downloaded (see readBounded)
	// is a truncated response. The same io.ErrUnexpectedEOF also comes from
	// decoding a truncated manifest or layer, which is malformed content.
	return errors.Is(err, errTruncatedResponse)
}

// isReferrerTransportFailure reports whether an error fetching a listed
// referrer (its manifest or blob) is a transport failure. It is stricter than
// isTransportFailure for authorization errors: the referrers listing already
// succeeded with the same credentials, so a 401 or 403 for one referrer is a
// per-artifact decision of the registry (for example a policy engine blocking
// a freshly pushed artifact). Treating it as a transport failure would let
// anyone who can push such an artifact turn a deny into the fetch failure
// policy, so it counts as a verification failure instead.
func isReferrerTransportFailure(err error) bool {
	if transportErr, ok := errors.AsType[*transport.Error](err); ok {
		switch transportErr.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			return false
		default:
		}
	}

	return isTransportFailure(err)
}

// classifyFetchError maps an error from fetching a referrer manifest to an
// outcome. A referrer that no longer exists is skipped, a transport failure
// makes the attestation set incomplete, and any other error means the
// registry served content that is not a valid attestation.
func classifyFetchError(
	ctx context.Context, what string, desc *ociV1.Descriptor, err error,
) referrerOutcome {
	if isRegistryNotFound(err) {
		slog.WarnContext(ctx, "Referrer listed but not found, skipping",
			"kind", what,
			"digest", desc.Digest.String(),
		)

		return outcomeSkipped
	}

	if !isContentError(err) && isReferrerTransportFailure(err) {
		slog.WarnContext(ctx, "Failed to fetch referrer",
			"kind", what,
			"digest", desc.Digest.String(),
			"error", err,
		)

		return outcomeFetchFailed
	}

	slog.WarnContext(ctx, "Invalid referrer content",
		"kind", what,
		"digest", desc.Digest.String(),
		"error", err,
	)

	return outcomeVerifyFailed
}

// classifyReadError maps an error from reading a referrer layer to an
// outcome. Oversized layers exceed a limit, so the attestation set is
// incomplete and must not be evaluated.
func classifyReadError(
	ctx context.Context, what string, desc *ociV1.Descriptor, err error,
) referrerOutcome {
	switch {
	case errors.Is(err, errAttestationTooLarge), errors.Is(err, errDownloadLimitExceeded):
		slog.WarnContext(ctx, "Referrer exceeds the attestation size limit",
			"kind", what,
			"digest", desc.Digest.String(),
			"error", err,
		)

		return outcomeLimitExceeded
	case isContentError(err):
		slog.WarnContext(ctx, "Invalid referrer content",
			"kind", what,
			"digest", desc.Digest.String(),
			"error", err,
		)

		return outcomeVerifyFailed
	default:
		return classifyFetchError(ctx, what, desc, err)
	}
}

func logReferrers(
	ctx context.Context, ref name.Digest, digest string,
	manifests []ociV1.Descriptor,
) {
	if !slog.Default().Enabled(ctx, slog.LevelDebug) {
		return
	}

	slog.DebugContext(ctx, "Referrers lookup result",
		"ref", ref.String(),
		"digest", digest,
		"manifests_count", len(manifests),
	)

	for idx := range manifests {
		if idx >= maxLoggedReferrers {
			break
		}

		slog.DebugContext(ctx, "Referrer manifest",
			"index", idx,
			"artifact_type", manifests[idx].ArtifactType,
			"digest", manifests[idx].Digest.String(),
			"annotations", manifests[idx].Annotations,
		)
	}
}

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

// classifyCosignLayerError maps an error from reading a cosign attestation
// layer to an outcome.
// Content errors are checked first: decoding a truncated layer fails with the
// same io.ErrUnexpectedEOF that a dropped connection produces.
func classifyCosignLayerError(err error) (referrerOutcome, error) {
	switch {
	case errors.Is(err, errAttestationTooLarge), errors.Is(err, errDownloadLimitExceeded):
		return outcomeLimitExceeded, err
	case isContentError(err):
		return outcomeVerifyFailed, nil
	case isReferrerTransportFailure(err):
		return outcomeFetchFailed, err
	default:
		return outcomeVerifyFailed, nil
	}
}

// tagContentError keeps transport failures as plain fetch errors and marks
// every other error on the cosign attestation tag as a verification failure.
func tagContentError(err error) error {
	if !isContentError(err) && isTransportFailure(err) {
		return err
	}

	return fmt.Errorf("%w: %w: %w", ErrVerificationFailed, errInvalidReferrer, err)
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

	keyHints := trustedKeyHints(ctx, fetchOpts)

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

		att, outcome, err := f.processCosignLayer(ctx, layer, desc, digest, keyHints, fetchOpts)
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
	digest string, keyHints []string, fetchOpts *FetchOptions,
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
		converted, convErr := legacyLayerToBundles(data, annotations, keyHints)
		if convErr != nil {
			slog.WarnContext(ctx, "Cosign attestation layer is not a verifiable bundle",
				"error", convErr,
			)

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
		return VerifiedAttestation{}, outcomeFetchFailed, joined
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

func trustedKeyHints(ctx context.Context, opts *FetchOptions) []string {
	hints := make([]string, 0, len(opts.TrustedKeys))

	for idx := range opts.TrustedKeys {
		pub, err := loadPublicKeyFromPEM(opts.TrustedKeys[idx].Path)
		if err != nil {
			slog.WarnContext(ctx, "Failed to load trusted key for cosign tag discovery",
				"key", opts.TrustedKeys[idx].Path,
				"error", err,
			)

			continue
		}

		hint, err := computeKeyHint(pub)
		if err != nil {
			continue
		}

		hints = append(hints, hint)
	}

	return hints
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

// collectBundles fetches and verifies Sigstore bundle referrers.
func (f *OCIFetcher) collectBundles(
	ctx context.Context, candidates []*ociV1.Descriptor,
	ref name.Digest, digest string, remoteOpts []remote.Option,
	fetchOpts *FetchOptions,
) ([]VerifiedAttestation, *collectStats) {
	var (
		totalSize atomic.Int64
		stats     collectStats
		seen      blobSet
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

			att, outcome, err := f.processDescriptor(
				groupCtx, desc, ref, digest, remoteOpts, fetchOpts, &seen,
			)
			stats.record(outcome, err)

			if outcome != outcomeVerified {
				return nil
			}

			newTotal := totalSize.Add(int64(len(att.Payload)))
			if newTotal > maxTotalAttestationSize {
				slog.WarnContext(groupCtx,
					"Aggregate attestation size exceeds limit, attestation set is incomplete",
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
		slog.WarnContext(ctx, "Unexpected error during attestation collection", "error", err)
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

	err := chargeManifestDownload(ctx, desc)
	if err != nil {
		return VerifiedAttestation{}, outcomeLimitExceeded, err
	}

	img, err := f.fetchImage(attestRef, remoteOpts...)
	if err != nil {
		return VerifiedAttestation{}, classifyFetchError(ctx, "attestation image", desc, err), err
	}

	bundleBytes, err := f.readFirstLayer(ctx, img)
	if err != nil {
		return VerifiedAttestation{}, classifyReadError(ctx, "attestation layer", desc, err), err
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
			return VerifiedAttestation{}, outcomeFetchFailed, err
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

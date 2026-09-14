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
	"crypto"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"golang.org/x/sync/singleflight"
	"golang.org/x/time/rate"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/registry"
)

// ExportDefaultVerifyBundle exposes verifyBundleWithCache (nil cache) for external tests.
func ExportDefaultVerifyBundle(
	ctx context.Context, data []byte,
	opts *FetchOptions,
) (*VerifiedBundle, error) {
	return verifyBundleWithCache(ctx, data, opts, nil)
}

// ExportVerifyBundleWithRoots verifies a bundle against the given trusted
// roots, each scoped to the matching issuer list. skipSCTs disables the SCT
// requirement for virtual Fulcio instances.
func ExportVerifyBundleWithRoots(
	ctx context.Context, data []byte, opts *FetchOptions,
	roots []*root.TrustedRoot, issuers [][]string, skipSCTs bool,
) (*VerifiedBundle, error) {
	sources := make([]rootSource, 0, len(roots))

	for idx, trustedRoot := range roots {
		var scoped []string
		if idx < len(issuers) {
			scoped = issuers[idx]
		}

		sources = append(sources, rootSource{
			name:    "test",
			issuers: scoped,
			get: func(context.Context) (*root.TrustedRoot, error) {
				return trustedRoot, nil
			},
			keylessDisabled: false,
			skipSCTs:        skipSCTs,
		})
	}

	return verifyBundleCommon(ctx, data, opts, sources)
}

// ExportVerifyBundleWithFailingRoot verifies a bundle against a single root
// source whose trusted root cannot be fetched.
func ExportVerifyBundleWithFailingRoot(
	ctx context.Context, data []byte, opts *FetchOptions, rootErr error,
) (*VerifiedBundle, error) {
	return verifyBundleCommon(ctx, data, opts, []rootSource{{
		name:    "failing",
		issuers: nil,
		get: func(context.Context) (*root.TrustedRoot, error) {
			return nil, rootErr
		},
		keylessDisabled: false,
		skipSCTs:        true,
	}})
}

// ExportScopeIssuers exposes scopeIssuers for external tests.
func ExportScopeIssuers(policyIssuers, rootIssuers []string) []string {
	return scopeIssuers(policyIssuers, rootIssuers)
}

// ExportLegacyLayerToBundles exposes legacyLayerToBundles for external tests.
func ExportLegacyLayerToBundles(
	envelopeJSON []byte, annotations map[string]string, keyHints []string,
) ([][]byte, error) {
	return legacyLayerToBundles(envelopeJSON, annotations, keyHints)
}

// ExportBuildCertificateID exposes buildCertificateIdentity for external tests.
func ExportBuildCertificateID(issuers, sanPatterns []string) (verify.CertificateIdentity, error) {
	return buildCertificateIdentity(issuers, sanPatterns)
}

// ExportBuildKeyMaterial exposes buildKeyMaterial for external tests.
func ExportBuildKeyMaterial(keys []TrustedKeyRef) (*root.TrustedPublicKeyMaterial, error) {
	loaded, err := buildKeyMaterial(keys)
	if err != nil {
		return nil, err
	}

	return loaded.material, nil
}

// ExportBuildKeyMaterialPaths exposes the configured paths per key hint of
// buildKeyMaterial.
func ExportBuildKeyMaterialPaths(keys []TrustedKeyRef) (map[string][]string, error) {
	loaded, err := buildKeyMaterial(keys)
	if err != nil {
		return nil, err
	}

	paths := make(map[string][]string, len(loaded.byHint))

	for hint, key := range loaded.byHint {
		for idx := range key.entries {
			paths[hint] = append(paths[hint], key.entries[idx].path)
		}
	}

	return paths, nil
}

// ExportLoadPublicKeyFromPEM exposes loadPublicKeyFromPEM for external tests.
func ExportLoadPublicKeyFromPEM(path string) (crypto.PublicKey, error) {
	return loadPublicKeyFromPEM(path)
}

// ExportParseDigestRef exposes parseDigestRef for external tests.
func ExportParseDigestRef(imageRef, digest string) (name.Digest, error) {
	return parseDigestRef(imageRef, digest, nil)
}

// ExportComputeKeyHint exposes computeKeyHint for external tests.
func ExportComputeKeyHint(pub crypto.PublicKey) (string, error) {
	return computeKeyHint(pub)
}

// ExportExtractVerifiedPayload exposes extractVerifiedPayload for external tests.
func ExportExtractVerifiedPayload(bndl *bundle.Bundle) ([]byte, error) {
	return extractVerifiedPayload(bndl)
}

// ExportErrEmptyAttestation returns the errEmptyAttestation sentinel for external tests.
func ExportErrEmptyAttestation() error { return errEmptyAttestation }

// ExportErrAttestationTooLarge returns the errAttestationTooLarge sentinel for external tests.
func ExportErrAttestationTooLarge() error { return errAttestationTooLarge }

// ExportErrInvalidPayloadType returns the errInvalidPayloadType sentinel for external tests.
func ExportErrInvalidPayloadType() error { return errInvalidPayloadType }

// ExportErrNoTrustedMaterial returns the errNoTrustedMaterial sentinel for external tests.
func ExportErrNoTrustedMaterial() error { return errNoTrustedMaterial }

// ExportErrNoTrustedRoot returns the errNoTrustedRoot sentinel for external tests.
func ExportErrNoTrustedRoot() error { return errNoTrustedRoot }

// ExportErrNoTrustedIssuers returns the errNoTrustedIssuers sentinel for external tests.
func ExportErrNoTrustedIssuers() error { return errNoTrustedIssuers }

// ExportErrMissingPredicateType returns the errMissingPredicateType sentinel for external tests.
func ExportErrMissingPredicateType() error { return errMissingPredicateType }

// ExportErrAllBundlesFailed returns the errAllBundlesFailed sentinel for external tests.
func ExportErrAllBundlesFailed() error { return errAllBundlesFailed }

// ExportMaxReferrers returns the maxReferrers constant for external tests.
func ExportMaxReferrers() int { return maxReferrers }

// VerifyBundle exposes the OCIFetcher's verifyBundle for testing.
func (f *OCIFetcher) VerifyBundle(
	ctx context.Context, data []byte,
	opts *FetchOptions,
) ([]byte, error) {
	verified, err := f.verifyBundle(ctx, data, opts)
	if err != nil {
		return nil, err
	}

	return verified.Payload, nil
}

// CollectAttestations exposes the OCIFetcher's collectAttestations for testing.
func (f *OCIFetcher) CollectAttestations(
	ctx context.Context,
	manifests []v1.Descriptor,
	ref name.Digest,
	digest string,
	remoteOpts []remote.Option,
	opts *FetchOptions,
) ([]VerifiedAttestation, bool) {
	selection := selectReferrers(ctx, manifests)
	atts, _ := f.collectBundles(ctx, selection.bundles, ref, digest, remoteOpts, opts)

	return atts, len(selection.bundles) > 0
}

// CollectAttestationsStats exposes collectBundles with its verification failure count.
func (f *OCIFetcher) CollectAttestationsStats(
	ctx context.Context,
	manifests []v1.Descriptor,
	ref name.Digest,
	digest string,
	remoteOpts []remote.Option,
	opts *FetchOptions,
) (atts []VerifiedAttestation, verifyFailures int, fetchErr error) {
	selection := selectReferrers(ctx, manifests)
	atts, stats := f.collectBundles(ctx, selection.bundles, ref, digest, remoteOpts, opts)

	return atts, stats.verifyFailures, stats.fetchErr
}

// ExportSelectReferrers returns the digests of the selected bundle, Notation,
// and baseline referrers.
func ExportSelectReferrers(
	ctx context.Context, manifests []v1.Descriptor,
) (bundles, notation, baselines []string) {
	selection := selectReferrers(ctx, manifests)

	for _, desc := range selection.bundles {
		bundles = append(bundles, desc.Digest.String())
	}

	for _, desc := range selection.notation {
		notation = append(notation, desc.Digest.String())
	}

	for _, desc := range selection.baselines {
		baselines = append(baselines, desc.Digest.String())
	}

	return bundles, notation, baselines
}

// ExportMaxNotationReferrers exposes maxNotationReferrers for external tests.
const ExportMaxNotationReferrers = maxNotationReferrers

// ExportMaxReferrerManifestSize exposes maxReferrerManifestSize for external tests.
const ExportMaxReferrerManifestSize = maxReferrerManifestSize

// TrustedRootFetchFunc is the type alias for trustedRootFetchFunc.
type TrustedRootFetchFunc = trustedRootFetchFunc

// TrustedRootCacheForTest is the exported type alias for trustedRootCache.
type TrustedRootCacheForTest = trustedRootCache

// NewTestTrustedRootCache creates a trustedRootCache with an injectable fetch function for testing.
func NewTestTrustedRootCache(fetchFn TrustedRootFetchFunc) *trustedRootCache {
	return &trustedRootCache{
		mu:           sync.RWMutex{},
		root:         nil,
		fetchedAt:    time.Time{},
		fetchRoot:    fetchFn,
		inflight:     singleflight.Group{},
		onFallback:   nil,
		lastFetchErr: time.Time{},
		lastErr:      nil,
		preSeeded:    nil,
		name:         "",
		issuers:      nil,
	}
}

// NewTestTrustedRootCacheWithRoot creates a cache pre-seeded with a root for testing.
func NewTestTrustedRootCacheWithRoot(
	fetchFn TrustedRootFetchFunc, cachedRoot *root.TrustedRoot, fetchedAt time.Time,
) *trustedRootCache {
	return &trustedRootCache{
		mu:           sync.RWMutex{},
		root:         cachedRoot,
		fetchedAt:    fetchedAt,
		fetchRoot:    fetchFn,
		inflight:     singleflight.Group{},
		onFallback:   nil,
		lastFetchErr: time.Time{},
		lastErr:      nil,
		preSeeded:    nil,
		name:         "",
		issuers:      nil,
	}
}

// NewTestTrustedRootCacheWithPreSeeded creates a cache with a pre-seeded fallback root for testing.
func NewTestTrustedRootCacheWithPreSeeded(
	fetchFn TrustedRootFetchFunc, preSeeded *root.TrustedRoot,
) *trustedRootCache {
	return &trustedRootCache{
		mu:           sync.RWMutex{},
		root:         nil,
		fetchedAt:    time.Time{},
		fetchRoot:    fetchFn,
		inflight:     singleflight.Group{},
		onFallback:   nil,
		lastFetchErr: time.Time{},
		lastErr:      nil,
		preSeeded:    preSeeded,
		name:         "",
		issuers:      nil,
	}
}

// NewTestTrustedRootCacheWithRootAndPreSeeded creates a cache with both a cached root and a
// pre-seeded fallback root for testing stale-cache-plus-pre-seeded interactions.
func NewTestTrustedRootCacheWithRootAndPreSeeded(
	fetchFn TrustedRootFetchFunc,
	cachedRoot *root.TrustedRoot,
	fetchedAt time.Time,
	preSeeded *root.TrustedRoot,
) *trustedRootCache {
	return &trustedRootCache{
		mu:           sync.RWMutex{},
		root:         cachedRoot,
		fetchedAt:    fetchedAt,
		fetchRoot:    fetchFn,
		inflight:     singleflight.Group{},
		onFallback:   nil,
		lastFetchErr: time.Time{},
		lastErr:      nil,
		preSeeded:    preSeeded,
		name:         "",
		issuers:      nil,
	}
}

// GetTrustedRoot exposes the cache's get method for testing.
func (c *trustedRootCache) GetTrustedRoot(ctx context.Context) (*root.TrustedRoot, error) {
	return c.get(ctx)
}

// ExportTrustedRootCacheTTL returns the cache TTL for testing.
func ExportTrustedRootCacheTTL() time.Duration { return trustedRootCacheTTL }

// ExportTrustedRootMaxStaleness returns the max staleness for testing.
func ExportTrustedRootMaxStaleness() time.Duration { return trustedRootMaxStaleness }

// NewTestOCIFetcher creates a fetcher with injectable dependencies for testing.
func NewTestOCIFetcher(verifier BundleVerifyFunc, imageFetcher ImageFetchFunc) *OCIFetcher {
	fetcher := &OCIFetcher{
		verifyBundle:       payloadOnlyVerifier(verifier),
		fetchImage:         imageFetcher,
		referrers:          nil,
		rootCache:          nil,
		rootCaches:         nil,
		limiter:            atomic.Pointer[rate.Limiter]{},
		transportCache:     atomic.Pointer[registry.TransportCache]{},
		maxAttestationSize: atomic.Int64{},
		downloadLimit:      atomic.Int64{},
		onMirrorFallback:   nil,
		onMirrorFallbackMu: sync.RWMutex{},
	}
	fetcher.maxAttestationSize.Store(config.DefaultMaxAttestationSize)

	return fetcher
}

// NewTestOCIFetcherFull creates a fetcher with all injectable dependencies for testing.
func NewTestOCIFetcherFull(
	verifier BundleVerifyFunc, imageFetcher ImageFetchFunc, referrersFn ReferrersFunc,
) *OCIFetcher {
	fetcher := &OCIFetcher{
		verifyBundle:       payloadOnlyVerifier(verifier),
		fetchImage:         imageFetcher,
		referrers:          referrersFn,
		rootCache:          nil,
		rootCaches:         nil,
		limiter:            atomic.Pointer[rate.Limiter]{},
		transportCache:     atomic.Pointer[registry.TransportCache]{},
		maxAttestationSize: atomic.Int64{},
		downloadLimit:      atomic.Int64{},
		onMirrorFallback:   nil,
		onMirrorFallbackMu: sync.RWMutex{},
	}
	fetcher.maxAttestationSize.Store(config.DefaultMaxAttestationSize)

	return fetcher
}

// ExportCosignAttestationTag exposes cosignAttestationTag for external tests.
func ExportCosignAttestationTag(ref name.Digest) name.Tag {
	return cosignAttestationTag(ref)
}

// ExportExtractPredicateType exposes extractPredicateType for external tests.
func ExportExtractPredicateType(payload []byte) string {
	return extractPredicateType(payload)
}

// FetchCosignTagAttestations exposes fetchCosignTagAttestations for external tests.
func (f *OCIFetcher) FetchCosignTagAttestations(
	ctx context.Context, ref name.Digest, digest string,
	remoteOpts []remote.Option,
	fetchOpts *FetchOptions,
) ([]VerifiedAttestation, error) {
	atts, _, err := f.fetchCosignTagAttestations(ctx, ref, digest, remoteOpts, fetchOpts)

	return atts, err
}

// CosignTagFallback exposes cosignTagFallback for external tests.
func (f *OCIFetcher) CosignTagFallback(
	ctx context.Context, ref name.Digest, digest string,
	remoteOpts []remote.Option,
	fetchOpts *FetchOptions,
) ([]VerifiedAttestation, error) {
	return f.cosignTagFallback(ctx, ref, digest, remoteOpts, fetchOpts)
}

// NewTestOCIFetcherSigned creates a fetcher with a signed verifier and injectable fetch functions.
func NewTestOCIFetcherSigned(
	verifier SignedBundleVerifyFunc, imageFetcher ImageFetchFunc, referrersFn ReferrersFunc,
) *OCIFetcher {
	fetcher := NewTestOCIFetcherFull(nil, imageFetcher, referrersFn)
	fetcher.verifyBundle = verifier

	return fetcher
}

// ExtractPayloadFromImage exposes extractPayloadFromImage for external tests.
func (f *OCIFetcher) ExtractPayloadFromImage(
	ctx context.Context, img v1.Image, fetchOpts *FetchOptions,
) ([]byte, error) {
	data, err := f.readFirstLayer(ctx, img)
	if err != nil {
		return nil, err
	}

	verified, err := f.verifyBundle(ctx, data, fetchOpts)
	if err != nil {
		return nil, err
	}

	return verified.Payload, nil
}

// NewTestBundle creates a bundle with a DSSE envelope for testing.
func NewTestBundle(payloadType, payload string) *bundle.Bundle {
	protoBundle := &protobundle.Bundle{
		MediaType: bundleMediaType,
		Content: &protobundle.Bundle_DsseEnvelope{
			DsseEnvelope: &protodsse.Envelope{
				Payload:     []byte(payload),
				PayloadType: payloadType,
				Signatures: []*protodsse.Signature{
					{Sig: []byte("test-sig"), Keyid: "test-key"},
				},
			},
		},
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_PublicKey{
				PublicKey: &protocommon.PublicKeyIdentifier{
					Hint: "test-hint",
				},
			},
			TlogEntries:               nil,
			TimestampVerificationData: nil,
		},
	}

	bndl, err := bundle.NewBundle(protoBundle)
	if err != nil {
		panic("creating test bundle: " + err.Error())
	}

	return bndl
}

// ExportIsTransientError exposes isTransientError for external tests.
func ExportIsTransientError(err error) bool {
	return isTransientError(err)
}

// ExportArtifactPolicy wraps artifactPolicy for external tests.
func ExportArtifactPolicy(digest string) error {
	_, err := artifactPolicy(digest)

	return err
}

// ExportBundleMediaType exposes bundleMediaType for external tests.
const ExportBundleMediaType = bundleMediaType

// ExportOCIEmptyMediaType exposes ociEmptyMediaType for external tests.
const ExportOCIEmptyMediaType = ociEmptyMediaType

// ExportAnnotationPredicateType exposes annotationPredicateType for external tests.
const ExportAnnotationPredicateType = annotationPredicateType

// ExportDSSEPayloadType exposes dssePayloadType for external tests.
const ExportDSSEPayloadType = dssePayloadType

// ExportNotationSignatureMediaType exposes NotationSignatureMediaType for external tests.
const ExportNotationSignatureMediaType = NotationSignatureMediaType

// ExportIsNotationCandidate exposes isNotationCandidate for external tests.
func ExportIsNotationCandidate(artifactType string) bool {
	return isNotationCandidate(artifactType)
}

// ExportMaxAttestationSize returns the default max attestation size for external tests.
const ExportMaxAttestationSize = config.DefaultMaxAttestationSize

// FetchNotationSignature exposes fetchNotationSignature for external tests.
func (f *OCIFetcher) FetchNotationSignature(
	ctx context.Context,
	desc *v1.Descriptor,
	ref name.Digest,
	digest string,
	remoteOpts []remote.Option,
) (VerifiedAttestation, bool) {
	att, outcome, _ := f.fetchNotationSignature(ctx, desc, ref, digest, remoteOpts)

	return att, outcome == outcomeVerified
}

// ExportReadNotationEnvelope exposes readNotationEnvelope for external tests.
func (f *OCIFetcher) ExportReadNotationEnvelope(
	ctx context.Context, img v1.Image, _ string,
) ([]byte, bool) {
	data, err := f.readFirstLayer(ctx, img)

	return data, err == nil
}

// CollectNotationSignatures exposes collectNotationSignatures for external tests.
func (f *OCIFetcher) CollectNotationSignatures(
	ctx context.Context,
	manifests []v1.Descriptor,
	ref name.Digest,
	digest string,
	remoteOpts []remote.Option,
) []VerifiedAttestation {
	selection := selectReferrers(ctx, manifests)
	sigs, _ := f.collectNotationSignatures(ctx, selection.notation, ref, digest, remoteOpts)

	return sigs
}

// ExportMaxCircuitBreakers exposes maxCircuitBreakers for external tests.
const ExportMaxCircuitBreakers = maxCircuitBreakers

// ExportMaxTotalAttestationSize exposes maxTotalAttestationSize for external tests.
const ExportMaxTotalAttestationSize = maxTotalAttestationSize

// SetOnFallback sets the onFallback callback on a test cache for testing.
func (c *trustedRootCache) SetOnFallback(fn func()) {
	c.onFallback = fn
}

// OnFallback returns the onFallback callback for testing.
func (c *trustedRootCache) OnFallback() func() {
	return c.onFallback
}

// ExportNegativeCacheTTL returns the negative cache TTL for testing.
func ExportNegativeCacheTTL() time.Duration { return negativeCacheTTL }

// ExportExceededTotalAttestationSize exposes exceededTotalAttestationSize for external tests.
func ExportExceededTotalAttestationSize(ctx context.Context, totalSize int64) bool {
	return exceededTotalAttestationSize(ctx, totalSize)
}

// ExportIsOpen exposes the open state for external tests.
func (cb *CircuitBreaker) ExportIsOpen() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	return cb.state == circuitOpen
}

// ExportIsClosed exposes the closed state for external tests.
func (cb *CircuitBreaker) ExportIsClosed() bool {
	return cb.isClosed()
}

// ExportThreshold exposes threshold for external tests.
func (cb *CircuitBreaker) ExportThreshold() int {
	return cb.threshold
}

// ExportCooldown exposes cooldown for external tests.
func (cb *CircuitBreaker) ExportCooldown() time.Duration {
	return cb.cooldown
}

// ExportRegistryThreshold exposes threshold for external tests.
func (r *CircuitBreakerRegistry) ExportThreshold() int {
	return r.threshold
}

// ExportRegistryCooldown exposes cooldown for external tests.
func (r *CircuitBreakerRegistry) ExportCooldown() time.Duration {
	return r.cooldown
}

// ExportHasLimiter returns whether the fetcher has an active rate limiter.
func (f *OCIFetcher) ExportHasLimiter() bool {
	return f.limiter.Load() != nil
}

// ExportRootCaches returns the rootCaches slice for testing.
func (f *OCIFetcher) ExportRootCaches() []*trustedRootCache {
	return f.rootCaches
}

// ExportVerifyBundle exposes VerifyBundle for external tests.
func ExportVerifyBundle(
	ctx context.Context,
	bundleBytes []byte,
	opts *FetchOptions,
	trustedRoot *root.TrustedRoot,
) (*VerifiedBundle, error) {
	return VerifyBundle(ctx, bundleBytes, opts, trustedRoot)
}

// ExportVerifyBundleWithMultipleRoots exposes verifyBundleWithMultipleRoots for external tests.
func ExportVerifyBundleWithMultipleRoots(
	ctx context.Context,
	bundleBytes []byte,
	opts *FetchOptions,
	rootCaches []*trustedRootCache,
) (*VerifiedBundle, error) {
	return verifyBundleWithMultipleRoots(ctx, bundleBytes, opts, rootCaches)
}

// ExportFetchTrustedRootWithContext exposes fetchTrustedRootWithContext for external tests.
func ExportFetchTrustedRootWithContext(
	ctx context.Context,
	cachedRoot *trustedRootCache,
) (*root.TrustedRoot, error) {
	return fetchTrustedRootWithContext(ctx, cachedRoot)
}

// ExportFetchWithFallback exposes fetchWithFallback for external tests.
func (f *OCIFetcher) ExportFetchWithFallback(
	ctx context.Context,
	mirrorRef string,
	fallback *registry.FallbackInfo,
	mirrorErr error,
	opts *FetchOptions,
) ([]VerifiedAttestation, error) {
	return f.fetchWithFallback(ctx, mirrorRef, fallback, mirrorErr, opts)
}

// NewTestMessageSignatureBundle creates a bundle with a message signature (no DSSE envelope).
func NewTestMessageSignatureBundle() *bundle.Bundle {
	protoBundle := &protobundle.Bundle{
		MediaType: bundleMediaType,
		Content: &protobundle.Bundle_MessageSignature{
			MessageSignature: &protocommon.MessageSignature{
				MessageDigest: &protocommon.HashOutput{
					Algorithm: protocommon.HashAlgorithm_SHA2_256,
					Digest:    []byte("test-digest"),
				},
				Signature: []byte("test-sig"),
			},
		},
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_PublicKey{
				PublicKey: &protocommon.PublicKeyIdentifier{
					Hint: "test-hint",
				},
			},
			TlogEntries:               nil,
			TimestampVerificationData: nil,
		},
	}

	bndl, err := bundle.NewBundle(protoBundle)
	if err != nil {
		panic("creating test bundle: " + err.Error())
	}

	return bndl
}

// ExportSetDownloadLimit overrides the per-fetch download limit for tests.
func (f *OCIFetcher) ExportSetDownloadLimit(limit int64) {
	f.downloadLimit.Store(limit)
}

// ExportExpireFailure moves the last recorded refresh failure out of every
// negative cache window.
func (c *trustedRootCache) ExportExpireFailure() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.lastFetchErr = time.Now().Add(-24 * time.Hour)
}

// TestRootSource describes a trusted root source for tests: a root that is
// available, or an error returned when it is fetched.
type TestRootSource struct {
	Root    *root.TrustedRoot
	Err     error
	Issuers []string
}

// ExportVerifyBundleWithRootSources verifies a bundle against root sources
// that may be unavailable. SCTs are not required.
func ExportVerifyBundleWithRootSources(
	ctx context.Context, data []byte, opts *FetchOptions, sources []TestRootSource,
) (*VerifiedBundle, error) {
	converted := make([]rootSource, 0, len(sources))

	for idx := range sources {
		src := sources[idx]

		converted = append(converted, rootSource{
			name:    fmt.Sprintf("test-%d", idx),
			issuers: src.Issuers,
			get: func(context.Context) (*root.TrustedRoot, error) {
				return src.Root, src.Err
			},
			keylessDisabled: false,
			skipSCTs:        true,
		})
	}

	return verifyBundleCommon(ctx, data, opts, converted)
}

// ErrNoLegacyVerificationMaterial exposes errNoLegacyVerificationMaterial for
// external tests.
var ErrNoLegacyVerificationMaterial = errNoLegacyVerificationMaterial

// CollectSelectionParallel runs the production referrer collection of an
// image on manifests and returns the combined attestations in order.
func (f *OCIFetcher) CollectSelectionParallel(
	ctx context.Context, manifests []v1.Descriptor,
	ref name.Digest, digest string, opts *FetchOptions,
) ([]VerifiedAttestation, error) {
	ctx = withDownloadBudget(ctx, f.effectiveDownloadLimit())
	selection := selectReferrers(ctx, manifests)

	atts, sigs, baselines, err := f.collectSelection(ctx, &selection, ref, digest, nil, opts)
	if err != nil {
		return nil, err
	}

	return append(append(atts, sigs...), baselines...), nil
}

// CollectSelectionSerial runs the referrer collectors one after another, as
// the reference for the concurrent collection.
func (f *OCIFetcher) CollectSelectionSerial(
	ctx context.Context, manifests []v1.Descriptor,
	ref name.Digest, digest string, opts *FetchOptions,
) ([]VerifiedAttestation, error) {
	ctx = withDownloadBudget(ctx, f.effectiveDownloadLimit())
	selection := selectReferrers(ctx, manifests)

	atts, bundleStats := f.collectBundles(ctx, selection.bundles, ref, digest, nil, opts)
	sigs, notationStats := f.collectNotationSignatures(ctx, selection.notation, ref, digest, nil)
	baselines, baselineStats := f.collectBaselineSBOMs(
		ctx,
		selection.baselines,
		ref,
		digest,
		nil,
		opts,
	)

	err := evaluateCollection(len(atts)+len(sigs), bundleStats, notationStats, baselineStats)
	if err != nil {
		return nil, err
	}

	return append(append(atts, sigs...), baselines...), nil
}

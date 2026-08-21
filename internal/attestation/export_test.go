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
) ([]byte, error) {
	return verifyBundleWithCache(ctx, data, opts, nil)
}

// ExportBuildCertificateID exposes buildCertificateIdentity for external tests.
func ExportBuildCertificateID(issuers, sanPatterns []string) (verify.CertificateIdentity, error) {
	return buildCertificateIdentity(issuers, sanPatterns)
}

// ExportBuildKeyMaterial exposes buildKeyMaterial for external tests.
func ExportBuildKeyMaterial(keys []TrustedKeyRef) (*root.TrustedPublicKeyMaterial, error) {
	return buildKeyMaterial(keys)
}

// ExportLoadPublicKeyFromPEM exposes loadPublicKeyFromPEM for external tests.
func ExportLoadPublicKeyFromPEM(path string) (crypto.PublicKey, error) {
	return loadPublicKeyFromPEM(path)
}

// ExportBuildVerificationCfgErr exposes buildVerificationConfig for external tests,
// returning only the error to avoid the dogsled linter issue.
func ExportBuildVerificationCfgErr(
	ctx context.Context,
	opts *FetchOptions,
) error {
	_, _, _, err := buildVerificationConfig(ctx, opts, nil)

	return err
}

// ExportBuildVerificationCfgWithCache exposes buildVerificationConfig with a cache
// for external tests.
func ExportBuildVerificationCfgWithCache(
	ctx context.Context,
	opts *FetchOptions,
	cache *trustedRootCache,
) error {
	_, _, _, err := buildVerificationConfig(ctx, opts, cache)

	return err
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

// ExportErrAllBundlesFailed returns the errAllBundlesFailed sentinel for external tests.
func ExportErrAllBundlesFailed() error { return errAllBundlesFailed }

// ExportMaxReferrers returns the maxReferrers constant for external tests.
func ExportMaxReferrers() int { return maxReferrers }

// VerifyBundle exposes the OCIFetcher's verifyBundle for testing.
func (f *OCIFetcher) VerifyBundle(
	ctx context.Context, data []byte,
	opts *FetchOptions,
) ([]byte, error) {
	return f.verifyBundle(ctx, data, opts)
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
	return f.collectAttestations(ctx, manifests, ref, digest, remoteOpts, opts)
}

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
		preSeeded:    nil,
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
		preSeeded:    nil,
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
		preSeeded:    preSeeded,
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
		preSeeded:    preSeeded,
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
		verifyBundle:       verifier,
		fetchImage:         imageFetcher,
		referrers:          nil,
		rootCache:          nil,
		rootCaches:         nil,
		limiter:            atomic.Pointer[rate.Limiter]{},
		transportCache:     atomic.Pointer[registry.TransportCache]{},
		maxAttestationSize: atomic.Int64{},
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
		verifyBundle:       verifier,
		fetchImage:         imageFetcher,
		referrers:          referrersFn,
		rootCache:          nil,
		rootCaches:         nil,
		limiter:            atomic.Pointer[rate.Limiter]{},
		transportCache:     atomic.Pointer[registry.TransportCache]{},
		maxAttestationSize: atomic.Int64{},
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
	return f.fetchCosignTagAttestations(ctx, ref, digest, remoteOpts, fetchOpts)
}

// ExtractPayloadFromImage exposes extractPayloadFromImage for external tests.
func (f *OCIFetcher) ExtractPayloadFromImage(
	ctx context.Context, img v1.Image, fetchOpts *FetchOptions,
) ([]byte, error) {
	return f.extractPayloadFromImage(ctx, img, fetchOpts)
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
	return f.fetchNotationSignature(ctx, desc, ref, digest, remoteOpts)
}

// ExportReadNotationEnvelope exposes readNotationEnvelope for external tests.
func (f *OCIFetcher) ExportReadNotationEnvelope(
	ctx context.Context, img v1.Image, descDigest string,
) ([]byte, bool) {
	return f.readNotationEnvelope(ctx, img, descDigest)
}

// CollectNotationSignatures exposes collectNotationSignatures for external tests.
func (f *OCIFetcher) CollectNotationSignatures(
	ctx context.Context,
	manifests []v1.Descriptor,
	ref name.Digest,
	digest string,
	remoteOpts []remote.Option,
) []VerifiedAttestation {
	return f.collectNotationSignatures(ctx, manifests, ref, digest, remoteOpts)
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
) ([]byte, error) {
	return VerifyBundle(ctx, bundleBytes, opts, trustedRoot)
}

// ExportBuildVerificationCfgWithRoot exposes buildVerificationConfigWithRoot for external tests.
func ExportBuildVerificationCfgWithRoot(
	opts *FetchOptions,
	trustedRoot *root.TrustedRoot,
) error {
	_, _, _, err := buildVerificationConfigWithRoot(opts, trustedRoot)

	return err
}

// ExportBuildVerificationCfgMultiRoot exposes buildVerificationConfigMultiRoot for external tests.
func ExportBuildVerificationCfgMultiRoot(
	ctx context.Context,
	opts *FetchOptions,
	caches []*trustedRootCache,
) error {
	_, _, _, err := buildVerificationConfigMultiRoot(ctx, opts, caches)

	return err
}

// ExportVerifyBundleWithMultipleRoots exposes verifyBundleWithMultipleRoots for external tests.
func ExportVerifyBundleWithMultipleRoots(
	ctx context.Context,
	bundleBytes []byte,
	opts *FetchOptions,
	rootCaches []*trustedRootCache,
) ([]byte, error) {
	return verifyBundleWithMultipleRoots(ctx, bundleBytes, opts, rootCaches)
}

// ExportVerifyBundleCommon exposes verifyBundleCommon for external tests.
func ExportVerifyBundleCommon(
	ctx context.Context,
	bundleBytes []byte,
	opts *FetchOptions,
	buildConfig buildConfigFunc,
) ([]byte, error) {
	return verifyBundleCommon(ctx, bundleBytes, opts, buildConfig)
}

// ExportFetchTrustedRootWithContext exposes fetchTrustedRootWithContext for external tests.
func ExportFetchTrustedRootWithContext(
	ctx context.Context,
	cachedRoot *trustedRootCache,
) (*root.TrustedRoot, error) {
	return fetchTrustedRootWithContext(ctx, cachedRoot)
}

// BuildConfigFunc is the type alias for buildConfigFunc.
type BuildConfigFunc = buildConfigFunc

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

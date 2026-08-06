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
	"math/rand/v2"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	ociV1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"
	"golang.org/x/time/rate"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/registry"
)

var (
	errUnexpectedFetchResult = errors.New("fetcher: unexpected singleflight result type")
	errNilFetchOptions       = errors.New("fetch options must not be nil")
)

const (
	maxTotalAttestationSize   = 50 << 20 // 50 MiB aggregate limit per image
	maxReferrers              = 50
	maxConcurrentCollectFetch = 5
	trustedRootCacheTTL       = 1 * time.Hour
	trustedRootMaxStaleness   = 24 * time.Hour
	fetchMaxRetries           = 2
	fetchRetryBaseDelay       = 500 * time.Millisecond
	fetchRetryJitterDivisor   = 2
)

type trustedRootFetchFunc func() (*root.TrustedRoot, error)

type trustedRootCache struct {
	mu         sync.RWMutex
	root       *root.TrustedRoot
	fetchedAt  time.Time
	fetchRoot  trustedRootFetchFunc
	inflight   singleflight.Group
	onStaleHit func()
}

func (c *trustedRootCache) get(ctx context.Context) (*root.TrustedRoot, error) {
	c.mu.RLock()

	if c.root != nil && time.Since(c.fetchedAt) < trustedRootCacheTTL {
		cachedRoot := c.root

		c.mu.RUnlock()

		return cachedRoot, nil
	}

	c.mu.RUnlock()

	err := ctx.Err()
	if err != nil {
		return nil, fmt.Errorf("context canceled before fetching trusted root: %w", err)
	}

	ch := c.inflight.DoChan("trusted-root", c.refreshRoot)

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("context canceled during trusted root refresh: %w", ctx.Err())
	case res := <-ch:
		if res.Err != nil {
			return nil, fmt.Errorf("trusted root refresh: %w", res.Err)
		}

		tr, ok := res.Val.(*root.TrustedRoot)
		if !ok {
			return nil, fmt.Errorf("%w: %T", errUnexpectedFetchResult, res.Val)
		}

		return tr, nil
	}
}

func (c *trustedRootCache) refreshRoot() (any, error) {
	c.mu.RLock()

	if c.root != nil && time.Since(c.fetchedAt) < trustedRootCacheTTL {
		cachedRoot := c.root

		c.mu.RUnlock()

		return cachedRoot, nil
	}

	c.mu.RUnlock()

	trustedRoot, err := c.fetchRoot()

	c.mu.Lock()
	defer c.mu.Unlock()

	if err != nil {
		return c.handleRefreshError(err)
	}

	c.root = trustedRoot
	c.fetchedAt = time.Now()

	return trustedRoot, nil
}

func (c *trustedRootCache) handleRefreshError(err error) (*root.TrustedRoot, error) {
	if c.root != nil {
		age := time.Since(c.fetchedAt)
		if age > trustedRootMaxStaleness {
			return nil, fmt.Errorf(
				"trusted root is stale (%s old, max %s) and refresh failed: %w",
				age.Truncate(time.Second), trustedRootMaxStaleness, err,
			)
		}

		slog.Warn("Failed to refresh trusted root, using stale cache",
			"error", err,
			"age", age,
		)

		if c.onStaleHit != nil {
			c.onStaleHit()
		}

		return c.root, nil
	}

	return nil, fmt.Errorf("fetching sigstore trusted root: %w", err)
}

// ImageFetchFunc fetches an OCI image by reference.
type ImageFetchFunc func(ref name.Reference, options ...remote.Option) (ociV1.Image, error)

// ReferrersFunc lists OCI referrers for a digest.
type ReferrersFunc func(d name.Digest, options ...remote.Option) (ociV1.ImageIndex, error)

// RootSourceConfig describes a single Sigstore trusted root source for
// multi-root verification. When TUFMirror is empty, the public Sigstore
// trusted root is used.
type RootSourceConfig struct {
	Name         string
	TUFMirror    string // empty = public Sigstore
	TUFRootBytes []byte // nil = use default root.json
}

// OCIFetcher discovers attestations via the OCI Referrers API.
type OCIFetcher struct {
	verifyBundle BundleVerifyFunc
	fetchImage   ImageFetchFunc
	referrers    ReferrersFunc
	// rootCache is captured by the verifyBundle closure; stored for exhaustruct compliance.
	rootCache          *trustedRootCache
	rootCaches         []*trustedRootCache
	limiter            atomic.Pointer[rate.Limiter]
	transportCache     atomic.Pointer[registry.TransportCache]
	maxAttestationSize atomic.Int64
	onMirrorFallback   func(registryHost string)
	onMirrorFallbackMu sync.RWMutex
}

func newBaseFetcher(verifyFn BundleVerifyFunc) *OCIFetcher {
	fetcher := &OCIFetcher{
		verifyBundle:       verifyFn,
		fetchImage:         remote.Image,
		referrers:          remote.Referrers,
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

// NewOCIFetcher creates a new OCI-based attestation fetcher.
func NewOCIFetcher() *OCIFetcher {
	cachedRoot := &trustedRootCache{
		mu:         sync.RWMutex{},
		root:       nil,
		fetchedAt:  time.Time{},
		fetchRoot:  root.FetchTrustedRoot,
		inflight:   singleflight.Group{},
		onStaleHit: nil,
	}

	fetcher := newBaseFetcher(func(
		ctx context.Context, bundleBytes []byte, opts *FetchOptions,
	) ([]byte, error) {
		return verifyBundleWithCache(ctx, bundleBytes, opts, cachedRoot)
	})
	fetcher.rootCache = cachedRoot

	return fetcher
}

// NewOCIFetcherWithVerifier creates a fetcher with a custom bundle verification function.
func NewOCIFetcherWithVerifier(verifier BundleVerifyFunc) *OCIFetcher {
	return newBaseFetcher(verifier)
}

// NewOCIFetcherWithTUFMirror creates an OCI-based attestation fetcher that
// uses a custom TUF mirror for fetching the Sigstore trusted root. This
// supports private Sigstore deployments where the trusted root (containing
// Fulcio CA certificates and Rekor log keys) is served from an internal
// TUF repository.
//
// When tufRootBytes is non-nil, it replaces the embedded public Sigstore
// root.json as the TUF trust anchor. This is required for private Sigstore
// deployments that use their own root keys. When tufRootBytes is nil, the
// default public Sigstore root.json is used, treating the mirror as a CDN
// mirror of the public infrastructure.
func NewOCIFetcherWithTUFMirror(tufMirror string, tufRootBytes []byte) *OCIFetcher {
	cachedRoot := &trustedRootCache{
		mu:        sync.RWMutex{},
		root:      nil,
		fetchedAt: time.Time{},
		fetchRoot: func() (*root.TrustedRoot, error) {
			opts := tuf.DefaultOptions().
				WithRepositoryBaseURL(tufMirror).
				WithDisableLocalCache()

			if len(tufRootBytes) > 0 {
				opts = opts.WithRoot(tufRootBytes)
			}

			return root.FetchTrustedRootWithOptions(opts)
		},
		inflight:   singleflight.Group{},
		onStaleHit: nil,
	}

	fetcher := newBaseFetcher(func(
		ctx context.Context, bundleBytes []byte, opts *FetchOptions,
	) ([]byte, error) {
		return verifyBundleWithCache(ctx, bundleBytes, opts, cachedRoot)
	})
	fetcher.rootCache = cachedRoot

	return fetcher
}

// NewOCIFetcherWithMultipleRoots creates an OCI-based attestation fetcher that
// verifies bundles against multiple Sigstore trusted roots. Each source entry
// gets its own trustedRootCache that independently refreshes from its TUF
// mirror. When a source has an empty TUFMirror, the public Sigstore trusted
// root is used.
//
// Verification succeeds if any single trusted root validates the bundle.
func NewOCIFetcherWithMultipleRoots(sources []RootSourceConfig) *OCIFetcher {
	caches := make([]*trustedRootCache, len(sources))

	for i, src := range sources {
		fetchFn := buildFetchFunc(src)
		caches[i] = &trustedRootCache{
			mu:         sync.RWMutex{},
			root:       nil,
			fetchedAt:  time.Time{},
			fetchRoot:  fetchFn,
			inflight:   singleflight.Group{},
			onStaleHit: nil,
		}
	}

	fetcher := newBaseFetcher(func(
		ctx context.Context, bundleBytes []byte, opts *FetchOptions,
	) ([]byte, error) {
		return verifyBundleWithMultipleRoots(ctx, bundleBytes, opts, caches)
	})
	fetcher.rootCaches = caches

	return fetcher
}

func buildFetchFunc(src RootSourceConfig) trustedRootFetchFunc {
	if src.TUFMirror == "" {
		return root.FetchTrustedRoot
	}

	return func() (*root.TrustedRoot, error) {
		opts := tuf.DefaultOptions().
			WithRepositoryBaseURL(src.TUFMirror).
			WithDisableLocalCache()

		if len(src.TUFRootBytes) > 0 {
			opts = opts.WithRoot(src.TUFRootBytes)
		}

		return root.FetchTrustedRootWithOptions(opts)
	}
}

// SetStaleRootCallback sets a function to be called each time the fetcher
// serves a stale trusted root from cache after a refresh failure.
// Must be called during initialization, before any concurrent Fetch calls.
func (f *OCIFetcher) SetStaleRootCallback(callback func()) {
	if f.rootCache != nil {
		f.rootCache.onStaleHit = callback
	}

	for _, c := range f.rootCaches {
		c.onStaleHit = callback
	}
}

// SetMirrorFallbackCallback sets a function to be called each time the fetcher
// falls back to the original registry because a mirror is unreachable.
// The callback receives the original registry host. Safe for concurrent use.
func (f *OCIFetcher) SetMirrorFallbackCallback(fn func(registryHost string)) {
	f.onMirrorFallbackMu.Lock()
	defer f.onMirrorFallbackMu.Unlock()

	f.onMirrorFallback = fn
}

// SetRateLimit configures a rate limiter for outbound registry calls.
// A rate of 0 disables rate limiting. Safe for concurrent use with Fetch.
func (f *OCIFetcher) SetRateLimit(requestsPerSecond float64) {
	if requestsPerSecond <= 0 {
		f.limiter.Store(nil)

		return
	}

	lim := rate.NewLimiter(
		rate.Limit(requestsPerSecond), int(requestsPerSecond)+1,
	)
	f.limiter.Store(lim)
}

// SetTransportCache configures per-registry transport settings (mirrors, custom
// CAs, insecure) via a shared TransportCache. The cache provides connection
// pooling and TLS session reuse across requests. Safe for concurrent use.
func (f *OCIFetcher) SetTransportCache(cache *registry.TransportCache) {
	if old := f.transportCache.Swap(cache); old != nil {
		old.CloseIdleConnections()
	}
}

// TransportCache returns the current transport cache, or nil if none is set.
func (f *OCIFetcher) TransportCache() *registry.TransportCache {
	return f.transportCache.Load()
}

// SetMaxAttestationSize overrides the per-attestation size limit. Values <= 0
// are ignored and the existing limit is kept.
func (f *OCIFetcher) SetMaxAttestationSize(size int64) {
	if size > 0 {
		f.maxAttestationSize.Store(size)
	}
}

// IsMultiRoot reports whether this fetcher was configured with multiple
// trusted root sources (via NewOCIFetcherWithMultipleRoots).
func (f *OCIFetcher) IsMultiRoot() bool {
	return len(f.rootCaches) > 0
}

// Warm pre-fetches the Sigstore trusted root(s) so that the first verification
// does not pay the latency cost. Non-fatal: returns an error on failure but
// the fetcher remains usable (it will retry lazily on the first Fetch call).
// When multiple root caches are configured, all are warmed concurrently.
func (f *OCIFetcher) Warm(ctx context.Context) error {
	if f.rootCache != nil {
		_, err := f.rootCache.get(ctx)
		if err != nil {
			return fmt.Errorf("pre-warming trusted root: %w", err)
		}

		return nil
	}

	if len(f.rootCaches) == 0 {
		return nil
	}

	// Warm all root caches independently so that a failure in one does not
	// cancel the others via a derived context.
	var (
		warmMu sync.Mutex
		errs   []error
		warmWg sync.WaitGroup
	)

	for i := range f.rootCaches {
		cache := f.rootCaches[i]

		warmWg.Go(func() {
			_, err := cache.get(ctx)
			if err != nil {
				warmMu.Lock()

				errs = append(errs, fmt.Errorf("pre-warming trusted root: %w", err))
				warmMu.Unlock()
			}
		})
	}

	warmWg.Wait()

	return errors.Join(errs...)
}

// Fetch discovers and returns verified attestations for the given image.
// The digest used for reference parsing and attestation discovery is taken
// from opts.Digest, which must be set by the caller.
func (f *OCIFetcher) Fetch( //nolint:cyclop // slightly above threshold due to parsedRef optimization
	ctx context.Context,
	imageRef string,
	opts *FetchOptions,
) ([]VerifiedAttestation, error) {
	if opts == nil {
		return nil, errNilFetchOptions
	}

	if opts.Digest == "" {
		return nil, fmt.Errorf("%w for image %q", errEmptyDigest, imageRef)
	}

	if opts.Timeout > 0 {
		var cancel context.CancelFunc

		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	effectiveRef, remoteOpts, fallback, err := f.buildFetchOptions(ctx, imageRef)
	if err != nil {
		return nil, err
	}

	var parsedRef name.Reference
	if effectiveRef == imageRef {
		parsedRef = opts.ParsedRef
	}

	ref, err := parseDigestRef(effectiveRef, opts.Digest, parsedRef)
	if err != nil {
		return nil, fmt.Errorf("parsing image reference: %w", err)
	}

	result, fetchErr := f.fetchWithRetry(ctx, ref, opts.Digest, remoteOpts, opts)
	if fetchErr != nil && fallback != nil &&
		ctx.Err() == nil && registry.IsConnectionError(fetchErr) {
		return f.fetchWithFallback(ctx, effectiveRef, fallback, fetchErr, opts)
	}

	return result, fetchErr
}

func (f *OCIFetcher) buildFetchOptions(
	ctx context.Context, imageRef string,
) (string, []remote.Option, *registry.FallbackInfo, error) {
	effectiveRef := imageRef

	remoteOpts := []remote.Option{
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithContext(ctx),
	}

	var fallback *registry.FallbackInfo

	if cache := f.transportCache.Load(); cache != nil {
		rewritten, transportOpt, regFallback, regErr := registry.OptionsForRegistries(
			cache, imageRef,
		)
		if regErr != nil {
			return "", nil, nil, fmt.Errorf("building registry options: %w", regErr)
		}

		effectiveRef = rewritten
		fallback = regFallback

		if transportOpt != nil {
			remoteOpts = append(remoteOpts, transportOpt)
		}
	}

	return effectiveRef, remoteOpts, fallback, nil
}

func (f *OCIFetcher) fetchWithFallback(
	ctx context.Context,
	mirrorRef string,
	fallback *registry.FallbackInfo,
	mirrorErr error,
	opts *FetchOptions,
) ([]VerifiedAttestation, error) {
	slog.WarnContext(ctx,
		"Mirror unreachable for attestation fetch, falling back to original registry",
		"mirror_ref", mirrorRef,
		"original_ref", fallback.OriginalRef,
		"error", mirrorErr,
	)

	f.onMirrorFallbackMu.RLock()
	cb := f.onMirrorFallback
	f.onMirrorFallbackMu.RUnlock()

	if cb != nil {
		cb(registry.Host(fallback.OriginalRef))
	}

	fallbackOpts := []remote.Option{
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithContext(ctx),
	}

	if fallback.TransportOpt != nil {
		fallbackOpts = append(fallbackOpts, fallback.TransportOpt)
	}

	fallbackRef, err := parseDigestRef(fallback.OriginalRef, opts.Digest, opts.ParsedRef)
	if err != nil {
		return nil, fmt.Errorf("parsing fallback reference: %w", err)
	}

	result, fallbackErr := f.fetchWithRetry(ctx, fallbackRef, opts.Digest, fallbackOpts, opts)
	if fallbackErr != nil {
		return nil, fmt.Errorf(
			"fallback to %s: %w (mirror %s: %w)",
			fallback.OriginalRef, fallbackErr, mirrorRef, mirrorErr,
		)
	}

	return result, nil
}

func retryJitter(base time.Duration) time.Duration {
	maxJitter := max(int64(base)/fetchRetryJitterDivisor, 1)

	//nolint:gosec // jitter does not need cryptographic randomness
	return time.Duration(rand.Int64N(maxJitter))
}

func (f *OCIFetcher) fetchWithRetry(
	ctx context.Context,
	ref name.Digest,
	digest string,
	remoteOpts []remote.Option,
	fetchOpts *FetchOptions,
) ([]VerifiedAttestation, error) {
	var lastErr error

	for attempt := range fetchMaxRetries + 1 {
		if attempt > 0 {
			base := fetchRetryBaseDelay * time.Duration(1<<(attempt-1))
			delay := base + retryJitter(base)

			slog.Debug("Retrying attestation fetch",
				"attempt", attempt+1,
				"delay", delay,
			)

			timer := time.NewTimer(delay)

			select {
			case <-ctx.Done():
				timer.Stop()

				return nil, fmt.Errorf("attestation fetch interrupted: %w", ctx.Err())
			case <-timer.C:
			}
		}

		if lim := f.limiter.Load(); lim != nil {
			waitErr := lim.Wait(ctx)
			if waitErr != nil {
				return nil, fmt.Errorf("rate limit wait: %w", waitErr)
			}
		}

		attestations, err := f.fetchOnce(ctx, ref, digest, remoteOpts, fetchOpts)
		if err == nil {
			return attestations, nil
		}

		if ctx.Err() != nil {
			return nil, fmt.Errorf("attestation fetch interrupted: %w", ctx.Err())
		}

		if !isTransientError(err) {
			return nil, err
		}

		lastErr = err
	}

	return nil, fmt.Errorf(
		"attestation fetch failed after %d attempts: %w",
		fetchMaxRetries+1, lastErr,
	)
}

func (f *OCIFetcher) fetchOnce(
	ctx context.Context,
	ref name.Digest,
	digest string,
	remoteOpts []remote.Option,
	fetchOpts *FetchOptions,
) ([]VerifiedAttestation, error) {
	idx, err := f.referrers(ref, remoteOpts...)
	if err != nil {
		return nil, fmt.Errorf("listing referrers: %w", err)
	}

	manifest, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("reading referrers index: %w", err)
	}

	logReferrers(ctx, ref, digest, manifest.Manifests)

	attestations, hadBundles := f.collectAttestations(
		ctx, manifest.Manifests, ref, digest, remoteOpts, fetchOpts,
	)

	// Collect Notation signatures from referrers.
	notationSigs := f.collectNotationSignatures(ctx, manifest.Manifests, ref, digest, remoteOpts)
	attestations = append(attestations, notationSigs...)

	ctxErr := ctx.Err()
	if ctxErr != nil {
		return nil, fmt.Errorf("attestation fetch interrupted: %w", ctxErr)
	}

	if hadBundles && len(attestations) == 0 {
		return nil, fmt.Errorf(
			"%w: all referrer bundles failed verification", errAllBundlesFailed,
		)
	}

	if len(attestations) == 0 {
		return f.cosignTagFallback(ctx, ref, digest, remoteOpts, fetchOpts)
	}

	return attestations, nil
}

func isNotationCandidate(artifactType string) bool {
	return artifactType == NotationSignatureMediaType
}

func (f *OCIFetcher) collectNotationSignatures(
	ctx context.Context,
	manifests []ociV1.Descriptor, ref name.Digest, digest string,
	remoteOpts []remote.Option,
) []VerifiedAttestation {
	var (
		sigsMu sync.Mutex
		sigs   []VerifiedAttestation
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

			appendAttestation(&sigsMu, &sigs, &att)

			return nil
		})
	}

	_ = group.Wait()

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

func isTransientError(err error) bool {
	var transportErr *transport.Error
	if errors.As(err, &transportErr) {
		return transportErr.Temporary()
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}

	return false
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
				groupCtx,
				desc,
				ref,
				digest,
				predicateType,
				remoteOpts,
				fetchOpts,
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

	_ = group.Wait()

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

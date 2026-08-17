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
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	ociV1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"golang.org/x/time/rate"

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
	negativeCacheTTL          = 5 * time.Minute
	fetchMaxRetries           = 2
	fetchRetryBaseDelay       = 500 * time.Millisecond
	fetchRetryJitterDivisor   = 2
)

// ImageFetchFunc fetches an OCI image by reference.
type ImageFetchFunc func(ref name.Reference, options ...remote.Option) (ociV1.Image, error)

// ReferrersFunc lists OCI referrers for a digest.
type ReferrersFunc func(d name.Digest, options ...remote.Option) (ociV1.ImageIndex, error)

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

// SetFallbackCallback sets a function to be called each time the fetcher
// falls back to a non-fresh source (stale cache or pre-seeded root) after
// a refresh failure.
// Must be called during initialization, before any concurrent Fetch calls.
func (f *OCIFetcher) SetFallbackCallback(callback func()) {
	if f.rootCache != nil {
		f.rootCache.onFallback = callback
	}

	for _, c := range f.rootCaches {
		c.onFallback = callback
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

			slog.DebugContext(ctx, "Retrying attestation fetch",
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

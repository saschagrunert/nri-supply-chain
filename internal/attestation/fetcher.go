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
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	ociV1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/sigstore/sigstore-go/pkg/root"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"

	"github.com/saschagrunert/nri-supply-chain/internal/registry"
)

var (
	errUnexpectedFetchResult = errors.New("fetcher: unexpected singleflight result type")
	errNilFetchOptions       = errors.New("fetch options must not be nil")
)

const (
	maxTotalAttestationSize = 50 << 20 // 50 MiB aggregate limit per image
	// maxTotalDownloadSize bounds the bytes downloaded for one image fetch,
	// including referrers that turn out to be junk. Stored bundles carry the
	// payload base64 encoded plus signing material, so the limit leaves room
	// above maxTotalAttestationSize for legitimate attestation sets.
	maxTotalDownloadSize      = 2 * maxTotalAttestationSize
	maxReferrers              = 50      // Sigstore bundle referrers per image
	maxNotationReferrers      = 10      // Notation signature referrers per image
	maxBaselineReferrers      = 5       // baseline SBOM referrers per image
	maxReferrerManifestSize   = 4 << 20 // referrer manifests above this are skipped
	maxLoggedReferrers        = 100
	maxConcurrentCollectFetch = 5
	trustedRootCacheTTL       = 1 * time.Hour
	trustedRootMaxStaleness   = 24 * time.Hour
	negativeCacheTTL          = 5 * time.Minute
	// failedRootRetryInterval bounds how often a trusted root refresh is
	// retried while no cached or pre-seeded root is available.
	failedRootRetryInterval = 30 * time.Second
	fetchMaxRetries         = 2
	fetchRetryBaseDelay     = 500 * time.Millisecond
	fetchRetryJitterDivisor = 2
)

// ImageFetchFunc fetches an OCI image by reference.
type ImageFetchFunc func(ref name.Reference, options ...remote.Option) (ociV1.Image, error)

// ReferrersFunc lists OCI referrers for a digest.
type ReferrersFunc func(d name.Digest, options ...remote.Option) (ociV1.ImageIndex, error)

// OCIFetcher discovers attestations via the OCI Referrers API.
type OCIFetcher struct {
	verifyBundle SignedBundleVerifyFunc
	fetchImage   ImageFetchFunc
	referrers    ReferrersFunc
	// rootCache is captured by the verifyBundle closure; stored for exhaustruct compliance.
	rootCache          *trustedRootCache
	rootCaches         []*trustedRootCache
	limiter            atomic.Pointer[rate.Limiter]
	transportCache     atomic.Pointer[registry.TransportCache]
	maxAttestationSize atomic.Int64
	// downloadLimit overrides maxTotalDownloadSize when positive.
	downloadLimit      atomic.Int64
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

// CachedTrustedRoot returns the currently cached trusted root without
// triggering a network fetch. Returns nil if no root has been cached yet
// (call Warm first). For multi-root fetchers, returns the first cached root.
func (f *OCIFetcher) CachedTrustedRoot() *root.TrustedRoot {
	if f.rootCache != nil {
		f.rootCache.mu.RLock()
		tr, ok := f.rootCache.cachedHit()
		f.rootCache.mu.RUnlock()

		if ok {
			return tr
		}

		return nil
	}

	for _, c := range f.rootCaches {
		c.mu.RLock()
		tr, ok := c.cachedHit()
		c.mu.RUnlock()

		if ok {
			return tr
		}
	}

	return nil
}

// CachedTrustedRoots returns every currently cached trusted root with its
// source name and issuer restriction, without triggering a network fetch.
// Roots that have not been cached yet are left out (call Warm first).
func (f *OCIFetcher) CachedTrustedRoots() []StaticRoot {
	caches := f.rootCaches
	if f.rootCache != nil {
		caches = []*trustedRootCache{f.rootCache}
	}

	roots := make([]StaticRoot, 0, len(caches))

	for _, cache := range caches {
		cache.mu.RLock()
		trustedRoot, ok := cache.cachedHit()
		cache.mu.RUnlock()

		if !ok {
			continue
		}

		roots = append(roots, StaticRoot{
			Name:            cache.name,
			Root:            trustedRoot,
			Issuers:         slices.Clone(cache.issuers),
			KeylessDisabled: false,
		})
	}

	return roots
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
		registry.AuthOption(),
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
		registry.AuthOption(),
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

		finalErr := finalFetchError(ctx, err)
		if finalErr != nil {
			return nil, finalErr
		}

		lastErr = err
	}

	return nil, fmt.Errorf(
		"attestation fetch failed after %d attempts: %w",
		fetchMaxRetries+1, lastErr,
	)
}

// finalFetchError returns the error that ends the retry loop for err, or nil
// when the fetch should be retried. Verification failures are final and win
// over an interruption, so the fetch deadline cannot turn a deny into the
// fetch failure policy.
func finalFetchError(ctx context.Context, err error) error {
	if errors.Is(err, ErrVerificationFailed) {
		return err
	}

	if ctx.Err() != nil {
		return fmt.Errorf("attestation fetch interrupted: %w", ctx.Err())
	}

	if !isTransientError(err) {
		return err
	}

	return nil
}

func (f *OCIFetcher) fetchOnce(
	ctx context.Context,
	ref name.Digest,
	digest string,
	remoteOpts []remote.Option,
	fetchOpts *FetchOptions,
) ([]VerifiedAttestation, error) {
	ctx = withDownloadBudget(ctx, f.effectiveDownloadLimit())

	idx, err := f.referrers(ref, remoteOpts...)
	if err != nil {
		return nil, referrersError("listing referrers", err)
	}

	manifest, err := idx.IndexManifest()
	if err != nil {
		return nil, referrersError("reading referrers index", err)
	}

	logReferrers(ctx, ref, digest, manifest.Manifests)

	selection := selectReferrers(ctx, manifest.Manifests)
	if selection.dropped > 0 {
		return nil, fmt.Errorf(
			"%w: %w: %d referrers exceed the per-image limits",
			ErrVerificationFailed, errReferrerLimitExceeded, selection.dropped,
		)
	}

	attestations, notationSigs, baselineSBOMs, err := f.collectSelection(
		ctx, &selection, ref, digest, remoteOpts, fetchOpts,
	)
	if err != nil {
		return nil, err
	}

	attestations = append(attestations, notationSigs...)

	if len(attestations) == 0 && len(baselineSBOMs) == 0 {
		return f.cosignTagFallback(ctx, ref, digest, remoteOpts, fetchOpts)
	}

	return append(attestations, baselineSBOMs...), nil
}

func (f *OCIFetcher) effectiveDownloadLimit() int64 {
	if limit := f.downloadLimit.Load(); limit > 0 {
		return limit
	}

	return maxTotalDownloadSize
}

// downloadBudget counts the bytes downloaded during one fetch pass, so junk
// referrers cannot make the plugin download without bound.
type downloadBudget struct {
	used  atomic.Int64
	limit int64
}

type downloadBudgetKey struct{}

func withDownloadBudget(ctx context.Context, limit int64) context.Context {
	return context.WithValue(
		ctx,
		downloadBudgetKey{},
		&downloadBudget{used: atomic.Int64{}, limit: limit},
	)
}

// reserveDownload checks that size more bytes fit the download budget of the
// fetch in ctx before they are downloaded.
func reserveDownload(ctx context.Context, size int64) error {
	budget, ok := ctx.Value(downloadBudgetKey{}).(*downloadBudget)
	if !ok {
		return nil
	}

	if used := budget.used.Load(); used+size > budget.limit {
		return fmt.Errorf(
			"%w: %d bytes already downloaded, %d more exceed %d",
			errDownloadLimitExceeded, used, size, budget.limit,
		)
	}

	return nil
}

// chargeDownload records size downloaded bytes against the download budget of
// the fetch in ctx.
func chargeDownload(ctx context.Context, size int64) error {
	budget, ok := ctx.Value(downloadBudgetKey{}).(*downloadBudget)
	if !ok {
		return nil
	}

	if used := budget.used.Add(size); used > budget.limit {
		return fmt.Errorf(
			"%w: %d bytes downloaded, limit %d", errDownloadLimitExceeded, used, budget.limit,
		)
	}

	return nil
}

// collectSelection fetches and verifies the selected referrers. The bundle,
// Notation, and baseline SBOM collectors are independent and run
// concurrently: they share the download budget in ctx, record their outcomes
// in separate stats that are merged afterwards, and return attestations in
// selection order, so the result does not depend on scheduling. An incomplete
// attestation set recorded before an interruption wins: the fetch deadline
// must not turn a deny into the fetch failure policy.
func (f *OCIFetcher) collectSelection(
	ctx context.Context, selection *referrerSelection,
	ref name.Digest, digest string, remoteOpts []remote.Option, fetchOpts *FetchOptions,
) (attestations, notationSigs, baselineSBOMs []VerifiedAttestation, err error) {
	var (
		group                                     errgroup.Group
		bundleStats, notationStats, baselineStats *collectStats
	)

	group.Go(func() error {
		attestations, bundleStats = f.collectBundles(
			ctx, selection.bundles, ref, digest, remoteOpts, fetchOpts,
		)

		return nil
	})

	group.Go(func() error {
		notationSigs, notationStats = f.collectNotationSignatures(
			ctx, selection.notation, ref, digest, remoteOpts,
		)

		return nil
	})

	group.Go(func() error {
		baselineSBOMs, baselineStats = f.collectBaselineSBOMs(
			ctx, selection.baselines, ref, digest, remoteOpts, fetchOpts,
		)

		return nil
	})

	// The collectors report outcomes through their stats, never through
	// the group.
	_ = group.Wait()

	err = evaluateCollection(
		len(attestations)+len(notationSigs), bundleStats, notationStats, baselineStats,
	)
	if errors.Is(err, ErrVerificationFailed) {
		return nil, nil, nil, err
	}

	ctxErr := ctx.Err()
	if ctxErr != nil {
		return nil, nil, nil, fmt.Errorf("attestation fetch interrupted: %w", ctxErr)
	}

	if err != nil {
		return nil, nil, nil, err
	}

	return attestations, notationSigs, baselineSBOMs, nil
}

// evaluateCollection turns referrer outcomes into a fetch error. An incomplete
// referrer set must not be evaluated, because a missing attestation could flip
// a decision:
//   - a referrer dropped because a size or count limit was exceeded wraps
//     ErrVerificationFailed, so the image is denied;
//   - a transport error fails the fetch (retries and fetch failure handling
//     apply), even if other referrers failed verification: the referrer that
//     could not be fetched might have verified;
//   - when nothing verified and at least one referrer failed verification or
//     was not a valid attestation, the error wraps ErrVerificationFailed.
func evaluateCollection(verified int, stats ...*collectStats) error {
	var merged collectStats

	for _, other := range stats {
		merged.merge(other)
	}

	if merged.limitErr != nil {
		return fmt.Errorf(
			"%w: %w: %w", ErrVerificationFailed, errReferrerLimitExceeded, merged.limitErr,
		)
	}

	if merged.fetchErr != nil {
		return fmt.Errorf("fetching referrer: %w", merged.fetchErr)
	}

	if verified == 0 && merged.verifyFailures > 0 {
		return fmt.Errorf(
			"%w: %w: all %d referrers failed verification",
			ErrVerificationFailed, errAllBundlesFailed, merged.verifyFailures,
		)
	}

	return nil
}

// referrersError classifies a failure to list the referrers of an image.
// The fallback referrers tag can be pushed by anyone with push access, so a
// listing that is reachable but malformed counts as a verification failure.
func referrersError(what string, err error) error {
	if isTransportFailure(err) {
		return fmt.Errorf("%s: %w", what, err)
	}

	return fmt.Errorf("%w: %w: %s: %w", ErrVerificationFailed, errInvalidReferrer, what, err)
}

func isTransientError(err error) bool {
	if transportErr, ok := errors.AsType[*transport.Error](err); ok {
		return transportErr.Temporary()
	}

	if netErr, ok := errors.AsType[net.Error](err); ok {
		return netErr.Timeout()
	}

	return false
}

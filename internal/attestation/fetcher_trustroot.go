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
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"golang.org/x/sync/singleflight"
	"golang.org/x/time/rate"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/registry"
)

type trustedRootFetchFunc func() (*root.TrustedRoot, error)

type trustedRootCache struct {
	mu           sync.RWMutex
	root         *root.TrustedRoot
	fetchedAt    time.Time
	fetchRoot    trustedRootFetchFunc
	inflight     singleflight.Group
	onFallback   func()
	lastFetchErr time.Time
	// lastErr is the refresh failure recorded at lastFetchErr when no root
	// could be returned. It is served for failedRootRetryInterval instead of
	// contacting the TUF repository on every verification.
	lastErr   error
	preSeeded *root.TrustedRoot
	// name labels the root source in errors and logs.
	name string
	// issuers restricts the certificate issuers this root may vouch for.
	// Empty means no restriction.
	issuers []string
}

// cachedHit returns a cached result without network access. It checks two
// cases: a fresh cache hit (within TTL) and a negative cache hit (a recent
// refresh failure). During the negative cache window the stale cached root is
// preferred while it is within the staleness limit, so verification does not
// alternate between the fetched root and the pre-seeded root. The caller must
// hold mu.RLock.
func (c *trustedRootCache) cachedHit() (*root.TrustedRoot, bool) {
	if c.root != nil && time.Since(c.fetchedAt) < trustedRootCacheTTL {
		return c.root, true
	}

	if c.lastFetchErr.IsZero() || time.Since(c.lastFetchErr) >= negativeCacheTTL {
		return nil, false
	}

	// A recent refresh failure was recorded: skip the network retry to avoid
	// repeated blocking in air-gapped environments.
	if c.root != nil && time.Since(c.fetchedAt) <= trustedRootMaxStaleness {
		return c.root, true
	}

	if c.preSeeded != nil {
		return c.preSeeded, true
	}

	return nil, false
}

// recentFailure returns the refresh failure recorded when no root could be
// returned, while it is within failedRootRetryInterval. The caller must hold
// mu.RLock.
func (c *trustedRootCache) recentFailure() error {
	if c.lastErr == nil || time.Since(c.lastFetchErr) >= failedRootRetryInterval {
		return nil
	}

	return c.lastErr
}

func (c *trustedRootCache) get(ctx context.Context) (*root.TrustedRoot, error) {
	c.mu.RLock()

	if hit, ok := c.cachedHit(); ok {
		c.mu.RUnlock()

		return hit, nil
	}

	failure := c.recentFailure()

	c.mu.RUnlock()

	if failure != nil {
		return nil, fmt.Errorf("trusted root refresh failed recently: %w", failure)
	}

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
	c.lastFetchErr = time.Time{}
	c.lastErr = nil

	return trustedRoot, nil
}

func (c *trustedRootCache) handleRefreshError(err error) (*root.TrustedRoot, error) {
	if c.root != nil {
		age := time.Since(c.fetchedAt)

		if age <= trustedRootMaxStaleness {
			slog.Warn("Failed to refresh trusted root, using stale cache",
				"error", err,
				"age", age,
			)

			c.lastFetchErr = time.Now()

			c.fireFallback()

			return c.root, nil
		}

		if c.preSeeded != nil {
			slog.Warn("Cached trusted root is too stale, falling back to pre-seeded root",
				"error", err,
				"age", age,
			)

			c.lastFetchErr = time.Now()

			c.fireFallback()

			return c.preSeeded, nil
		}

		return nil, c.recordFailure(fmt.Errorf(
			"trusted root is stale (%s old, max %s) and refresh failed: %w",
			age.Truncate(time.Second), trustedRootMaxStaleness, err,
		))
	}

	if c.preSeeded != nil {
		slog.Warn("Trusted root fetch failed, falling back to pre-seeded root",
			"error", err,
		)

		c.lastFetchErr = time.Now()

		c.fireFallback()

		return c.preSeeded, nil
	}

	return nil, c.recordFailure(fmt.Errorf("fetching sigstore trusted root: %w", err))
}

// recordFailure remembers a refresh failure that left no root to return, so
// verifications within failedRootRetryInterval fail fast. The caller must
// hold mu.
func (c *trustedRootCache) recordFailure(err error) error {
	c.lastFetchErr = time.Now()
	c.lastErr = err

	return err
}

func (c *trustedRootCache) fireFallback() {
	if c.onFallback != nil {
		c.onFallback()
	}
}

// RootSourceConfig describes a single Sigstore trusted root source for
// multi-root verification. When TUFMirror is empty, the public Sigstore
// trusted root is used.
type RootSourceConfig struct {
	Name         string
	TUFMirror    string // empty = public Sigstore
	TUFRootBytes []byte // nil = use default root.json
	// Issuers restricts the OIDC issuers whose certificates this root may
	// vouch for. Empty means any issuer trusted by the policy is accepted.
	Issuers []string
}

// RootScope describes one trusted root source of a fetcher and the issuers
// it may vouch for. Empty Issuers means no restriction.
type RootScope struct {
	Name    string
	Issuers []string
}

// RootScopes returns the trusted root sources of the fetcher with their
// issuer restrictions.
func (f *OCIFetcher) RootScopes() []RootScope {
	caches := f.rootCaches
	if f.rootCache != nil {
		caches = []*trustedRootCache{f.rootCache}
	}

	scopes := make([]RootScope, 0, len(caches))

	for _, cache := range caches {
		scopes = append(scopes, RootScope{
			Name:    cache.name,
			Issuers: slices.Clone(cache.issuers),
		})
	}

	return scopes
}

func newBaseFetcher(verifyFn SignedBundleVerifyFunc) *OCIFetcher {
	fetcher := &OCIFetcher{
		verifyBundle:       verifyFn,
		fetchImage:         remote.Image,
		referrers:          remote.Referrers,
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

// NewOCIFetcher creates a new OCI-based attestation fetcher.
func NewOCIFetcher() *OCIFetcher {
	cachedRoot := &trustedRootCache{
		mu:           sync.RWMutex{},
		root:         nil,
		fetchedAt:    time.Time{},
		fetchRoot:    root.FetchTrustedRoot,
		inflight:     singleflight.Group{},
		onFallback:   nil,
		lastFetchErr: time.Time{},
		lastErr:      nil,
		preSeeded:    nil,
		name:         "",
		issuers:      nil,
	}

	fetcher := newBaseFetcher(func(
		ctx context.Context, bundleBytes []byte, opts *FetchOptions,
	) (*VerifiedBundle, error) {
		return verifyBundleWithCache(ctx, bundleBytes, opts, cachedRoot)
	})
	fetcher.rootCache = cachedRoot

	return fetcher
}

// NewOCIFetcherWithPreSeededRoot creates an OCI-based attestation fetcher
// that tries the public Sigstore CDN first and falls back to a pre-seeded
// trusted root loaded from a local JSON file when the CDN is unreachable.
// This supports air-gapped environments where the trusted root is
// pre-provisioned on disk.
//
// When the CDN fetch fails and the pre-seeded root is used, a negative
// cache prevents repeated CDN retries for a short window
// (negativeCacheTTL). This avoids blocking in disconnected environments
// while still allowing recovery once the window expires.
func NewOCIFetcherWithPreSeededRoot(preSeeded *root.TrustedRoot) *OCIFetcher {
	cachedRoot := &trustedRootCache{
		mu:           sync.RWMutex{},
		root:         nil,
		fetchedAt:    time.Time{},
		fetchRoot:    root.FetchTrustedRoot,
		inflight:     singleflight.Group{},
		onFallback:   nil,
		lastFetchErr: time.Time{},
		lastErr:      nil,
		preSeeded:    preSeeded,
		name:         "",
		issuers:      nil,
	}

	fetcher := newBaseFetcher(func(
		ctx context.Context, bundleBytes []byte, opts *FetchOptions,
	) (*VerifiedBundle, error) {
		return verifyBundleWithCache(ctx, bundleBytes, opts, cachedRoot)
	})
	fetcher.rootCache = cachedRoot

	return fetcher
}

// NewOCIFetcherWithVerifier creates a fetcher with a custom payload-only
// bundle verification function. Attestations returned by such a fetcher carry
// a zero Signer, so identity bindings evaluated later fail closed. Use
// NewOCIFetcherWithSignedVerifier when the signer identity is needed.
func NewOCIFetcherWithVerifier(verifier BundleVerifyFunc) *OCIFetcher {
	return newBaseFetcher(payloadOnlyVerifier(verifier))
}

// NewOCIFetcherWithSignedVerifier creates a fetcher with a custom bundle
// verification function that reports the signer identity.
func NewOCIFetcherWithSignedVerifier(verifier SignedBundleVerifyFunc) *OCIFetcher {
	return newBaseFetcher(verifier)
}

func payloadOnlyVerifier(verifier BundleVerifyFunc) SignedBundleVerifyFunc {
	return func(ctx context.Context, bundleBytes []byte, opts *FetchOptions) (*VerifiedBundle, error) {
		payload, err := verifier(ctx, bundleBytes, opts)
		if err != nil {
			return nil, err
		}

		return &VerifiedBundle{
			Payload:       payload,
			PredicateType: extractPredicateType(payload),
			Signer:        SignerIdentity{KeyPath: "", KeyPaths: nil, Issuer: "", SAN: ""},
		}, nil
	}
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
		inflight:     singleflight.Group{},
		onFallback:   nil,
		lastFetchErr: time.Time{},
		lastErr:      nil,
		preSeeded:    nil,
		name:         "",
		issuers:      nil,
	}

	fetcher := newBaseFetcher(func(
		ctx context.Context, bundleBytes []byte, opts *FetchOptions,
	) (*VerifiedBundle, error) {
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
		fetchFn := buildFetchFunc(&sources[i])
		caches[i] = &trustedRootCache{
			mu:           sync.RWMutex{},
			root:         nil,
			fetchedAt:    time.Time{},
			fetchRoot:    fetchFn,
			inflight:     singleflight.Group{},
			onFallback:   nil,
			lastFetchErr: time.Time{},
			lastErr:      nil,
			preSeeded:    nil,
			name:         src.Name,
			issuers:      src.Issuers,
		}
	}

	fetcher := newBaseFetcher(func(
		ctx context.Context, bundleBytes []byte, opts *FetchOptions,
	) (*VerifiedBundle, error) {
		return verifyBundleWithMultipleRoots(ctx, bundleBytes, opts, caches)
	})
	fetcher.rootCaches = caches

	return fetcher
}

func buildFetchFunc(src *RootSourceConfig) trustedRootFetchFunc {
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

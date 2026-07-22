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
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	ociV1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
	"golang.org/x/sync/singleflight"
	"golang.org/x/time/rate"

	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

var errUnexpectedSingleflightResult = errors.New("fetcher: unexpected singleflight result type")

const (
	maxAttestationSize      = 10 << 20 // 10 MiB
	maxReferrers            = 100
	trustedRootCacheTTL     = 1 * time.Hour
	trustedRootMaxStaleness = 24 * time.Hour
	fetchMaxRetries         = 2
	fetchRetryBaseDelay     = 500 * time.Millisecond
	fetchRetryJitterDivisor = 2
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

	result, fetchErr, _ := c.inflight.Do("trusted-root", c.refreshRoot)
	if fetchErr != nil {
		return nil, fmt.Errorf("trusted root refresh: %w", fetchErr)
	}

	tr, ok := result.(*root.TrustedRoot)
	if !ok {
		return nil, fmt.Errorf("%w: %T", errUnexpectedSingleflightResult, result)
	}

	return tr, nil
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

// OCIFetcher discovers attestations via the OCI Referrers API.
type OCIFetcher struct {
	verifyBundle BundleVerifyFunc
	fetchImage   ImageFetchFunc
	referrers    ReferrersFunc
	// rootCache is captured by the verifyBundle closure; stored for exhaustruct compliance.
	rootCache *trustedRootCache
	limiter   atomic.Pointer[rate.Limiter]
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

	return &OCIFetcher{
		verifyBundle: func(
			ctx context.Context, bundleBytes []byte, opts *FetchOptions,
		) ([]byte, error) {
			return verifyBundleWithCache(ctx, bundleBytes, opts, cachedRoot)
		},
		fetchImage: remote.Image,
		referrers:  remote.Referrers,
		rootCache:  cachedRoot,
		limiter:    atomic.Pointer[rate.Limiter]{},
	}
}

// NewOCIFetcherWithVerifier creates a fetcher with a custom bundle verification function.
func NewOCIFetcherWithVerifier(verifier BundleVerifyFunc) *OCIFetcher {
	return &OCIFetcher{
		verifyBundle: verifier,
		fetchImage:   remote.Image,
		referrers:    remote.Referrers,
		rootCache:    nil,
		limiter:      atomic.Pointer[rate.Limiter]{},
	}
}

// SetStaleRootCallback sets a function to be called each time the fetcher
// serves a stale trusted root from cache after a refresh failure.
func (f *OCIFetcher) SetStaleRootCallback(fn func()) {
	if f.rootCache != nil {
		f.rootCache.onStaleHit = fn
	}
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

// Warm pre-fetches the Sigstore trusted root so that the first verification
// does not pay the latency cost. Non-fatal: returns an error on failure but
// the fetcher remains usable (it will retry lazily on the first Fetch call).
func (f *OCIFetcher) Warm(ctx context.Context) error {
	if f.rootCache == nil {
		return nil
	}

	_, err := f.rootCache.get(ctx)
	if err != nil {
		return fmt.Errorf("pre-warming trusted root: %w", err)
	}

	return nil
}

// Fetch discovers and returns verified attestations for the given image.
// If opts.Digest is empty, it defaults to the digest parameter.
func (f *OCIFetcher) Fetch(
	ctx context.Context, imageRef, digest string,
	opts *FetchOptions,
) ([]VerifiedAttestation, error) {
	if opts.Digest == "" {
		opts.Digest = digest
	}

	if opts.Timeout > 0 {
		var cancel context.CancelFunc

		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	ref, err := parseDigestRef(imageRef, digest)
	if err != nil {
		return nil, fmt.Errorf("parsing image reference: %w", err)
	}

	remoteOpts := []remote.Option{
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithContext(ctx),
	}

	attestations, err := f.fetchWithRetry(ctx, ref, digest, remoteOpts, opts)
	if err != nil {
		return nil, err
	}

	return attestations, nil
}

func retryJitter(base time.Duration) time.Duration {
	maxJitter := max(int64(base)/fetchRetryJitterDivisor, 1)

	//nolint:gosec // jitter does not need cryptographic randomness
	return time.Duration(rand.IntN(int(maxJitter)))
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

	return nil, lastErr
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
		slog.DebugContext(ctx, "Cosign tag-based discovery failed",
			"error", tagErr,
		)

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
		strings.Replace(ref.DigestStr(), ":", "-", 1) + CosignAttestationTagSuffix,
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
		var transportErr *transport.Error
		if errors.As(fetchErr, &transportErr) &&
			transportErr.StatusCode == http.StatusNotFound {
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

	if len(layers) == 0 {
		return nil, nil
	}

	var attestations []VerifiedAttestation

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

		return VerifiedAttestation{PredicateType: "", Payload: nil, Digest: ""}, false
	}

	defer func() {
		closeErr := reader.Close()
		if closeErr != nil {
			slog.WarnContext(ctx, "Failed to close cosign layer reader",
				"error", closeErr,
			)
		}
	}()

	data, dataErr := io.ReadAll(io.LimitReader(reader, maxAttestationSize+1))
	if dataErr != nil {
		slog.WarnContext(ctx, "Failed to read cosign attestation data",
			"error", dataErr,
		)

		return VerifiedAttestation{PredicateType: "", Payload: nil, Digest: ""}, false
	}

	if int64(len(data)) > maxAttestationSize {
		slog.WarnContext(ctx, "Cosign attestation exceeds size limit",
			"size", len(data),
			"limit", maxAttestationSize,
		)

		return VerifiedAttestation{PredicateType: "", Payload: nil, Digest: ""}, false
	}

	payload, verifyErr := f.verifyBundle(ctx, data, fetchOpts)
	if verifyErr != nil {
		slog.DebugContext(ctx, "Cosign tag layer is not a valid sigstore bundle",
			"error", verifyErr,
		)

		return VerifiedAttestation{PredicateType: "", Payload: nil, Digest: ""}, false
	}

	predicateType := extractPredicateType(payload)

	return VerifiedAttestation{
		PredicateType: predicateType,
		Payload:       payload,
		Digest:        digest,
	}, true
}

func extractPredicateType(payload []byte) string {
	var stmt struct {
		PredicateType string `json:"predicateType"`
	}

	unmarshalErr := json.Unmarshal(payload, &stmt)
	if unmarshalErr != nil {
		return ""
	}

	return stmt.PredicateType
}

func (f *OCIFetcher) collectAttestations(
	ctx context.Context, manifests []ociV1.Descriptor,
	ref name.Digest, digest string, remoteOpts []remote.Option,
	fetchOpts *FetchOptions,
) ([]VerifiedAttestation, bool) {
	var (
		attestations []VerifiedAttestation
		hadBundles   bool
		processed    int
	)

	for idx := range manifests {
		if ctx.Err() != nil {
			break
		}

		desc := &manifests[idx]

		if desc.ArtifactType != BundleMediaType {
			continue
		}

		hadBundles = true
		processed++

		if processed > maxReferrers {
			slog.WarnContext(ctx, "Referrer count exceeds limit, skipping remaining",
				"limit", maxReferrers,
				"bundleReferrers", processed,
				"totalManifests", len(manifests),
			)

			break
		}

		predicateType := desc.Annotations[AnnotationPredicateType]

		att, ok := f.processDescriptor(ctx, desc, ref, digest, predicateType, remoteOpts, fetchOpts)
		if ok {
			attestations = append(attestations, att)
		}
	}

	return attestations, hadBundles
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

		return VerifiedAttestation{PredicateType: "", Payload: nil, Digest: ""}, false
	}

	if predicateType == "" {
		predicateType = resolvePredicateFromManifest(ctx, img, desc.Digest.String())
	}

	if predicateType == "" {
		slog.DebugContext(ctx, "Skipping referrer without predicate type",
			"digest", desc.Digest.String(),
		)

		return VerifiedAttestation{PredicateType: "", Payload: nil, Digest: ""}, false
	}

	payload, extractErr := f.extractPayloadFromImage(ctx, img, fetchOpts)
	if extractErr != nil {
		slog.WarnContext(ctx, "Failed to extract attestation payload",
			"digest", desc.Digest.String(),
			"error", extractErr,
		)

		return VerifiedAttestation{PredicateType: "", Payload: nil, Digest: ""}, false
	}

	return VerifiedAttestation{
		PredicateType: predicateType,
		Payload:       payload,
		Digest:        digest,
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

	return manifest.Annotations[AnnotationPredicateType]
}

func parseDigestRef(imageRef, digest string) (name.Digest, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return name.Digest{}, fmt.Errorf("parsing reference %q: %w", imageRef, err)
	}

	digestRef := ref.Context().Digest(digest)

	return digestRef, nil
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

	limited := io.LimitReader(reader, maxAttestationSize+1)

	bundleBytes, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("reading attestation bundle: %w", err)
	}

	if int64(len(bundleBytes)) > maxAttestationSize {
		return nil, fmt.Errorf(
			"attestation size %d exceeds limit of %d bytes: %w",
			len(bundleBytes), maxAttestationSize, errAttestationTooLarge,
		)
	}

	return f.verifyBundle(ctx, bundleBytes, fetchOpts)
}

func verifyBundleWithCache(
	ctx context.Context,
	bundleBytes []byte,
	opts *FetchOptions,
	cachedRoot *trustedRootCache,
) ([]byte, error) {
	err := ctx.Err()
	if err != nil {
		return nil, fmt.Errorf("context canceled before bundle verification: %w", err)
	}

	var bndl bundle.Bundle

	err = bndl.UnmarshalJSON(bundleBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing sigstore bundle: %w", err)
	}

	trustedMaterial, verifierOpts, policyOpts, err := buildVerificationConfig(ctx, opts, cachedRoot)
	if err != nil {
		return nil, err
	}

	verifier, err := verify.NewVerifier(trustedMaterial, verifierOpts...)
	if err != nil {
		return nil, fmt.Errorf("creating sigstore verifier: %w", err)
	}

	artPolicy, artErr := artifactPolicy(opts.Digest)
	if artErr != nil {
		return nil, fmt.Errorf("artifact policy: %w", artErr)
	}

	pol := verify.NewPolicy(
		artPolicy,
		policyOpts...,
	)

	_, err = verifier.Verify(&bndl, pol)
	if err != nil {
		return nil, fmt.Errorf("verifying sigstore bundle: %w", err)
	}

	return extractVerifiedPayload(&bndl)
}

func buildVerificationConfig(
	ctx context.Context,
	opts *FetchOptions,
	cachedRoot *trustedRootCache,
) (root.TrustedMaterialCollection, []verify.VerifierOption, []verify.PolicyOption, error) {
	var (
		materials    root.TrustedMaterialCollection
		verifierOpts []verify.VerifierOption
		policyOpts   []verify.PolicyOption
	)

	if len(opts.TrustedKeys) > 0 {
		keyMaterial, err := buildKeyMaterial(opts.TrustedKeys)
		if err != nil {
			return nil, nil, nil, err
		}

		materials = append(materials, keyMaterial)
		verifierOpts = append(
			verifierOpts,
			keyOnlyVerifierOpts(len(opts.TrustedIssuers) > 0, opts.RequireTransparencyLog)...,
		)
		policyOpts = append(policyOpts, verify.WithKey())
	}

	if len(opts.TrustedIssuers) > 0 {
		issuerMaterial, issuerVerifierOpts, issuerPolicyOpts, err := buildKeylessConfig(
			ctx, opts, cachedRoot,
		)
		if err != nil {
			return nil, nil, nil, err
		}

		materials = append(materials, issuerMaterial)
		verifierOpts = append(verifierOpts, issuerVerifierOpts...)
		policyOpts = append(policyOpts, issuerPolicyOpts...)
	}

	if len(materials) == 0 {
		return nil, nil, nil, fmt.Errorf(
			"%w: provide trusted keys or issuers in policy", errNoTrustedMaterial,
		)
	}

	return materials, verifierOpts, policyOpts, nil
}

func keyOnlyVerifierOpts(hasIssuers, requireTLog bool) []verify.VerifierOption {
	if hasIssuers {
		return nil
	}

	if requireTLog {
		return []verify.VerifierOption{verify.WithTransparencyLog(1)}
	}

	return []verify.VerifierOption{verify.WithNoObserverTimestamps()}
}

func buildKeyMaterial(keyPaths []string) (*root.TrustedPublicKeyMaterial, error) {
	verifiers := make(map[string]*root.ExpiringKey, len(keyPaths))

	for _, keyPath := range keyPaths {
		keyVerifier, err := signature.LoadVerifierFromPEMFile(keyPath, crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("loading public key %q: %w", keyPath, err)
		}

		hint, err := computeKeyHint(keyVerifier)
		if err != nil {
			return nil, fmt.Errorf("computing key hint for %q: %w", keyPath, err)
		}

		verifiers[hint] = root.NewExpiringKey(keyVerifier, time.Time{}, time.Time{})
	}

	return root.NewTrustedPublicKeyMaterialFromMapping(verifiers), nil
}

func computeKeyHint(v signature.Verifier) (string, error) {
	pub, err := v.PublicKey()
	if err != nil {
		return "", fmt.Errorf("extracting public key: %w", err)
	}

	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("encoding public key to DER: %w", err)
	}

	sum := sha256.Sum256(der)

	return base64.StdEncoding.EncodeToString(sum[:]), nil
}

func buildKeylessConfig(
	ctx context.Context,
	opts *FetchOptions,
	cachedRoot *trustedRootCache,
) (*root.TrustedRoot, []verify.VerifierOption, []verify.PolicyOption, error) {
	var (
		trustedRoot *root.TrustedRoot
		err         error
	)

	if cachedRoot != nil {
		trustedRoot, err = cachedRoot.get(ctx)
	} else {
		ctxErr := ctx.Err()
		if ctxErr != nil {
			return nil, nil, nil, fmt.Errorf(
				"context canceled before fetching trusted root: %w", ctxErr,
			)
		}

		trustedRoot, err = root.FetchTrustedRoot()
	}

	if err != nil {
		return nil, nil, nil, fmt.Errorf("fetching sigstore trusted root: %w", err)
	}

	verifierOpts := []verify.VerifierOption{
		verify.WithSignedCertificateTimestamps(1),
		verify.WithObserverTimestamps(1),
	}

	if opts.RequireTransparencyLog {
		verifierOpts = append(verifierOpts, verify.WithTransparencyLog(1))
	}

	certID, err := buildCertificateIdentity(opts.TrustedIssuers, opts.SANPatterns)
	if err != nil {
		return nil, nil, nil, err
	}

	policyOpts := []verify.PolicyOption{verify.WithCertificateIdentity(certID)}

	return trustedRoot, verifierOpts, policyOpts, nil
}

func buildCertificateIdentity(issuers, sanPatterns []string) (verify.CertificateIdentity, error) {
	if len(issuers) == 0 {
		return verify.CertificateIdentity{}, errNoIssuers
	}

	sanRegex := ".*"

	if len(sanPatterns) == 0 {
		warnNoSANPatterns(issuers)
	}

	if len(sanPatterns) > 0 {
		converted := make([]string, len(sanPatterns))
		for idx, p := range sanPatterns {
			converted[idx] = globToRegex(p)
		}

		sanRegex = "^(?:" + strings.Join(converted, "|") + ")$"
	}

	if len(issuers) == 1 {
		certID, err := verify.NewShortCertificateIdentity(issuers[0], "", "", sanRegex)
		if err != nil {
			return verify.CertificateIdentity{}, fmt.Errorf(
				"creating certificate identity: %w",
				err,
			)
		}

		return certID, nil
	}

	escaped := make([]string, len(issuers))
	for idx, issuer := range issuers {
		escaped[idx] = regexp.QuoteMeta(issuer)
	}

	issuerPattern := "^(?:" + strings.Join(escaped, "|") + ")$"

	certID, err := verify.NewShortCertificateIdentity("", issuerPattern, "", sanRegex)
	if err != nil {
		return verify.CertificateIdentity{}, fmt.Errorf("creating certificate identity: %w", err)
	}

	return certID, nil
}

var warnedSANPatterns sync.Map //nolint:gochecknoglobals // dedup per unique issuer set

// ResetSANPatternWarnings clears the deduplication state so that SAN pattern
// warnings are re-emitted on the next verification cycle. Call this after a
// config reload to ensure warnings reflect the new policy state.
func ResetSANPatternWarnings() {
	warnedSANPatterns.Range(func(key, _ any) bool {
		warnedSANPatterns.Delete(key)

		return true
	})
}

func warnNoSANPatterns(issuers []string) {
	key := strings.Join(issuers, "\x00")

	if _, loaded := warnedSANPatterns.LoadOrStore(key, struct{}{}); loaded {
		return
	}

	slog.Warn("No SAN patterns configured for keyless verification; "+
		"any certificate identity from a trusted issuer will be accepted",
		"issuers", issuers,
	)
}

func extractVerifiedPayload(bndl *bundle.Bundle) ([]byte, error) {
	envelope, err := bndl.Envelope()
	if err != nil {
		return nil, fmt.Errorf("extracting DSSE envelope from bundle: %w", err)
	}

	rawEnvelope := envelope.RawEnvelope()
	if rawEnvelope.PayloadType != DSSEPayloadType {
		return nil, fmt.Errorf(
			"%w: expected %q, got %q",
			errInvalidPayloadType, DSSEPayloadType, rawEnvelope.PayloadType,
		)
	}

	payload, err := rawEnvelope.DecodeB64Payload()
	if err != nil {
		return nil, fmt.Errorf("decoding DSSE payload: %w", err)
	}

	return payload, nil
}

var errMalformedDigest = errors.New("malformed digest")

func artifactPolicy(digest string) (verify.ArtifactPolicyOption, error) {
	if digest == "" {
		return verify.WithoutArtifactUnsafe(), nil
	}

	algo, hashHex := types.ParseDigest(digest)
	if algo == "" {
		return nil, fmt.Errorf("%w: %q", errMalformedDigest, digest)
	}

	hashBytes, err := hex.DecodeString(hashHex)
	if err != nil {
		return nil, fmt.Errorf("%w: %q: %w", errMalformedDigest, digest, err)
	}

	return verify.WithArtifactDigest(algo, hashBytes), nil
}

// globToRegex converts a glob pattern to a regex string, consistent with
// path.Match semantics: '*' matches non-'/' characters, '?' matches a single
// non-'/' character, and '[...]' character classes have backslash escapes
// consumed to prevent glob/regex semantic divergence (e.g. [\d] in glob
// matches only 'd', not the regex digit class).
func globToRegex(pattern string) string {
	var builder strings.Builder

	runes := []rune(pattern)

	for idx := 0; idx < len(runes); idx++ {
		switch runes[idx] {
		case '\\':
			if idx+1 < len(runes) {
				idx++
				builder.WriteString(regexp.QuoteMeta(string(runes[idx])))
			} else {
				builder.WriteString(regexp.QuoteMeta(`\`))
			}
		case '*':
			builder.WriteString("[^/]*")
		case '?':
			builder.WriteString("[^/]")
		case '[':
			converted, end := convertBracketExpr(runes, idx)
			builder.WriteString(converted)

			if end > idx {
				idx = end
			}
		default:
			builder.WriteString(regexp.QuoteMeta(string(runes[idx])))
		}
	}

	return builder.String()
}

func convertBracketExpr(runes []rune, idx int) (converted string, end int) {
	end = findBracketEnd(runes, idx)
	if end < 0 {
		return regexp.QuoteMeta("["), idx
	}

	class := escapeCharClass(runes[idx : end+1])

	_, compileErr := regexp.Compile(class)
	if compileErr != nil {
		var escaped strings.Builder

		for _, r := range runes[idx : end+1] {
			escaped.WriteString(regexp.QuoteMeta(string(r)))
		}

		return escaped.String(), end
	}

	return class, end
}

func escapeCharClass(runes []rune) string {
	var builder strings.Builder

	builder.WriteRune(runes[0])

	for idx := 1; idx < len(runes)-1; idx++ {
		if runes[idx] == '\\' && idx+1 < len(runes)-1 {
			idx++

			ch := runes[idx]
			if ch == '\\' || ch == ']' || ch == '-' || ch == '^' {
				builder.WriteRune('\\')
			}

			builder.WriteRune(ch)
		} else {
			builder.WriteRune(runes[idx])
		}
	}

	builder.WriteRune(runes[len(runes)-1])

	return builder.String()
}

func findBracketEnd(runes []rune, start int) int {
	idx := start + 1
	if idx < len(runes) && runes[idx] == '^' {
		idx++
	}

	if idx < len(runes) && runes[idx] == ']' {
		idx++
	}

	for idx < len(runes) {
		if runes[idx] == '\\' && idx+1 < len(runes) {
			idx += 2

			continue
		}

		if runes[idx] == ']' {
			return idx
		}

		idx++
	}

	return -1
}

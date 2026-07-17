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
	"io"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	ociV1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
)

const (
	maxAttestationSize      = 10 << 20 // 10 MiB
	maxReferrers            = 100
	trustedRootCacheTTL     = 1 * time.Hour
	trustedRootMaxStaleness = 24 * time.Hour
)

type trustedRootFetchFunc func() (*root.TrustedRoot, error)

type trustedRootCache struct {
	mu        sync.RWMutex
	root      *root.TrustedRoot
	fetchedAt time.Time
	fetchRoot trustedRootFetchFunc
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

	trustedRoot, fetchErr := c.fetchRoot()

	c.mu.Lock()
	defer c.mu.Unlock()

	if fetchErr != nil {
		if c.root != nil {
			age := time.Since(c.fetchedAt)
			if age > trustedRootMaxStaleness {
				return nil, fmt.Errorf(
					"trusted root is stale (%s old, max %s) and refresh failed: %w",
					age.Truncate(time.Second), trustedRootMaxStaleness, fetchErr,
				)
			}

			slog.Warn("Failed to refresh trusted root, using stale cache",
				"error", fetchErr,
				"age", age,
			)

			return c.root, nil
		}

		return nil, fmt.Errorf("fetching sigstore trusted root: %w", fetchErr)
	}

	c.root = trustedRoot
	c.fetchedAt = time.Now()

	return trustedRoot, nil
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
}

// NewOCIFetcher creates a new OCI-based attestation fetcher.
func NewOCIFetcher() *OCIFetcher {
	cachedRoot := &trustedRootCache{
		mu:        sync.RWMutex{},
		root:      nil,
		fetchedAt: time.Time{},
		fetchRoot: root.FetchTrustedRoot,
	}

	return &OCIFetcher{
		verifyBundle: func(
			ctx context.Context, bundleBytes []byte, opts FetchOptions,
		) ([]byte, error) {
			return verifyBundleWithCache(ctx, bundleBytes, opts, cachedRoot)
		},
		fetchImage: remote.Image,
		referrers:  remote.Referrers,
		rootCache:  cachedRoot,
	}
}

// NewOCIFetcherWithVerifier creates a fetcher with a custom bundle verification function.
func NewOCIFetcherWithVerifier(verifier BundleVerifyFunc) *OCIFetcher {
	return &OCIFetcher{
		verifyBundle: verifier,
		fetchImage:   remote.Image,
		referrers:    remote.Referrers,
		rootCache:    nil,
	}
}

// Fetch discovers and returns verified attestations for the given image.
func (f *OCIFetcher) Fetch(
	ctx context.Context, imageRef, digest string,
	opts FetchOptions, //nolint:gocritic // matches Fetcher interface
) ([]VerifiedAttestation, error) {
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

	idx, err := f.referrers(ref, remoteOpts...)
	if err != nil {
		return nil, fmt.Errorf("listing referrers: %w", err)
	}

	manifest, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("reading referrers index: %w", err)
	}

	attestations, hadBundles := f.collectAttestations(
		ctx,
		manifest.Manifests,
		ref,
		digest,
		remoteOpts,
		opts,
	)

	ctxErr := ctx.Err()
	if ctxErr != nil {
		return nil, fmt.Errorf("attestation fetch interrupted: %w", ctxErr)
	}

	if hadBundles && len(attestations) == 0 {
		return nil, fmt.Errorf("%w: all referrer bundles failed verification", errAllBundlesFailed)
	}

	return attestations, nil
}

func (f *OCIFetcher) collectAttestations(
	ctx context.Context, manifests []ociV1.Descriptor,
	ref name.Digest, digest string, remoteOpts []remote.Option,
	fetchOpts FetchOptions, //nolint:gocritic // passed through to processDescriptor
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

		predicateType := desc.Annotations[AnnotationPredicateType]
		if predicateType == "" {
			slog.DebugContext(ctx, "Skipping referrer without predicate type annotation",
				"digest", desc.Digest.String(),
			)

			continue
		}

		hadBundles = true
		processed++

		if processed > maxReferrers {
			slog.WarnContext(ctx, "Referrer count exceeds limit, skipping remaining",
				"limit", maxReferrers,
				"total", len(manifests),
			)

			break
		}

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
	fetchOpts FetchOptions, //nolint:gocritic // passed through to extractPayload
) (VerifiedAttestation, bool) {
	payload, extractErr := f.extractPayload(ctx, ref, desc.Digest.String(), remoteOpts, fetchOpts)
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

func parseDigestRef(imageRef, digest string) (name.Digest, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return name.Digest{}, fmt.Errorf("parsing reference %q: %w", imageRef, err)
	}

	digestRef := ref.Context().Digest(digest)

	return digestRef, nil
}

func (f *OCIFetcher) extractPayload(
	ctx context.Context,
	baseRef name.Digest,
	descDigest string,
	remoteOpts []remote.Option,
	fetchOpts FetchOptions, //nolint:gocritic // passed through to verifyBundle
) ([]byte, error) {
	attestRef := baseRef.Context().Digest(descDigest)

	img, err := f.fetchImage(attestRef, remoteOpts...)
	if err != nil {
		return nil, fmt.Errorf("fetching attestation image: %w", err)
	}

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
	opts FetchOptions, //nolint:gocritic // matches BundleVerifyFunc signature
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

	// Artifact binding is skipped at the Sigstore level because downstream
	// verifiers provide their own binding: SLSA checks subject digest, VSA
	// checks resource URI. VEX requires explicit product matching (empty
	// products are rejected by matchesImage).
	pol := verify.NewPolicy(
		verify.WithoutArtifactUnsafe(),
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
	opts FetchOptions, //nolint:gocritic // passed through from verifyBundleWithCache
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

		if len(opts.TrustedIssuers) == 0 {
			verifierOpts = append(verifierOpts, verify.WithNoObserverTimestamps())
		}

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

func buildKeyMaterial(keyPaths []string) (*root.TrustedPublicKeyMaterial, error) {
	verifiers := make(map[string]*root.ExpiringKey, len(keyPaths))

	for _, keyPath := range keyPaths {
		verifier, err := signature.LoadVerifierFromPEMFile(keyPath, crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("loading public key %q: %w", keyPath, err)
		}

		verifiers[keyPath] = root.NewExpiringKey(verifier, time.Time{}, time.Time{})
	}

	return root.NewTrustedPublicKeyMaterialFromMapping(verifiers), nil
}

func buildKeylessConfig(
	ctx context.Context,
	opts FetchOptions, //nolint:gocritic // passed through from buildVerificationConfig
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
		slog.Debug("No SAN patterns configured for keyless verification; " +
			"any certificate identity from a trusted issuer will be accepted")
	}

	if len(sanPatterns) > 0 {
		escaped := make([]string, len(sanPatterns))
		for idx, p := range sanPatterns {
			escaped[idx] = regexp.QuoteMeta(p)
		}

		sanRegex = "^(?:" + strings.Join(escaped, "|") + ")$"
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

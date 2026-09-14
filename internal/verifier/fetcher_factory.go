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

package verifier

import (
	"context"
	"fmt"
	"log/slog"
	"slices"

	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/bundle"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/fileutil"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/registry"
)

// publicRootSourceName labels the public Sigstore trusted root source.
const publicRootSourceName = "public-sigstore"

func createAndWarmFetcher(
	ctx context.Context, cfg *config.Config, transportCache *registry.TransportCache,
) (*attestation.OCIFetcher, error) {
	ociFetcher, err := createFetcher(cfg)
	if err != nil {
		return nil, err
	}

	if cfg.FetchRateLimit > 0 {
		ociFetcher.SetRateLimit(cfg.FetchRateLimit)
	}

	ociFetcher.SetMaxAttestationSize(cfg.MaxAttestationSize)

	if transportCache != nil {
		ociFetcher.SetTransportCache(transportCache)
	} else if len(cfg.Registries) > 0 {
		ociFetcher.SetTransportCache(registry.NewTransportCache(cfg.Registries))
	}

	warmCtx, warmCancel := context.WithTimeout(ctx, warmTimeout)
	defer warmCancel()

	warmErr := ociFetcher.Warm(warmCtx)
	if warmErr != nil {
		slog.WarnContext(ctx,
			"Failed to pre-warm Sigstore trusted root",
			"error", warmErr,
		)
	}

	return ociFetcher, nil
}

func createFetcher(cfg *config.Config) (*attestation.OCIFetcher, error) {
	effectiveRoots := cfg.Sigstore.EffectiveRoots()

	if len(effectiveRoots) == 0 {
		return attestation.NewOCIFetcher(), nil
	}

	// Legacy scalar path: when the user set tuf_mirror/tuf_root (not the
	// roots array), preserve the old single-root behavior exactly.
	//nolint:staticcheck // backward compatibility: scalar TUFMirror/TUFRoot fields
	scalarMirror := cfg.Sigstore.TUFMirror
	//nolint:staticcheck // backward compatibility: scalar TUFMirror/TUFRoot fields
	scalarRoot := cfg.Sigstore.TUFRoot

	if len(cfg.Sigstore.Roots) == 0 {
		return createScalarFetcher(scalarMirror, scalarRoot)
	}

	// New roots array path: an unscoped single root without public root
	// inclusion uses the simpler single-root constructor. Scoped roots always
	// use the multi-root constructor, which applies the issuer restriction.
	if len(effectiveRoots) == 1 && !cfg.Sigstore.ShouldIncludePublicRoot() &&
		len(effectiveRoots[0].Issuers) == 0 {
		return createSingleRootFetcher(effectiveRoots[0])
	}

	// Multiple roots or a single custom root plus the public root.
	sources, err := buildRootSourceConfigs(cfg, effectiveRoots)
	if err != nil {
		return nil, err
	}

	return attestation.NewOCIFetcherWithMultipleRoots(sources), nil
}

// createScalarFetcher handles the legacy scalar tuf_mirror/tuf_root config.
// When tuf_mirror is set, verification is locked to that private mirror.
// When only tuf_root is set (no mirror), the fetcher tries the public
// Sigstore CDN first and falls back to the pre-seeded trusted root when
// the CDN is unreachable (air-gapped environments).
func createScalarFetcher(mirror, rootPath string) (*attestation.OCIFetcher, error) {
	if mirror != "" {
		tufRootBytes, err := readTUFRootBytes(rootPath)
		if err != nil {
			return nil, err
		}

		return attestation.NewOCIFetcherWithTUFMirror(mirror, tufRootBytes), nil
	}

	if rootPath != "" {
		preSeeded, err := loadPreSeededTrustedRoot(rootPath)
		if err != nil {
			return nil, err
		}

		return attestation.NewOCIFetcherWithPreSeededRoot(preSeeded), nil
	}

	return attestation.NewOCIFetcher(), nil
}

// createSingleRootFetcher handles the roots array path when there is
// exactly one root source and public root inclusion is disabled.
func createSingleRootFetcher(
	rootSource config.SigstoreRootSource,
) (*attestation.OCIFetcher, error) {
	if rootSource.TUFMirror == "" {
		return attestation.NewOCIFetcher(), nil
	}

	tufRootBytes, err := readTUFRootBytes(rootSource.TUFRoot)
	if err != nil {
		return nil, err
	}

	return attestation.NewOCIFetcherWithTUFMirror(
		rootSource.TUFMirror, tufRootBytes,
	), nil
}

// plannedRoot is a trusted root source derived from the configuration before
// any TUF root file is read.
type plannedRoot struct {
	name    string
	mirror  string
	tufRoot string
	issuers []string
}

// planRootSources derives the trusted root sources of a roots array
// configuration. When the public root is included, user roots with an empty
// TUF mirror describe that same public root: they do not get a cache of their
// own, but their issuer restrictions apply to the public root, so scoping
// configured on them is never dropped.
func planRootSources(
	cfg *config.Config, roots []config.SigstoreRootSource,
) []plannedRoot {
	var planned []plannedRoot

	includePublic := cfg.Sigstore.ShouldIncludePublicRoot()

	if includePublic {
		planned = append(planned, plannedRoot{
			name:    publicRootSourceName,
			mirror:  "",
			tufRoot: "",
			issuers: publicRootIssuers(roots),
		})
	}

	for _, root := range roots {
		if root.TUFMirror == "" && includePublic {
			continue
		}

		planned = append(planned, plannedRoot{
			name:    root.Name,
			mirror:  root.TUFMirror,
			tufRoot: root.TUFRoot,
			issuers: root.Issuers,
		})
	}

	return planned
}

// publicRootIssuers returns the issuer restriction of the included public
// root: the union of the issuers of user roots with an empty TUF mirror, or
// no restriction when there is no such root or one of them is unscoped.
func publicRootIssuers(roots []config.SigstoreRootSource) []string {
	var (
		issuers []string
		found   bool
	)

	for _, root := range roots {
		if root.TUFMirror != "" {
			continue
		}

		if len(root.Issuers) == 0 {
			return nil
		}

		found = true

		for _, issuer := range root.Issuers {
			if !slices.Contains(issuers, issuer) {
				issuers = append(issuers, issuer)
			}
		}
	}

	if !found {
		return nil
	}

	return issuers
}

func buildRootSourceConfigs(
	cfg *config.Config, roots []config.SigstoreRootSource,
) ([]attestation.RootSourceConfig, error) {
	planned := planRootSources(cfg, roots)
	sources := make([]attestation.RootSourceConfig, 0, len(planned))

	for idx := range planned {
		tufRootBytes, err := readTUFRootBytes(planned[idx].tufRoot)
		if err != nil {
			return nil, err
		}

		if len(planned[idx].issuers) == 0 && planned[idx].mirror != "" {
			slog.Warn("Sigstore root has no issuers restriction; certificates for any "+
				"policy issuer are accepted from it (set issuers to scope the root)",
				"root", planned[idx].name,
			)
		}

		sources = append(sources, attestation.RootSourceConfig{
			Name:         planned[idx].name,
			TUFMirror:    planned[idx].mirror,
			TUFRootBytes: tufRootBytes,
			Issuers:      planned[idx].issuers,
		})
	}

	return sources, nil
}

// offlineRootScope is the issuer restriction a verifying node applies to a
// trusted root embedded in an offline bundle.
type offlineRootScope struct {
	issuers         []string
	keylessDisabled bool
	// known is true when the embedded root was matched to a configured root
	// source by name.
	known bool
}

// scopeOfflineRoot returns the issuer restriction for a trusted root embedded
// in an offline bundle. The restriction always comes from the local
// configuration, never from the bundle:
//   - without a sigstore.roots array, the online fetcher trusts a single
//     unscoped root, so embedded roots are unscoped as well;
//   - a root named after a configured root source gets that source's issuers,
//     exactly as online;
//   - a root without a matching name (bundles of older releases, or a root
//     given with --trusted-root) gets only the issuers that every configured
//     root allows, so it can never vouch for more than any configured root.
//     When no issuer is allowed by all of them, it is not trusted for
//     certificates at all.
func scopeOfflineRoot(cfg *config.Config, rootName string) offlineRootScope {
	if len(cfg.Sigstore.Roots) == 0 {
		return offlineRootScope{issuers: nil, keylessDisabled: false, known: true}
	}

	planned := planRootSources(cfg, cfg.Sigstore.EffectiveRoots())

	if rootName != "" {
		for idx := range planned {
			if planned[idx].name == rootName {
				return offlineRootScope{
					issuers: planned[idx].issuers, keylessDisabled: false, known: true,
				}
			}
		}
	}

	var (
		allowed    []string
		restricted bool
	)

	for idx := range planned {
		if len(planned[idx].issuers) == 0 {
			continue
		}

		if !restricted {
			allowed = slices.Clone(planned[idx].issuers)
			restricted = true

			continue
		}

		allowed = slices.DeleteFunc(allowed, func(issuer string) bool {
			return !slices.Contains(planned[idx].issuers, issuer)
		})
	}

	return offlineRootScope{
		issuers:         allowed,
		keylessDisabled: restricted && len(allowed) == 0,
		known:           false,
	}
}

// offlineStaticRoots scopes the trusted roots embedded in an offline bundle
// with the local configuration.
func offlineStaticRoots(
	cfg *config.Config, embedded []bundle.TrustedRootSource,
) []attestation.StaticRoot {
	roots := make([]attestation.StaticRoot, 0, len(embedded))

	for idx := range embedded {
		scope := scopeOfflineRoot(cfg, embedded[idx].Name)

		if !scope.known {
			slog.Warn("Bundle trusted root does not match a configured Sigstore root "+
				"source; it is only trusted for issuers allowed by every configured root",
				"root", embedded[idx].Name,
				"issuers", scope.issuers,
				"keylessDisabled", scope.keylessDisabled,
			)
		}

		rootName := embedded[idx].Name
		if rootName == "" {
			rootName = "bundle"
		}

		roots = append(roots, attestation.StaticRoot{
			Name:            rootName,
			Root:            embedded[idx].Root,
			Issuers:         scope.issuers,
			KeylessDisabled: scope.keylessDisabled,
		})
	}

	return roots
}

func readTUFRootBytes(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}

	data, err := fileutil.ReadLimited(path, fileutil.MaxCredentialFileSize)
	if err != nil {
		return nil, fmt.Errorf("reading custom TUF root %q: %w", path, err)
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("%w: %q", config.ErrTUFRootEmpty, path)
	}

	return data, nil
}

func loadPreSeededTrustedRoot(path string) (*root.TrustedRoot, error) {
	data, err := readTUFRootBytes(path)
	if err != nil {
		return nil, err
	}

	trustedRoot, err := root.NewTrustedRootFromJSON(data)
	if err != nil {
		return nil, fmt.Errorf("parsing pre-seeded trusted root %q: %w", path, err)
	}

	return trustedRoot, nil
}

func createFetcherForMode( //nolint:ireturn // returns Fetcher, FallbackFetcher, or OCIFetcher
	ctx context.Context, cfg *config.Config, transportCache *registry.TransportCache,
	bundleMetrics *bundle.Metrics,
) (attestation.Fetcher, error) {
	switch cfg.Offline.Mode { //nolint:exhaustive // OfflineModeDisabled falls through to default
	case config.OfflineModeOffline:
		return createBundleFetcher(cfg, bundleMetrics)

	case config.OfflineModePreferBundle:
		bundleFetcher, err := createBundleFetcher(cfg, bundleMetrics)
		if err != nil {
			return nil, fmt.Errorf("creating bundle fetcher for prefer-bundle mode: %w", err)
		}

		ociFetcher, err := createAndWarmFetcher(ctx, cfg, transportCache)
		if err != nil {
			return nil, fmt.Errorf("creating OCI fetcher for prefer-bundle mode: %w", err)
		}

		return bundle.NewFallbackFetcher(bundleFetcher, ociFetcher), nil

	default:
		return createAndWarmFetcher(ctx, cfg, transportCache)
	}
}

func createBundleFetcher(
	cfg *config.Config, bundleMetrics *bundle.Metrics,
) (*bundle.Fetcher, error) {
	store, err := bundle.OpenStore(cfg.Offline.AttestationStore)
	if err != nil {
		return nil, fmt.Errorf("opening bundle store: %w", err)
	}

	embedded, err := store.TrustedRoots()
	if err != nil {
		slog.Warn("Bundle has no embedded trusted root; only key-based "+
			"attestations verified without a transparency log can be accepted",
			"error", err)

		embedded = nil
	}

	roots := offlineStaticRoots(cfg, embedded)

	if cfg.Offline.BundleSignatureKey == "" && slices.ContainsFunc(roots, unscopedStaticRoot) {
		slog.Warn("Bundle trusted root is accepted for every policy issuer and the " +
			"bundle manifest is not signature verified; set offline.bundle_signature_key " +
			"and scope every sigstore.roots entry with issuers")
	}

	// Every bundled attestation is cryptographically verified. Without a
	// trusted root, key-based bundles still verify against the policy keys
	// while keyless bundles and transparency log checks fail closed.
	verifyFunc := func(
		ctx context.Context, bundleBytes []byte, opts *attestation.FetchOptions,
	) (*attestation.VerifiedBundle, error) {
		return attestation.VerifyBundleWithStaticRoots(ctx, bundleBytes, opts, roots)
	}

	opts := []bundle.FetcherOption{
		bundle.WithMaxAge(cfg.Offline.BundleMaxAge.Duration),
		bundle.WithExpiryPolicy(bundle.ExpiryPolicy(cfg.Offline.BundleExpiryPolicy)),
		bundle.WithRequireBundleSignature(cfg.Offline.RequireBundleSignature),
	}

	if cfg.Offline.BundleSignatureKey != "" {
		opts = append(opts, bundle.WithBundleSignatureKey(cfg.Offline.BundleSignatureKey))
	}

	if bundleMetrics != nil {
		opts = append(opts, bundle.WithMetrics(bundleMetrics))
	}

	return bundle.NewFetcher(store, verifyFunc, opts...), nil
}

func unscopedStaticRoot(staticRoot attestation.StaticRoot) bool {
	return len(staticRoot.Issuers) == 0 && !staticRoot.KeylessDisabled
}

func setBundleMetricsOnFetcher(fetcher attestation.Fetcher, met *metrics.Metrics) {
	target := fetcher

	if fb, ok := fetcher.(*bundle.FallbackFetcher); ok {
		target = fb.Primary()
	}

	if bf, ok := target.(*bundle.Fetcher); ok {
		bf.SetMetrics(&bundle.Metrics{
			OnStaleness:    func(pol string) { met.BundleStalenessTotal.WithLabelValues(pol).Inc() },
			OnVerification: func(res string) { met.BundleVerificationsTotal.WithLabelValues(res).Inc() },
			SetAge:         met.BundleAgeSeconds.Set,
			SetImageCount:  met.BundleImageCount.Set,
		})
	}
}

func transportCacheFromFetcher(fetcher attestation.Fetcher) *registry.TransportCache {
	ociFetcher := ociFetcherFromFetcher(fetcher)
	if ociFetcher != nil {
		return ociFetcher.TransportCache()
	}

	return nil
}

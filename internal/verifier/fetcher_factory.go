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

	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/bundle"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/fileutil"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/registry"
)

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

	// New roots array path: single root without public root inclusion uses
	// the simpler single-root constructor.
	if len(effectiveRoots) == 1 && !cfg.Sigstore.ShouldIncludePublicRoot() {
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

func buildRootSourceConfigs(
	cfg *config.Config, roots []config.SigstoreRootSource,
) ([]attestation.RootSourceConfig, error) {
	var sources []attestation.RootSourceConfig

	includePublic := cfg.Sigstore.ShouldIncludePublicRoot()

	if includePublic {
		sources = append(sources, attestation.RootSourceConfig{
			Name:         "public-sigstore",
			TUFMirror:    "",
			TUFRootBytes: nil,
		})
	}

	for _, root := range roots {
		// Skip user roots with empty TUF mirror when the public root is
		// already included, avoiding duplicate caches for the same root.
		if root.TUFMirror == "" && includePublic {
			continue
		}

		tufRootBytes, err := readTUFRootBytes(root.TUFRoot)
		if err != nil {
			return nil, err
		}

		sources = append(sources, attestation.RootSourceConfig{
			Name:         root.Name,
			TUFMirror:    root.TUFMirror,
			TUFRootBytes: tufRootBytes,
		})
	}

	return sources, nil
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

	trustedRoot, err := store.TrustedRoot()
	if err != nil {
		slog.Warn("Bundle has no embedded trusted root, "+
			"attestation verification will require key-based policy",
			"error", err)
	}

	var verifyFunc attestation.BundleVerifyFunc
	if trustedRoot != nil {
		verifyFunc = func(ctx context.Context, bundleBytes []byte, opts *attestation.FetchOptions) ([]byte, error) {
			return attestation.VerifyBundle(ctx, bundleBytes, opts, trustedRoot)
		}
	} else {
		// Without a trusted root, attestations are extracted but not
		// cryptographically verified at the bundle layer. Security
		// still relies on the bundle manifest signature (when
		// configured) and any key-based policy checks in the verifier.
		verifyFunc = func(_ context.Context, bundleBytes []byte, _ *attestation.FetchOptions) ([]byte, error) {
			return attestation.ExtractBundlePayload(bundleBytes)
		}
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

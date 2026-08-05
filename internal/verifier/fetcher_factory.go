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

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/fileutil"
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

	if transportCache != nil {
		ociFetcher.SetTransportCache(transportCache)
	} else if len(cfg.Registries) > 0 {
		ociFetcher.SetTransportCache(registry.NewTransportCache(cfg.Registries))
	}

	warmCtx, warmCancel := context.WithTimeout(ctx, warmTimeout)
	defer warmCancel()

	warmErr := ociFetcher.Warm(warmCtx)
	if warmErr != nil {
		slog.Warn(
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
	// roots array), preserve the old single-root behavior exactly. The
	// public Sigstore root is NOT included, matching the pre-roots behavior
	// where setting tuf_mirror locked verification to the private mirror.
	//nolint:staticcheck // backward compatibility: scalar TUFMirror/TUFRoot fields
	scalarMirror := cfg.Sigstore.TUFMirror
	//nolint:staticcheck // backward compatibility: scalar TUFMirror/TUFRoot fields
	scalarRoot := cfg.Sigstore.TUFRoot

	if len(cfg.Sigstore.Roots) == 0 && scalarMirror != "" {
		tufRootBytes, err := readTUFRootBytes(scalarRoot)
		if err != nil {
			return nil, err
		}

		return attestation.NewOCIFetcherWithTUFMirror(
			scalarMirror, tufRootBytes,
		), nil
	}

	// New roots array path: single root without public root inclusion uses
	// the simpler single-root constructor.
	if len(effectiveRoots) == 1 && !cfg.Sigstore.ShouldIncludePublicRoot() {
		if effectiveRoots[0].TUFMirror == "" {
			return attestation.NewOCIFetcher(), nil
		}

		tufRootBytes, err := readTUFRootBytes(effectiveRoots[0].TUFRoot)
		if err != nil {
			return nil, err
		}

		return attestation.NewOCIFetcherWithTUFMirror(
			effectiveRoots[0].TUFMirror, tufRootBytes,
		), nil
	}

	// Multiple roots or a single custom root plus the public root.
	sources, err := buildRootSourceConfigs(cfg, effectiveRoots)
	if err != nil {
		return nil, err
	}

	return attestation.NewOCIFetcherWithMultipleRoots(sources), nil
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

func transportCacheFromFetcher(fetcher attestation.Fetcher) *registry.TransportCache {
	if ociFetcher, ok := fetcher.(*attestation.OCIFetcher); ok && ociFetcher != nil {
		return ociFetcher.TransportCache()
	}

	return nil
}

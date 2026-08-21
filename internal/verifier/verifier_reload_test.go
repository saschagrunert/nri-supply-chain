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

package verifier_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/bundle"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

const (
	testNonexistent     = "/nonexistent"
	testNonexistentPath = "/nonexistent/path"
)

func createTestBundleStore(
	t *testing.T, createdAt time.Time,
) string {
	t.Helper()

	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "oci-layout"),
		[]byte(`{"imageLayoutVersion":"1.0.0"}`))
	writeFile(t, filepath.Join(dir, "index.json"),
		[]byte(`{"schemaVersion":2,"manifests":[]}`))

	blobsDir := filepath.Join(dir, "blobs", "sha256")

	err := os.MkdirAll(blobsDir, 0o750)
	if err != nil {
		t.Fatal(err)
	}

	manifest := map[string]any{
		"version":   1,
		"createdAt": createdAt.Format(time.RFC3339Nano),
		"images":    map[string]any{},
	}

	manifestData, marshalErr := json.MarshalIndent(manifest, "", "  ")
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}

	writeFile(t, filepath.Join(dir, "bundle-manifest.json"), manifestData)

	return dir
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()

	err := os.WriteFile(path, data, 0o600)
	if err != nil {
		t.Fatal(err)
	}
}

func openTestStore(t *testing.T, storePath string) *bundle.Store {
	t.Helper()

	store, err := bundle.OpenStore(storePath)
	if err != nil {
		t.Fatalf("opening test store: %v", err)
	}

	return store
}

func noopVerify(
	_ context.Context, _ []byte, _ *attestation.FetchOptions,
) ([]byte, error) {
	return nil, nil
}

func TestBundleFetcherFromFetcher(t *testing.T) {
	t.Parallel()

	storePath := createTestBundleStore(t, time.Now().UTC())
	store := openTestStore(t, storePath)
	bundleFetcher := bundle.NewFetcher(store, noopVerify)

	t.Run("direct bundle fetcher", func(t *testing.T) {
		t.Parallel()

		result := verifier.ExportBundleFetcherFromFetcher(bundleFetcher)
		if result == nil {
			t.Fatal("expected non-nil result for direct *bundle.Fetcher")
		}

		if result != bundleFetcher {
			t.Error("expected same pointer back")
		}
	})

	t.Run("fallback fetcher wrapping bundle", func(t *testing.T) {
		t.Parallel()

		fallback := bundle.NewFallbackFetcher(
			bundleFetcher, &mockFetcher{}, //nolint:exhaustruct_v5 // test data
		)

		result := verifier.ExportBundleFetcherFromFetcher(fallback)
		if result == nil {
			t.Fatal("expected non-nil result from FallbackFetcher")
		}

		if result != bundleFetcher {
			t.Error("expected inner bundle.Fetcher pointer")
		}
	})

	t.Run("non-bundle fetcher returns nil", func(t *testing.T) {
		t.Parallel()

		mock := &mockFetcher{} //nolint:exhaustruct_v5 // test data

		result := verifier.ExportBundleFetcherFromFetcher(mock)
		if result != nil {
			t.Error("expected nil for non-bundle fetcher")
		}
	})

	t.Run("nil fetcher returns nil", func(t *testing.T) {
		t.Parallel()

		result := verifier.ExportBundleFetcherFromFetcher(nil)
		if result != nil {
			t.Error("expected nil for nil fetcher")
		}
	})

	t.Run("fallback with non-bundle primary returns nil", func(t *testing.T) {
		t.Parallel()

		fallback := bundle.NewFallbackFetcher(
			&mockFetcher{}, //nolint:exhaustruct_v5 // test data
			&mockFetcher{}, //nolint:exhaustruct_v5 // test data
		)

		result := verifier.ExportBundleFetcherFromFetcher(fallback)
		if result != nil {
			t.Error("expected nil when FallbackFetcher primary is not bundle.Fetcher")
		}
	})
}

func TestBundleStoreChangedOnDisk(t *testing.T) {
	t.Parallel()

	t.Run("disabled mode returns false", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Offline.Mode = config.OfflineModeDisabled

		mock := &mockFetcher{} //nolint:exhaustruct_v5 // test data

		changed := verifier.ExportBundleStoreChangedOnDisk(mock, cfg)
		if changed {
			t.Error("expected false when mode is disabled")
		}
	})

	t.Run("non-bundle fetcher returns false", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Offline.Mode = config.OfflineModeOffline
		cfg.Offline.AttestationStore = testNonexistent

		mock := &mockFetcher{} //nolint:exhaustruct_v5 // test data

		changed := verifier.ExportBundleStoreChangedOnDisk(mock, cfg)
		if changed {
			t.Error("expected false when fetcher is not a bundle fetcher")
		}
	})

	t.Run("store open failure returns false", func(t *testing.T) {
		t.Parallel()

		storePath := createTestBundleStore(t, time.Now().UTC())
		store := openTestStore(t, storePath)
		bundleFetcher := bundle.NewFetcher(store, noopVerify)

		cfg := config.DefaultConfig()
		cfg.Offline.Mode = config.OfflineModeOffline
		cfg.Offline.AttestationStore = testNonexistentPath

		changed := verifier.ExportBundleStoreChangedOnDisk(bundleFetcher, cfg)
		if changed {
			t.Error("expected false when on-disk store cannot be opened")
		}
	})

	t.Run("same timestamps returns false", func(t *testing.T) {
		t.Parallel()

		createdAt := time.Now().UTC().Truncate(time.Second)
		storePath := createTestBundleStore(t, createdAt)
		store := openTestStore(t, storePath)
		bundleFetcher := bundle.NewFetcher(store, noopVerify)

		cfg := config.DefaultConfig()
		cfg.Offline.Mode = config.OfflineModeOffline
		cfg.Offline.AttestationStore = storePath

		changed := verifier.ExportBundleStoreChangedOnDisk(bundleFetcher, cfg)
		if changed {
			t.Error("expected false when timestamps match")
		}
	})

	t.Run("different timestamps returns true", func(t *testing.T) {
		t.Parallel()

		oldTime := time.Now().UTC().Add(-1 * time.Hour).Truncate(time.Second)
		storePath := createTestBundleStore(t, oldTime)
		store := openTestStore(t, storePath)
		bundleFetcher := bundle.NewFetcher(store, noopVerify)

		newTime := time.Now().UTC().Truncate(time.Second)
		newManifest := map[string]any{
			"version":   1,
			"createdAt": newTime.Format(time.RFC3339Nano),
			"images":    map[string]any{},
		}

		manifestData, err := json.MarshalIndent(newManifest, "", "  ")
		if err != nil {
			t.Fatal(err)
		}

		writeFile(t, filepath.Join(storePath, "bundle-manifest.json"), manifestData)

		cfg := config.DefaultConfig()
		cfg.Offline.Mode = config.OfflineModeOffline
		cfg.Offline.AttestationStore = storePath

		changed := verifier.ExportBundleStoreChangedOnDisk(bundleFetcher, cfg)
		if !changed {
			t.Error("expected true when on-disk store has different timestamp")
		}
	})

	t.Run("works with fallback fetcher", func(t *testing.T) {
		t.Parallel()

		createdAt := time.Now().UTC().Truncate(time.Second)
		storePath := createTestBundleStore(t, createdAt)
		store := openTestStore(t, storePath)
		bundleFetcher := bundle.NewFetcher(store, noopVerify)
		fallback := bundle.NewFallbackFetcher(
			bundleFetcher,
			&mockFetcher{}, //nolint:exhaustruct_v5 // test data
		)

		cfg := config.DefaultConfig()
		cfg.Offline.Mode = config.OfflineModePreferBundle
		cfg.Offline.AttestationStore = storePath

		changed := verifier.ExportBundleStoreChangedOnDisk(fallback, cfg)
		if changed {
			t.Error("expected false when timestamps match via FallbackFetcher")
		}
	})
}

func TestSetBundleMetricsOnFetcher(t *testing.T) {
	t.Parallel()

	t.Run("sets metrics on direct bundle fetcher", func(t *testing.T) {
		t.Parallel()

		storePath := createTestBundleStore(t, time.Now().UTC())
		store := openTestStore(t, storePath)
		bundleFetcher := bundle.NewFetcher(store, noopVerify)

		met := metrics.New()
		verifier.ExportSetBundleMetricsOnFetcher(bundleFetcher, met)

		bundleFetcher.SetMetrics(nil)
	})

	t.Run("sets metrics through fallback fetcher", func(t *testing.T) {
		t.Parallel()

		storePath := createTestBundleStore(t, time.Now().UTC())
		store := openTestStore(t, storePath)
		bundleFetcher := bundle.NewFetcher(store, noopVerify)
		fallback := bundle.NewFallbackFetcher(
			bundleFetcher,
			&mockFetcher{}, //nolint:exhaustruct_v5 // test data
		)

		met := metrics.New()
		verifier.ExportSetBundleMetricsOnFetcher(fallback, met)

		bundleFetcher.SetMetrics(nil)
	})

	t.Run("no-op for non-bundle fetcher", func(t *testing.T) {
		t.Parallel()

		met := metrics.New()
		verifier.ExportSetBundleMetricsOnFetcher(
			&mockFetcher{}, //nolint:exhaustruct_v5 // test data
			met,
		)
	})
}

func TestOCIFetcherFromFetcher(t *testing.T) {
	t.Parallel()

	t.Run("nil for non-OCI fetcher", func(t *testing.T) {
		t.Parallel()

		mock := &mockFetcher{} //nolint:exhaustruct_v5 // test data

		result := verifier.ExportOCIFetcherFromFetcher(mock)
		if result != nil {
			t.Error("expected nil for mockFetcher")
		}
	})

	t.Run("nil for bundle fetcher", func(t *testing.T) {
		t.Parallel()

		storePath := createTestBundleStore(t, time.Now().UTC())
		store := openTestStore(t, storePath)
		bundleFetcher := bundle.NewFetcher(store, noopVerify)

		result := verifier.ExportOCIFetcherFromFetcher(bundleFetcher)
		if result != nil {
			t.Error("expected nil for bundle.Fetcher")
		}
	})
}

func TestCreateBundleFetcher(t *testing.T) {
	t.Parallel()

	t.Run("success with store", func(t *testing.T) {
		t.Parallel()

		storePath := createTestBundleStore(t, time.Now().UTC())

		cfg := config.DefaultConfig()
		cfg.Offline.AttestationStore = storePath

		fetcher, err := verifier.ExportCreateBundleFetcher(cfg, nil)
		if err != nil {
			t.Fatalf("createBundleFetcher() error: %v", err)
		}

		if fetcher == nil {
			t.Fatal("expected non-nil fetcher")
		}
	})

	t.Run("success with metrics", func(t *testing.T) {
		t.Parallel()

		storePath := createTestBundleStore(t, time.Now().UTC())

		cfg := config.DefaultConfig()
		cfg.Offline.AttestationStore = storePath

		met := &bundle.Metrics{
			OnStaleness:    func(_ string) {},
			OnVerification: func(_ string) {},
			SetAge:         func(_ float64) {},
			SetImageCount:  func(_ float64) {},
		}

		fetcher, err := verifier.ExportCreateBundleFetcher(cfg, met)
		if err != nil {
			t.Fatalf("createBundleFetcher() error: %v", err)
		}

		if fetcher == nil {
			t.Fatal("expected non-nil fetcher")
		}
	})

	t.Run("fails with invalid store path", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Offline.AttestationStore = testNonexistentPath

		_, err := verifier.ExportCreateBundleFetcher(cfg, nil)
		if err == nil {
			t.Fatal("expected error for invalid store path")
		}
	})
}

func TestCreateFetcherForMode(t *testing.T) {
	t.Parallel()

	t.Run("disabled mode returns OCI fetcher", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Offline.Mode = config.OfflineModeDisabled

		fetcher, err := verifier.ExportCreateFetcherForMode(
			context.Background(), cfg, nil, nil,
		)
		if err != nil {
			t.Fatalf("createFetcherForMode() error: %v", err)
		}

		if fetcher == nil {
			t.Fatal("expected non-nil fetcher")
		}

		if _, ok := fetcher.(*attestation.OCIFetcher); !ok {
			t.Errorf("expected *attestation.OCIFetcher, got %T", fetcher)
		}
	})

	t.Run("offline mode returns bundle fetcher", func(t *testing.T) {
		t.Parallel()

		storePath := createTestBundleStore(t, time.Now().UTC())

		cfg := config.DefaultConfig()
		cfg.Offline.Mode = config.OfflineModeOffline
		cfg.Offline.AttestationStore = storePath

		fetcher, err := verifier.ExportCreateFetcherForMode(
			context.Background(), cfg, nil, nil,
		)
		if err != nil {
			t.Fatalf("createFetcherForMode() error: %v", err)
		}

		if fetcher == nil {
			t.Fatal("expected non-nil fetcher")
		}

		if _, ok := fetcher.(*bundle.Fetcher); !ok {
			t.Errorf("expected *bundle.Fetcher, got %T", fetcher)
		}
	})

	t.Run("prefer-bundle mode returns fallback fetcher", func(t *testing.T) {
		t.Parallel()

		storePath := createTestBundleStore(t, time.Now().UTC())

		cfg := config.DefaultConfig()
		cfg.Offline.Mode = config.OfflineModePreferBundle
		cfg.Offline.AttestationStore = storePath

		fetcher, err := verifier.ExportCreateFetcherForMode(
			context.Background(), cfg, nil, nil,
		)
		if err != nil {
			t.Fatalf("createFetcherForMode() error: %v", err)
		}

		if fetcher == nil {
			t.Fatal("expected non-nil fetcher")
		}

		if _, ok := fetcher.(*bundle.FallbackFetcher); !ok {
			t.Errorf("expected *bundle.FallbackFetcher, got %T", fetcher)
		}
	})

	t.Run("offline mode with invalid store fails", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Offline.Mode = config.OfflineModeOffline
		cfg.Offline.AttestationStore = testNonexistent

		_, err := verifier.ExportCreateFetcherForMode(
			context.Background(), cfg, nil, nil,
		)
		if err == nil {
			t.Fatal("expected error for invalid store path")
		}
	})

	t.Run("prefer-bundle mode with invalid store fails", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Offline.Mode = config.OfflineModePreferBundle
		cfg.Offline.AttestationStore = testNonexistent

		_, err := verifier.ExportCreateFetcherForMode(
			context.Background(), cfg, nil, nil,
		)
		if err == nil {
			t.Fatal("expected error for invalid store path in prefer-bundle mode")
		}
	})
}

func TestBundleMetricsIntegration(t *testing.T) {
	t.Parallel()

	storePath := createTestBundleStore(t, time.Now().UTC())
	store := openTestStore(t, storePath)
	bundleFetcher := bundle.NewFetcher(store, noopVerify)

	met := metrics.New()
	verifier.ExportSetBundleMetricsOnFetcher(bundleFetcher, met)

	fetchOpts := &attestation.FetchOptions{
		Digest: "sha256:nonexistent",
	}

	_, _ = bundleFetcher.Fetch(
		context.Background(),
		"test-image",
		fetchOpts,
	)

	verificationCount := promtestutil.ToFloat64(
		met.BundleVerificationsTotal.WithLabelValues("success"),
	) + promtestutil.ToFloat64(
		met.BundleVerificationsTotal.WithLabelValues("error"),
	)

	if verificationCount == 0 {
		t.Error("expected at least one verification metric recorded")
	}
}

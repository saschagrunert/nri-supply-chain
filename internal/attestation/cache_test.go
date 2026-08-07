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

package attestation_test

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
)

var errRootFetchFailed = errors.New("root fetch failed")

func fakeTrustedRoot() *root.TrustedRoot {
	return &root.TrustedRoot{}
}

func TestTrustedRootCacheFreshFetch(t *testing.T) {
	t.Parallel()

	expected := fakeTrustedRoot()
	cache := attestation.NewTestTrustedRootCache(func() (*root.TrustedRoot, error) {
		return expected, nil
	})

	got, err := cache.GetTrustedRoot(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got != expected {
		t.Error("expected returned root to match fetched root")
	}
}

func TestTrustedRootCacheHit(t *testing.T) {
	t.Parallel()

	expected := fakeTrustedRoot()

	var fetchCount atomic.Int32

	cache := attestation.NewTestTrustedRootCacheWithRoot(
		func() (*root.TrustedRoot, error) {
			fetchCount.Add(1)

			return fakeTrustedRoot(), nil
		},
		expected,
		time.Now(),
	)

	got, err := cache.GetTrustedRoot(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got != expected {
		t.Error("expected cached root to be returned")
	}

	if fetchCount.Load() != 0 {
		t.Errorf("expected no fetch calls, got %d", fetchCount.Load())
	}
}

func TestTrustedRootCacheExpiredRefreshes(t *testing.T) {
	t.Parallel()

	staleRoot := fakeTrustedRoot()
	freshRoot := fakeTrustedRoot()

	cache := attestation.NewTestTrustedRootCacheWithRoot(
		func() (*root.TrustedRoot, error) {
			return freshRoot, nil
		},
		staleRoot,
		time.Now().Add(-2*attestation.ExportTrustedRootCacheTTL()),
	)

	got, err := cache.GetTrustedRoot(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got != freshRoot {
		t.Error("expected fresh root after TTL expiry")
	}
}

func TestTrustedRootCacheFetchErrorFallsBackToStale(t *testing.T) {
	t.Parallel()

	staleRoot := fakeTrustedRoot()

	cache := attestation.NewTestTrustedRootCacheWithRoot(
		func() (*root.TrustedRoot, error) {
			return nil, errRootFetchFailed
		},
		staleRoot,
		time.Now().Add(-2*attestation.ExportTrustedRootCacheTTL()),
	)

	got, err := cache.GetTrustedRoot(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got != staleRoot {
		t.Error("expected stale root as fallback")
	}
}

func TestTrustedRootCacheMaxStalenessRejectsOldRoot(t *testing.T) {
	t.Parallel()

	staleRoot := fakeTrustedRoot()

	cache := attestation.NewTestTrustedRootCacheWithRoot(
		func() (*root.TrustedRoot, error) {
			return nil, errRootFetchFailed
		},
		staleRoot,
		time.Now().Add(-2*attestation.ExportTrustedRootMaxStaleness()),
	)

	_, err := cache.GetTrustedRoot(context.Background())
	if err == nil {
		t.Fatal("expected error for stale root beyond max staleness")
	}

	if !strings.Contains(err.Error(), "stale") {
		t.Errorf("expected staleness error, got: %v", err)
	}
}

func TestTrustedRootCacheFetchErrorNoCachedRoot(t *testing.T) {
	t.Parallel()

	cache := attestation.NewTestTrustedRootCache(func() (*root.TrustedRoot, error) {
		return nil, errRootFetchFailed
	})

	_, err := cache.GetTrustedRoot(context.Background())
	if err == nil {
		t.Fatal("expected error when no cached root and fetch fails")
	}

	if !errors.Is(err, errRootFetchFailed) {
		t.Errorf("expected wrapped errRootFetchFailed, got: %v", err)
	}
}

func TestTrustedRootCacheCanceledContext(t *testing.T) {
	t.Parallel()

	staleRoot := fakeTrustedRoot()

	cache := attestation.NewTestTrustedRootCacheWithRoot(
		func() (*root.TrustedRoot, error) {
			t.Error("fetch should not be called with canceled context")

			return nil, errRootFetchFailed
		},
		staleRoot,
		time.Now().Add(-2*attestation.ExportTrustedRootCacheTTL()),
	)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := cache.GetTrustedRoot(ctx)
	if err == nil {
		t.Fatal("expected error for canceled context")
	}

	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

func TestTrustedRootCacheFallbackCallbackInvoked(t *testing.T) {
	t.Parallel()

	staleRoot := fakeTrustedRoot()

	var fallbackCount atomic.Int32

	cache := attestation.NewTestTrustedRootCacheWithRoot(
		func() (*root.TrustedRoot, error) {
			return nil, errRootFetchFailed
		},
		staleRoot,
		time.Now().Add(-2*attestation.ExportTrustedRootCacheTTL()),
	)
	cache.SetOnFallback(func() {
		fallbackCount.Add(1)
	})

	got, err := cache.GetTrustedRoot(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got != staleRoot {
		t.Error("expected stale root as fallback")
	}

	if fallbackCount.Load() != 1 {
		t.Errorf("expected onFallback to be called once, got %d", fallbackCount.Load())
	}
}

func TestTrustedRootCacheFallbackCallbackNotCalledOnSuccess(t *testing.T) {
	t.Parallel()

	staleRoot := fakeTrustedRoot()
	freshRoot := fakeTrustedRoot()

	var fallbackCount atomic.Int32

	cache := attestation.NewTestTrustedRootCacheWithRoot(
		func() (*root.TrustedRoot, error) {
			return freshRoot, nil
		},
		staleRoot,
		time.Now().Add(-2*attestation.ExportTrustedRootCacheTTL()),
	)
	cache.SetOnFallback(func() {
		fallbackCount.Add(1)
	})

	got, err := cache.GetTrustedRoot(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got != freshRoot {
		t.Error("expected fresh root after successful refresh")
	}

	if fallbackCount.Load() != 0 {
		t.Errorf("expected onFallback not to be called on success, got %d", fallbackCount.Load())
	}
}

func TestTrustedRootCacheFallbackCallbackNotCalledWhenTooStale(t *testing.T) {
	t.Parallel()

	staleRoot := fakeTrustedRoot()

	var fallbackCount atomic.Int32

	cache := attestation.NewTestTrustedRootCacheWithRoot(
		func() (*root.TrustedRoot, error) {
			return nil, errRootFetchFailed
		},
		staleRoot,
		time.Now().Add(-2*attestation.ExportTrustedRootMaxStaleness()),
	)
	cache.SetOnFallback(func() {
		fallbackCount.Add(1)
	})

	_, err := cache.GetTrustedRoot(context.Background())
	if err == nil {
		t.Fatal("expected error for root beyond max staleness")
	}

	if fallbackCount.Load() != 0 {
		t.Errorf("expected onFallback not to be called when root is too stale, got %d",
			fallbackCount.Load())
	}
}

func TestTrustedRootCachePreSeededFallback(t *testing.T) {
	t.Parallel()

	preSeeded := fakeTrustedRoot()

	cache := attestation.NewTestTrustedRootCacheWithPreSeeded(
		func() (*root.TrustedRoot, error) {
			return nil, errRootFetchFailed
		},
		preSeeded,
	)

	got, err := cache.GetTrustedRoot(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got != preSeeded {
		t.Error("expected pre-seeded root as fallback when fetch fails")
	}
}

func TestTrustedRootCachePreSeededNotUsedOnSuccess(t *testing.T) {
	t.Parallel()

	freshRoot := fakeTrustedRoot()
	preSeeded := fakeTrustedRoot()

	cache := attestation.NewTestTrustedRootCacheWithPreSeeded(
		func() (*root.TrustedRoot, error) {
			return freshRoot, nil
		},
		preSeeded,
	)

	got, err := cache.GetTrustedRoot(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got != freshRoot {
		t.Error("expected fresh root when fetch succeeds, not pre-seeded")
	}

	if got == preSeeded {
		t.Error("pre-seeded root should not be used when fetch succeeds")
	}
}

func TestTrustedRootCacheStaleCacheFallsBackToPreSeeded(t *testing.T) {
	t.Parallel()

	staleRoot := fakeTrustedRoot()
	preSeeded := fakeTrustedRoot()

	var fallbackCount atomic.Int32

	cache := attestation.NewTestTrustedRootCacheWithRootAndPreSeeded(
		func() (*root.TrustedRoot, error) {
			return nil, errRootFetchFailed
		},
		staleRoot,
		time.Now().Add(-2*attestation.ExportTrustedRootMaxStaleness()),
		preSeeded,
	)
	cache.SetOnFallback(func() {
		fallbackCount.Add(1)
	})

	got, err := cache.GetTrustedRoot(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got != preSeeded {
		t.Error("expected pre-seeded root when cached root is beyond max staleness")
	}

	if got == staleRoot {
		t.Error("stale root beyond max staleness should not be returned when pre-seeded exists")
	}

	if fallbackCount.Load() != 1 {
		t.Errorf("expected onFallback to be called once, got %d", fallbackCount.Load())
	}
}

func TestTrustedRootCachePreSeededCallbackInvoked(t *testing.T) {
	t.Parallel()

	preSeeded := fakeTrustedRoot()

	var fallbackCount atomic.Int32

	cache := attestation.NewTestTrustedRootCacheWithPreSeeded(
		func() (*root.TrustedRoot, error) {
			return nil, errRootFetchFailed
		},
		preSeeded,
	)
	cache.SetOnFallback(func() {
		fallbackCount.Add(1)
	})

	got, err := cache.GetTrustedRoot(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got != preSeeded {
		t.Error("expected pre-seeded root as fallback")
	}

	if fallbackCount.Load() != 1 {
		t.Errorf("expected onFallback to be called once for pre-seeded fallback, got %d",
			fallbackCount.Load())
	}
}

func TestTrustedRootCacheNegativeCacheSkipsCDN(t *testing.T) {
	t.Parallel()

	preSeeded := fakeTrustedRoot()

	var fetchCount atomic.Int32

	cache := attestation.NewTestTrustedRootCacheWithPreSeeded(
		func() (*root.TrustedRoot, error) {
			fetchCount.Add(1)

			return nil, errRootFetchFailed
		},
		preSeeded,
	)

	// First call: hits the CDN, fails, falls back to pre-seeded root.
	got, err := cache.GetTrustedRoot(context.Background())
	if err != nil {
		t.Fatalf("unexpected error on first call: %v", err)
	}

	if got != preSeeded {
		t.Error("expected pre-seeded root on first call")
	}

	if fetchCount.Load() != 1 {
		t.Fatalf("expected exactly 1 CDN fetch on first call, got %d", fetchCount.Load())
	}

	// Second call: within negative cache window, should skip CDN entirely.
	got, err = cache.GetTrustedRoot(context.Background())
	if err != nil {
		t.Fatalf("unexpected error on second call: %v", err)
	}

	if got != preSeeded {
		t.Error("expected pre-seeded root on second call (negative cache)")
	}

	if fetchCount.Load() != 1 {
		t.Errorf("expected CDN fetch count to remain 1 (negative cache), got %d",
			fetchCount.Load())
	}
}

func TestTrustedRootCacheNegativeCacheDoesNotApplyWithoutPreSeeded(t *testing.T) {
	t.Parallel()

	var fetchCount atomic.Int32

	cache := attestation.NewTestTrustedRootCache(func() (*root.TrustedRoot, error) {
		fetchCount.Add(1)

		return nil, errRootFetchFailed
	})

	// First call fails with no pre-seeded root available.
	_, err := cache.GetTrustedRoot(context.Background())
	if err == nil {
		t.Fatal("expected error when no pre-seeded root and fetch fails")
	}

	// Second call should still attempt CDN (no negative cache without pre-seeded root).
	_, err = cache.GetTrustedRoot(context.Background())
	if err == nil {
		t.Fatal("expected error on second call")
	}

	if fetchCount.Load() < 2 {
		t.Errorf("expected at least 2 CDN fetches without pre-seeded root, got %d",
			fetchCount.Load())
	}
}

func TestTrustedRootCacheNegativeCacheServesPreSeeded(t *testing.T) {
	t.Parallel()

	preSeeded := fakeTrustedRoot()
	freshRoot := fakeTrustedRoot()

	callNum := atomic.Int32{}

	cache := attestation.NewTestTrustedRootCacheWithPreSeeded(
		func() (*root.TrustedRoot, error) {
			n := callNum.Add(1)

			if n == 1 {
				return nil, errRootFetchFailed
			}

			return freshRoot, nil
		},
		preSeeded,
	)

	// First call: CDN fails, falls back to pre-seeded root.
	got, err := cache.GetTrustedRoot(context.Background())
	if err != nil {
		t.Fatalf("unexpected error on first call: %v", err)
	}

	if got != preSeeded {
		t.Error("expected pre-seeded root on first call")
	}

	// Second call within negative cache window: CDN is skipped, pre-seeded
	// root is returned directly without a fetch attempt.
	got, err = cache.GetTrustedRoot(context.Background())
	if err != nil {
		t.Fatalf("unexpected error on second call: %v", err)
	}

	if got != preSeeded {
		t.Error("expected pre-seeded root on second call (within negative cache window)")
	}
}

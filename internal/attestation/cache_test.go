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

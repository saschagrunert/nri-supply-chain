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

package cache_test

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/saschagrunert/nri-supply-chain/internal/cache"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const testGaugeHelp = "test"

func TestNewWithGaugeResetsToZero(t *testing.T) {
	t.Parallel()

	testGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "test_cache_reset",
		Help: testGaugeHelp,
	})
	testGauge.Set(42)

	_ = cache.NewWithGauge(time.Hour, testGauge)

	val := testutil.ToFloat64(testGauge)
	if val != 0 {
		t.Errorf("expected gauge reset to 0, got %f", val)
	}
}

func TestNewWithGaugeNilGauge(t *testing.T) {
	t.Parallel()

	testCache := cache.NewWithGauge(time.Hour, nil)
	testCache.Set("sha256:abc", "default", &types.Result{
		Allowed: true, Reason: "ok", CheckResults: nil,
	})

	if testCache.Len() != 1 {
		t.Errorf("expected 1 entry, got %d", testCache.Len())
	}
}

func TestGaugeUpdatesOnSetAndClear(t *testing.T) {
	t.Parallel()

	testGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "test_cache_set_clear",
		Help: testGaugeHelp,
	})

	testCache := cache.NewWithGauge(time.Hour, testGauge)

	testCache.Set("sha256:a", "default", &types.Result{
		Allowed: true, Reason: "", CheckResults: nil,
	})

	if val := testutil.ToFloat64(testGauge); val != 1 {
		t.Errorf("expected gauge 1 after set, got %f", val)
	}

	testCache.Set("sha256:b", "default", &types.Result{
		Allowed: true, Reason: "", CheckResults: nil,
	})

	if val := testutil.ToFloat64(testGauge); val != 2 {
		t.Errorf("expected gauge 2 after second set, got %f", val)
	}

	testCache.Clear()

	if val := testutil.ToFloat64(testGauge); val != 0 {
		t.Errorf("expected gauge 0 after clear, got %f", val)
	}
}

func TestGaugeUpdatesOnExpiry(t *testing.T) {
	t.Parallel()

	testGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "test_cache_expiry",
		Help: testGaugeHelp,
	})

	testCache := cache.NewWithGauge(time.Millisecond, testGauge)

	testCache.Set("sha256:a", "default", &types.Result{
		Allowed: true, Reason: "", CheckResults: nil,
	})

	if val := testutil.ToFloat64(testGauge); val != 1 {
		t.Errorf("expected gauge 1 after set, got %f", val)
	}

	time.Sleep(5 * time.Millisecond)

	got := testCache.Get("sha256:a", "default")
	if got != nil {
		t.Error("expected expired entry to be nil")
	}

	if val := testutil.ToFloat64(testGauge); val != 0 {
		t.Errorf("expected gauge 0 after expiry eviction, got %f", val)
	}
}

func TestCacheGetSet(t *testing.T) {
	t.Parallel()

	c := cache.New(time.Hour)

	result := &types.Result{Allowed: true, Reason: "test", CheckResults: nil}
	c.Set("sha256:abc", "default", result)

	got := c.Get("sha256:abc", "default")
	if got == nil {
		t.Fatal("expected cached result, got nil")
	} else if got.Reason != "test" {
		t.Errorf("expected reason 'test', got %q", got.Reason)
	}
}

func TestCacheMiss(t *testing.T) {
	t.Parallel()

	c := cache.New(time.Hour)

	if got := c.Get("sha256:notfound", "default"); got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

func TestCacheNamespaceIsolation(t *testing.T) {
	t.Parallel()

	testCache := cache.New(time.Hour)

	testCache.Set("sha256:abc", "ns1", &types.Result{
		Allowed: true, Reason: "ns1", CheckResults: nil,
	})
	testCache.Set("sha256:abc", "ns2", &types.Result{
		Allowed: false, Reason: "ns2", CheckResults: nil,
	})

	got1 := testCache.Get("sha256:abc", "ns1")
	if got1 == nil || got1.Reason != "ns1" {
		t.Errorf("expected ns1 result, got %v", got1)
	}

	got2 := testCache.Get("sha256:abc", "ns2")
	if got2 == nil || got2.Reason != "ns2" {
		t.Errorf("expected ns2 result, got %v", got2)
	}
}

func TestCacheExpiry(t *testing.T) {
	t.Parallel()

	testCache := cache.New(time.Millisecond)

	testCache.Set("sha256:abc", "default", &types.Result{
		Allowed: true, Reason: "", CheckResults: nil,
	})

	time.Sleep(5 * time.Millisecond)

	if got := testCache.Get("sha256:abc", "default"); got != nil {
		t.Error("expected expired entry to be nil")
	}
}

func TestCacheZeroTTLSkipsSet(t *testing.T) {
	t.Parallel()

	testCache := cache.New(0)

	testCache.Set("sha256:abc", "default", &types.Result{
		Allowed: true, Reason: "", CheckResults: nil,
	})

	if got := testCache.Get("sha256:abc", "default"); got != nil {
		t.Error("expected nil with zero TTL")
	}
}

func TestCacheCapacityEviction(t *testing.T) {
	t.Parallel()

	testCache := cache.New(time.Hour)

	for idx := range 10001 {
		testCache.Set(
			fmt.Sprintf("sha256:%d", idx), "default",
			&types.Result{Allowed: true, Reason: "", CheckResults: nil},
		)
	}

	const expectedSize = 10000
	if testCache.Len() != expectedSize {
		t.Errorf("expected cache size %d after eviction, got %d", expectedSize, testCache.Len())
	}

	got := testCache.Get("sha256:10000", "default")
	if got == nil {
		t.Error("expected new entry to be stored after oldest eviction")
	}
}

func TestCacheLen(t *testing.T) {
	t.Parallel()

	testCache := cache.New(time.Hour)

	if testCache.Len() != 0 {
		t.Errorf("expected empty cache, got %d", testCache.Len())
	}

	testCache.Set("sha256:abc", "default", &types.Result{
		Allowed: true, Reason: "", CheckResults: nil,
	})

	if testCache.Len() != 1 {
		t.Errorf("expected 1 entry, got %d", testCache.Len())
	}
}

func TestCacheCapacityEvictsExpired(t *testing.T) {
	t.Parallel()

	testCache := cache.New(time.Millisecond)

	for idx := range 10000 {
		testCache.Set(
			fmt.Sprintf("sha256:%d", idx), "default",
			&types.Result{Allowed: true, Reason: "", CheckResults: nil},
		)
	}

	time.Sleep(5 * time.Millisecond)

	testCache.Set("sha256:new", "default", &types.Result{
		Allowed: true, Reason: "fresh", CheckResults: nil,
	})

	if got := testCache.Get("sha256:new", "default"); got == nil {
		t.Fatal("expected new entry after expired eviction")
	} else if got.Reason != "fresh" {
		t.Errorf("expected reason 'fresh', got %q", got.Reason)
	}
}

func TestCacheOverwriteUpdatesExpiry(t *testing.T) {
	t.Parallel()

	testCache := cache.New(time.Hour)

	testCache.Set("sha256:abc", "default", &types.Result{
		Allowed: true, Reason: "old", CheckResults: nil,
	})
	testCache.Set("sha256:abc", "default", &types.Result{
		Allowed: true, Reason: "new", CheckResults: nil,
	})

	if testCache.Len() != 1 {
		t.Errorf("expected 1 entry after overwrite, got %d", testCache.Len())
	}

	got := testCache.Get("sha256:abc", "default")
	if got == nil || got.Reason != "new" {
		t.Errorf("expected reason 'new', got %v", got)
	}
}

func TestCacheConcurrent(t *testing.T) {
	t.Parallel()

	testCache := cache.New(50 * time.Millisecond)

	const goroutines = 10

	const iterations = 200

	var waitGroup sync.WaitGroup

	waitGroup.Add(goroutines)

	for goroutine := range goroutines {
		go func() {
			defer waitGroup.Done()

			for iter := range iterations {
				digest := fmt.Sprintf("sha256:%d-%d", goroutine, iter)

				testCache.Set(digest, "default", &types.Result{
					Allowed: true, Reason: digest, CheckResults: nil,
				})

				testCache.Get(digest, "default")
				testCache.Len()

				if iter%50 == 0 {
					testCache.Clear()
				}
			}
		}()
	}

	waitGroup.Wait()
}

func TestCacheCapacityEvictionUpdatesGauge(t *testing.T) {
	t.Parallel()

	testGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "test_cache_eviction",
		Help: testGaugeHelp,
	})

	testCache := cache.NewWithGauge(time.Hour, testGauge)

	for idx := range 10001 {
		testCache.Set(
			fmt.Sprintf("sha256:%d", idx), "default",
			&types.Result{Allowed: true, Reason: "", CheckResults: nil},
		)
	}

	const expectedSize = 10000
	if testCache.Len() != expectedSize {
		t.Errorf("expected cache size %d, got %d", expectedSize, testCache.Len())
	}

	if val := testutil.ToFloat64(testGauge); val != expectedSize {
		t.Errorf("expected gauge %d after eviction, got %f", expectedSize, val)
	}
}

func TestCacheOverwriteAtCapacityKeepsGauge(t *testing.T) {
	t.Parallel()

	testGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "test_cache_overwrite_at_cap",
		Help: testGaugeHelp,
	})

	testCache := cache.NewWithGauge(time.Hour, testGauge)

	const maxSize = 10000
	for idx := range maxSize {
		testCache.Set(
			fmt.Sprintf("sha256:%d", idx), "default",
			&types.Result{Allowed: true, Reason: "old", CheckResults: nil},
		)
	}

	testCache.Set("sha256:0", "default", &types.Result{
		Allowed: true, Reason: "updated", CheckResults: nil,
	})

	if testCache.Len() != maxSize {
		t.Errorf("expected cache size %d, got %d", maxSize, testCache.Len())
	}

	if val := testutil.ToFloat64(testGauge); val != maxSize {
		t.Errorf("expected gauge %d after overwrite, got %f", maxSize, val)
	}

	got := testCache.Get("sha256:0", "default")
	if got == nil || got.Reason != "updated" {
		t.Errorf("expected updated entry, got %v", got)
	}
}

func TestCacheSetWithTTLOverride(t *testing.T) {
	t.Parallel()

	testCache := cache.New(time.Hour)

	// Set with a short TTL override.
	testCache.Set("sha256:fail", "default", &types.Result{
		Allowed: false, Reason: "fetch failed", CheckResults: nil,
	}, 10*time.Millisecond)

	// Set with normal TTL (no override).
	testCache.Set("sha256:pass", "default", &types.Result{
		Allowed: true, Reason: "ok", CheckResults: nil,
	})

	// Both should be present immediately.
	if got := testCache.Get("sha256:fail", "default"); got == nil {
		t.Error("expected failure entry to be present immediately")
	}

	if got := testCache.Get("sha256:pass", "default"); got == nil {
		t.Error("expected pass entry to be present immediately")
	}

	// Wait for the short TTL to expire.
	time.Sleep(20 * time.Millisecond)

	// Failure entry should have expired.
	if got := testCache.Get("sha256:fail", "default"); got != nil {
		t.Error("expected failure entry to have expired with short TTL override")
	}

	// Success entry should still be present.
	if got := testCache.Get("sha256:pass", "default"); got == nil {
		t.Error("expected pass entry to still be present with normal TTL")
	}
}

func TestCacheSetZeroTTLOverrideUsesDefault(t *testing.T) {
	t.Parallel()

	testCache := cache.New(time.Hour)

	// Zero override should use the default TTL.
	testCache.Set("sha256:abc", "default", &types.Result{
		Allowed: true, Reason: "ok", CheckResults: nil,
	}, 0)

	if got := testCache.Get("sha256:abc", "default"); got == nil {
		t.Error("expected entry to be present when zero TTL override falls back to default")
	}
}

func TestCacheClear(t *testing.T) {
	t.Parallel()

	testCache := cache.New(time.Hour)
	testCache.Set("sha256:abc", "default", &types.Result{
		Allowed: true, Reason: "", CheckResults: nil,
	})

	testCache.Clear()

	if got := testCache.Get("sha256:abc", "default"); got != nil {
		t.Error("expected nil after clear")
	}
}

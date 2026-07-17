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
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/cache"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

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

	got := testCache.Get("sha256:10000", "default")
	if got == nil {
		t.Error("expected new entry to be stored after random eviction")
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

	got := testCache.Get("sha256:new", "default")
	if got == nil {
		t.Fatal("expected new entry after expired eviction")
	}

	if got.Reason != "fresh" {
		t.Errorf("expected reason 'fresh', got %q", got.Reason)
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

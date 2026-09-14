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

package cache

import (
	"fmt"
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const indexTestDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

func indexTestResult() *types.Result {
	return &types.Result{Allowed: true, Verified: true, Mode: "", Reason: "", CheckResults: nil}
}

// assertIndexConsistent checks that the digest index holds exactly the keys
// of the cache entries and the expiry heap.
func assertIndexConsistent(t *testing.T, c *Cache) {
	t.Helper()

	c.mu.RLock()
	defer c.mu.RUnlock()

	indexed := 0

	for digest, keys := range c.digestIndex {
		if len(keys) == 0 {
			t.Errorf("digest index keeps an empty key set for %s", digest)
		}

		for cacheKey := range keys {
			indexed++

			if cacheKey.digest != digest {
				t.Errorf("key %+v indexed under digest %s", cacheKey, digest)
			}

			if _, ok := c.entries[cacheKey]; !ok {
				t.Errorf("digest index references removed entry %+v", cacheKey)
			}
		}
	}

	if indexed != len(c.entries) {
		t.Errorf("digest index holds %d keys, cache has %d entries", indexed, len(c.entries))
	}

	if len(c.heapIndex) != len(c.entries) || c.expHeap.Len() != len(c.entries) {
		t.Errorf("heap holds %d/%d keys, cache has %d entries",
			len(c.heapIndex), c.expHeap.Len(), len(c.entries))
	}
}

func TestDigestIndexStaysConsistent(t *testing.T) {
	t.Parallel()

	testCache := NewWithGauge(time.Hour, 5, nil, nil)
	t.Cleanup(testCache.Stop)

	const victimDigest = "sha256:victim"

	testCache.Set(indexTestDigest, "ns", indexTestResult())
	testCache.Set(indexTestDigest, "ns\x00ghcr.io/org/app", indexTestResult())
	testCache.Set(indexTestDigest, "ns\x00r0", indexTestResult())
	testCache.SetWithTTL(indexTestDigest, "nsother", indexTestResult(), 2*time.Hour)
	testCache.SetWithTTL(victimDigest, "ns", indexTestResult(), time.Minute)
	assertIndexConsistent(t, testCache)

	// Overwriting an entry keeps a single index entry.
	testCache.Set(indexTestDigest, "ns", indexTestResult())
	assertIndexConsistent(t, testCache)

	// Capacity eviction removes the entry expiring first from the index.
	testCache.Set("sha256:other", "ns", indexTestResult())
	assertIndexConsistent(t, testCache)

	if testCache.Get(victimDigest, "ns") != nil {
		t.Error("expected capacity eviction to remove the entry expiring first")
	}

	if removed := testCache.DeleteAll(indexTestDigest, "ns"); removed == 0 {
		t.Error("expected DeleteAll to remove entries")
	}

	assertIndexConsistent(t, testCache)

	if testCache.Get(indexTestDigest, "nsother") == nil {
		t.Error("expected DeleteAll to keep an entry whose namespace only shares a prefix")
	}

	if !testCache.Delete(indexTestDigest, "nsother") {
		t.Error("expected Delete to remove the remaining entry")
	}

	assertIndexConsistent(t, testCache)

	testCache.Clear()
	assertIndexConsistent(t, testCache)
}

func TestDigestIndexExpiry(t *testing.T) {
	t.Parallel()

	testCache := NewWithGauge(time.Hour, 10, nil, nil)
	t.Cleanup(testCache.Stop)

	testCache.SetWithTTL(indexTestDigest, "get", indexTestResult(), time.Millisecond)
	testCache.SetWithTTL(indexTestDigest, "evict", indexTestResult(), time.Millisecond)
	testCache.Set(indexTestDigest, "keep", indexTestResult())

	time.Sleep(5 * time.Millisecond)

	// Get removes an expired entry.
	if testCache.Get(indexTestDigest, "get") != nil {
		t.Error("expected expired entry to be gone")
	}

	assertIndexConsistent(t, testCache)

	// Background eviction removes the other expired entry.
	testCache.mu.Lock()
	testCache.evictExpiredLocked()
	testCache.mu.Unlock()

	assertIndexConsistent(t, testCache)

	if removed := testCache.DeleteAll(indexTestDigest, "keep"); removed != 1 {
		t.Errorf("expected DeleteAll to remove 1 entry, removed %d", removed)
	}

	assertIndexConsistent(t, testCache)
}

func BenchmarkDeleteAll(b *testing.B) {
	testCache := NewWithGauge(time.Hour, DefaultMaxSize, nil, nil)
	b.Cleanup(testCache.Stop)

	for idx := range DefaultMaxSize - 1 {
		testCache.Set(fmt.Sprintf("sha256:%064d", idx), "ns", indexTestResult())
	}

	b.ResetTimer()

	for range b.N {
		testCache.Set(indexTestDigest, "ns", indexTestResult())
		testCache.DeleteAll(indexTestDigest, "ns")
	}
}

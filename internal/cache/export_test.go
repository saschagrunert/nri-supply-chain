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
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

// New creates a new verification result cache with the given TTL.
func New(ttl time.Duration) *Cache {
	return NewWithGauge(ttl, 0, nil, nil)
}

// Set stores a verification result in the cache using the default TTL.
func (c *Cache) Set(digest, namespace string, result *types.Result) {
	c.SetWithTTL(digest, namespace, result, c.ttl)
}

// SetWithTTL stores a verification result in the cache with an explicit TTL
// (e.g., a shorter TTL for failure results).
func (c *Cache) SetWithTTL(digest, namespace string, result *types.Result, ttl time.Duration) {
	if ttl <= 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.setLocked(digest, namespace, result, ttl)
}

// Delete removes a single cached entry for the given digest and namespace.
// Returns true if an entry was deleted, false if no entry existed.
func (c *Cache) Delete(digest, namespace string) bool {
	cacheKey := key{digest: digest, namespace: namespace}

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, found := c.entries[cacheKey]; !found {
		return false
	}

	c.removeLocked(cacheKey)
	c.updateGaugeLocked()

	return true
}

// Clear removes all cached entries. Like DeleteAll it advances every
// invalidation epoch, so a verification that started before cannot store its
// result afterwards.
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for shard := range c.epochs {
		c.epochs[shard]++
	}

	c.entries = make(map[key]entry)
	c.expHeap = nil
	c.heapIndex = make(map[key]*heapEntry)
	c.digestIndex = make(map[string]map[key]struct{})

	c.updateGaugeLocked()
}

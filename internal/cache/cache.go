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

// Package cache provides TTL-based caching for supply chain verification results.
package cache

import (
	"sync"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

// maxSize is the maximum number of entries allowed in the cache.
const maxSize = 10000

type key struct {
	digest    string
	namespace string
}

type entry struct {
	result    *types.Result
	expiresAt time.Time
}

// Cache stores supply chain verification results with TTL-based expiry.
type Cache struct {
	mu      sync.Mutex
	entries map[key]entry
	ttl     time.Duration
}

// New creates a new verification result cache with the given TTL.
func New(ttl time.Duration) *Cache {
	return &Cache{
		mu:      sync.Mutex{},
		entries: make(map[key]entry),
		ttl:     ttl,
	}
}

// Get retrieves a cached result for the given digest and namespace.
// Returns nil if no valid cache entry exists.
func (c *Cache) Get(digest, namespace string) *types.Result {
	c.mu.Lock()
	defer c.mu.Unlock()

	cacheKey := key{digest: digest, namespace: namespace}

	cacheEntry, found := c.entries[cacheKey]
	if !found {
		return nil
	}

	if time.Now().After(cacheEntry.expiresAt) {
		delete(c.entries, cacheKey)

		return nil
	}

	return cacheEntry.result
}

// Set stores a verification result in the cache.
func (c *Cache) Set(digest, namespace string, result *types.Result) {
	if c.ttl <= 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.entries) >= maxSize {
		c.evictExpiredLocked()
	}

	if len(c.entries) >= maxSize {
		c.evictRandomLocked()
	}

	cacheKey := key{digest: digest, namespace: namespace}
	c.entries[cacheKey] = entry{
		result:    result,
		expiresAt: time.Now().Add(c.ttl),
	}
}

// Clear removes all cached entries.
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make(map[key]entry)
}

// Len returns the current number of entries in the cache.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return len(c.entries)
}

func (c *Cache) evictRandomLocked() {
	for k := range c.entries {
		delete(c.entries, k)

		break
	}
}

func (c *Cache) evictExpiredLocked() {
	now := time.Now()

	for cacheKey, cacheEntry := range c.entries {
		if now.After(cacheEntry.expiresAt) {
			delete(c.entries, cacheKey)
		}
	}
}

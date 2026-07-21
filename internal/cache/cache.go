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
	"container/heap"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const jitterDivisor = 10

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

type heapEntry struct {
	cacheKey  key
	expiresAt time.Time
	index     int
}

type expiryHeap []*heapEntry

func (h *expiryHeap) Len() int           { return len(*h) }
func (h *expiryHeap) Less(i, j int) bool { return (*h)[i].expiresAt.Before((*h)[j].expiresAt) }

func (h *expiryHeap) Swap(i, j int) {
	(*h)[i], (*h)[j] = (*h)[j], (*h)[i]
	(*h)[i].index = i
	(*h)[j].index = j
}

func (h *expiryHeap) Push(x any) {
	entry := x.(*heapEntry) //nolint:forcetypeassert // heap.Interface contract guarantees *heapEntry
	entry.index = len(*h)
	*h = append(*h, entry)
}

func (h *expiryHeap) Pop() any {
	old := *h
	length := len(old)
	entry := old[length-1]
	old[length-1] = nil
	entry.index = -1
	*h = old[:length-1]

	return entry
}

// Cache stores supply chain verification results with TTL-based expiry.
type Cache struct {
	mu        sync.RWMutex
	entries   map[key]entry
	ttl       time.Duration
	gauge     prometheus.Gauge
	expHeap   expiryHeap
	heapIndex map[key]*heapEntry
}

// New creates a new verification result cache with the given TTL.
func New(ttl time.Duration) *Cache {
	return &Cache{
		mu:        sync.RWMutex{},
		entries:   make(map[key]entry),
		ttl:       ttl,
		gauge:     nil,
		expHeap:   nil,
		heapIndex: make(map[key]*heapEntry),
	}
}

// NewWithGauge creates a cache that updates the given Prometheus gauge
// on entry count changes.
func NewWithGauge(ttl time.Duration, gauge prometheus.Gauge) *Cache {
	if gauge != nil {
		gauge.Set(0)
	}

	return &Cache{
		mu:        sync.RWMutex{},
		entries:   make(map[key]entry),
		ttl:       ttl,
		gauge:     gauge,
		expHeap:   nil,
		heapIndex: make(map[key]*heapEntry),
	}
}

// Get retrieves a cached result for the given digest and namespace.
// Returns nil if no valid cache entry exists.
func (c *Cache) Get(digest, namespace string) *types.Result {
	cacheKey := key{digest: digest, namespace: namespace}

	c.mu.RLock()
	cacheEntry, found := c.entries[cacheKey]

	if !found {
		c.mu.RUnlock()

		return nil
	}

	if !time.Now().After(cacheEntry.expiresAt) {
		result := cacheEntry.result

		c.mu.RUnlock()

		return result
	}

	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	cacheEntry, found = c.entries[cacheKey]
	if !found {
		return nil
	}

	if !time.Now().After(cacheEntry.expiresAt) {
		return cacheEntry.result
	}

	delete(c.entries, cacheKey)

	if heapEnt, ok := c.heapIndex[cacheKey]; ok {
		heap.Remove(&c.expHeap, heapEnt.index)
		delete(c.heapIndex, cacheKey)
	}

	c.updateGaugeLocked()

	return nil
}

// Set stores a verification result in the cache.
// An optional ttlOverride can be provided to use a different TTL for this entry
// (e.g., a shorter TTL for failure results).
func (c *Cache) Set(digest, namespace string, result *types.Result, ttlOverride ...time.Duration) {
	effectiveTTL := c.ttl

	if len(ttlOverride) > 0 && ttlOverride[0] > 0 {
		effectiveTTL = ttlOverride[0]
	}

	if effectiveTTL <= 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	cacheKey := key{digest: digest, namespace: namespace}

	if _, exists := c.entries[cacheKey]; !exists && len(c.entries) >= maxSize {
		c.evictExpiredLocked()

		if len(c.entries) >= maxSize {
			c.evictOldestLocked()
		}
	}

	expiresAt := time.Now().Add(effectiveTTL + jitter(effectiveTTL))

	c.entries[cacheKey] = entry{
		result:    result,
		expiresAt: expiresAt,
	}

	if heapEnt, ok := c.heapIndex[cacheKey]; ok {
		heapEnt.expiresAt = expiresAt
		heap.Fix(&c.expHeap, heapEnt.index)
	} else {
		heapEnt = &heapEntry{cacheKey: cacheKey, expiresAt: expiresAt, index: 0}
		heap.Push(&c.expHeap, heapEnt)
		c.heapIndex[cacheKey] = heapEnt
	}

	c.updateGaugeLocked()
}

// Clear removes all cached entries.
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make(map[key]entry)
	c.expHeap = nil
	c.heapIndex = make(map[key]*heapEntry)

	c.updateGaugeLocked()
}

// Len returns the current number of entries in the cache.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.entries)
}

func (c *Cache) updateGaugeLocked() {
	if c.gauge != nil {
		c.gauge.Set(float64(len(c.entries)))
	}
}

func (c *Cache) evictOldestLocked() {
	if c.expHeap.Len() == 0 {
		return
	}

	popped, ok := heap.Pop(&c.expHeap).(*heapEntry)
	if !ok {
		return
	}

	delete(c.entries, popped.cacheKey)
	delete(c.heapIndex, popped.cacheKey)
}

func (c *Cache) evictExpiredLocked() {
	now := time.Now()

	for c.expHeap.Len() > 0 && now.After(c.expHeap[0].expiresAt) {
		popped, ok := heap.Pop(&c.expHeap).(*heapEntry)
		if !ok {
			return
		}

		delete(c.entries, popped.cacheKey)
		delete(c.heapIndex, popped.cacheKey)
	}
}

func jitter(ttl time.Duration) time.Duration {
	maxJitter := int64(ttl / jitterDivisor)
	if maxJitter <= 0 {
		return 0
	}

	//nolint:gosec // jitter does not need cryptographic randomness
	return time.Duration(rand.IntN(int(maxJitter)))
}

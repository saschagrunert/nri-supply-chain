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
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

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
	entry := x.(*heapEntry) //nolint:forcetypeassert // heap.Interface contract
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
	mu        sync.Mutex
	entries   map[key]entry
	ttl       time.Duration
	gauge     prometheus.Gauge
	expHeap   expiryHeap
	heapIndex map[key]*heapEntry
}

// New creates a new verification result cache with the given TTL.
func New(ttl time.Duration) *Cache {
	return &Cache{
		mu:        sync.Mutex{},
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
		mu:        sync.Mutex{},
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
	c.mu.Lock()
	defer c.mu.Unlock()

	cacheKey := key{digest: digest, namespace: namespace}

	cacheEntry, found := c.entries[cacheKey]
	if !found {
		return nil
	}

	if time.Now().After(cacheEntry.expiresAt) {
		delete(c.entries, cacheKey)

		if heapEnt, ok := c.heapIndex[cacheKey]; ok {
			heap.Remove(&c.expHeap, heapEnt.index)
			delete(c.heapIndex, cacheKey)
		}

		c.updateGaugeLocked()

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
		c.evictOldestLocked()
	}

	cacheKey := key{digest: digest, namespace: namespace}
	expiresAt := time.Now().Add(c.ttl)

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
	c.mu.Lock()
	defer c.mu.Unlock()

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

	he := heap.Pop(&c.expHeap).(*heapEntry) //nolint:forcetypeassert // heap contains only *heapEntry
	delete(c.entries, he.cacheKey)
	delete(c.heapIndex, he.cacheKey)
}

func (c *Cache) evictExpiredLocked() {
	now := time.Now()

	for c.expHeap.Len() > 0 && now.After(c.expHeap[0].expiresAt) {
		he := heap.Pop(&c.expHeap).(*heapEntry) //nolint:forcetypeassert // heap contains only *heapEntry
		delete(c.entries, he.cacheKey)
		delete(c.heapIndex, he.cacheKey)
	}
}

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

const (
	jitterDivisor = 10

	// DefaultMaxSize is the default maximum number of entries in the cache.
	DefaultMaxSize = 10000

	evictionIntervalDivisor = 10
	minEvictionInterval     = 10 * time.Second
	maxEvictionInterval     = 5 * time.Minute
)

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
	maxSize   int
	gauge     prometheus.Gauge
	evictions *prometheus.CounterVec
	expHeap   expiryHeap
	heapIndex map[key]*heapEntry
	stopOnce  sync.Once
	stopCh    chan struct{}
}

// New creates a new verification result cache with the given TTL.
func New(ttl time.Duration) *Cache {
	return NewWithGauge(ttl, 0, nil, nil)
}

// NewWithGauge creates a cache that updates the given Prometheus gauge
// on entry count changes and tracks evictions. If maxSize is <= 0,
// DefaultMaxSize is used as a fallback.
func NewWithGauge(
	ttl time.Duration, maxSize int,
	gauge prometheus.Gauge, evictions *prometheus.CounterVec,
) *Cache {
	if gauge != nil {
		gauge.Set(0)
	}

	effectiveMaxSize := maxSize
	if effectiveMaxSize <= 0 {
		effectiveMaxSize = DefaultMaxSize
	}

	c := &Cache{ //nolint:varnamelen // c is the standard receiver name for Cache
		mu:        sync.RWMutex{},
		entries:   make(map[key]entry),
		ttl:       ttl,
		maxSize:   effectiveMaxSize,
		gauge:     gauge,
		evictions: evictions,
		expHeap:   nil,
		heapIndex: make(map[key]*heapEntry),
		stopOnce:  sync.Once{},
		stopCh:    make(chan struct{}),
	}

	if ttl > 0 {
		go c.backgroundEvict(evictionInterval(ttl))
	}

	return c
}

// Get retrieves a cached result for the given digest and namespace.
// Returns nil if no valid cache entry exists.
func (c *Cache) Get(digest, namespace string) *types.Result {
	cacheKey := key{digest: digest, namespace: namespace}
	now := time.Now()

	c.mu.RLock()
	cacheEntry, found := c.entries[cacheKey]

	if !found {
		c.mu.RUnlock()

		return nil
	}

	if !now.After(cacheEntry.expiresAt) {
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

	cacheKey := key{digest: digest, namespace: namespace}

	if _, exists := c.entries[cacheKey]; !exists && len(c.entries) >= c.maxSize {
		c.evictExpiredLocked()

		if len(c.entries) >= c.maxSize {
			c.evictOldestLocked()
		}
	}

	expiresAt := time.Now().Add(ttl + jitter(ttl))

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

// Delete removes a single cached entry for the given digest and namespace.
// Returns true if an entry was deleted, false if no entry existed.
func (c *Cache) Delete(digest, namespace string) bool {
	cacheKey := key{digest: digest, namespace: namespace}

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, found := c.entries[cacheKey]; !found {
		return false
	}

	delete(c.entries, cacheKey)

	if heapEnt, ok := c.heapIndex[cacheKey]; ok {
		heap.Remove(&c.expHeap, heapEnt.index)
		delete(c.heapIndex, cacheKey)
	}

	c.updateGaugeLocked()

	return true
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

// MaxSize returns the maximum number of entries the cache can hold.
func (c *Cache) MaxSize() int {
	return c.maxSize
}

// Stop terminates the background eviction goroutine. Safe to call multiple
// times; only the first call has an effect. After Stop returns, no further
// background eviction will occur.
func (c *Cache) Stop() {
	c.stopOnce.Do(func() { close(c.stopCh) })
}

func (c *Cache) backgroundEvict(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.mu.Lock()
			c.evictExpiredLocked()
			c.updateGaugeLocked()
			c.mu.Unlock()
		}
	}
}

func evictionInterval(ttl time.Duration) time.Duration {
	return min(
		max(ttl/evictionIntervalDivisor, minEvictionInterval),
		maxEvictionInterval,
	)
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
	c.recordEviction("capacity")
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
		c.recordEviction("expired")
	}
}

func (c *Cache) recordEviction(reason string) {
	if c.evictions != nil {
		c.evictions.WithLabelValues(reason).Inc()
	}
}

func jitter(ttl time.Duration) time.Duration {
	maxJitter := int64(ttl / jitterDivisor)
	if maxJitter <= 0 {
		return 0
	}

	//nolint:gosec // jitter does not need cryptographic randomness
	return time.Duration(rand.Int64N(maxJitter))
}

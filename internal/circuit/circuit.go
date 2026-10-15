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

// Package circuit provides circuit breakers that short-circuit requests to
// unavailable remote services (registries, GUAC).
package circuit

import (
	"sync"
	"sync/atomic"
	"time"
)

const maxBreakers = 1000

type circuitState int

const (
	circuitClosed circuitState = iota
	circuitOpen
	circuitHalfOpen
)

// Breaker prevents repeated fetch attempts when a registry is unavailable.
// After a configurable number of consecutive failures, it short-circuits to the
// configured failure policy for a cooldown period before allowing a probe request.
type Breaker struct {
	mu                  sync.RWMutex
	state               circuitState
	consecutiveFailures int
	lastFailureTime     time.Time
	threshold           int
	cooldown            time.Duration
	// probe identifies the request admitted as the half-open probe; it is
	// incremented for every new probe so stale permits never match.
	probe uint64
}

// Permit records how Acquire admitted a request. Only the permit of the
// half-open probe can release the probe or decide its outcome, so a request
// admitted before the breaker tripped cannot interfere with the probe.
type Permit struct {
	probe uint64
}

// NewBreaker creates a circuit breaker that opens after threshold
// consecutive failures and stays open for the cooldown duration.
func NewBreaker(threshold int, cooldown time.Duration) *Breaker {
	return &Breaker{
		mu:                  sync.RWMutex{},
		state:               circuitClosed,
		consecutiveFailures: 0,
		lastFailureTime:     time.Time{},
		threshold:           threshold,
		cooldown:            cooldown,
		probe:               0,
	}
}

// Allow returns true if the request should proceed. When the circuit is open
// and the cooldown has elapsed, it transitions to half-open and allows a
// single probe request. Use Acquire when the caller needs to release the
// probe or report its outcome.
func (cb *Breaker) Allow() bool {
	_, allowed := cb.Acquire()

	return allowed
}

// Acquire reports whether a request should proceed and returns its permit.
// Uses RLock for the common closed-state fast path to avoid write-lock
// contention. When the circuit is open and the cooldown has elapsed, it
// transitions to half-open and admits a single probe request.
func (cb *Breaker) Acquire() (Permit, bool) {
	cb.mu.RLock()
	state := cb.state
	cb.mu.RUnlock()

	if state == circuitClosed {
		return Permit{probe: 0}, true
	}

	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case circuitClosed:
		return Permit{probe: 0}, true

	case circuitOpen:
		if time.Since(cb.lastFailureTime) >= cb.cooldown {
			cb.state = circuitHalfOpen
			cb.probe++

			return Permit{probe: cb.probe}, true
		}

		return Permit{probe: 0}, false

	case circuitHalfOpen:
		return Permit{probe: 0}, false

	default:
		return Permit{probe: 0}, true
	}
}

// RecordSuccess resets the circuit breaker to the closed state.
func (cb *Breaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.recordSuccessLocked()
}

// Succeeded records a successful request admitted with permit. While the
// breaker is half-open only the probe's outcome counts.
func (cb *Breaker) Succeeded(permit Permit) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if !cb.decidesLocked(permit) {
		return
	}

	cb.recordSuccessLocked()
}

// RecordFailure records a failure. If the failure count reaches the threshold,
// the circuit transitions to open. Returns true only on the initial trip
// (closed to open), not on re-entry from half-open after a failed probe.
func (cb *Breaker) RecordFailure() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	return cb.recordFailureLocked()
}

// Failed records a failed request admitted with permit and reports whether
// it tripped the breaker. While the breaker is half-open only the probe's
// outcome counts.
func (cb *Breaker) Failed(permit Permit) bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if !cb.decidesLocked(permit) {
		return false
	}

	return cb.recordFailureLocked()
}

// Release returns a half-open breaker to the open state without recording a
// failure when permit belongs to the probe. Call it when a request ended
// without a registry outcome (for example a local concurrency limit), so the
// next request can probe again instead of the breaker staying half-open.
// Permits of other requests are ignored.
func (cb *Breaker) Release(permit Permit) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.state == circuitHalfOpen && permit.probe != 0 && permit.probe == cb.probe {
		cb.state = circuitOpen
	}
}

// decidesLocked reports whether the outcome of the request admitted with
// permit may change the breaker state: always, except while half-open, when
// only the probe decides.
func (cb *Breaker) decidesLocked(permit Permit) bool {
	return cb.state != circuitHalfOpen || (permit.probe != 0 && permit.probe == cb.probe)
}

func (cb *Breaker) recordSuccessLocked() {
	cb.consecutiveFailures = 0
	cb.state = circuitClosed
}

func (cb *Breaker) recordFailureLocked() bool {
	cb.consecutiveFailures++
	cb.lastFailureTime = time.Now()

	if cb.consecutiveFailures >= cb.threshold {
		tripped := cb.state == circuitClosed
		cb.state = circuitOpen

		return tripped
	}

	return false
}

func (cb *Breaker) isClosed() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	return cb.state == circuitClosed
}

// Registry manages per-host circuit breakers. Each registry host gets its
// own breaker so that a failing registry does not block requests to healthy
// registries.
//
// Lock ordering: r.mu must be acquired before any breaker.mu. The eviction
// methods acquire breaker.mu (via isClosed) while holding r.mu; callers must
// not hold a breaker.mu when calling Get.
type Registry struct {
	mu        sync.RWMutex
	breakers  map[string]*registryEntry
	threshold int
	cooldown  time.Duration
	// clock orders the uses of entries for least recently used eviction.
	clock atomic.Uint64
}

// registryEntry is a breaker of a Registry and its last use.
type registryEntry struct {
	breaker  *Breaker
	lastUsed atomic.Uint64
}

// NewRegistry creates a registry that lazily creates per-host circuit
// breakers with the given threshold and cooldown.
func NewRegistry(threshold int, cooldown time.Duration) *Registry {
	return &Registry{
		mu:        sync.RWMutex{},
		breakers:  make(map[string]*registryEntry),
		threshold: threshold,
		cooldown:  cooldown,
		clock:     atomic.Uint64{},
	}
}

// Get returns the circuit breaker for the given registry host, creating one
// if it does not exist. The registry is capped at 1000 entries. When it is
// full, closed breakers are evicted first; when every breaker is open or
// half-open, the least recently used one is evicted. Every host keeps a
// breaker of its own, so hosts that keep failing cannot trip the breaker of
// another host, and an evicted host merely starts over with a closed breaker.
func (r *Registry) Get(host string) *Breaker {
	r.mu.RLock()
	entry, found := r.breakers[host]
	r.mu.RUnlock()

	if found {
		entry.lastUsed.Store(r.clock.Add(1))

		return entry.breaker
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	entry, found = r.breakers[host]
	if found {
		entry.lastUsed.Store(r.clock.Add(1))

		return entry.breaker
	}

	if len(r.breakers) >= maxBreakers {
		r.evictClosedLocked()
	}

	if len(r.breakers) >= maxBreakers {
		r.evictLeastRecentlyUsedLocked()
	}

	entry = &registryEntry{
		breaker:  NewBreaker(r.threshold, r.cooldown),
		lastUsed: atomic.Uint64{},
	}
	entry.lastUsed.Store(r.clock.Add(1))
	r.breakers[host] = entry

	return entry.breaker
}

// States returns a map of registry host to circuit breaker state string.
// Possible values are "closed", "open", and "half-open".
// Lock ordering: acquires r.mu (read), then each breaker.mu (read).
func (r *Registry) States() map[string]string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	states := make(map[string]string, len(r.breakers))

	for host, entry := range r.breakers {
		states[host] = breakerStateName(entry.breaker)
	}

	return states
}

func breakerStateName(breaker *Breaker) string {
	breaker.mu.RLock()
	defer breaker.mu.RUnlock()

	switch breaker.state {
	case circuitClosed:
		return "closed"
	case circuitOpen:
		return "open"
	case circuitHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// evictClosedLocked removes the breakers in the closed state; they hold no
// state worth keeping.
// Lock ordering: r.mu must be held; acquires breaker.mu via isClosed.
func (r *Registry) evictClosedLocked() {
	for host, entry := range r.breakers {
		if entry.breaker.isClosed() {
			delete(r.breakers, host)
		}
	}
}

// evictLeastRecentlyUsedLocked removes the breaker that was used least
// recently. r.mu must be held.
func (r *Registry) evictLeastRecentlyUsedLocked() {
	var (
		oldestHost string
		oldestUse  uint64
		found      bool
	)

	for host, entry := range r.breakers {
		used := entry.lastUsed.Load()
		if !found || used < oldestUse {
			oldestHost, oldestUse, found = host, used, true
		}
	}

	if found {
		delete(r.breakers, oldestHost)
	}
}

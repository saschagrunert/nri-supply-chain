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

package attestation

import (
	"log/slog"
	"sync"
	"time"
)

const maxCircuitBreakers = 1000

type circuitState int

const (
	circuitClosed circuitState = iota
	circuitOpen
	circuitHalfOpen
)

// CircuitBreaker prevents repeated fetch attempts when a registry is unavailable.
// After a configurable number of consecutive failures, it short-circuits to the
// configured failure policy for a cooldown period before allowing a probe request.
type CircuitBreaker struct {
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

// NewCircuitBreaker creates a circuit breaker that opens after threshold
// consecutive failures and stays open for the cooldown duration.
func NewCircuitBreaker(threshold int, cooldown time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
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
func (cb *CircuitBreaker) Allow() bool {
	_, allowed := cb.Acquire()

	return allowed
}

// Acquire reports whether a request should proceed and returns its permit.
// Uses RLock for the common closed-state fast path to avoid write-lock
// contention. When the circuit is open and the cooldown has elapsed, it
// transitions to half-open and admits a single probe request.
func (cb *CircuitBreaker) Acquire() (Permit, bool) {
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
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.recordSuccessLocked()
}

// Succeeded records a successful request admitted with permit. While the
// breaker is half-open only the probe's outcome counts.
func (cb *CircuitBreaker) Succeeded(permit Permit) {
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
func (cb *CircuitBreaker) RecordFailure() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	return cb.recordFailureLocked()
}

// Failed records a failed request admitted with permit and reports whether
// it tripped the breaker. While the breaker is half-open only the probe's
// outcome counts.
func (cb *CircuitBreaker) Failed(permit Permit) bool {
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
func (cb *CircuitBreaker) Release(permit Permit) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.state == circuitHalfOpen && permit.probe != 0 && permit.probe == cb.probe {
		cb.state = circuitOpen
	}
}

// decidesLocked reports whether the outcome of the request admitted with
// permit may change the breaker state: always, except while half-open, when
// only the probe decides.
func (cb *CircuitBreaker) decidesLocked(permit Permit) bool {
	return cb.state != circuitHalfOpen || (permit.probe != 0 && permit.probe == cb.probe)
}

func (cb *CircuitBreaker) recordSuccessLocked() {
	cb.consecutiveFailures = 0
	cb.state = circuitClosed
}

func (cb *CircuitBreaker) recordFailureLocked() bool {
	cb.consecutiveFailures++
	cb.lastFailureTime = time.Now()

	if cb.consecutiveFailures >= cb.threshold {
		tripped := cb.state == circuitClosed
		cb.state = circuitOpen

		return tripped
	}

	return false
}

func (cb *CircuitBreaker) isClosed() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	return cb.state == circuitClosed
}

// CircuitBreakerRegistry manages per-host circuit breakers. Each registry host
// gets its own breaker so that a failing registry does not block requests to
// healthy registries.
//
// Lock ordering: r.mu must be acquired before any breaker.mu. The
// evictNonOpenLocked method acquires breaker.mu (via isClosed) while
// holding r.mu; callers must not hold a breaker.mu when calling Get.
type CircuitBreakerRegistry struct {
	mu        sync.RWMutex
	breakers  map[string]*CircuitBreaker
	overflow  *CircuitBreaker
	threshold int
	cooldown  time.Duration
}

// NewCircuitBreakerRegistry creates a registry that lazily creates per-host
// circuit breakers with the given threshold and cooldown.
func NewCircuitBreakerRegistry(threshold int, cooldown time.Duration) *CircuitBreakerRegistry {
	return &CircuitBreakerRegistry{
		mu:        sync.RWMutex{},
		breakers:  make(map[string]*CircuitBreaker),
		overflow:  nil,
		threshold: threshold,
		cooldown:  cooldown,
	}
}

// Get returns the circuit breaker for the given registry host, creating one
// if it does not exist. The registry is capped at 1000 entries; when full,
// existing closed breakers are evicted before adding new ones.
func (r *CircuitBreakerRegistry) Get(host string) *CircuitBreaker {
	r.mu.RLock()
	breaker, found := r.breakers[host]
	r.mu.RUnlock()

	if found {
		return breaker
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	breaker, found = r.breakers[host]
	if found {
		return breaker
	}

	if len(r.breakers) >= maxCircuitBreakers {
		r.evictNonOpenLocked()
	}

	if len(r.breakers) >= maxCircuitBreakers {
		// All hosts beyond capacity share a single overflow breaker.
		// This prevents unbounded map growth at the cost of per-host
		// isolation for the overflow set.
		slog.Warn("Circuit breaker registry at capacity, using shared overflow breaker",
			"host", host, "capacity", maxCircuitBreakers)

		if r.overflow == nil {
			r.overflow = NewCircuitBreaker(r.threshold, r.cooldown)
		}

		return r.overflow
	}

	breaker = NewCircuitBreaker(r.threshold, r.cooldown)
	r.breakers[host] = breaker

	return breaker
}

// States returns a map of registry host to circuit breaker state string.
// Possible values are "closed", "open", and "half-open".
// The shared overflow breaker (if active) is reported under the key "(overflow)".
// Lock ordering: acquires r.mu (read), then each breaker.mu (read).
func (r *CircuitBreakerRegistry) States() map[string]string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	states := make(map[string]string, len(r.breakers)+1)

	for host, breaker := range r.breakers {
		states[host] = breakerStateName(breaker)
	}

	if r.overflow != nil {
		states["(overflow)"] = breakerStateName(r.overflow)
	}

	return states
}

func breakerStateName(breaker *CircuitBreaker) string {
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

// evictNonOpenLocked removes breakers in the closed state. Half-open
// breakers are preserved because they are awaiting a probe result.
// Lock ordering: r.mu must be held; acquires breaker.mu via isClosed.
func (r *CircuitBreakerRegistry) evictNonOpenLocked() {
	for host, breaker := range r.breakers {
		if breaker.isClosed() {
			delete(r.breakers, host)
		}
	}
}

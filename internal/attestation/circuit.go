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
	}
}

// Allow returns true if the request should proceed. Uses RLock for the
// common closed-state fast path to avoid write-lock contention. When the
// circuit is open and the cooldown has elapsed, it transitions to half-open
// and allows a single probe request.
func (cb *CircuitBreaker) Allow() bool {
	cb.mu.RLock()
	state := cb.state
	cb.mu.RUnlock()

	if state == circuitClosed {
		return true
	}

	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case circuitClosed:
		return true

	case circuitOpen:
		if time.Since(cb.lastFailureTime) >= cb.cooldown {
			cb.state = circuitHalfOpen

			return true
		}

		return false

	case circuitHalfOpen:
		return false

	default:
		return true
	}
}

// RecordSuccess resets the circuit breaker to the closed state.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.consecutiveFailures = 0
	cb.state = circuitClosed
}

// RecordFailure records a failure. If the failure count reaches the threshold,
// the circuit transitions to open. Returns true only on the initial trip
// (closed to open), not on re-entry from half-open after a failed probe.
func (cb *CircuitBreaker) RecordFailure() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

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

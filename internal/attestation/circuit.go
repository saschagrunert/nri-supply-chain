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
	mu                  sync.Mutex
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
		mu:                  sync.Mutex{},
		state:               circuitClosed,
		consecutiveFailures: 0,
		lastFailureTime:     time.Time{},
		threshold:           threshold,
		cooldown:            cooldown,
	}
}

// Allow returns true if the request should proceed. When the circuit is open
// and the cooldown has elapsed, it transitions to half-open and allows a single
// probe request.
func (cb *CircuitBreaker) Allow() bool {
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

// IsOpen returns true if the circuit breaker is in the open state.
func (cb *CircuitBreaker) IsOpen() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	return cb.state == circuitOpen
}

// Threshold returns the configured failure threshold.
// Safe to call without synchronization: threshold is immutable after construction.
func (cb *CircuitBreaker) Threshold() int {
	return cb.threshold
}

// Cooldown returns the configured cooldown duration.
// Safe to call without synchronization: cooldown is immutable after construction.
func (cb *CircuitBreaker) Cooldown() time.Duration {
	return cb.cooldown
}

// CircuitBreakerRegistry manages per-host circuit breakers. Each registry host
// gets its own breaker so that a failing registry does not block requests to
// healthy registries.
type CircuitBreakerRegistry struct {
	mu        sync.Mutex
	breakers  map[string]*CircuitBreaker
	threshold int
	cooldown  time.Duration
}

// NewCircuitBreakerRegistry creates a registry that lazily creates per-host
// circuit breakers with the given threshold and cooldown.
func NewCircuitBreakerRegistry(threshold int, cooldown time.Duration) *CircuitBreakerRegistry {
	return &CircuitBreakerRegistry{
		mu:        sync.Mutex{},
		breakers:  make(map[string]*CircuitBreaker),
		threshold: threshold,
		cooldown:  cooldown,
	}
}

// Get returns the circuit breaker for the given registry host, creating one
// if it does not exist. The registry is capped at 1000 entries; when full,
// existing closed breakers are evicted before adding new ones.
func (r *CircuitBreakerRegistry) Get(host string) *CircuitBreaker {
	r.mu.Lock()
	defer r.mu.Unlock()

	breaker, ok := r.breakers[host]
	if ok {
		return breaker
	}

	if len(r.breakers) >= maxCircuitBreakers {
		r.evictNonOpenLocked()
	}

	if len(r.breakers) >= maxCircuitBreakers {
		slog.Warn("Circuit breaker registry at capacity, reusing default breaker",
			"host", host, "capacity", maxCircuitBreakers)

		return NewCircuitBreaker(r.threshold, r.cooldown)
	}

	breaker = NewCircuitBreaker(r.threshold, r.cooldown)
	r.breakers[host] = breaker

	return breaker
}

// Threshold returns the configured failure threshold.
// Safe to call without synchronization: threshold is immutable after construction.
func (r *CircuitBreakerRegistry) Threshold() int {
	return r.threshold
}

// Cooldown returns the configured cooldown duration.
// Safe to call without synchronization: cooldown is immutable after construction.
func (r *CircuitBreakerRegistry) Cooldown() time.Duration {
	return r.cooldown
}

func (r *CircuitBreakerRegistry) evictNonOpenLocked() {
	for host, breaker := range r.breakers {
		if !breaker.IsOpen() {
			delete(r.breakers, host)
		}
	}
}

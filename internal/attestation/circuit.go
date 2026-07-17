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
	"sync"
	"time"
)

type circuitState int

const (
	circuitClosed circuitState = iota
	circuitOpen
	circuitHalfOpen
)

// CircuitBreaker prevents repeated fetch attempts when the registry is unavailable.
// After a configurable number of consecutive failures, it short-circuits to the
// configured failure policy for a cooldown period before allowing a probe request.
// The breaker is global (not per-registry): one failing registry can open the
// breaker for all registries.
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
func (cb *CircuitBreaker) Threshold() int {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	return cb.threshold
}

// Cooldown returns the configured cooldown duration.
func (cb *CircuitBreaker) Cooldown() time.Duration {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	return cb.cooldown
}

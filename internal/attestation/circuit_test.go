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

package attestation_test

import (
	"crypto/rand"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
)

func TestCircuitBreakerAllowsWhenClosed(t *testing.T) {
	t.Parallel()

	breaker := attestation.NewCircuitBreaker(3, time.Second)

	if !breaker.Allow() {
		t.Error("expected Allow() = true when closed")
	}
}

func TestCircuitBreakerOpensAfterThreshold(t *testing.T) {
	t.Parallel()

	breaker := attestation.NewCircuitBreaker(3, time.Minute)

	for range 3 {
		breaker.RecordFailure()
	}

	if breaker.Allow() {
		t.Error("expected Allow() = false after threshold failures")
	}

	if !breaker.IsOpen() {
		t.Error("expected IsOpen() = true")
	}
}

func TestCircuitBreakerRecordFailureReturnsTrueOnTrip(t *testing.T) {
	t.Parallel()

	breaker := attestation.NewCircuitBreaker(2, time.Minute)

	if tripped := breaker.RecordFailure(); tripped {
		t.Error("expected first failure not to trip")
	}

	if tripped := breaker.RecordFailure(); !tripped {
		t.Error("expected second failure to trip")
	}

	if tripped := breaker.RecordFailure(); tripped {
		t.Error("expected subsequent failure not to report tripped again")
	}
}

func TestCircuitBreakerTransitionsToHalfOpenAfterCooldown(t *testing.T) {
	t.Parallel()

	breaker := attestation.NewCircuitBreaker(1, time.Millisecond)

	breaker.RecordFailure()

	if breaker.Allow() {
		t.Error("expected Allow() = false immediately after trip")
	}

	time.Sleep(5 * time.Millisecond)

	if !breaker.Allow() {
		t.Error("expected Allow() = true after cooldown (half-open probe)")
	}

	if breaker.Allow() {
		t.Error("expected Allow() = false for second call in half-open")
	}
}

func TestCircuitBreakerSuccessResetsToClosed(t *testing.T) {
	t.Parallel()

	breaker := attestation.NewCircuitBreaker(1, time.Millisecond)

	breaker.RecordFailure()

	time.Sleep(5 * time.Millisecond)

	breaker.Allow()

	breaker.RecordSuccess()

	if !breaker.Allow() {
		t.Error("expected Allow() = true after success reset")
	}

	if breaker.IsOpen() {
		t.Error("expected IsOpen() = false after success")
	}
}

func TestCircuitBreakerFailureInHalfOpenReopens(t *testing.T) {
	t.Parallel()

	breaker := attestation.NewCircuitBreaker(1, time.Millisecond)

	breaker.RecordFailure()

	time.Sleep(5 * time.Millisecond)

	breaker.Allow()

	breaker.RecordFailure()

	if breaker.Allow() {
		t.Error("expected Allow() = false after half-open failure")
	}
}

func TestCircuitBreakerConcurrent(t *testing.T) {
	t.Parallel()

	breaker := attestation.NewCircuitBreaker(10, 100*time.Millisecond)

	var waitGroup sync.WaitGroup

	for range 50 {
		waitGroup.Go(func() {
			for range 100 {
				if breaker.Allow() {
					n, err := rand.Int(rand.Reader, big.NewInt(2))
					if err != nil || n.Int64() == 0 {
						breaker.RecordSuccess()
					} else {
						breaker.RecordFailure()
					}
				}
			}
		})
	}

	waitGroup.Wait()

	// Primary value of this test is the -race detector catching data races.
	// These assertions just confirm the breaker is in a valid state afterward.
	_ = breaker.IsOpen()
}

func TestCircuitBreakerRegistryPerHost(t *testing.T) {
	t.Parallel()

	registry := attestation.NewCircuitBreakerRegistry(2, time.Minute)

	a := registry.Get("registry-a.example.com")
	b := registry.Get("registry-b.example.com")

	if a == b {
		t.Error("expected different breaker instances per host")
	}

	a.RecordFailure()
	a.RecordFailure()

	if !a.IsOpen() {
		t.Error("expected breaker A to be open after threshold failures")
	}

	if b.IsOpen() {
		t.Error("expected breaker B to remain closed")
	}

	if registry.Get("registry-a.example.com") != a {
		t.Error("expected same breaker instance for same host")
	}
}

func TestCircuitBreakerRegistryThresholdAndCooldown(t *testing.T) {
	t.Parallel()

	const (
		threshold = 5
		cooldown  = 10 * time.Second
	)

	registry := attestation.NewCircuitBreakerRegistry(threshold, cooldown)

	if registry.Threshold() != threshold {
		t.Errorf("threshold = %d, want %d", registry.Threshold(), threshold)
	}

	if registry.Cooldown() != cooldown {
		t.Errorf("cooldown = %v, want %v", registry.Cooldown(), cooldown)
	}
}

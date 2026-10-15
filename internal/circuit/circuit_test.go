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

package circuit_test

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/circuit"
)

func TestBreakerAllowsWhenClosed(t *testing.T) {
	t.Parallel()

	breaker := circuit.NewBreaker(3, time.Second)

	if !breaker.Allow() {
		t.Error("expected Allow() = true when closed")
	}
}

func TestBreakerOpensAfterThreshold(t *testing.T) {
	t.Parallel()

	breaker := circuit.NewBreaker(3, time.Minute)

	for range 3 {
		breaker.RecordFailure()
	}

	if breaker.Allow() {
		t.Error("expected Allow() = false after threshold failures")
	}

	if !breaker.ExportIsOpen() {
		t.Error("expected IsOpen() = true")
	}
}

func TestBreakerRecordFailureReturnsTrueOnTrip(t *testing.T) {
	t.Parallel()

	breaker := circuit.NewBreaker(2, time.Minute)

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

func TestBreakerTransitionsToHalfOpenAfterCooldown(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		breaker := circuit.NewBreaker(1, 10*time.Millisecond)

		breaker.RecordFailure()

		if breaker.Allow() {
			t.Error("expected Allow() = false immediately after trip")
		}

		time.Sleep(100 * time.Millisecond)

		if !breaker.Allow() {
			t.Error("expected Allow() = true after cooldown (half-open probe)")
		}

		if breaker.Allow() {
			t.Error("expected Allow() = false for second call in half-open")
		}
	})
}

func TestBreakerSuccessResetsToClosed(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		breaker := circuit.NewBreaker(1, 10*time.Millisecond)

		breaker.RecordFailure()

		time.Sleep(100 * time.Millisecond)

		breaker.Allow()

		breaker.RecordSuccess()

		if !breaker.Allow() {
			t.Error("expected Allow() = true after success reset")
		}

		if breaker.ExportIsOpen() {
			t.Error("expected IsOpen() = false after success")
		}
	})
}

func TestBreakerReleaseAllowsNewProbe(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		breaker := circuit.NewBreaker(1, 10*time.Millisecond)

		breaker.RecordFailure()

		time.Sleep(100 * time.Millisecond)

		probe, allowed := breaker.Acquire()
		if !allowed {
			t.Fatal("expected half-open probe to be allowed")
		}

		if breaker.Allow() {
			t.Fatal("expected second request in half-open to be rejected")
		}

		breaker.Release(probe)

		if !breaker.Allow() {
			t.Error("expected a new probe after releasing the probe")
		}

		closed := circuit.NewBreaker(1, time.Minute)

		permit, _ := closed.Acquire()
		closed.Release(permit)

		if !closed.Allow() {
			t.Error("expected Release to leave a closed breaker closed")
		}
	})
}

func TestBreakerStalePermitCannotReleaseProbe(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		breaker := circuit.NewBreaker(1, 10*time.Millisecond)

		// Admitted while closed, still running when the breaker trips.
		stale, allowed := breaker.Acquire()
		if !allowed {
			t.Fatal("expected a closed breaker to admit the request")
		}

		breaker.RecordFailure()

		time.Sleep(100 * time.Millisecond)

		probe, allowed := breaker.Acquire()
		if !allowed {
			t.Fatal("expected half-open probe to be allowed")
		}

		breaker.Release(stale)

		if breaker.Allow() {
			t.Fatal("expected a stale permit not to release the probe of another request")
		}

		breaker.Succeeded(stale)

		if breaker.ExportIsClosed() {
			t.Fatal("expected a stale permit not to decide the probe outcome")
		}

		if tripped := breaker.Failed(stale); tripped || breaker.Allow() {
			t.Fatal("expected a stale failure to leave the probe in charge")
		}

		breaker.Succeeded(probe)

		if !breaker.ExportIsClosed() {
			t.Error("expected the probe success to close the breaker")
		}
	})
}

func TestBreakerFailureInHalfOpenReopens(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		breaker := circuit.NewBreaker(1, 10*time.Millisecond)

		breaker.RecordFailure()

		time.Sleep(100 * time.Millisecond)

		breaker.Allow()

		breaker.RecordFailure()

		if breaker.Allow() {
			t.Error("expected Allow() = false after half-open failure")
		}
	})
}

func TestBreakerConcurrent(t *testing.T) {
	t.Parallel()

	breaker := circuit.NewBreaker(10, 100*time.Millisecond)

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
	_ = breaker.ExportIsOpen()
}

func TestRegistryPerHost(t *testing.T) {
	t.Parallel()

	registry := circuit.NewRegistry(2, time.Minute)

	a := registry.Get("registry-a.example.com")
	b := registry.Get("registry-b.example.com")

	if a == b {
		t.Error("expected different breaker instances per host")
	}

	a.RecordFailure()
	a.RecordFailure()

	if !a.ExportIsOpen() {
		t.Error("expected breaker A to be open after threshold failures")
	}

	if b.ExportIsOpen() {
		t.Error("expected breaker B to remain closed")
	}

	if registry.Get("registry-a.example.com") != a {
		t.Error("expected same breaker instance for same host")
	}
}

func TestRegistryEvictsClosedAtCapacity(t *testing.T) {
	t.Parallel()

	registry := circuit.NewRegistry(2, time.Minute)

	for idx := range circuit.ExportMaxBreakers {
		registry.Get(fmt.Sprintf("host-%d.example.com", idx))
	}

	extra := registry.Get("overflow.example.com")

	if extra == nil {
		t.Fatal("expected non-nil breaker for overflow host")
	}

	if !extra.Allow() {
		t.Error("expected overflow breaker to allow requests")
	}
}

func TestRegistryPreservesHalfOpenOnEviction(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		registry := circuit.NewRegistry(1, 10*time.Millisecond)

		var halfOpen *circuit.Breaker

		for idx := range circuit.ExportMaxBreakers {
			breaker := registry.Get(fmt.Sprintf("host-%d.example.com", idx))

			if idx == 0 {
				halfOpen = breaker
				breaker.RecordFailure()

				time.Sleep(100 * time.Millisecond)

				if !breaker.Allow() {
					t.Fatal("expected half-open breaker to allow probe after cooldown")
				}
			}
		}

		if extra := registry.Get("new-host.example.com"); extra == halfOpen {
			t.Fatal("expected a breaker of its own for the new host")
		}

		if registry.Get("host-0.example.com") != halfOpen {
			t.Fatal("expected half-open breaker to survive eviction")
		}
	})
}

// TestRegistryEvictsLeastRecentlyUsedWhenAllOpen checks that a full registry
// of open breakers evicts the least recently used one, so a new host gets a
// breaker of its own that other hosts cannot trip.
func TestRegistryEvictsLeastRecentlyUsedWhenAllOpen(t *testing.T) {
	t.Parallel()

	registry := circuit.NewRegistry(1, time.Minute)

	breakers := make([]*circuit.Breaker, circuit.ExportMaxBreakers)
	for idx := range breakers {
		breakers[idx] = registry.Get(fmt.Sprintf("host-%d.example.com", idx))
		breakers[idx].RecordFailure()
	}

	// host-0 is used again, so host-1 is now the least recently used.
	registry.Get("host-0.example.com")

	fresh := registry.Get("new-host.example.com")
	if !fresh.Allow() {
		t.Fatal("expected the new host to get a closed breaker")
	}

	other := registry.Get("other-host.example.com")
	if other == fresh {
		t.Fatal("expected new hosts not to share a breaker")
	}

	if registry.Get("host-0.example.com") != breakers[0] {
		t.Error("expected the recently used breaker to be kept")
	}

	if registry.Get("host-1.example.com") == breakers[1] {
		t.Error("expected the least recently used breaker to be evicted")
	}

	if states := registry.States(); len(states) > circuit.ExportMaxBreakers {
		t.Errorf("expected at most %d breakers, got %d", circuit.ExportMaxBreakers, len(states))
	}
}

func TestRegistryConcurrentStress(t *testing.T) {
	t.Parallel()

	registry := circuit.NewRegistry(5, 50*time.Millisecond)

	const (
		goroutines = 100
		hosts      = 20
		iterations = 100
	)

	var waitGroup sync.WaitGroup

	for range goroutines {
		waitGroup.Go(func() {
			for iter := range iterations {
				host := fmt.Sprintf("host-%d.example.com", iter%hosts)
				breaker := registry.Get(host)

				if breaker.Allow() {
					n, err := rand.Int(rand.Reader, big.NewInt(3))
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

	// Verify the registry returns non-nil breakers after concurrent access.
	for i := range hosts {
		host := fmt.Sprintf("host-%d.example.com", i)
		breaker := registry.Get(host)

		if breaker == nil {
			t.Errorf("expected non-nil breaker for %s after concurrent stress", host)
		}
	}

	// Verify a fresh breaker trips deterministically after threshold failures.
	tripBreaker := registry.Get("trip-test.example.com")
	for range 5 {
		tripBreaker.RecordFailure()
	}

	if !tripBreaker.ExportIsOpen() {
		t.Error("expected breaker to trip after threshold failures")
	}
}

func TestRegistryStates(t *testing.T) {
	t.Parallel()

	registry := circuit.NewRegistry(2, time.Minute)

	closedBreaker := registry.Get("closed.example.com")
	_ = closedBreaker // keep breaker in closed state

	openBreaker := registry.Get("open.example.com")
	openBreaker.RecordFailure()
	openBreaker.RecordFailure()

	states := registry.States()

	if states["closed.example.com"] != "closed" {
		t.Errorf(
			"closed.example.com = %q, want closed",
			states["closed.example.com"],
		)
	}

	if states["open.example.com"] != "open" {
		t.Errorf(
			"open.example.com = %q, want open",
			states["open.example.com"],
		)
	}
}

func TestRegistryStatesHalfOpen(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		registry := circuit.NewRegistry(1, 10*time.Millisecond)

		breaker := registry.Get("half-open.example.com")
		breaker.RecordFailure()

		time.Sleep(100 * time.Millisecond)

		// Transition to half-open by calling Allow after cooldown.
		if !breaker.Allow() {
			t.Fatal("expected Allow() = true after cooldown (half-open)")
		}

		states := registry.States()

		if states["half-open.example.com"] != "half-open" {
			t.Errorf(
				"half-open.example.com = %q, want half-open",
				states["half-open.example.com"],
			)
		}
	})
}

func TestRegistryStatesEmpty(t *testing.T) {
	t.Parallel()

	registry := circuit.NewRegistry(2, time.Minute)

	states := registry.States()
	if len(states) != 0 {
		t.Errorf("expected empty states map, got %d entries", len(states))
	}
}

func TestRegistryThresholdAndCooldown(t *testing.T) {
	t.Parallel()

	const (
		threshold = 5
		cooldown  = 10 * time.Second
	)

	registry := circuit.NewRegistry(threshold, cooldown)

	if registry.ExportThreshold() != threshold {
		t.Errorf("threshold = %d, want %d", registry.ExportThreshold(), threshold)
	}

	if registry.ExportCooldown() != cooldown {
		t.Errorf("cooldown = %v, want %v", registry.ExportCooldown(), cooldown)
	}
}

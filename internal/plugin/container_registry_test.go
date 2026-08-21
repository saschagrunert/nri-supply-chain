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

package plugin //nolint:testpackage // needs access to unexported containerRegistry

import (
	"testing"
	"time"
)

func TestContainerRegistryLen(t *testing.T) {
	t.Parallel()

	reg := newContainerRegistry()

	if reg.Len() != 0 {
		t.Errorf("expected Len()=0 for empty registry, got %d", reg.Len())
	}

	reg.Store("a", &containerState{createdAt: time.Now()}) //nolint:exhaustruct_v5 // test
	reg.Store("b", &containerState{createdAt: time.Now()}) //nolint:exhaustruct_v5 // test

	if reg.Len() != 2 {
		t.Errorf("expected Len()=2, got %d", reg.Len())
	}
}

func TestContainerRegistryStateCounts(t *testing.T) {
	t.Parallel()

	reg := newContainerRegistry()

	reg.Store("v1", &containerState{state: StateVerified})  //nolint:exhaustruct_v5 // test
	reg.Store("v2", &containerState{state: StateVerified})  //nolint:exhaustruct_v5 // test
	reg.Store("d1", &containerState{state: StateDegraded})  //nolint:exhaustruct_v5 // test
	reg.Store("t1", &containerState{state: StateThrottled}) //nolint:exhaustruct_v5 // test

	counts := reg.StateCounts()

	if counts[StateVerified] != 2 {
		t.Errorf("expected 2 verified, got %d", counts[StateVerified])
	}

	if counts[StateDegraded] != 1 {
		t.Errorf("expected 1 degraded, got %d", counts[StateDegraded])
	}

	if counts[StateThrottled] != 1 {
		t.Errorf("expected 1 throttled, got %d", counts[StateThrottled])
	}
}

func TestContainerRegistryStateCountsEmpty(t *testing.T) {
	t.Parallel()

	reg := newContainerRegistry()
	counts := reg.StateCounts()

	if len(counts) != 0 {
		t.Errorf("expected empty counts for empty registry, got %v", counts)
	}
}

func TestContainerRegistryCleanStale(t *testing.T) {
	t.Parallel()

	reg := newContainerRegistry()

	reg.Store("keep-1", &containerState{state: StateVerified})  //nolint:exhaustruct_v5 // test
	reg.Store("keep-2", &containerState{state: StateDegraded})  //nolint:exhaustruct_v5 // test
	reg.Store("stale-1", &containerState{state: StateVerified}) //nolint:exhaustruct_v5 // test
	reg.Store("stale-2", &containerState{state: StateVerified}) //nolint:exhaustruct_v5 // test

	active := map[string]struct{}{
		"keep-1": {},
		"keep-2": {},
	}

	reg.cleanStale(active)

	if reg.Len() != 2 {
		t.Errorf("expected 2 containers after cleanStale, got %d", reg.Len())
	}

	if _, found := reg.Load("keep-1"); !found {
		t.Error("expected keep-1 to be retained")
	}

	if _, found := reg.Load("keep-2"); !found {
		t.Error("expected keep-2 to be retained")
	}

	if _, found := reg.Load("stale-1"); found {
		t.Error("expected stale-1 to be removed")
	}

	if _, found := reg.Load("stale-2"); found {
		t.Error("expected stale-2 to be removed")
	}
}

func TestContainerRegistryCleanStaleEmpty(t *testing.T) {
	t.Parallel()

	reg := newContainerRegistry()

	reg.Store("a", &containerState{state: StateVerified}) //nolint:exhaustruct_v5 // test

	reg.cleanStale(map[string]struct{}{})

	if reg.Len() != 0 {
		t.Errorf("expected 0 containers after cleanStale with empty active set, got %d", reg.Len())
	}
}

func TestContainerRegistryUpdateStateNotFound(t *testing.T) {
	t.Parallel()

	reg := newContainerRegistry()

	called := false

	found := reg.UpdateState("nonexistent", func(_ *containerState) {
		called = true
	})

	if found {
		t.Error("expected UpdateState to return false for nonexistent container")
	}

	if called {
		t.Error("expected callback not to be called for nonexistent container")
	}
}

func TestContainerRegistryReadStateNotFound(t *testing.T) {
	t.Parallel()

	reg := newContainerRegistry()

	called := false

	found := reg.ReadState("nonexistent", func(_ *containerState) {
		called = true
	})

	if found {
		t.Error("expected ReadState to return false for nonexistent container")
	}

	if called {
		t.Error("expected callback not to be called for nonexistent container")
	}
}

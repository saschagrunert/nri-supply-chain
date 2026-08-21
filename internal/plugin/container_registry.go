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

package plugin

import (
	"sync"
	"time"

	"github.com/containerd/nri/pkg/api"

	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

// VerificationState represents the current verification state of a running
// container in the continuous verification state machine.
type VerificationState int

const (
	// StateVerified means the container has passed verification.
	StateVerified VerificationState = iota
	// StateDegraded means re-verification produced a worse result than the
	// original. In warn mode, only logging and metrics are emitted.
	StateDegraded
	// StateThrottled means cgroup resource limits have been applied because
	// the container's verification state degraded.
	StateThrottled
)

// String returns a human-readable label for the verification state.
func (s VerificationState) String() string {
	switch s {
	case StateVerified:
		return "verified"
	case StateDegraded:
		return "degraded"
	case StateThrottled:
		return "throttled"
	default:
		return "unknown"
	}
}

// containerState tracks a running container's identity, verification state,
// and original resource limits for rollback.
type containerState struct {
	imageRef           string
	digest             string
	indexDigest        string
	namespace          string
	serviceAccount     string
	createdAt          time.Time
	state              VerificationState
	lastResult         *types.Result
	lastRemediation    time.Time
	lastTriggerHash    string
	originalResources  *api.LinuxResources
	purls              []string
	recoveredOnRestart bool
}

// containerRegistry is a typed concurrent map from container ID to
// containerState, replacing the simpler containerTimeMap.
type containerRegistry struct {
	mu sync.RWMutex
	m  map[string]*containerState
}

func newContainerRegistry() *containerRegistry {
	return &containerRegistry{ //nolint:exhaustruct_v5 // mutex zero-value is valid
		m: make(map[string]*containerState),
	}
}

// Store adds or replaces a container state entry.
func (r *containerRegistry) Store(id string, cs *containerState) {
	r.mu.Lock()
	r.m[id] = cs
	r.mu.Unlock()
}

// Load retrieves a container state by ID.
func (r *containerRegistry) Load(id string) (*containerState, bool) {
	r.mu.RLock()
	cs, found := r.m[id]
	r.mu.RUnlock()

	return cs, found
}

// LoadAndDelete retrieves and removes a container state by ID.
func (r *containerRegistry) LoadAndDelete(id string) (*containerState, bool) {
	r.mu.Lock()

	state, found := r.m[id]
	if found {
		delete(r.m, id)
	}

	r.mu.Unlock()

	return state, found
}

// SnapshotIDs returns a shallow value copy of all container IDs and states.
// Pointer/slice fields in the copy share backing data with the live entry,
// but callers only read value-type fields (imageRef, digest, state, etc.).
func (r *containerRegistry) SnapshotIDs() map[string]containerState {
	r.mu.RLock()
	defer r.mu.RUnlock()

	snapshot := make(map[string]containerState, len(r.m))
	for id, cs := range r.m {
		snapshot[id] = *cs
	}

	return snapshot
}

// UpdateState applies updateFn to the container state identified by id
// while holding the write lock. Returns false if the container no longer
// exists (e.g., removed mid-iteration).
func (r *containerRegistry) UpdateState(id string, updateFn func(cs *containerState)) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	state, found := r.m[id]
	if !found {
		return false
	}

	updateFn(state)

	return true
}

// Len returns the number of tracked containers.
func (r *containerRegistry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return len(r.m)
}

// StateCounts returns the number of containers in each verification state.
func (r *containerRegistry) StateCounts() map[VerificationState]int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	counts := make(map[VerificationState]int)
	for _, state := range r.m {
		counts[state.state]++
	}

	return counts
}

// ReadState reads container fields under the read lock to avoid races with
// UpdateState. Returns false if the container does not exist.
func (r *containerRegistry) ReadState(
	id string, readFn func(cs *containerState),
) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	state, found := r.m[id]
	if !found {
		return false
	}

	readFn(state)

	return true
}

func (r *containerRegistry) cleanStale(activeIDs map[string]struct{}) {
	r.mu.Lock()
	for id := range r.m {
		if _, exists := activeIDs[id]; !exists {
			delete(r.m, id)
		}
	}

	r.mu.Unlock()
}

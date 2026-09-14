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
	"encoding/json"
	"fmt"
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
	// StateSkipped means verification was skipped (e.g. missing annotations).
	StateSkipped
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
	case StateSkipped:
		return "skipped"
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
	consecutiveErrors  int
	// consecutiveIncomplete counts re-verifications in a row that could not
	// complete (for example during a registry outage).
	consecutiveIncomplete int
	// unresolvedDigest is the digest the runtime reports for the image while
	// digest and indexDigest are not resolved from it: digest is empty, or
	// the runtime digest itself when the registry was unreachable. The
	// continuous verifier resolves it before re-verifying the container.
	unresolvedDigest string
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

// StoreIfAbsent adds a container state entry unless one is already tracked
// for id. Returns true when cs was stored.
func (r *containerRegistry) StoreIfAbsent(containerID string, state *containerState) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	_, exists := r.m[containerID]
	if exists {
		return false
	}

	r.m[containerID] = state

	return true
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

// IncompleteCount returns the number of containers whose last threshold (or
// more) re-verifications in a row were incomplete.
func (r *containerRegistry) IncompleteCount(threshold int) int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	count := 0

	for _, state := range r.m {
		if state.consecutiveIncomplete >= threshold {
			count++
		}
	}

	return count
}

// ReadState reads container fields under the read lock to avoid races with
// UpdateState. Returns false if the container does not exist.
func (r *containerRegistry) ReadState(
	id string, readFn func(cs containerState),
) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	state, found := r.m[id]
	if !found {
		return false
	}

	readFn(*state)

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

// AnnotationOriginalResources records the CPU and memory limits a container
// was created with. Throttling is only applied to, and rolled back from,
// recorded limits: after a plugin restart the container's current limits
// may already be throttled and cannot be trusted as originals.
const AnnotationOriginalResources = "supply-chain.nri/original-resources"

// originalResourcesRecord is the JSON form of AnnotationOriginalResources.
// It only holds the limits the continuous verifier changes.
type originalResourcesRecord struct {
	CPUQuota    *int64  `json:"cpuQuota,omitempty"`
	CPUShares   *uint64 `json:"cpuShares,omitempty"`
	MemoryLimit *int64  `json:"memoryLimit,omitempty"`
}

// OriginalResourcesAnnotation encodes the throttleable limits of res as the
// value of AnnotationOriginalResources. ok is false when res carries no such
// limits. CreateContainer adds the annotation so throttling survives plugin
// restarts.
func OriginalResourcesAnnotation(res *api.LinuxResources) (value string, ok bool) {
	var record originalResourcesRecord

	if quota := res.GetCpu().GetQuota(); quota != nil {
		v := quota.GetValue()
		record.CPUQuota = &v
	}

	if shares := res.GetCpu().GetShares(); shares != nil {
		v := shares.GetValue()
		record.CPUShares = &v
	}

	if limit := res.GetMemory().GetLimit(); limit != nil {
		v := limit.GetValue()
		record.MemoryLimit = &v
	}

	if record.CPUQuota == nil && record.CPUShares == nil && record.MemoryLimit == nil {
		return "", false
	}

	data, err := json.Marshal(record)
	if err != nil {
		return "", false
	}

	return string(data), true
}

// decodeOriginalResources parses an AnnotationOriginalResources value.
func decodeOriginalResources(value string) (*api.LinuxResources, error) {
	var record originalResourcesRecord

	err := json.Unmarshal([]byte(value), &record)
	if err != nil {
		return nil, fmt.Errorf("decoding %s annotation: %w", AnnotationOriginalResources, err)
	}

	resources := &api.LinuxResources{}

	if record.CPUQuota != nil || record.CPUShares != nil {
		resources.Cpu = &api.LinuxCPU{}

		if record.CPUQuota != nil {
			resources.Cpu.Quota = &api.OptionalInt64{Value: *record.CPUQuota}
		}

		if record.CPUShares != nil {
			resources.Cpu.Shares = &api.OptionalUInt64{Value: *record.CPUShares}
		}
	}

	if record.MemoryLimit != nil {
		resources.Memory = &api.LinuxMemory{
			Limit: &api.OptionalInt64{Value: *record.MemoryLimit},
		}
	}

	return resources, nil
}

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
	"context"
	"sync"
	"sync/atomic"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
)

// prewarmState tracks cache pre-warming for containers that were already
// running when the plugin connected.
type prewarmState struct {
	// done is a test hook called whenever prewarmCache completes.
	done func()
	// doneCh is closed when prewarmCache completes for the first time.
	doneCh   chan struct{}
	doneOnce sync.Once
	mu       sync.Mutex
	cancel   context.CancelFunc
	// images are the last known running images, for re-warming after reload.
	images []prewarmImage
}

func newPrewarmState() *prewarmState {
	return &prewarmState{ //nolint:exhaustruct_v5 // zero-value fields are intentional
		doneCh: make(chan struct{}),
	}
}

// markDone closes doneCh once.
func (s *prewarmState) markDone() {
	s.doneOnce.Do(func() { close(s.doneCh) })
}

// ConfigApplier applies a configuration passed by the runtime in Configure:
// it reloads the verifier and the plugin-side settings. It runs outside the
// runtime's request deadline.
type ConfigApplier func(ctx context.Context, cfg *config.Config) error

// runtimeConfigState tracks the configuration passed by the runtime until it
// has been applied.
type runtimeConfigState struct {
	applier atomic.Pointer[ConfigApplier]
	// mu serializes applies.
	mu sync.Mutex
	// pending is the latest configuration that has not been applied yet.
	pending atomic.Pointer[pendingRuntimeConfig]
	// lastApplied is the last configuration applied successfully, as passed
	// by the runtime.
	lastApplied atomic.Pointer[string]
	// failure describes why applying pending failed, if it did.
	failure atomic.Pointer[string]
	// retryInitial and retryMaximum bound the backoff between retries of a
	// failed apply (time.Duration values).
	retryInitial atomic.Int64
	retryMaximum atomic.Int64
}

// remediationState holds the continuous verifier's triggers, settings, and
// the NRI stub used to update running containers.
type remediationState struct {
	// reverifyTrigger is buffered(1) and signals an on-demand re-verify.
	reverifyTrigger chan struct{}
	// feedTrigger is buffered(1) and carries feed PURLs for a filtered
	// re-verify.
	feedTrigger chan []string
	mode        atomic.Pointer[config.RemediationMode]
	cfg         atomic.Pointer[config.RemediationConfig]
	stub        StubUpdater
	stubMu      sync.RWMutex
	feedMu      sync.Mutex
	started     atomic.Bool
}

func newRemediationState() *remediationState {
	state := &remediationState{ //nolint:exhaustruct_v5 // zero-value fields are intentional
		reverifyTrigger: make(chan struct{}, 1),
		feedTrigger:     make(chan []string, 1),
	}

	disabledMode := config.RemediationModeDisabled
	state.mode.Store(&disabledMode)

	return state
}

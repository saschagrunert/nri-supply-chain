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

package plugin_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/api"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/plugin"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

type cvTestVerifier struct {
	mu      sync.Mutex
	result  *types.Result
	err     error
	calls   int
	deleted map[string]struct{}
}

func (v *cvTestVerifier) Verify(
	_ context.Context,
	_, _, _, _, _ string,
) (*types.Result, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.calls++

	return v.result, v.err
}

func (v *cvTestVerifier) Ready() (ready bool, reason string) { return true, "" }
func (v *cvTestVerifier) Enforcing() bool                    { return false }

//
//nolint:exhaustruct_v5 // test stub
func (v *cvTestVerifier) Status() types.StatusResponse                     { return types.StatusResponse{} }
func (v *cvTestVerifier) Reload(_ context.Context, _ *config.Config) error { return nil }

func (v *cvTestVerifier) EffectiveModeForNamespace(_ string) config.VerificationMode {
	return config.ModeWarn
}

func (v *cvTestVerifier) InvalidateCache(digest, namespace string) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.deleted == nil {
		v.deleted = make(map[string]struct{})
	}

	v.deleted[digest+"/"+namespace] = struct{}{}
}

type cvTestStub struct {
	mu      sync.Mutex
	updates []*api.ContainerUpdate
	err     error
	failed  []*api.ContainerUpdate
}

func (s *cvTestStub) UpdateContainers(
	updates []*api.ContainerUpdate,
) ([]*api.ContainerUpdate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.updates = append(s.updates, updates...)

	return s.failed, s.err
}

var errStubUpdate = errors.New("update failed")

const (
	testDegradedReason = "degraded"
	testFailStatus     = "fail"
	testPURLGolangFoo  = "pkg:golang/foo@1.0"
	testPURLNpmBar     = "pkg:npm/bar@2.0"
	testMetadataPURLs  = "purls"
)

func newCVTestPlugin(v plugin.ImageVerifier) *plugin.Plugin {
	met := metrics.New()

	return plugin.New(v, met, "", 30*time.Second, time.Second, nil)
}

func TestRunContinuousVerifierWaitsForPrewarm(t *testing.T) {
	t.Parallel()

	verif := &cvTestVerifier{ //nolint:exhaustruct_v5 // zero-value fields intentional
		result: &types.Result{
			Allowed: true, Reason: "", CheckResults: nil,
		},
	}
	plug := newCVTestPlugin(verif)
	plug.SetRemediationMode(config.RemediationModeWarn)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	done := make(chan struct{})

	go func() {
		plug.RunContinuousVerifier(ctx, 50*time.Millisecond)
		close(done)
	}()

	// The continuous verifier should block on prewarmDoneCh.
	// Cancel before prewarm completes, so it should exit without running any cycles.
	<-done

	verif.mu.Lock()
	calls := verif.calls
	verif.mu.Unlock()

	if calls != 0 {
		t.Errorf("expected 0 verify calls before prewarm, got %d", calls)
	}
}

func TestRunContinuousVerifierTimerTick(t *testing.T) {
	t.Parallel()

	verif := &cvTestVerifier{ //nolint:exhaustruct_v5 // zero-value fields intentional
		result: &types.Result{
			Allowed: true, Reason: "", CheckResults: nil,
		},
	}
	plug := newCVTestPlugin(verif)
	plug.SetRemediationMode(config.RemediationModeWarn)

	plug.ExportStoreContainerTime(testContainerID, time.Now())

	// Complete prewarm
	plug.ExportSetPrewarmDone(nil)
	plug.ExportPrewarmCache(context.Background(), nil)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})

	go func() {
		plug.RunContinuousVerifier(ctx, 50*time.Millisecond)
		close(done)
	}()

	// Wait for at least one tick
	time.Sleep(150 * time.Millisecond)
	cancel()
	<-done

	verif.mu.Lock()
	calls := verif.calls
	verif.mu.Unlock()

	if calls < 1 {
		t.Errorf("expected at least 1 verify call after timer tick, got %d", calls)
	}
}

func TestRunContinuousVerifierTrigger(t *testing.T) {
	t.Parallel()

	verif := &cvTestVerifier{ //nolint:exhaustruct_v5 // zero-value fields intentional
		result: &types.Result{
			Allowed: true, Reason: "", CheckResults: nil,
		},
	}
	plug := newCVTestPlugin(verif)
	plug.SetRemediationMode(config.RemediationModeWarn)

	plug.ExportStoreContainerTime("ctr-trigger", time.Now())

	// Complete prewarm
	plug.ExportSetPrewarmDone(nil)
	plug.ExportPrewarmCache(context.Background(), nil)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})

	go func() {
		// Use a very long interval so timer won't fire
		plug.RunContinuousVerifier(ctx, time.Hour)
		close(done)
	}()

	// Wait for goroutine to start and pass prewarm
	time.Sleep(50 * time.Millisecond)

	// Send trigger
	plug.TriggerReverify()

	// Wait for trigger to be processed
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	verif.mu.Lock()
	calls := verif.calls
	verif.mu.Unlock()

	if calls < 1 {
		t.Errorf("expected at least 1 verify call after trigger, got %d", calls)
	}
}

func TestStateTransitionVerifiedToDegraded(t *testing.T) {
	t.Parallel()

	verif := &cvTestVerifier{ //nolint:exhaustruct_v5 // zero-value fields intentional
		result: &types.Result{
			Allowed: false, Reason: testDegradedReason,
			CheckResults: []types.CheckResult{
				{ //nolint:exhaustruct_v5 // zero-value fields intentional
					Type:   types.CheckTypeSBOM,
					Passed: false,
					Status: testFailStatus,
				},
			},
		},
	}
	plug := newCVTestPlugin(verif)
	plug.SetRemediationMode(config.RemediationModeWarn)

	plug.ExportStoreContainerTime("ctr-degrade", time.Now())

	// Complete prewarm
	plug.ExportSetPrewarmDone(nil)
	plug.ExportPrewarmCache(context.Background(), nil)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})

	go func() {
		plug.RunContinuousVerifier(ctx, time.Hour)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	plug.TriggerReverify()
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	// In warn mode, the container should be in Degraded state but no UpdateContainers call
	verif.mu.Lock()
	calls := verif.calls
	verif.mu.Unlock()

	if calls < 1 {
		t.Errorf("expected verify call, got %d", calls)
	}
}

func TestStateTransitionThrottleMode(t *testing.T) {
	t.Parallel()

	verif := &cvTestVerifier{ //nolint:exhaustruct_v5 // zero-value fields intentional
		result: &types.Result{
			Allowed: false, Reason: testDegradedReason,
			CheckResults: []types.CheckResult{
				{ //nolint:exhaustruct_v5 // zero-value fields intentional
					Type:   types.CheckTypeSBOM,
					Passed: false,
					Status: testFailStatus,
				},
			},
		},
	}

	met := metrics.New()
	plug := plugin.New(verif, met, "", 30*time.Second, time.Second, nil)

	plug.SetRemediationMode(config.RemediationModeThrottle)
	plug.SetRemediationConfig(
		&config.RemediationConfig{ //nolint:exhaustruct_v5 // zero-value fields intentional
			Mode:      config.RemediationModeThrottle,
			BatchSize: 10,
			Throttle: config.ThrottleConfig{
				CPUQuotaPercent:    10,
				MemoryLimitPercent: 50,
			},
		},
	)

	stubMock := &cvTestStub{} //nolint:exhaustruct_v5 // zero-value fields intentional
	plug.SetStub(stubMock)

	originalResources := &api.LinuxResources{
		Cpu: &api.LinuxCPU{
			Quota:  &api.OptionalInt64{Value: 100000},
			Shares: &api.OptionalUInt64{Value: 1024},
		},
		Memory: &api.LinuxMemory{
			Limit: &api.OptionalInt64{Value: 536870912},
		},
	}
	plug.ExportStoreContainerWithResources(
		"ctr-throttle", "img:latest", "sha256:abc", originalResources,
	)

	// Complete prewarm
	plug.ExportSetPrewarmDone(nil)
	plug.ExportPrewarmCache(context.Background(), nil)

	// Phase 1: long interval so only the manual trigger fires -> Degraded
	ctx1, cancel1 := context.WithCancel(context.Background())

	done1 := make(chan struct{})

	go func() {
		plug.RunContinuousVerifier(ctx1, time.Hour)
		close(done1)
	}()

	time.Sleep(50 * time.Millisecond)
	plug.TriggerReverify()
	time.Sleep(100 * time.Millisecond)
	cancel1()
	<-done1

	state, found := plug.ExportGetContainerState("ctr-throttle")
	if !found {
		t.Fatal("expected container in registry after first trigger")
	}

	if state.State != plugin.StateDegraded {
		t.Errorf("expected StateDegraded after first trigger, got %v", state.State)
	}

	// Phase 2: short timer tick -> Degraded -> Throttled
	ctx2, cancel2 := context.WithCancel(context.Background())

	done2 := make(chan struct{})

	go func() {
		plug.RunContinuousVerifier(ctx2, 50*time.Millisecond)
		close(done2)
	}()

	time.Sleep(150 * time.Millisecond)
	cancel2()
	<-done2

	verif.mu.Lock()
	calls := verif.calls
	verif.mu.Unlock()

	if calls < 2 {
		t.Errorf("expected at least 2 verify calls, got %d", calls)
	}

	state, found = plug.ExportGetContainerState("ctr-throttle")
	if !found {
		t.Fatal("expected container to still exist in registry")
	}

	if state.State != plugin.StateThrottled {
		t.Errorf("expected StateThrottled, got %v", state.State)
	}

	stubMock.mu.Lock()
	updates := len(stubMock.updates)
	stubMock.mu.Unlock()

	if updates == 0 {
		t.Error("expected stub.UpdateContainers to be called with throttle update")
	}
}

func TestContainerRegistrySnapshot(t *testing.T) {
	t.Parallel()

	//nolint:exhaustruct_v5 // zero-value fields intentional
	plug := newCVTestPlugin(&cvTestVerifier{
		result: &types.Result{Allowed: true, Reason: "", CheckResults: nil},
	})

	plug.ExportStoreContainerTime("a", time.Now())
	plug.ExportStoreContainerTime("b", time.Now())

	_, okA := plug.ExportLoadContainerTime("a")
	_, okB := plug.ExportLoadContainerTime("b")

	if !okA || !okB {
		t.Fatal("expected both containers to be stored")
	}
}

func TestMatchFeedPURLs(t *testing.T) {
	t.Parallel()

	//nolint:exhaustruct_v5 // zero-value fields intentional
	plug := newCVTestPlugin(&cvTestVerifier{
		result: &types.Result{Allowed: true, Reason: "", CheckResults: nil},
	})

	plug.ExportStoreContainerWithPURLs("ctr-a", []string{testPURLGolangFoo, testPURLNpmBar})
	plug.ExportStoreContainerWithPURLs("ctr-b", []string{"pkg:golang/baz@3.0"})
	plug.ExportStoreContainerWithPURLs("ctr-c", nil)

	matched := plug.ExportMatchFeedPURLs([]string{testPURLNpmBar, "pkg:golang/baz@3.0"})

	if _, ok := matched["ctr-a"]; !ok {
		t.Error("expected ctr-a to match (has pkg:npm/bar@2.0)")
	}

	if _, ok := matched["ctr-b"]; !ok {
		t.Error("expected ctr-b to match (has pkg:golang/baz@3.0)")
	}

	if _, ok := matched["ctr-c"]; ok {
		t.Error("expected ctr-c to not match (no PURLs)")
	}
}

func TestMatchFeedPURLsNoOverlap(t *testing.T) {
	t.Parallel()

	//nolint:exhaustruct_v5 // zero-value fields intentional
	plug := newCVTestPlugin(&cvTestVerifier{
		result: &types.Result{Allowed: true, Reason: "", CheckResults: nil},
	})

	plug.ExportStoreContainerWithPURLs("ctr-a", []string{testPURLGolangFoo})

	matched := plug.ExportMatchFeedPURLs([]string{"pkg:golang/other@1.0"})

	if len(matched) != 0 {
		t.Errorf("expected no matches, got %d", len(matched))
	}
}

func TestTriggerFeedReverifyRespectsOnNewCVE(t *testing.T) {
	t.Parallel()

	//nolint:exhaustruct_v5 // zero-value fields intentional
	plug := newCVTestPlugin(&cvTestVerifier{
		result: &types.Result{Allowed: true, Reason: "", CheckResults: nil},
	})

	plug.SetRemediationConfig(
		&config.RemediationConfig{ //nolint:exhaustruct_v5 // zero-value fields intentional
			Mode: config.RemediationModeWarn,
			Triggers: config.TriggerConfig{
				OnNewCVE:             false,
				OnAttestationRevoked: true,
				OnPolicyChange:       true,
			},
		},
	)

	plug.ExportStoreContainerWithPURLs("ctr-feed", []string{testPURLGolangFoo})

	plug.TriggerFeedReverify([]string{testPURLGolangFoo})

	// Give the channel a moment to be consumed if it were sent.
	<-time.After(50 * time.Millisecond)

	// The feed trigger should NOT have been sent because on_new_cve is false.
	select {
	case <-plug.ExportFeedTrigger():
		t.Error("expected feed trigger to be suppressed when on_new_cve=false")
	default:
	}
}

func TestTimerTickBypassesTriggerHash(t *testing.T) {
	t.Parallel()

	verif := &cvTestVerifier{ //nolint:exhaustruct_v5 // zero-value fields intentional
		result: &types.Result{
			Allowed: false, Reason: testDegradedReason,
			CheckResults: []types.CheckResult{
				{ //nolint:exhaustruct_v5 // zero-value fields intentional
					Type:   types.CheckTypeSBOM,
					Passed: false,
					Status: testFailStatus,
				},
			},
		},
	}

	met := metrics.New()
	plug := plugin.New(verif, met, "", 30*time.Second, time.Second, nil)

	originalResources := &api.LinuxResources{
		Cpu: &api.LinuxCPU{
			Quota:  &api.OptionalInt64{Value: 100000},
			Shares: &api.OptionalUInt64{Value: 1024},
		},
		Memory: &api.LinuxMemory{
			Limit: &api.OptionalInt64{Value: 536870912},
		},
	}
	plug.ExportStoreContainerWithResources(
		"ctr-timer", "img:latest", "sha256:abc", originalResources,
	)

	// Start with warn mode. First trigger: Verified -> Degraded.
	plug.SetRemediationMode(config.RemediationModeWarn)

	// Complete prewarm
	plug.ExportSetPrewarmDone(nil)
	plug.ExportPrewarmCache(context.Background(), nil)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})

	// Use a short timer interval so the ticker fires for the second cycle.
	go func() {
		plug.RunContinuousVerifier(ctx, 80*time.Millisecond)
		close(done)
	}()

	// Wait for at least one trigger cycle to move to Degraded.
	time.Sleep(50 * time.Millisecond)
	plug.TriggerReverify()
	time.Sleep(100 * time.Millisecond)

	// Switch to throttle mode with a stub. The next timer tick should
	// escalate Degraded -> Throttled despite producing the same trigger
	// hash, because timer ticks bypass the hash check.
	stubMock := &cvTestStub{} //nolint:exhaustruct_v5 // zero-value fields intentional
	plug.SetStub(stubMock)

	plug.SetRemediationMode(config.RemediationModeThrottle)
	plug.SetRemediationConfig(
		&config.RemediationConfig{ //nolint:exhaustruct_v5 // zero-value fields intentional
			Mode:      config.RemediationModeThrottle,
			BatchSize: 10,
			Throttle: config.ThrottleConfig{
				CPUQuotaPercent:    10,
				MemoryLimitPercent: 50,
			},
		},
	)

	// Wait for timer tick to fire (interval is 80ms).
	time.Sleep(150 * time.Millisecond)
	cancel()
	<-done

	verif.mu.Lock()
	calls := verif.calls
	verif.mu.Unlock()

	if calls < 2 {
		t.Errorf("expected at least 2 verify calls, got %d", calls)
	}

	state, found := plug.ExportGetContainerState("ctr-timer")
	if !found {
		t.Fatal("expected container to still exist in registry")
	}

	if state.State != plugin.StateThrottled {
		t.Errorf("expected StateThrottled after timer tick bypass, got %v", state.State)
	}

	stubMock.mu.Lock()
	updates := len(stubMock.updates)
	stubMock.mu.Unlock()

	if updates == 0 {
		t.Error("expected stub.UpdateContainers to be called with throttle update")
	}
}

func TestComputeTriggerHashDeterministic(t *testing.T) {
	t.Parallel()

	h1 := plugin.ExportComputeTriggerHash("timer", "sha256:abc", nil)
	h2 := plugin.ExportComputeTriggerHash("timer", "sha256:abc", nil)
	h3 := plugin.ExportComputeTriggerHash("feed", "sha256:abc", nil)

	if h1 != h2 {
		t.Error("expected same hash for same inputs")
	}

	if h1 == h3 {
		t.Error("expected different hash for different triggers")
	}

	h4 := plugin.ExportComputeTriggerHash("feed", "sha256:abc", []string{"pkg:golang/foo@1.0"})
	h5 := plugin.ExportComputeTriggerHash("feed", "sha256:abc", []string{"pkg:golang/bar@2.0"})

	if h3 == h4 {
		t.Error("expected different hash when feed PURLs differ from nil")
	}

	if h4 == h5 {
		t.Error("expected different hash for different feed PURLs")
	}
}

func TestBuildRollbackUpdate(t *testing.T) {
	t.Parallel()

	original := &api.LinuxResources{
		Cpu: &api.LinuxCPU{
			Quota:  &api.OptionalInt64{Value: 100000},
			Shares: &api.OptionalUInt64{Value: 1024},
		},
		Memory: &api.LinuxMemory{
			Limit: &api.OptionalInt64{Value: 536870912},
		},
	}

	update := plugin.ExportBuildRollbackUpdate(testContainerID, original)

	if update == nil {
		t.Fatal("expected non-nil update")
	}

	if update.GetContainerId() != testContainerID {
		t.Errorf("expected container ID ctr-1, got %s", update.GetContainerId())
	}

	restored := update.GetLinux().GetResources()
	if restored == original {
		t.Error("expected deep copy, not pointer alias")
	}

	if restored.GetCpu().GetQuota().GetValue() != original.GetCpu().GetQuota().GetValue() {
		t.Error("expected restored CPU quota to match original")
	}

	if restored.GetCpu().GetShares().GetValue() != original.GetCpu().GetShares().GetValue() {
		t.Error("expected restored CPU shares to match original")
	}

	if restored.GetMemory().GetLimit().GetValue() != original.GetMemory().GetLimit().GetValue() {
		t.Error("expected restored memory limit to match original")
	}

	if !update.GetIgnoreFailure() {
		t.Error("expected IgnoreFailure to be true")
	}
}

func TestThrottleAndRollbackLifecycle(t *testing.T) {
	t.Parallel()

	degradedResult := &types.Result{
		Allowed: false, Reason: testDegradedReason,
		CheckResults: []types.CheckResult{
			{ //nolint:exhaustruct_v5 // zero-value fields intentional
				Type:   types.CheckTypeSBOM,
				Passed: false,
				Status: testFailStatus,
			},
		},
	}
	verifiedResult := &types.Result{
		Allowed: true, Reason: "", CheckResults: nil,
	}

	verif := &cvTestVerifier{ //nolint:exhaustruct_v5 // zero-value fields intentional
		result: degradedResult,
	}

	met := metrics.New()
	plug := plugin.New(verif, met, "", 30*time.Second, time.Second, nil)

	plug.SetRemediationMode(config.RemediationModeThrottle)
	plug.SetRemediationConfig(
		&config.RemediationConfig{ //nolint:exhaustruct_v5 // zero-value fields intentional
			Mode:      config.RemediationModeThrottle,
			BatchSize: 10,
			Throttle: config.ThrottleConfig{
				CPUQuotaPercent:    10,
				MemoryLimitPercent: 50,
			},
		},
	)

	stubMock := &cvTestStub{} //nolint:exhaustruct_v5 // zero-value fields intentional
	plug.SetStub(stubMock)

	originalResources := &api.LinuxResources{
		Cpu: &api.LinuxCPU{
			Quota:  &api.OptionalInt64{Value: 100000},
			Shares: &api.OptionalUInt64{Value: 1024},
		},
		Memory: &api.LinuxMemory{
			Limit: &api.OptionalInt64{Value: 536870912},
		},
	}
	plug.ExportStoreContainerWithResources(
		"ctr-lifecycle", "img:latest", "sha256:abc", originalResources,
	)

	plug.ExportSetPrewarmDone(nil)
	plug.ExportPrewarmCache(context.Background(), nil)

	// Phase 1a: long interval so only the manual trigger fires -> Degraded
	ctx1, cancel1 := context.WithCancel(context.Background())

	done1 := make(chan struct{})

	go func() {
		plug.RunContinuousVerifier(ctx1, time.Hour)
		close(done1)
	}()

	time.Sleep(50 * time.Millisecond)
	plug.TriggerReverify()
	time.Sleep(100 * time.Millisecond)
	cancel1()
	<-done1

	state, found := plug.ExportGetContainerState("ctr-lifecycle")
	if !found {
		t.Fatal("expected container in registry after degrade")
	}

	if state.State != plugin.StateDegraded {
		t.Errorf("phase 1a: expected StateDegraded, got %v", state.State)
	}

	// Phase 1b: short timer tick -> Degraded -> Throttled
	ctx2, cancel2 := context.WithCancel(context.Background())

	done2 := make(chan struct{})

	go func() {
		plug.RunContinuousVerifier(ctx2, 50*time.Millisecond)
		close(done2)
	}()

	time.Sleep(150 * time.Millisecond)

	state, found = plug.ExportGetContainerState("ctr-lifecycle")
	if !found {
		t.Fatal("expected container in registry after throttle")
	}

	if state.State != plugin.StateThrottled {
		t.Errorf("phase 1b: expected StateThrottled, got %v", state.State)
	}

	stubMock.mu.Lock()
	throttleUpdates := len(stubMock.updates)
	stubMock.mu.Unlock()

	if throttleUpdates == 0 {
		t.Fatal("phase 1b: expected throttle update to be sent")
	}

	// Phase 2: switch verifier to pass, trigger again to rollback
	verif.mu.Lock()
	verif.result = verifiedResult
	verif.mu.Unlock()

	stubMock.mu.Lock()
	stubMock.updates = nil
	stubMock.mu.Unlock()

	plug.TriggerReverify()
	time.Sleep(100 * time.Millisecond)
	cancel2()
	<-done2

	state, found = plug.ExportGetContainerState("ctr-lifecycle")
	if !found {
		t.Fatal("expected container in registry after rollback")
	}

	if state.State != plugin.StateVerified {
		t.Errorf("phase 2: expected StateVerified after rollback, got %v", state.State)
	}

	stubMock.mu.Lock()
	rollbackUpdates := len(stubMock.updates)
	stubMock.mu.Unlock()

	if rollbackUpdates == 0 {
		t.Error("phase 2: expected rollback update to be sent")
	}
}

func TestRecoveredOnRestartSkipsRollback(t *testing.T) {
	t.Parallel()

	verifiedResult := &types.Result{
		Allowed: true, Reason: "", CheckResults: nil,
	}

	verif := &cvTestVerifier{ //nolint:exhaustruct_v5 // zero-value fields intentional
		result: verifiedResult,
	}

	met := metrics.New()
	plug := plugin.New(verif, met, "", 30*time.Second, time.Second, nil)

	plug.SetRemediationMode(config.RemediationModeThrottle)
	plug.SetRemediationConfig(
		&config.RemediationConfig{ //nolint:exhaustruct_v5 // zero-value fields intentional
			Mode:      config.RemediationModeThrottle,
			BatchSize: 10,
			Throttle: config.ThrottleConfig{
				CPUQuotaPercent:    10,
				MemoryLimitPercent: 50,
			},
		},
	)

	stubMock := &cvTestStub{} //nolint:exhaustruct_v5 // zero-value fields intentional
	plug.SetStub(stubMock)

	originalResources := &api.LinuxResources{
		Cpu: &api.LinuxCPU{
			Quota:  &api.OptionalInt64{Value: 100000},
			Shares: &api.OptionalUInt64{Value: 1024},
		},
		Memory: &api.LinuxMemory{
			Limit: &api.OptionalInt64{Value: 536870912},
		},
	}
	plug.ExportStoreRecoveredContainer(
		"ctr-recovered", "img:latest", "sha256:abc", originalResources,
	)

	plug.ExportSetPrewarmDone(nil)
	plug.ExportPrewarmCache(context.Background(), nil)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})

	go func() {
		plug.RunContinuousVerifier(ctx, time.Hour)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	plug.TriggerReverify()
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	state, found := plug.ExportGetContainerState("ctr-recovered")
	if !found {
		t.Fatal("expected container in registry")
	}

	if state.State != plugin.StateVerified {
		t.Errorf("expected StateVerified, got %v", state.State)
	}

	if state.RecoveredOnRestart {
		t.Error("recoveredOnRestart should be cleared after recovery")
	}

	stubMock.mu.Lock()
	updates := len(stubMock.updates)
	stubMock.mu.Unlock()

	if updates != 0 {
		t.Errorf("expected no rollback for restart-recovered container, got %d updates", updates)
	}
}

func TestRollbackAfterModeDowngrade(t *testing.T) {
	t.Parallel()

	degradedResult := &types.Result{
		Allowed: false, Reason: testDegradedReason,
		CheckResults: []types.CheckResult{
			{ //nolint:exhaustruct_v5 // zero-value fields intentional
				Type:   types.CheckTypeSBOM,
				Passed: false,
				Status: testFailStatus,
			},
		},
	}
	verifiedResult := &types.Result{
		Allowed: true, Reason: "", CheckResults: nil,
	}

	verif := &cvTestVerifier{ //nolint:exhaustruct_v5 // zero-value fields intentional
		result: degradedResult,
	}

	met := metrics.New()
	plug := plugin.New(verif, met, "", 30*time.Second, time.Second, nil)

	plug.SetRemediationMode(config.RemediationModeThrottle)
	plug.SetRemediationConfig(
		&config.RemediationConfig{ //nolint:exhaustruct_v5 // zero-value fields intentional
			Mode:      config.RemediationModeThrottle,
			BatchSize: 10,
			Throttle: config.ThrottleConfig{
				CPUQuotaPercent:    10,
				MemoryLimitPercent: 50,
			},
		},
	)

	stubMock := &cvTestStub{} //nolint:exhaustruct_v5 // zero-value fields intentional
	plug.SetStub(stubMock)

	originalResources := &api.LinuxResources{
		Cpu: &api.LinuxCPU{
			Quota:  &api.OptionalInt64{Value: 100000},
			Shares: &api.OptionalUInt64{Value: 1024},
		},
		Memory: &api.LinuxMemory{
			Limit: &api.OptionalInt64{Value: 536870912},
		},
	}
	plug.ExportStoreContainerWithResources(
		"ctr-downgrade", "img:latest", "sha256:abc", originalResources,
	)

	plug.ExportSetPrewarmDone(nil)
	plug.ExportPrewarmCache(context.Background(), nil)

	// Phase 1: Verified -> Degraded (manual trigger)
	ctx1, cancel1 := context.WithCancel(context.Background())

	done1 := make(chan struct{})

	go func() {
		plug.RunContinuousVerifier(ctx1, time.Hour)
		close(done1)
	}()

	time.Sleep(50 * time.Millisecond)
	plug.TriggerReverify()
	time.Sleep(100 * time.Millisecond)
	cancel1()
	<-done1

	// Phase 2: Degraded -> Throttled (timer tick)
	ctx2, cancel2 := context.WithCancel(context.Background())

	done2 := make(chan struct{})

	go func() {
		plug.RunContinuousVerifier(ctx2, 50*time.Millisecond)
		close(done2)
	}()

	time.Sleep(150 * time.Millisecond)

	state, found := plug.ExportGetContainerState("ctr-downgrade")
	if !found {
		t.Fatal("expected container in registry after throttle")
	}

	if state.State != plugin.StateThrottled {
		t.Fatalf("expected StateThrottled, got %v", state.State)
	}

	// Phase 3: Downgrade mode to warn, switch to passing, trigger recovery.
	// The rollback update must still be sent to restore cgroup resources.
	plug.SetRemediationMode(config.RemediationModeWarn)

	verif.mu.Lock()
	verif.result = verifiedResult
	verif.mu.Unlock()

	stubMock.mu.Lock()
	stubMock.updates = nil
	stubMock.mu.Unlock()

	plug.TriggerReverify()
	time.Sleep(100 * time.Millisecond)
	cancel2()
	<-done2

	state, found = plug.ExportGetContainerState("ctr-downgrade")
	if !found {
		t.Fatal("expected container in registry after mode-downgrade recovery")
	}

	if state.State != plugin.StateVerified {
		t.Errorf("expected StateVerified after recovery, got %v", state.State)
	}

	stubMock.mu.Lock()
	rollbackUpdates := len(stubMock.updates)
	stubMock.mu.Unlock()

	if rollbackUpdates == 0 {
		t.Error("expected rollback update even after mode downgrade to warn")
	}
}

func TestVerifyErrorIncrementMetric(t *testing.T) {
	t.Parallel()

	verif := &cvTestVerifier{ //nolint:exhaustruct_v5 // zero-value fields intentional
		result: nil,
		err:    errVerifyFailed,
	}
	plug := newCVTestPlugin(verif)
	plug.SetRemediationMode(config.RemediationModeWarn)

	plug.ExportStoreContainerTime("ctr-err", time.Now())

	plug.ExportSetPrewarmDone(nil)
	plug.ExportPrewarmCache(context.Background(), nil)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})

	go func() {
		plug.RunContinuousVerifier(ctx, time.Hour)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	plug.TriggerReverify()
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	verif.mu.Lock()
	calls := verif.calls
	verif.mu.Unlock()

	if calls < 1 {
		t.Errorf("expected at least 1 verify call, got %d", calls)
	}

	state, found := plug.ExportGetContainerState("ctr-err")
	if !found {
		t.Fatal("expected container to remain in registry after error")
	}

	if state.State != plugin.StateVerified {
		t.Errorf("expected state unchanged after error, got %v", state.State)
	}
}

func TestFeedTriggerPath(t *testing.T) {
	t.Parallel()

	verif := &cvTestVerifier{ //nolint:exhaustruct_v5 // zero-value fields intentional
		result: &types.Result{
			Allowed: false, Reason: testDegradedReason,
			CheckResults: []types.CheckResult{
				{ //nolint:exhaustruct_v5 // zero-value fields intentional
					Type:   types.CheckTypeSBOM,
					Passed: false,
					Status: testFailStatus,
				},
			},
		},
	}
	plug := newCVTestPlugin(verif)
	plug.SetRemediationMode(config.RemediationModeWarn)
	plug.SetRemediationConfig(
		&config.RemediationConfig{ //nolint:exhaustruct_v5 // zero-value fields intentional
			Mode: config.RemediationModeWarn,
			Triggers: config.TriggerConfig{
				OnNewCVE:             true,
				OnAttestationRevoked: true,
				OnPolicyChange:       true,
			},
		},
	)

	plug.ExportStoreContainerWithPURLs("ctr-feed-match", []string{testPURLGolangFoo})
	plug.ExportStoreContainerWithPURLs("ctr-feed-nomatch", []string{"pkg:npm/other@1.0"})

	plug.ExportSetPrewarmDone(nil)
	plug.ExportPrewarmCache(context.Background(), nil)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})

	go func() {
		plug.RunContinuousVerifier(ctx, time.Hour)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	plug.TriggerFeedReverify([]string{testPURLGolangFoo})
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	state, found := plug.ExportGetContainerState("ctr-feed-match")
	if !found {
		t.Fatal("expected matched container in registry")
	}

	if state.State != plugin.StateDegraded {
		t.Errorf("expected matched container degraded, got %v", state.State)
	}

	state, found = plug.ExportGetContainerState("ctr-feed-nomatch")
	if !found {
		t.Fatal("expected unmatched container in registry")
	}

	if state.State != plugin.StateVerified {
		t.Errorf("expected unmatched container still verified, got %v", state.State)
	}
}

func TestRecoverMetricInWarnMode(t *testing.T) {
	t.Parallel()

	degradedResult := &types.Result{
		Allowed: false, Reason: testDegradedReason,
		CheckResults: []types.CheckResult{
			{ //nolint:exhaustruct_v5 // zero-value fields intentional
				Type:   types.CheckTypeSBOM,
				Passed: false,
				Status: testFailStatus,
			},
		},
	}
	verif := &cvTestVerifier{ //nolint:exhaustruct_v5 // zero-value fields intentional
		result: degradedResult,
	}
	plug := newCVTestPlugin(verif)
	plug.SetRemediationMode(config.RemediationModeWarn)

	plug.ExportStoreContainerTime("ctr-recover", time.Now())

	plug.ExportSetPrewarmDone(nil)
	plug.ExportPrewarmCache(context.Background(), nil)

	// Phase 1: degrade
	ctx1, cancel1 := context.WithCancel(context.Background())

	done1 := make(chan struct{})

	go func() {
		plug.RunContinuousVerifier(ctx1, time.Hour)
		close(done1)
	}()

	time.Sleep(50 * time.Millisecond)
	plug.TriggerReverify()
	time.Sleep(100 * time.Millisecond)
	cancel1()
	<-done1

	state, found := plug.ExportGetContainerState("ctr-recover")
	if !found {
		t.Fatal("expected container in registry")
	}

	if state.State != plugin.StateDegraded {
		t.Fatalf("expected degraded, got %v", state.State)
	}

	// Phase 2: recover (switch to passing result)
	verif.mu.Lock()
	verif.result = &types.Result{
		Allowed: true, Reason: "", CheckResults: nil,
	}
	verif.mu.Unlock()

	ctx2, cancel2 := context.WithCancel(context.Background())

	done2 := make(chan struct{})

	go func() {
		plug.RunContinuousVerifier(ctx2, time.Hour)
		close(done2)
	}()

	time.Sleep(50 * time.Millisecond)
	plug.TriggerReverify()
	time.Sleep(100 * time.Millisecond)
	cancel2()
	<-done2

	state, found = plug.ExportGetContainerState("ctr-recover")
	if !found {
		t.Fatal("expected container in registry after recover")
	}

	if state.State != plugin.StateVerified {
		t.Errorf("expected verified after recover, got %v", state.State)
	}
}

func TestApplyUpdatesStubError(t *testing.T) {
	t.Parallel()

	verif := &cvTestVerifier{ //nolint:exhaustruct_v5 // zero-value fields intentional
		result: &types.Result{
			Allowed: false, Reason: testDegradedReason,
			CheckResults: []types.CheckResult{
				{ //nolint:exhaustruct_v5 // zero-value fields intentional
					Type:   types.CheckTypeSBOM,
					Passed: false,
					Status: testFailStatus,
				},
			},
		},
	}

	met := metrics.New()
	plug := plugin.New(verif, met, "", 30*time.Second, time.Second, nil)
	plug.SetRemediationMode(config.RemediationModeThrottle)
	plug.SetRemediationConfig(
		&config.RemediationConfig{ //nolint:exhaustruct_v5 // zero-value fields intentional
			Mode:      config.RemediationModeThrottle,
			BatchSize: 10,
			Throttle: config.ThrottleConfig{
				CPUQuotaPercent:    10,
				MemoryLimitPercent: 50,
			},
		},
	)

	//nolint:exhaustruct_v5 // zero-value fields intentional
	stubMock := &cvTestStub{err: errStubUpdate}
	plug.SetStub(stubMock)

	originalResources := &api.LinuxResources{
		Cpu: &api.LinuxCPU{
			Quota:  &api.OptionalInt64{Value: 100000},
			Shares: &api.OptionalUInt64{Value: 1024},
		},
		Memory: &api.LinuxMemory{
			Limit: &api.OptionalInt64{Value: 536870912},
		},
	}
	plug.ExportStoreContainerWithResources(
		"ctr-stuberr", "img:latest", "sha256:abc", originalResources,
	)

	plug.ExportSetPrewarmDone(nil)
	plug.ExportPrewarmCache(context.Background(), nil)

	// Phase 1: degrade
	ctx1, cancel1 := context.WithCancel(context.Background())

	done1 := make(chan struct{})

	go func() {
		plug.RunContinuousVerifier(ctx1, time.Hour)
		close(done1)
	}()

	time.Sleep(50 * time.Millisecond)
	plug.TriggerReverify()
	time.Sleep(100 * time.Millisecond)
	cancel1()
	<-done1

	// Phase 2: short timer for throttle (stub returns error)
	ctx2, cancel2 := context.WithCancel(context.Background())

	done2 := make(chan struct{})

	go func() {
		plug.RunContinuousVerifier(ctx2, 50*time.Millisecond)
		close(done2)
	}()

	time.Sleep(150 * time.Millisecond)
	cancel2()
	<-done2

	// The test passes if no panic occurs; the stub error is logged.
}

func TestApplyUpdatesPartialFailure(t *testing.T) {
	t.Parallel()

	verif := &cvTestVerifier{ //nolint:exhaustruct_v5 // zero-value fields intentional
		result: &types.Result{
			Allowed: false, Reason: testDegradedReason,
			CheckResults: []types.CheckResult{
				{ //nolint:exhaustruct_v5 // zero-value fields intentional
					Type:   types.CheckTypeSBOM,
					Passed: false,
					Status: testFailStatus,
				},
			},
		},
	}

	met := metrics.New()
	plug := plugin.New(verif, met, "", 30*time.Second, time.Second, nil)
	plug.SetRemediationMode(config.RemediationModeThrottle)
	plug.SetRemediationConfig(
		&config.RemediationConfig{ //nolint:exhaustruct_v5 // zero-value fields intentional
			Mode:      config.RemediationModeThrottle,
			BatchSize: 10,
			Throttle: config.ThrottleConfig{
				CPUQuotaPercent:    10,
				MemoryLimitPercent: 50,
			},
		},
	)

	failedUpdate := &api.ContainerUpdate{
		ContainerId: "ctr-partial",
	}
	stubMock := &cvTestStub{ //nolint:exhaustruct_v5 // zero-value fields intentional
		failed: []*api.ContainerUpdate{failedUpdate},
	}
	plug.SetStub(stubMock)

	originalResources := &api.LinuxResources{
		Cpu: &api.LinuxCPU{
			Quota:  &api.OptionalInt64{Value: 100000},
			Shares: &api.OptionalUInt64{Value: 1024},
		},
		Memory: &api.LinuxMemory{
			Limit: &api.OptionalInt64{Value: 536870912},
		},
	}
	plug.ExportStoreContainerWithResources(
		"ctr-partial", "img:latest", "sha256:abc", originalResources,
	)

	plug.ExportSetPrewarmDone(nil)
	plug.ExportPrewarmCache(context.Background(), nil)

	// Phase 1: degrade
	ctx1, cancel1 := context.WithCancel(context.Background())

	done1 := make(chan struct{})

	go func() {
		plug.RunContinuousVerifier(ctx1, time.Hour)
		close(done1)
	}()

	time.Sleep(50 * time.Millisecond)
	plug.TriggerReverify()
	time.Sleep(100 * time.Millisecond)
	cancel1()
	<-done1

	// Phase 2: short timer for throttle (stub returns partial failure)
	ctx2, cancel2 := context.WithCancel(context.Background())

	done2 := make(chan struct{})

	go func() {
		plug.RunContinuousVerifier(ctx2, 50*time.Millisecond)
		close(done2)
	}()

	time.Sleep(150 * time.Millisecond)
	cancel2()
	<-done2

	// The test passes if no panic occurs; partial failures are logged.
}

func TestApplyUpdatesNoStub(t *testing.T) {
	t.Parallel()

	verif := &cvTestVerifier{ //nolint:exhaustruct_v5 // zero-value fields intentional
		result: &types.Result{
			Allowed: false, Reason: testDegradedReason,
			CheckResults: []types.CheckResult{
				{ //nolint:exhaustruct_v5 // zero-value fields intentional
					Type:   types.CheckTypeSBOM,
					Passed: false,
					Status: testFailStatus,
				},
			},
		},
	}

	met := metrics.New()
	plug := plugin.New(verif, met, "", 30*time.Second, time.Second, nil)
	plug.SetRemediationMode(config.RemediationModeThrottle)
	plug.SetRemediationConfig(
		&config.RemediationConfig{ //nolint:exhaustruct_v5 // zero-value fields intentional
			Mode:      config.RemediationModeThrottle,
			BatchSize: 10,
			Throttle: config.ThrottleConfig{
				CPUQuotaPercent:    10,
				MemoryLimitPercent: 50,
			},
		},
	)

	originalResources := &api.LinuxResources{
		Cpu: &api.LinuxCPU{
			Quota:  &api.OptionalInt64{Value: 100000},
			Shares: &api.OptionalUInt64{Value: 1024},
		},
		Memory: &api.LinuxMemory{
			Limit: &api.OptionalInt64{Value: 536870912},
		},
	}
	plug.ExportStoreContainerWithResources(
		"ctr-nostub", "img:latest", "sha256:abc", originalResources,
	)

	plug.ExportSetPrewarmDone(nil)
	plug.ExportPrewarmCache(context.Background(), nil)

	// Phase 1: degrade
	ctx1, cancel1 := context.WithCancel(context.Background())

	done1 := make(chan struct{})

	go func() {
		plug.RunContinuousVerifier(ctx1, time.Hour)
		close(done1)
	}()

	time.Sleep(50 * time.Millisecond)
	plug.TriggerReverify()
	time.Sleep(100 * time.Millisecond)
	cancel1()
	<-done1

	// Phase 2: short timer for throttle (no stub set)
	ctx2, cancel2 := context.WithCancel(context.Background())

	done2 := make(chan struct{})

	go func() {
		plug.RunContinuousVerifier(ctx2, 50*time.Millisecond)
		close(done2)
	}()

	time.Sleep(150 * time.Millisecond)
	cancel2()
	<-done2

	// The test passes if no panic occurs; missing stub is logged.
}

func TestVerificationStateString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		state plugin.VerificationState
		want  string
	}{
		{plugin.StateVerified, "verified"},
		{plugin.StateDegraded, "degraded"},
		{plugin.StateThrottled, "throttled"},
		{plugin.VerificationState(99), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("VerificationState(%d).String() = %q, want %q", tt.state, got, tt.want)
		}
	}
}

func TestDeepCopyLinuxResourcesAllFields(t *testing.T) {
	t.Parallel()

	src := &api.LinuxResources{
		Cpu: &api.LinuxCPU{
			Quota:           &api.OptionalInt64{Value: 50000},
			Shares:          &api.OptionalUInt64{Value: 1024},
			Period:          &api.OptionalUInt64{Value: 100000},
			RealtimeRuntime: &api.OptionalInt64{Value: 9500},
			RealtimePeriod:  &api.OptionalUInt64{Value: 10000},
			Cpus:            "0-3",
			Mems:            "0",
		},
		Memory: &api.LinuxMemory{
			Limit:            &api.OptionalInt64{Value: 1073741824},
			Reservation:      &api.OptionalInt64{Value: 536870912},
			Swap:             &api.OptionalInt64{Value: 2147483648},
			Kernel:           &api.OptionalInt64{Value: 67108864},
			KernelTcp:        &api.OptionalInt64{Value: 33554432},
			Swappiness:       &api.OptionalUInt64{Value: 60},
			DisableOomKiller: &api.OptionalBool{Value: true},
			UseHierarchy:     &api.OptionalBool{Value: true},
		},
		HugepageLimits: []*api.HugepageLimit{
			{PageSize: "2MB", Limit: 1048576},
		},
		BlockioClass: &api.OptionalString{Value: "high"},
		RdtClass:     &api.OptionalString{Value: "gold"},
		Unified:      map[string]string{"memory.high": "900000000"},
		Devices: []*api.LinuxDeviceCgroup{
			{
				Allow:  true,
				Type:   "c",
				Major:  &api.OptionalInt64{Value: 1},
				Minor:  &api.OptionalInt64{Value: 5},
				Access: "rwm",
			},
		},
		Pids: &api.LinuxPids{Limit: 512},
	}

	dst := plugin.ExportDeepCopyLinuxResources(src)

	if dst.GetCpu().GetQuota().GetValue() != 50000 {
		t.Error("CPU quota not copied")
	}

	if dst.GetCpu().GetRealtimeRuntime().GetValue() != 9500 {
		t.Error("CPU realtime runtime not copied")
	}

	if dst.GetCpu().GetRealtimePeriod().GetValue() != 10000 {
		t.Error("CPU realtime period not copied")
	}

	if dst.GetCpu().GetCpus() != "0-3" {
		t.Error("CPU cpus not copied")
	}

	if dst.GetCpu().GetMems() != "0" {
		t.Error("CPU mems not copied")
	}

	if dst.GetMemory().GetKernel().GetValue() != 67108864 {
		t.Error("Memory kernel not copied")
	}

	if dst.GetMemory().GetKernelTcp().GetValue() != 33554432 {
		t.Error("Memory kernel TCP not copied")
	}

	if dst.GetMemory().GetSwappiness().GetValue() != 60 {
		t.Error("Memory swappiness not copied")
	}

	if !dst.GetMemory().GetDisableOomKiller().GetValue() {
		t.Error("Memory disable OOM killer not copied")
	}

	if !dst.GetMemory().GetUseHierarchy().GetValue() {
		t.Error("Memory use hierarchy not copied")
	}

	if len(dst.GetHugepageLimits()) != 1 || dst.GetHugepageLimits()[0].GetPageSize() != "2MB" {
		t.Error("HugepageLimits not copied")
	}

	if dst.GetBlockioClass().GetValue() != "high" {
		t.Error("BlockioClass not copied")
	}

	if dst.GetRdtClass().GetValue() != "gold" {
		t.Error("RdtClass not copied")
	}

	if dst.GetUnified()["memory.high"] != "900000000" {
		t.Error("Unified not copied")
	}

	if len(dst.GetDevices()) != 1 || dst.GetDevices()[0].GetMajor().GetValue() != 1 {
		t.Error("Devices not copied")
	}

	if dst.GetPids().GetLimit() != 512 {
		t.Error("Pids not copied")
	}

	// Verify deep isolation: mutating src must not affect dst.
	src.GetCpu().GetQuota().Value = 99999
	src.GetUnified()["memory.high"] = "changed"

	if dst.GetCpu().GetQuota().GetValue() != 50000 {
		t.Error("deep copy shares CPU quota pointer with source")
	}

	if dst.GetUnified()["memory.high"] != "900000000" {
		t.Error("deep copy shares unified map with source")
	}
}

func TestCooldownBlocksRemediation(t *testing.T) {
	t.Parallel()

	verif := &cvTestVerifier{ //nolint:exhaustruct_v5 // zero-value fields intentional
		result: &types.Result{
			Allowed: false, Reason: testDegradedReason,
			CheckResults: []types.CheckResult{
				{ //nolint:exhaustruct_v5 // zero-value fields intentional
					Type:   types.CheckTypeSBOM,
					Passed: false,
					Status: testFailStatus,
				},
			},
		},
	}

	met := metrics.New()
	plug := plugin.New(verif, met, "", 30*time.Second, time.Second, nil)

	plug.SetRemediationMode(config.RemediationModeThrottle)
	plug.SetRemediationConfig(
		&config.RemediationConfig{ //nolint:exhaustruct_v5 // zero-value fields intentional
			Mode:      config.RemediationModeThrottle,
			BatchSize: 10,
			Cooldown:  config.Duration{Duration: time.Hour},
			Throttle: config.ThrottleConfig{
				CPUQuotaPercent:    10,
				MemoryLimitPercent: 50,
			},
		},
	)

	stubMock := &cvTestStub{} //nolint:exhaustruct_v5 // zero-value fields intentional
	plug.SetStub(stubMock)

	originalResources := &api.LinuxResources{
		Cpu: &api.LinuxCPU{
			Quota:  &api.OptionalInt64{Value: 100000},
			Shares: &api.OptionalUInt64{Value: 1024},
		},
		Memory: &api.LinuxMemory{
			Limit: &api.OptionalInt64{Value: 536870912},
		},
	}

	plug.ExportStoreContainerInState(
		"ctr-cooldown", "img:latest", "sha256:abc",
		plugin.StateDegraded, originalResources, time.Now(),
	)

	plug.ExportSetPrewarmDone(nil)
	plug.ExportPrewarmCache(context.Background(), nil)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})

	go func() {
		plug.RunContinuousVerifier(ctx, 50*time.Millisecond)
		close(done)
	}()

	time.Sleep(150 * time.Millisecond)
	cancel()
	<-done

	state, found := plug.ExportGetContainerState("ctr-cooldown")
	if !found {
		t.Fatal("expected container in registry")
	}

	if state.State != plugin.StateDegraded {
		t.Errorf("expected StateDegraded (cooldown should block throttle), got %v", state.State)
	}

	stubMock.mu.Lock()
	updates := len(stubMock.updates)
	stubMock.mu.Unlock()

	if updates != 0 {
		t.Errorf("expected no updates during cooldown, got %d", updates)
	}
}

func TestExtractPURLsFromResult(t *testing.T) {
	t.Parallel()

	t.Run("nil result", func(t *testing.T) {
		t.Parallel()

		result := plugin.ExportExtractPURLsFromResult(nil)
		if result != nil {
			t.Errorf("expected nil for nil result, got %v", result)
		}
	})

	t.Run("no SBOM check", func(t *testing.T) {
		t.Parallel()

		result := plugin.ExportExtractPURLsFromResult(&types.Result{
			Allowed: true, Reason: "",
			CheckResults: []types.CheckResult{
				{ //nolint:exhaustruct_v5 // zero-value fields intentional
					Type:   types.CheckTypeSLSA,
					Passed: true,
				},
			},
		})

		if result != nil {
			t.Errorf("expected nil for non-SBOM result, got %v", result)
		}
	})

	t.Run("SBOM with empty purls", func(t *testing.T) {
		t.Parallel()

		result := plugin.ExportExtractPURLsFromResult(&types.Result{
			Allowed: true, Reason: "",
			CheckResults: []types.CheckResult{
				{ //nolint:exhaustruct_v5 // zero-value fields intentional
					Type:     types.CheckTypeSBOM,
					Passed:   true,
					Metadata: map[string]any{testMetadataPURLs: []string{}},
				},
			},
		})

		if result != nil {
			t.Errorf("expected nil for empty purls, got %v", result)
		}
	})

	t.Run("SBOM with purls", func(t *testing.T) {
		t.Parallel()

		result := plugin.ExportExtractPURLsFromResult(&types.Result{
			Allowed: true, Reason: "",
			CheckResults: []types.CheckResult{
				{ //nolint:exhaustruct_v5 // zero-value fields intentional
					Type:   types.CheckTypeSBOM,
					Passed: true,
					Metadata: map[string]any{
						testMetadataPURLs: []string{testPURLGolangFoo, testPURLNpmBar},
					},
				},
			},
		})

		if len(result) != 2 {
			t.Errorf("expected 2 purls, got %d", len(result))
		}
	})

	t.Run("SBOM with wrong type metadata", func(t *testing.T) {
		t.Parallel()

		result := plugin.ExportExtractPURLsFromResult(&types.Result{
			Allowed: true, Reason: "",
			CheckResults: []types.CheckResult{
				{ //nolint:exhaustruct_v5 // zero-value fields intentional
					Type:     types.CheckTypeSBOM,
					Passed:   true,
					Metadata: map[string]any{testMetadataPURLs: "not-a-slice"},
				},
			},
		})

		if result != nil {
			t.Errorf("expected nil for wrong type purls, got %v", result)
		}
	})
}

func TestCaptureLinuxResources(t *testing.T) {
	t.Parallel()

	t.Run("nil container linux", func(t *testing.T) {
		t.Parallel()

		ctr := &api.Container{}
		result := plugin.ExportCaptureLinuxResources(ctr)

		if result != nil {
			t.Error("expected nil for container without linux")
		}
	})

	t.Run("container with resources", func(t *testing.T) {
		t.Parallel()

		ctr := &api.Container{
			Linux: &api.LinuxContainer{
				Resources: &api.LinuxResources{
					Cpu: &api.LinuxCPU{
						Quota: &api.OptionalInt64{Value: 50000},
					},
				},
			},
		}
		result := plugin.ExportCaptureLinuxResources(ctr)

		if result == nil {
			t.Fatal("expected non-nil resources")
		}

		if result.GetCpu().GetQuota().GetValue() != 50000 {
			t.Error("expected CPU quota to be copied")
		}

		if result == ctr.GetLinux().GetResources() {
			t.Error("expected deep copy, not pointer alias")
		}
	})
}

func TestThrottlePercentsClampsUpperBound(t *testing.T) {
	t.Parallel()

	//nolint:exhaustruct_v5 // zero-value fields intentional
	plug := newCVTestPlugin(&cvTestVerifier{})

	plug.SetRemediationConfig(
		&config.RemediationConfig{ //nolint:exhaustruct_v5 // zero-value fields intentional
			Mode:     config.RemediationModeThrottle,
			Cooldown: config.Duration{Duration: time.Second},
			Throttle: config.ThrottleConfig{
				CPUQuotaPercent:    200,
				MemoryLimitPercent: 150,
			},
			Triggers: config.TriggerConfig{ //nolint:exhaustruct_v5 // zero-value fields intentional
				OnNewCVE: true,
			},
		},
	)

	cpuPct, memPct := plug.ExportThrottlePercents()

	if cpuPct > 100 {
		t.Errorf("CPU percent not clamped: got %d, want <= 100", cpuPct)
	}

	if memPct > 100 {
		t.Errorf("Memory percent not clamped: got %d, want <= 100", memPct)
	}
}

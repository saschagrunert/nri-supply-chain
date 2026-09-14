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
	"testing"
	"time"

	"github.com/containerd/nri/pkg/api"
	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/plugin"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const remediationTestDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

func degradedTestResult() *types.Result {
	return &types.Result{
		Allowed: false, Verified: false, Mode: "", Reason: testDegradedReason,
		CheckResults: []types.CheckResult{
			{ //nolint:exhaustruct_v5 // zero-value fields intentional
				Type:   types.CheckTypeSBOM,
				Passed: false,
				Status: testFailStatus,
			},
		},
	}
}

func throttleTestResources() *api.LinuxResources {
	return &api.LinuxResources{
		Cpu: &api.LinuxCPU{
			Quota:  &api.OptionalInt64{Value: 100000},
			Shares: &api.OptionalUInt64{Value: 1024},
		},
		Memory: &api.LinuxMemory{
			Limit: &api.OptionalInt64{Value: 536870912},
		},
	}
}

func newRemediationTestPlugin(
	t *testing.T, verif plugin.ImageVerifier, stub *cvTestStub, memPercent int,
) *plugin.Plugin {
	t.Helper()

	plug := plugin.New(verif, metrics.New(), "", 30*time.Second, time.Second, nil)
	plug.SetRemediationMode(config.RemediationModeThrottle)
	plug.SetRemediationConfig(
		&config.RemediationConfig{ //nolint:exhaustruct_v5 // zero-value fields intentional
			Mode:      config.RemediationModeThrottle,
			BatchSize: 10,
			Throttle: config.ThrottleConfig{
				CPUQuotaPercent:    10,
				MemoryLimitPercent: memPercent,
			},
		},
	)

	if stub != nil {
		plug.SetStub(stub)
	}

	return plug
}

func assertContainerState(
	t *testing.T, plug *plugin.Plugin, id string, want plugin.VerificationState,
) {
	t.Helper()

	state, found := plug.ExportGetContainerState(id)
	if !found {
		t.Fatalf("expected container %s in registry", id)
	}

	if state.State != want {
		t.Errorf("expected state %v, got %v", want, state.State)
	}
}

func TestThrottleStateCommittedOnlyAfterUpdateSucceeds(t *testing.T) {
	t.Parallel()

	verif := &cvTestVerifier{ //nolint:exhaustruct_v5 // zero-value fields intentional
		result: degradedTestResult(),
	}
	stub := &cvTestStub{ //nolint:exhaustruct_v5 // zero-value fields intentional
		err: errStubUpdate,
	}
	plug := newRemediationTestPlugin(t, verif, stub, 50)

	plug.ExportStoreContainerState(
		"ctr-retry", remediationTestDigest, plugin.StateDegraded, throttleTestResources(), false,
	)

	plug.ExportRunVerificationCycle(t.Context(), plugin.ExportTriggerTimer)
	assertContainerState(t, plug, "ctr-retry", plugin.StateDegraded)

	stub.mu.Lock()
	stub.err = nil
	stub.mu.Unlock()

	plug.ExportRunVerificationCycle(t.Context(), plugin.ExportTriggerTimer)
	assertContainerState(t, plug, "ctr-retry", plugin.StateThrottled)
}

func TestThrottleStateNotCommittedForFailedContainer(t *testing.T) {
	t.Parallel()

	verif := &cvTestVerifier{ //nolint:exhaustruct_v5 // zero-value fields intentional
		result: degradedTestResult(),
	}
	stub := &cvTestStub{ //nolint:exhaustruct_v5 // zero-value fields intentional
		failed: []*api.ContainerUpdate{{ContainerId: "ctr-failed"}},
	}
	plug := newRemediationTestPlugin(t, verif, stub, 50)

	plug.ExportStoreContainerState(
		"ctr-failed", remediationTestDigest, plugin.StateDegraded, throttleTestResources(), false,
	)
	plug.ExportStoreContainerState(
		"ctr-applied", remediationTestDigest, plugin.StateDegraded, throttleTestResources(), false,
	)

	plug.ExportRunVerificationCycle(t.Context(), plugin.ExportTriggerTimer)

	assertContainerState(t, plug, "ctr-failed", plugin.StateDegraded)
	assertContainerState(t, plug, "ctr-applied", plugin.StateThrottled)
}

func TestRollbackStateCommittedOnlyAfterUpdateSucceeds(t *testing.T) {
	t.Parallel()

	verif := &cvTestVerifier{ //nolint:exhaustruct_v5 // zero-value fields intentional
		result: &types.Result{
			Allowed: true, Verified: true, Mode: "", Reason: "", CheckResults: nil,
		},
	}
	stub := &cvTestStub{err: errStubUpdate} //nolint:exhaustruct_v5 // zero-value fields intentional
	plug := newRemediationTestPlugin(t, verif, stub, 50)

	plug.ExportStoreContainerState(
		"ctr-rollback",
		remediationTestDigest,
		plugin.StateThrottled,
		throttleTestResources(),
		false,
	)

	plug.ExportRunVerificationCycle(t.Context(), plugin.ExportTriggerManual)
	assertContainerState(t, plug, "ctr-rollback", plugin.StateThrottled)

	stub.mu.Lock()
	stub.err = nil
	stub.mu.Unlock()

	plug.ExportRunVerificationCycle(t.Context(), plugin.ExportTriggerManual)
	assertContainerState(t, plug, "ctr-rollback", plugin.StateVerified)
}

func TestRecoveredContainerIsNotThrottled(t *testing.T) {
	t.Parallel()

	verif := &cvTestVerifier{ //nolint:exhaustruct_v5 // zero-value fields intentional
		result: degradedTestResult(),
	}
	stub := &cvTestStub{} //nolint:exhaustruct_v5 // zero-value fields intentional
	plug := newRemediationTestPlugin(t, verif, stub, 50)

	plug.ExportStoreContainerState(
		"ctr-recovered", remediationTestDigest, plugin.StateDegraded, throttleTestResources(), true,
	)

	plug.ExportRunVerificationCycle(t.Context(), plugin.ExportTriggerTimer)

	assertContainerState(t, plug, "ctr-recovered", plugin.StateDegraded)

	stub.mu.Lock()
	defer stub.mu.Unlock()

	if len(stub.updates) != 0 {
		t.Errorf("expected no throttle for resources captured after restart, got %d updates",
			len(stub.updates))
	}
}

func TestVerificationCycleSkipsContainersWithoutDigest(t *testing.T) {
	t.Parallel()

	verif := &cvTestVerifier{ //nolint:exhaustruct_v5 // zero-value fields intentional
		result: degradedTestResult(),
	}
	plug := newRemediationTestPlugin(t, verif, nil, 50)

	plug.ExportStoreContainerState("ctr-nodigest", "", plugin.StateSkipped, nil, false)

	plug.ExportRunVerificationCycle(t.Context(), plugin.ExportTriggerManual)

	verif.mu.Lock()
	calls := verif.calls
	verif.mu.Unlock()

	if calls != 0 {
		t.Errorf("expected no verification for a container without digest, got %d calls", calls)
	}

	assertContainerState(t, plug, "ctr-nodigest", plugin.StateSkipped)
}

func TestBuildThrottleUpdateMemoryDefault(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		memPercent int
		wantMemory bool
	}{
		{name: "default leaves memory untouched", memPercent: 100, wantMemory: false},
		{name: "explicit percent throttles memory", memPercent: 50, wantMemory: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			verif := &cvTestVerifier{} //nolint:exhaustruct_v5 // zero-value fields intentional
			plug := newRemediationTestPlugin(t, verif, nil, tc.memPercent)

			update := plug.ExportBuildThrottleUpdate("ctr", throttleTestResources())
			resources := update.GetLinux().GetResources()

			if got := resources.GetMemory() != nil; got != tc.wantMemory {
				t.Errorf("expected memory update=%v, got %v", tc.wantMemory, got)
			}

			if resources.GetCpu().GetQuota().GetValue() != 10000 {
				t.Errorf("expected CPU quota throttled to 10%%, got %d",
					resources.GetCpu().GetQuota().GetValue())
			}
		})
	}
}

func TestOriginalResourcesAnnotationRoundTrip(t *testing.T) {
	t.Parallel()

	value, ok := plugin.OriginalResourcesAnnotation(throttleTestResources())
	if !ok {
		t.Fatal("expected annotation for resources with limits")
	}

	decoded, err := plugin.ExportDecodeOriginalResources(value)
	testutil.AssertNoError(t, err)

	if decoded.GetCpu().GetQuota().GetValue() != 100000 ||
		decoded.GetCpu().GetShares().GetValue() != 1024 ||
		decoded.GetMemory().GetLimit().GetValue() != 536870912 {
		t.Errorf("unexpected decoded resources: %v", decoded)
	}

	if _, ok := plugin.OriginalResourcesAnnotation(&api.LinuxResources{}); ok {
		t.Error("expected no annotation for resources without limits")
	}

	if _, ok := plugin.OriginalResourcesAnnotation(nil); ok {
		t.Error("expected no annotation for nil resources")
	}

	_, err = plugin.ExportDecodeOriginalResources("{not json")
	testutil.AssertError(t, err)
}

func TestSynchronizeTrustsOriginalResourcesAnnotation(t *testing.T) {
	t.Parallel()

	plug, done := newTestPluginWithPrewarmSignal(t, config.ModeDisabled, "")

	value, ok := plugin.OriginalResourcesAnnotation(throttleTestResources())
	if !ok {
		t.Fatal("expected annotation value")
	}

	pods := []*api.PodSandbox{{Id: testPodID, Namespace: testNamespace, Name: testPodName}}
	containers := []*api.Container{
		{
			Id:           "ctr-annotated",
			PodSandboxId: testPodID,
			Name:         testCtrName,
			Annotations: map[string]string{
				plugin.AnnotationImage:                 testImage,
				plugin.AnnotationImageRef:              testDigest,
				plugin.AnnotationOriginalResources:     value,
				plugin.AnnotationServiceAccountPersist: "",
			},
		},
		{
			Id:           "ctr-invalid",
			PodSandboxId: testPodID,
			Name:         testCtrName,
			Annotations: map[string]string{
				plugin.AnnotationImage:             testImage,
				plugin.AnnotationImageRef:          testDigest,
				plugin.AnnotationOriginalResources: "{bad",
			},
		},
	}

	_, err := plug.Synchronize(context.Background(), pods, containers)
	testutil.AssertNoError(t, err)
	waitForPrewarm(t, done)

	annotated, found := plug.ExportGetContainerState("ctr-annotated")
	if !found {
		t.Fatal("expected annotated container in registry")
	}

	if annotated.RecoveredOnRestart || !annotated.HasOriginals {
		t.Errorf("expected trusted originals from annotation, got %+v", annotated)
	}

	invalid, found := plug.ExportGetContainerState("ctr-invalid")
	if !found {
		t.Fatal("expected invalid container in registry")
	}

	if !invalid.RecoveredOnRestart {
		t.Error("expected an invalid annotation to be treated as untrusted")
	}
}

func TestNRIConnectedGauge(t *testing.T) {
	t.Parallel()

	met := metrics.New()
	verif := &cvTestVerifier{} //nolint:exhaustruct_v5 // zero-value fields intentional
	plug := plugin.New(verif, met, "", time.Second, time.Second, nil)

	if got := promtestutil.ToFloat64(met.NRIConnected); got != 0 {
		t.Errorf("expected gauge 0 before connecting, got %v", got)
	}

	_, err := plug.Configure(t.Context(), "", "fake", "0.0.0")
	testutil.AssertNoError(t, err)

	if got := promtestutil.ToFloat64(met.NRIConnected); got != 1 {
		t.Errorf("expected gauge 1 after Configure, got %v", got)
	}

	plug.SetDisconnected()

	if got := promtestutil.ToFloat64(met.NRIConnected); got != 0 {
		t.Errorf("expected gauge 0 after disconnect, got %v", got)
	}
}

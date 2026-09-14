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
	"maps"
	"testing"

	"github.com/containerd/nri/pkg/api"
	"google.golang.org/protobuf/proto"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/plugin"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

func recoveryTestPlugin(t *testing.T) (plug *plugin.Plugin, done <-chan struct{}) {
	t.Helper()

	verif := &cvTestVerifier{ //nolint:exhaustruct_v5 // zero-value fields intentional
		result: &types.Result{
			Allowed: true, Verified: true, Mode: "", Reason: "", CheckResults: nil,
		},
	}

	stub := &cvTestStub{} //nolint:exhaustruct_v5 // zero-value fields intentional
	plug = newRemediationTestPlugin(t, verif, stub, 100)

	ch := make(chan struct{}, 1)

	plug.ExportSetPrewarmDone(func() { ch <- struct{}{} })

	return plug, ch
}

func recoveryContainer(
	id string, current *api.LinuxResources, annotations map[string]string,
) *api.Container {
	merged := map[string]string{
		plugin.AnnotationImage:    testImage,
		plugin.AnnotationImageRef: testDigest,
	}

	maps.Copy(merged, annotations)

	return &api.Container{
		Id:           id,
		PodSandboxId: testPodID,
		Name:         testCtrName,
		Annotations:  merged,
		Linux:        &api.LinuxContainer{Resources: current},
	}
}

// throttledResources returns the limits a throttle update derived from
// original leaves on a container: throttled CPU, unchanged memory.
func throttledResources(
	t *testing.T, plug *plugin.Plugin, original *api.LinuxResources,
) *api.LinuxResources {
	t.Helper()

	update := plug.ExportBuildThrottleUpdate("probe", original)
	if update == nil {
		t.Fatal("expected a throttle update")
	}

	current, ok := proto.Clone(original).(*api.LinuxResources)
	if !ok {
		t.Fatal("cloning resources")
	}

	current.Cpu = update.GetLinux().GetResources().GetCpu()

	return current
}

func TestSynchronizePreservesTrackedContainerState(t *testing.T) {
	t.Parallel()

	plug, done := recoveryTestPlugin(t)

	const id = "ctr-tracked"

	plug.ExportStoreContainerState(
		id,
		testDigest,
		plugin.StateThrottled,
		throttleTestResources(),
		false,
	)
	plug.ExportStoreContainerWithPURLsFor(id, []string{testPURLGolangFoo})

	pods := []*api.PodSandbox{{Id: testPodID, Namespace: testNamespace, Name: testPodName}}
	containers := []*api.Container{recoveryContainer(id, throttleTestResources(), nil)}

	_, err := plug.Synchronize(context.Background(), pods, containers)
	testutil.AssertNoError(t, err)
	waitForPrewarm(t, done)

	state, found := plug.ExportGetContainerState(id)
	if !found {
		t.Fatal("expected tracked container to stay registered")
	}

	if state.State != plugin.StateThrottled {
		t.Errorf("state = %v, want %v (reconnect must not reset remediation state)",
			state.State, plugin.StateThrottled)
	}

	if len(state.PURLs) != 1 {
		t.Errorf("expected PURLs to be preserved, got %v", state.PURLs)
	}

	if state.RecoveredOnRestart {
		t.Error("expected trusted originals to be preserved")
	}
}

func TestSynchronizeReconstructsThrottledState(t *testing.T) {
	t.Parallel()

	plug, done := recoveryTestPlugin(t)

	original := throttleTestResources()

	value, ok := plugin.OriginalResourcesAnnotation(original)
	if !ok {
		t.Fatal("expected annotation value")
	}

	resized, ok := proto.Clone(original).(*api.LinuxResources)
	if !ok {
		t.Fatal("cloning resources")
	}

	resized.Cpu.Quota = &api.OptionalInt64{Value: 200000}

	annotations := map[string]string{plugin.AnnotationOriginalResources: value}
	pods := []*api.PodSandbox{{Id: testPodID, Namespace: testNamespace, Name: testPodName}}
	containers := []*api.Container{
		recoveryContainer("ctr-throttled", throttledResources(t, plug, original), annotations),
		recoveryContainer("ctr-unchanged", throttleTestResources(), annotations),
		recoveryContainer("ctr-resized", resized, annotations),
	}

	_, err := plug.Synchronize(context.Background(), pods, containers)
	testutil.AssertNoError(t, err)
	waitForPrewarm(t, done)

	tests := []struct {
		id   string
		want plugin.VerificationState
	}{
		{id: "ctr-throttled", want: plugin.StateThrottled},
		{id: "ctr-unchanged", want: plugin.StateVerified},
		{id: "ctr-resized", want: plugin.StateVerified},
	}

	for _, tc := range tests {
		state, found := plug.ExportGetContainerState(tc.id)
		if !found {
			t.Fatalf("expected %s in registry", tc.id)
		}

		if state.State != tc.want {
			t.Errorf("%s: state = %v, want %v", tc.id, state.State, tc.want)
		}

		if state.RecoveredOnRestart {
			t.Errorf("%s: expected trusted originals from annotation", tc.id)
		}
	}
}

func TestSynchronizeReconstructedThrottleRollsBack(t *testing.T) {
	t.Parallel()

	plug, done := recoveryTestPlugin(t)
	stub := &cvTestStub{} //nolint:exhaustruct_v5 // zero-value fields intentional
	plug.SetStub(stub)

	original := throttleTestResources()

	value, ok := plugin.OriginalResourcesAnnotation(original)
	if !ok {
		t.Fatal("expected annotation value")
	}

	pods := []*api.PodSandbox{{Id: testPodID, Namespace: testNamespace, Name: testPodName}}
	containers := []*api.Container{
		recoveryContainer("ctr-throttled", throttledResources(t, plug, original),
			map[string]string{plugin.AnnotationOriginalResources: value}),
	}

	_, err := plug.Synchronize(context.Background(), pods, containers)
	testutil.AssertNoError(t, err)
	waitForPrewarm(t, done)

	plug.ExportRunVerificationCycle(context.Background(), plugin.ExportTriggerTimer)

	assertContainerState(t, plug, "ctr-throttled", plugin.StateVerified)

	stub.mu.Lock()
	defer stub.mu.Unlock()

	if len(stub.updates) != 1 {
		t.Fatalf("expected one rollback update, got %d", len(stub.updates))
	}

	restored := stub.updates[0].GetLinux().GetResources().GetCpu().GetQuota().GetValue()
	if restored != original.GetCpu().GetQuota().GetValue() {
		t.Errorf("rollback quota = %d, want %d", restored, original.GetCpu().GetQuota().GetValue())
	}
}

func TestPrewarmDoesNotBindResolvedDigestForRemediation(t *testing.T) {
	t.Parallel()

	plug, done := newTestPluginWithPrewarmSignal(t, config.ModeDisabled, "")
	plug.ExportSetDigestResolver(func(context.Context, string) (string, string, error) {
		return testDigest, "", nil
	})

	pods := []*api.PodSandbox{{Id: testPodID, Namespace: testNamespace, Name: testPodName}}
	containers := []*api.Container{
		{
			Id:           "ctr-a",
			PodSandboxId: testPodID,
			Name:         testCtrName,
			Annotations:  map[string]string{plugin.AnnotationContainerdImage: testImage},
		},
	}

	_, err := plug.Synchronize(context.Background(), pods, containers)
	testutil.AssertNoError(t, err)
	waitForPrewarm(t, done)

	state, found := plug.ExportGetContainerState("ctr-a")
	if !found {
		t.Fatal("expected ctr-a in registry")
	}

	// The tag's current registry digest need not be the running image, so
	// it must not drive re-verification and remediation.
	if state.Digest != "" {
		t.Errorf("expected no digest bound from registry resolution, got %q", state.Digest)
	}
}

func TestRemediationUpdatesDoNotIgnoreFailures(t *testing.T) {
	t.Parallel()

	verif := &cvTestVerifier{} //nolint:exhaustruct_v5 // zero-value fields intentional
	plug := newRemediationTestPlugin(t, verif, nil, 50)

	throttle := plug.ExportBuildThrottleUpdate("ctr", throttleTestResources())
	if throttle == nil || throttle.GetIgnoreFailure() {
		t.Errorf("throttle update must not ignore failures: %+v", throttle)
	}

	rollback := plugin.ExportBuildRollbackUpdate("ctr", throttleTestResources())
	if rollback == nil || rollback.GetIgnoreFailure() {
		t.Errorf("rollback update must not ignore failures: %+v", rollback)
	}
}

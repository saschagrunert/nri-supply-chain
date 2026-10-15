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
	"fmt"
	"testing"
	"testing/synctest"
	"time"

	"github.com/containerd/nri/pkg/api"
	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/plugin"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const lifecycleContainerID = "ctr-lifecycle"

// TestStopContinuousVerifierReleasesThrottledContainers checks that stopping
// the continuous verifier (remediation disabled by a reload) restores the
// limits of throttled containers, that they stay degraded, and that the
// verifier can be started again.
func TestStopContinuousVerifierReleasesThrottledContainers(t *testing.T) {
	t.Parallel()

	verif := &cvTestVerifier{ //nolint:exhaustruct_v5 // zero-value fields intentional
		result: degradedTestResult(),
	}
	stub := &cvTestStub{} //nolint:exhaustruct_v5 // zero-value fields intentional
	plug := newRemediationTestPlugin(t, verif, stub, 50)

	plug.ExportStoreContainerState(
		lifecycleContainerID, remediationTestDigest, plugin.StateThrottled,
		throttleTestResources(), false,
	)

	plug.StartContinuousVerifier(t.Context(), time.Hour)
	plug.StopContinuousVerifier(t.Context())

	assertContainerState(t, plug, lifecycleContainerID, plugin.StateDegraded)

	stub.mu.Lock()
	updates := len(stub.updates)
	stub.mu.Unlock()

	testutil.AssertEqual(t, 1, updates)

	if got := plug.ExportContinuousVerifierInterval(); got != time.Hour {
		t.Fatalf("interval = %v, want the last run's interval", got)
	}

	// Stopping again is a no-op; starting again works.
	plug.StopContinuousVerifier(t.Context())
	plug.StartContinuousVerifier(t.Context(), 2*time.Hour)

	if got := plug.ExportContinuousVerifierInterval(); got != 2*time.Hour {
		t.Errorf("interval = %v, want the restarted run's interval", got)
	}

	plug.StopContinuousVerifier(t.Context())
}

// TestBuildRollbackUpdateRestoresOnlyThrottledLimits checks that a rollback
// restores the limits a throttle changes and leaves other settings alone.
func TestBuildRollbackUpdateRestoresOnlyThrottledLimits(t *testing.T) {
	t.Parallel()

	original := throttleTestResources()
	original.Cpu.Cpus = "1-2"
	original.Pids = &api.LinuxPids{Limit: 100}

	restored := plugin.ExportBuildRollbackUpdate(testContainerID, original).
		GetLinux().GetResources()

	testutil.AssertEqual(t, original.GetCpu().GetQuota().GetValue(),
		restored.GetCpu().GetQuota().GetValue())
	testutil.AssertEqual(t, original.GetCpu().GetShares().GetValue(),
		restored.GetCpu().GetShares().GetValue())
	testutil.AssertEqual(t, original.GetMemory().GetLimit().GetValue(),
		restored.GetMemory().GetLimit().GetValue())

	if restored.GetCpu().GetCpus() != "" || restored.GetPids() != nil {
		t.Errorf("expected only throttled limits in the rollback, got %+v", restored)
	}
}

// TestPostUpdateContainerRecordsResize checks that an in-place resize becomes
// the container's original resources and ends throttling, while the plugin's
// own throttle update is not recorded.
func TestPostUpdateContainerRecordsResize(t *testing.T) {
	t.Parallel()

	verif := &cvTestVerifier{ //nolint:exhaustruct_v5 // zero-value fields intentional
		result: degradedTestResult(),
	}
	plug := newRemediationTestPlugin(t, verif, nil, 50)

	original := throttleTestResources()
	plug.ExportStoreContainerState(
		lifecycleContainerID, remediationTestDigest, plugin.StateThrottled, original, false,
	)

	container := func(resources *api.LinuxResources) *api.Container {
		return &api.Container{
			Id:    lifecycleContainerID,
			Linux: &api.LinuxContainer{Resources: resources},
		}
	}

	throttled := plug.ExportBuildThrottleUpdate(lifecycleContainerID, original).
		GetLinux().GetResources()
	testutil.AssertNoError(t, plug.PostUpdateContainer(t.Context(), nil, container(throttled)))
	assertContainerState(t, plug, lifecycleContainerID, plugin.StateThrottled)

	resized := throttleTestResources()
	resized.Cpu.Quota = &api.OptionalInt64{Value: 400000}
	testutil.AssertNoError(t, plug.PostUpdateContainer(t.Context(), nil, container(resized)))
	assertContainerState(t, plug, lifecycleContainerID, plugin.StateDegraded)

	rollback := plug.ExportBuildRollbackUpdateFor(lifecycleContainerID)
	testutil.AssertEqual(
		t,
		int64(400000),
		rollback.GetLinux().GetResources().GetCpu().GetQuota().GetValue(),
	)
}

// blockingVerifier blocks every verification until its context is done.
type blockingVerifier struct {
	*cvTestVerifier

	started chan struct{}
}

func (v *blockingVerifier) Verify(
	ctx context.Context, _ *types.VerifyRequest,
) (*types.Result, error) {
	v.started <- struct{}{}

	<-ctx.Done()

	return nil, fmt.Errorf("verification interrupted: %w", ctx.Err())
}

// TestStopContinuousVerifierIgnoresCancelledVerifications checks that a
// re-verification cancelled by stopping the continuous verifier is not
// counted as a re-verification error, which would degrade the container
// after consecutive errors.
func TestStopContinuousVerifierIgnoresCancelledVerifications(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		verif := &blockingVerifier{
			cvTestVerifier: &cvTestVerifier{}, //nolint:exhaustruct_v5 // zero-value fields intentional
			started:        make(chan struct{}, 1),
		}
		met := metrics.New()
		plug := plugin.New(verif, met, "", time.Second, nil)
		plug.SetRemediationMode(config.RemediationModeWarn)
		plug.ExportStoreContainerTime(lifecycleContainerID, time.Now())
		plug.ExportSetPrewarmDone(nil)
		plug.ExportPrewarmCache(context.Background(), nil)

		plug.StartContinuousVerifier(t.Context(), time.Hour)
		plug.TriggerReverify()

		<-verif.started

		plug.StopContinuousVerifier(t.Context())

		if got := promtestutil.CollectAndCount(met.ReverificationTotal); got != 0 {
			t.Errorf("expected no re-verification outcome for a cancelled cycle, got %d", got)
		}

		assertContainerState(t, plug, lifecycleContainerID, plugin.StateVerified)
	})
}

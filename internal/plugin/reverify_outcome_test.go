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
	"fmt"
	"testing"

	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/plugin"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

// enforceDenial returns the error an enforce-mode verifier returns together
// with a failed result.
func enforceDenial() error {
	return fmt.Errorf("%w: img:latest: degraded", types.ErrVerificationFailed)
}

func incompleteTestResult() *types.Result {
	return &types.Result{
		Allowed:  false,
		Verified: false,
		Mode:     string(config.ModeEnforce),
		Reason:   "attestation fetch failed",
		CheckResults: []types.CheckResult{
			*types.FailResult(types.CheckTypeFetch, "attestation fetch failed", nil),
		},
	}
}

func TestReverifyEnforceDenialThrottles(t *testing.T) {
	t.Parallel()

	verif := &cvTestVerifier{ //nolint:exhaustruct_v5 // zero-value fields intentional
		result: degradedTestResult(),
		err:    enforceDenial(),
	}
	stub := &cvTestStub{} //nolint:exhaustruct_v5 // zero-value fields intentional
	plug := newRemediationTestPlugin(t, verif, stub, 50)

	plug.ExportStoreContainerState(
		"ctr-enforce", remediationTestDigest, plugin.StateDegraded, throttleTestResources(), false,
	)

	plug.ExportRunVerificationCycle(t.Context(), plugin.ExportTriggerTimer)
	assertContainerState(t, plug, "ctr-enforce", plugin.StateThrottled)
}

func TestReverifyIncompleteResultDoesNotDegrade(t *testing.T) {
	t.Parallel()

	verif := &cvTestVerifier{ //nolint:exhaustruct_v5 // zero-value fields intentional
		result: incompleteTestResult(),
		err:    enforceDenial(),
	}
	stub := &cvTestStub{} //nolint:exhaustruct_v5 // zero-value fields intentional
	plug := newRemediationTestPlugin(t, verif, stub, 50)

	plug.ExportStoreContainerState(
		"ctr-outage", remediationTestDigest, plugin.StateVerified, throttleTestResources(), false,
	)

	for range 5 {
		plug.ExportRunVerificationCycle(t.Context(), plugin.ExportTriggerTimer)
	}

	assertContainerState(t, plug, "ctr-outage", plugin.StateVerified)

	// Persistent outages keep the state but must stay visible.
	incomplete := promtestutil.ToFloat64(plug.ExportMetrics().ReverificationIncompleteContainers)
	if got := incomplete; got != 1 {
		t.Errorf("expected one container with persistently incomplete re-verification, got %v", got)
	}

	verif.mu.Lock()
	verif.result = degradedTestResult()
	verif.mu.Unlock()

	plug.ExportRunVerificationCycle(t.Context(), plugin.ExportTriggerTimer)

	incomplete = promtestutil.ToFloat64(
		plug.ExportMetrics().ReverificationIncompleteContainers,
	)
	if incomplete != 0 {
		t.Errorf(
			"expected a completed re-verification to reset the incomplete count, got %v",
			incomplete,
		)
	}
}

func TestReverifyIncompleteResultDoesNotRollBack(t *testing.T) {
	t.Parallel()

	verif := &cvTestVerifier{ //nolint:exhaustruct_v5 // zero-value fields intentional
		result: &types.Result{
			Allowed:  true,
			Verified: false,
			Mode:     string(config.ModeWarn),
			Reason:   "attestation fetch failed",
			CheckResults: []types.CheckResult{
				*types.WarnResult(types.CheckTypeFetch, "attestation fetch failed"),
			},
		},
	}
	stub := &cvTestStub{} //nolint:exhaustruct_v5 // zero-value fields intentional
	plug := newRemediationTestPlugin(t, verif, stub, 50)

	plug.ExportStoreContainerState(
		"ctr-throttled",
		remediationTestDigest,
		plugin.StateThrottled,
		throttleTestResources(),
		false,
	)

	plug.ExportRunVerificationCycle(t.Context(), plugin.ExportTriggerManual)
	assertContainerState(t, plug, "ctr-throttled", plugin.StateThrottled)

	stub.mu.Lock()
	defer stub.mu.Unlock()

	if len(stub.updates) != 0 {
		t.Errorf("expected no rollback for an incomplete result, got %d updates", len(stub.updates))
	}
}

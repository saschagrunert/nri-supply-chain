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

package daemon //nolint:testpackage // tests use unexported daemon internals

import (
	"context"
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

// mockRuntimeConfigPlugin records the plugin-side settings applied from a
// configuration passed by the runtime.
type mockRuntimeConfigPlugin struct {
	mockPluginReloader

	continuousInterval time.Duration
}

func (m *mockRuntimeConfigPlugin) StartContinuousVerifier(
	_ context.Context, interval time.Duration,
) {
	m.continuousInterval = interval
}

//nolint:paralleltest // modifies package-level LogLevel
func TestRuntimeConfigApplierAppliesPluginSettings(t *testing.T) {
	policyDir := t.TempDir()
	testutil.WritePolicy(t, policyDir, "default.json", `{}`)

	startup := config.DefaultConfig()
	met := metrics.New()

	verif, err := verifier.New(t.Context(), startup, met, &mockAttestationFetcher{})
	testutil.AssertNoError(t, err)
	t.Cleanup(verif.Stop)

	cfg, err := config.LoadFromString(`verification = "warn"
policy_dir = "` + policyDir + `"
fetch_timeout = "7s"
digest_resolve_timeout = "2s"

[remediation]
mode = "warn"
interval = "5m"
`)
	testutil.AssertNoError(t, err)

	mock := &mockRuntimeConfigPlugin{} //nolint:exhaustruct_v5 // zero-value mock

	applier := runtimeConfigApplier(t.Context(), startup, verif, met, mock)
	testutil.AssertNoError(t, applier(t.Context(), cfg))

	testutil.AssertEqual(t, verif.CurrentConfig().Verification, config.ModeWarn)
	testutil.AssertEqual(t, mock.fetchTimeout, 7*time.Second)
	testutil.AssertEqual(t, mock.digestResolveTimeout, 2*time.Second)
	testutil.AssertEqual(t, mock.remediationMode, config.RemediationModeWarn)
	testutil.AssertEqual(t, mock.continuousInterval, 5*time.Minute)
	testutil.AssertEqual(t, mock.prewarmAfterReloadCalled, true)
}

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
	"os"
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/plugin"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

func writeTestConfig(t *testing.T, path, policyDir, mode string) {
	t.Helper()

	data := "verification = \"" + mode + "\"\npolicy_dir = \"" + policyDir + "\"\n"

	err := os.WriteFile(path, []byte(data), 0o600)
	if err != nil {
		t.Fatalf("writing config: %v", err)
	}
}

func newDisabledPlugin(t *testing.T) *plugin.Plugin {
	t.Helper()

	cfg := config.DefaultConfig()
	met := metrics.New()

	v, err := verifier.New(t.Context(), cfg, met, nil)
	if err != nil {
		t.Fatalf("creating verifier: %v", err)
	}

	return plugin.New(v, met, "", 30*time.Second, 5*time.Second, nil)
}

type mockAttestationFetcher struct{}

func (m *mockAttestationFetcher) Fetch(
	_ context.Context, _ string, _ *attestation.FetchOptions,
) ([]attestation.VerifiedAttestation, error) {
	return nil, nil
}

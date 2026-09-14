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
	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/plugin"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
)

var errApplyRuntimeConfig = errors.New("apply failed")

const testDisabledRuntimeConfig = `verification = "disabled"` + "\n"

// blockingApplier records applied configurations and blocks until released.
type blockingApplier struct {
	release chan struct{}
	err     error

	mu      sync.Mutex
	applied []*config.Config
}

func (a *blockingApplier) apply(_ context.Context, cfg *config.Config) error {
	<-a.release

	a.mu.Lock()
	defer a.mu.Unlock()

	a.applied = append(a.applied, cfg)

	return a.err
}

func (a *blockingApplier) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()

	return len(a.applied)
}

func waitForReady(t *testing.T, plug *plugin.Plugin, want bool) string {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)

	for {
		ready, reason := plug.VerifierReady()
		if ready == want {
			return reason
		}

		if time.Now().After(deadline) {
			t.Fatalf("expected ready=%v, last reason %q", want, reason)
		}

		time.Sleep(10 * time.Millisecond)
	}
}

func TestConfigureAppliesRuntimeConfigInBackground(t *testing.T) {
	t.Parallel()

	verif := newDigestTestVerifier(true)
	plug := plugin.New(verif, metrics.New(), "", time.Second, time.Second, nil)

	applier := &blockingApplier{
		release: make(chan struct{}), err: nil, mu: sync.Mutex{}, applied: nil,
	}
	plug.SetConfigApplier(applier.apply)

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	start := time.Now()
	_, err := plug.Configure(ctx, `verification = "enforce"`+"\n"+
		`policy_dir = "`+t.TempDir()+`"`+"\n", "fake", "0.0.0")
	testutil.AssertNoError(t, err)

	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("expected Configure to return before the request deadline, took %s", elapsed)
	}

	waitForReady(t, plug, false)

	_, _, err = plug.CreateContainer(t.Context(), admissionPod(), admissionContainer(testDigest))
	if !errors.Is(err, plugin.ErrRuntimeConfigPending) {
		t.Fatalf("expected enforce admission to deny while the config is applied, got %v", err)
	}

	close(applier.release)
	waitForReady(t, plug, true)

	testutil.AssertEqual(t, applier.count(), 1)

	_, _, err = plug.CreateContainer(t.Context(), admissionPod(), admissionContainer(testDigest))
	testutil.AssertNoError(t, err)
}

func TestConfigureRuntimeConfigFailureKeepsPluginNotReady(t *testing.T) {
	t.Parallel()

	verif := newDigestTestVerifier(true)
	plug := plugin.New(verif, metrics.New(), "", time.Second, time.Second, nil)

	applier := &blockingApplier{
		release: make(chan struct{}), err: errApplyRuntimeConfig, mu: sync.Mutex{}, applied: nil,
	}
	close(applier.release)
	plug.SetConfigApplier(applier.apply)

	_, err := plug.Configure(t.Context(), `verification = "enforce"`+"\n"+
		`policy_dir = "`+t.TempDir()+`"`+"\n", "fake", "0.0.0")
	testutil.AssertNoError(t, err)

	deadline := time.Now().Add(5 * time.Second)
	for applier.count() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("expected the runtime configuration to be applied")
		}

		time.Sleep(10 * time.Millisecond)
	}

	reason := waitForReady(t, plug, false)
	if reason == "" {
		t.Error("expected a reason for the failed runtime configuration")
	}

	_, _, err = plug.CreateContainer(t.Context(), admissionPod(), admissionContainer(testDigest))
	if !errors.Is(err, plugin.ErrRuntimeConfigPending) {
		t.Fatalf("expected enforce admission to deny after a failed apply, got %v", err)
	}
}

func TestConfigureNonEnforceRuntimeConfigDoesNotDeny(t *testing.T) {
	t.Parallel()

	verif := newDigestTestVerifier(true)
	plug := plugin.New(verif, metrics.New(), "", time.Second, time.Second, nil)

	applier := &blockingApplier{
		release: make(chan struct{}), err: nil, mu: sync.Mutex{}, applied: nil,
	}

	t.Cleanup(func() { close(applier.release) })
	plug.SetConfigApplier(applier.apply)

	_, err := plug.Configure(t.Context(), testDisabledRuntimeConfig, "fake", "0.0.0")
	testutil.AssertNoError(t, err)

	_, _, err = plug.CreateContainer(t.Context(), admissionPod(), admissionContainer(testDigest))
	if errors.Is(err, plugin.ErrRuntimeConfigPending) {
		t.Fatalf("expected a pending non-enforce config not to deny, got %v", err)
	}
}

// failingThenApplier fails the first failures applies and then succeeds.
type failingThenApplier struct {
	failures int

	mu      sync.Mutex
	applied int
}

func (a *failingThenApplier) apply(_ context.Context, _ *config.Config) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.applied++
	if a.applied <= a.failures {
		return errApplyRuntimeConfig
	}

	return nil
}

func (a *failingThenApplier) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.applied
}

func namespacePod(namespace string) *api.PodSandbox {
	return &api.PodSandbox{Namespace: namespace, Name: testPodName}
}

func TestConfigurePendingRuntimeConfigDeniesEnforcingNamespace(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{}`)
	testutil.WritePolicy(t, dir, "prod.json", `{"mode": "enforce"}`)

	verif := newDigestTestVerifier(true)
	plug := plugin.New(verif, metrics.New(), "", time.Second, time.Second, nil)

	applier := &blockingApplier{
		release: make(chan struct{}), err: nil, mu: sync.Mutex{}, applied: nil,
	}

	t.Cleanup(func() { close(applier.release) })
	plug.SetConfigApplier(applier.apply)

	_, err := plug.Configure(t.Context(), `verification = "warn"`+"\n"+
		`policy_dir = "`+dir+`"`+"\n", "fake", "0.0.0")
	testutil.AssertNoError(t, err)

	_, _, err = plug.CreateContainer(
		t.Context(), namespacePod("prod"), admissionContainer(testDigest),
	)
	if !errors.Is(err, plugin.ErrRuntimeConfigPending) {
		t.Fatalf(
			"expected the enforcing namespace to deny while the config is pending, got %v", err,
		)
	}

	_, _, err = plug.CreateContainer(
		t.Context(), namespacePod("dev"), admissionContainer(testDigest),
	)
	if errors.Is(err, plugin.ErrRuntimeConfigPending) {
		t.Fatalf("expected a warn namespace not to deny while the config is pending, got %v", err)
	}
}

func TestConfigurePendingOCIRuntimeConfigDenies(t *testing.T) {
	t.Parallel()

	verif := newDigestTestVerifier(true)
	plug := plugin.New(verif, metrics.New(), "", time.Second, time.Second, nil)

	applier := &blockingApplier{
		release: make(chan struct{}), err: nil, mu: sync.Mutex{}, applied: nil,
	}

	t.Cleanup(func() { close(applier.release) })
	plug.SetConfigApplier(applier.apply)

	_, err := plug.Configure(t.Context(), `verification = "warn"`+"\n"+
		"[policy]\n"+`source = "oci"`+"\n"+`oci_ref = "registry.example.com/policies:latest"`+"\n",
		"fake", "0.0.0")
	testutil.AssertNoError(t, err)

	_, _, err = plug.CreateContainer(
		t.Context(), namespacePod("dev"), admissionContainer(testDigest),
	)
	if !errors.Is(err, plugin.ErrRuntimeConfigPending) {
		t.Fatalf("expected OCI policies to be treated as enforcing while pending, got %v", err)
	}
}

func TestConfigureRetriesFailedRuntimeConfig(t *testing.T) {
	t.Parallel()

	verif := newDigestTestVerifier(true)
	met := metrics.New()
	plug := plugin.New(verif, met, "", time.Second, time.Second, nil)
	plug.ExportSetRuntimeConfigRetry(10*time.Millisecond, 20*time.Millisecond)

	applier := &failingThenApplier{failures: 2, mu: sync.Mutex{}, applied: 0}
	plug.SetConfigApplier(applier.apply)

	_, err := plug.Configure(t.Context(), `verification = "enforce"`+"\n"+
		`policy_dir = "`+t.TempDir()+`"`+"\n", "fake", "0.0.0")
	testutil.AssertNoError(t, err)

	waitForReady(t, plug, true)

	if got := applier.count(); got != 3 {
		t.Errorf("expected two failed applies and one successful retry, got %d applies", got)
	}

	if got := promtestutil.ToFloat64(met.RuntimeConfigApplyFailed); got != 0 {
		t.Errorf("expected the apply failure gauge to reset after success, got %v", got)
	}
}

func TestConfigureSkipsUnchangedRuntimeConfig(t *testing.T) {
	t.Parallel()

	verif := newDigestTestVerifier(true)
	plug := plugin.New(verif, metrics.New(), "", time.Second, time.Second, nil)

	applier := &failingThenApplier{failures: 0, mu: sync.Mutex{}, applied: 0}
	plug.SetConfigApplier(applier.apply)

	runtimeConfig := `verification = "enforce"` + "\n" + `policy_dir = "` + t.TempDir() + `"` + "\n"

	_, err := plug.Configure(t.Context(), runtimeConfig, "fake", "0.0.0")
	testutil.AssertNoError(t, err)
	waitForReady(t, plug, true)

	// A reconnect passes the same configuration again.
	_, err = plug.Configure(t.Context(), runtimeConfig, "fake", "0.0.0")
	testutil.AssertNoError(t, err)

	ready, reason := plug.VerifierReady()
	if !ready {
		t.Errorf("expected an unchanged configuration to keep the plugin ready, got %q", reason)
	}

	testutil.AssertEqual(t, applier.count(), 1)
}

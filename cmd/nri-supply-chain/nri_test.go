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

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"

	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
)

const testPluginName = "supply-chain"

var errFakeStubCreate = errors.New("stub create failed")

// fakeNRIStub simulates an NRI connection. Start configures the plugin (or
// blocks forever when wedged, like a stub whose runtime connection dropped
// after registration), and the connection then either drops after runFor or
// stays up until Stop.
type fakeNRIStub struct {
	handler  nriHandler
	runFor   time.Duration
	fail     bool
	wedged   bool
	release  chan struct{}
	stopOnce sync.Once
	stopped  chan struct{}
}

func newFakeNRIStub(handler nriHandler) *fakeNRIStub {
	return &fakeNRIStub{ //nolint:exhaustruct_v5 // zero-value fields intentional
		handler: handler,
		runFor:  time.Millisecond,
		release: make(chan struct{}),
		stopped: make(chan struct{}),
	}
}

func (s *fakeNRIStub) Start(ctx context.Context) error {
	if s.wedged {
		<-s.release

		return nil
	}

	_, err := s.handler.Configure(ctx, "", "fake", "0.0.0")
	if err != nil {
		return fmt.Errorf("configure: %w", err)
	}

	return nil
}

func (s *fakeNRIStub) Wait() {
	if !s.fail {
		<-s.stopped

		return
	}

	timer := time.NewTimer(s.runFor)
	defer timer.Stop()

	select {
	case <-s.stopped:
	case <-timer.C:
	}
}

func (s *fakeNRIStub) Stop() {
	s.stopOnce.Do(func() { close(s.stopped) })
}

func (s *fakeNRIStub) UpdateContainers(
	_ []*api.ContainerUpdate,
) ([]*api.ContainerUpdate, error) {
	return nil, nil
}

// fakeStubFactory hands out stubs that fail (or wedge) a number of times
// before a stub that stays connected.
type fakeStubFactory struct {
	mu       sync.Mutex
	failures int
	wedges   int
	created  atomic.Int32
	opts     [][]stub.Option
	stubs    []*fakeNRIStub
	err      error
}

func (f *fakeStubFactory) create(
	handler nriHandler, opts ...stub.Option,
) (nriStub, error) {
	if f.err != nil {
		return nil, f.err
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	f.opts = append(f.opts, opts)
	count := int(f.created.Add(1))

	fake := newFakeNRIStub(handler)
	fake.wedged = count <= f.wedges
	fake.fail = !fake.wedged && count <= f.wedges+f.failures
	f.stubs = append(f.stubs, fake)

	return fake, nil
}

func testReconnectPolicy() reconnectPolicy {
	return reconnectPolicy{
		initial:          time.Millisecond,
		maximum:          4 * time.Millisecond,
		stable:           time.Hour,
		configureTimeout: time.Hour,
		maxAbandoned:     0,
		socketExists:     nil,
	}
}

func noEnv(string) string { return "" }

func testNRISettings() nriSettings {
	return nriSettings{
		pluginName: testPluginName, pluginIdx: "10", socketPath: "", disconnectTimeout: 0,
		healthAddr: "",
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()

	deadline := time.After(5 * time.Second)

	for !cond() {
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for %s", what)
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

func TestRunNRIReconnectsAfterConnectionLoss(t *testing.T) {
	t.Parallel()

	plug := newDisabledPlugin(t)
	factory := &fakeStubFactory{ //nolint:exhaustruct_v5 // zero-value fields intentional
		failures: 3,
	}

	ctx, cancel := context.WithCancel(t.Context())
	errCh := make(chan error, 1)

	go func() {
		errCh <- runNRI(ctx, plug, testNRISettings(), factory.create, noEnv,
			testReconnectPolicy(), newNRIConnection(time.Now()))
	}()

	waitFor(t, "reconnect", func() bool {
		return factory.created.Load() >= 4 && plug.Connected()
	})

	cancel()

	err := <-errCh
	testutil.AssertNoError(t, err)

	if plug.Connected() {
		t.Error("expected plugin to be disconnected after shutdown")
	}
}

func TestRunNRIAbandonsStubStuckBeforeConfigure(t *testing.T) {
	t.Parallel()

	plug := newDisabledPlugin(t)
	factory := &fakeStubFactory{ //nolint:exhaustruct_v5 // zero-value fields intentional
		wedges: 1,
	}

	policy := testReconnectPolicy()
	policy.configureTimeout = 20 * time.Millisecond

	ctx, cancel := context.WithCancel(t.Context())
	errCh := make(chan error, 1)

	go func() {
		errCh <- runNRI(ctx, plug, testNRISettings(), factory.create, noEnv,
			policy, newNRIConnection(time.Now()))
	}()

	waitFor(t, "reconnect after a wedged registration", func() bool {
		return factory.created.Load() >= 2 && plug.Connected()
	})

	cancel()
	testutil.AssertNoError(t, <-errCh)

	factory.mu.Lock()
	close(factory.stubs[0].release)
	factory.mu.Unlock()
}

func TestRunNRIReturnsOnCancelWhileStartIsWedged(t *testing.T) {
	t.Parallel()

	plug := newDisabledPlugin(t)
	factory := &fakeStubFactory{ //nolint:exhaustruct_v5 // zero-value fields intentional
		wedges: 1,
	}

	ctx, cancel := context.WithCancel(t.Context())
	errCh := make(chan error, 1)

	go func() {
		errCh <- runNRI(ctx, plug, testNRISettings(), factory.create, noEnv,
			testReconnectPolicy(), newNRIConnection(time.Now()))
	}()

	waitFor(t, "first connection attempt", func() bool { return factory.created.Load() == 1 })

	cancel()

	select {
	case err := <-errCh:
		testutil.AssertNoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("runNRI did not return after cancellation while Start was wedged")
	}

	factory.mu.Lock()
	close(factory.stubs[0].release)
	factory.mu.Unlock()
}

func TestRunNRIPreinstalledDoesNotReconnect(t *testing.T) {
	t.Parallel()

	plug := newDisabledPlugin(t)
	factory := &fakeStubFactory{ //nolint:exhaustruct_v5 // zero-value fields intentional
		failures: 1,
	}

	env := map[string]string{
		api.PluginSocketEnvVar: "3",
		api.PluginNameEnvVar:   testPluginName,
		api.PluginIdxEnvVar:    "10",
	}

	err := runNRI(t.Context(), plug, testNRISettings(), factory.create,
		func(key string) string { return env[key] }, testReconnectPolicy(),
		newNRIConnection(time.Now()))

	testutil.AssertErrorIs(t, err, errNRIConnectionLost)

	if got := factory.created.Load(); got != 1 {
		t.Errorf("expected a single connection attempt, got %d", got)
	}
}

func TestRunNRIStubCreationError(t *testing.T) {
	t.Parallel()

	factory := &fakeStubFactory{ //nolint:exhaustruct_v5 // zero-value fields intentional
		err: errFakeStubCreate,
	}

	err := runNRI(t.Context(), newDisabledPlugin(t), testNRISettings(), factory.create,
		noEnv, testReconnectPolicy(), newNRIConnection(time.Now()))

	testutil.AssertErrorIs(t, err, errFakeStubCreate)
}

func TestRunStubPublishesStubOnlyAfterStart(t *testing.T) {
	t.Parallel()

	fake := newFakeNRIStub(newDisabledPlugin(t))
	fake.wedged = true

	var published atomic.Bool

	ctx, cancel := context.WithCancel(t.Context())
	errCh := make(chan error, 1)

	go func() {
		errCh <- runStub(ctx, fake, time.Hour, func() { published.Store(true) })
	}()

	time.Sleep(20 * time.Millisecond)

	if published.Load() {
		t.Fatal("stub must not be published before Start returns")
	}

	close(fake.release)

	waitFor(t, "stub to be published after Start", published.Load)

	cancel()
	testutil.AssertErrorIs(t, <-errCh, context.Canceled)
}

func TestHandleNRICloseIgnoresPreviousConnection(t *testing.T) {
	t.Parallel()

	plug := newDisabledPlugin(t)
	conn := newNRIConnection(time.Now())

	previous := conn.begin()
	current := conn.begin()

	_, err := plug.Configure(t.Context(), "", "fake", "0.0.0")
	testutil.AssertNoError(t, err)
	conn.markConnected()

	handleNRIClose(t.Context(), plug, conn, previous)

	if !plug.Connected() {
		t.Error("a late close of a previous connection must not disconnect the live one")
	}

	handleNRIClose(t.Context(), plug, conn, current)

	if plug.Connected() {
		t.Error("expected the current connection's close to disconnect the plugin")
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	handleNRIClose(ctx, plug, conn, conn.begin())
}

func TestNRIConnectionLiveness(t *testing.T) {
	t.Parallel()

	start := time.Now()
	conn := newNRIConnection(start)

	socketUp := func() bool { return true }

	testutil.AssertNoError(t, conn.liveness(time.Minute, start.Add(30*time.Second), socketUp))
	testutil.AssertErrorIs(t, conn.liveness(time.Minute, start.Add(2*time.Minute), socketUp),
		errNRIDisconnectedTooLong)

	// A zero timeout disables the check.
	testutil.AssertNoError(t, conn.liveness(0, start.Add(time.Hour), socketUp))

	conn.markConnected()
	testutil.AssertNoError(t, conn.liveness(time.Minute, start.Add(time.Hour), socketUp))

	gen := conn.begin()
	conn.markDisconnected(gen, start.Add(time.Hour))
	testutil.AssertNoError(t,
		conn.liveness(time.Minute, start.Add(time.Hour+30*time.Second), socketUp))
	testutil.AssertErrorIs(t, conn.liveness(time.Minute, start.Add(2*time.Hour), socketUp),
		errNRIDisconnectedTooLong)
}

// TestNRIConnectionLivenessIgnoresMissingSocket checks that a runtime that is
// down (no NRI socket) does not fail liveness: restarting the plugin cannot
// help, and the restart would add a crash-loop backoff when the runtime
// comes back.
func TestNRIConnectionLivenessIgnoresMissingSocket(t *testing.T) {
	t.Parallel()

	start := time.Now()
	conn := newNRIConnection(start)

	testutil.AssertNoError(t,
		conn.liveness(time.Minute, start.Add(time.Hour), func() bool { return false }))
	testutil.AssertErrorIs(t,
		conn.liveness(time.Minute, start.Add(time.Hour), func() bool { return true }),
		errNRIDisconnectedTooLong)
}

func TestNRISocketExists(t *testing.T) {
	t.Parallel()

	dir, err := os.MkdirTemp("", "nri") //nolint:usetesting // unix socket path length
	testutil.AssertNoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	socketPath := filepath.Join(dir, "nri.sock")
	testutil.AssertEqual(t, nriSocketExists(socketPath)(), false)

	regular := filepath.Join(dir, "file")
	testutil.AssertNoError(t, os.WriteFile(regular, nil, 0o600))
	testutil.AssertEqual(t, nriSocketExists(regular)(), false)

	listenCfg := net.ListenConfig{} //nolint:exhaustruct_v5 // zero value is valid

	listener, err := listenCfg.Listen(t.Context(), "unix", socketPath)
	testutil.AssertNoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	testutil.AssertEqual(t, nriSocketExists(socketPath)(), true)
}

func TestWaitForRetryWakesWhenSocketAppears(t *testing.T) {
	t.Parallel()

	var appeared atomic.Bool

	time.AfterFunc(20*time.Millisecond, func() { appeared.Store(true) })

	start := time.Now()

	if !waitForRetry(t.Context(), time.Hour, appeared.Load, time.Millisecond) {
		t.Fatal("expected the wait to end when the socket appears")
	}

	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("expected an early retry, waited %s", elapsed)
	}

	// With the socket present from the start, the full backoff applies.
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()

	if waitForRetry(ctx, time.Hour, func() bool { return true }, time.Millisecond) {
		t.Error("expected the backoff to apply while the socket exists")
	}
}

func TestConnectionHandlerIgnoresStaleConfigure(t *testing.T) {
	t.Parallel()

	plug := newDisabledPlugin(t)
	conn := newNRIConnection(time.Now())

	abandoned := newConnectionHandler(plug, conn, conn.begin())
	conn.begin()

	_, err := abandoned.Configure(t.Context(), "", "fake", "0.0.0")
	testutil.AssertErrorIs(t, err, errStaleNRIConnection)

	if plug.Connected() {
		t.Error("a Configure of an abandoned connection must not mark the plugin connected")
	}
}

func TestRunNRIGivesUpAfterTooManyAbandonedConnections(t *testing.T) {
	t.Parallel()

	plug := newDisabledPlugin(t)
	factory := &fakeStubFactory{ //nolint:exhaustruct_v5 // zero-value fields intentional
		wedges: 100,
	}

	policy := testReconnectPolicy()
	policy.configureTimeout = 5 * time.Millisecond
	policy.maxAbandoned = 3

	err := runNRI(t.Context(), plug, testNRISettings(), factory.create, noEnv,
		policy, newNRIConnection(time.Now()))
	testutil.AssertErrorIs(t, err, errTooManyAbandonedNRIConnections)

	factory.mu.Lock()
	defer factory.mu.Unlock()

	testutil.AssertEqual(t, len(factory.stubs), 3)

	for _, fake := range factory.stubs {
		close(fake.release)
	}
}

func TestStubOptionsPluginIdentity(t *testing.T) {
	t.Parallel()

	settings := testNRISettings()

	tests := []struct {
		name string
		env  map[string]string
		want int
	}{
		{name: "flags applied without env", env: nil, want: 3},
		{
			name: "runtime env takes precedence",
			env: map[string]string{
				api.PluginNameEnvVar: testPluginName,
				api.PluginIdxEnvVar:  "10",
			},
			want: 1,
		},
		{
			name: "only index from env",
			env:  map[string]string{api.PluginIdxEnvVar: "05"},
			want: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts := stubOptions(settings, func(key string) string { return tc.env[key] }, func() {})
			if len(opts) != tc.want {
				t.Errorf("expected %d options, got %d", tc.want, len(opts))
			}
		})
	}

	withSocket := settings
	withSocket.socketPath = "/run/nri/custom.sock"

	if got := len(stubOptions(withSocket, noEnv, func() {})); got != 4 {
		t.Errorf("expected socket option to be added, got %d options", got)
	}
}

// TestStubOptionsPreinstalledEnv builds a real stub with the runtime's
// identity environment set, which failed with "plugin ID already set" when
// the index flag was applied unconditionally.
func TestStubOptionsPreinstalledEnv(t *testing.T) {
	t.Setenv(api.PluginNameEnvVar, testPluginName)
	t.Setenv(api.PluginIdxEnvVar, "10")

	plug := newDisabledPlugin(t)

	_, err := newNRIStub(plug, stubOptions(
		testNRISettings(),
		func(key string) string {
			if key == api.PluginNameEnvVar || key == api.PluginIdxEnvVar {
				return "set"
			}

			return ""
		},
		func() {},
	)...)
	testutil.AssertNoError(t, err)
}

func TestSleepContext(t *testing.T) {
	t.Parallel()

	if !sleepContext(t.Context(), time.Millisecond) {
		t.Error("expected sleep to complete")
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if sleepContext(ctx, time.Hour) {
		t.Error("expected cancelled sleep to return false")
	}
}

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
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/net/multiplex"
	"github.com/containerd/ttrpc"

	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
)

// fakeRuntimeService acknowledges plugin registrations.
type fakeRuntimeService struct {
	registered chan struct{}
}

func (s *fakeRuntimeService) RegisterPlugin(
	_ context.Context, _ *api.RegisterPluginRequest,
) (*api.Empty, error) {
	select {
	case s.registered <- struct{}{}:
	default:
	}

	return &api.Empty{}, nil
}

func (s *fakeRuntimeService) UpdateContainers(
	_ context.Context, _ *api.UpdateContainersRequest,
) (*api.UpdateContainersResponse, error) {
	return &api.UpdateContainersResponse{}, nil
}

// serveFakeNRIRuntime accepts plugin connections on socketPath. The first
// dropFirst connections are closed right after the plugin registered, before
// it is configured; later connections are configured and kept open.
func serveFakeNRIRuntime(t *testing.T, socketPath string, dropFirst int32) *atomic.Int32 {
	t.Helper()

	listenCfg := net.ListenConfig{} //nolint:exhaustruct_v5 // zero-value config is valid

	listener, err := listenCfg.Listen(t.Context(), "unix", socketPath)
	testutil.AssertNoError(t, err)

	accepted := &atomic.Int32{}

	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}

			go handleFakeNRIConnection(t, conn, accepted.Add(1) <= dropFirst)
		}
	}()

	return accepted
}

func handleFakeNRIConnection(t *testing.T, conn net.Conn, drop bool) {
	t.Helper()

	mux := multiplex.Multiplex(conn)

	t.Cleanup(func() { _ = mux.Close() })

	runtimeListener, err := mux.Listen(multiplex.RuntimeServiceConn)
	if err != nil {
		return
	}

	server, err := ttrpc.NewServer()
	if err != nil {
		return
	}

	service := &fakeRuntimeService{registered: make(chan struct{}, 1)}
	api.RegisterRuntimeService(server, service)

	go func() { _ = server.Serve(t.Context(), runtimeListener) }()

	select {
	case <-service.registered:
	case <-t.Context().Done():
		return
	}

	if drop {
		// Give the registration reply time to reach the plugin, then drop
		// the connection before configuring it.
		time.Sleep(10 * time.Millisecond)

		_ = mux.Close()

		return
	}

	pluginConn, err := mux.Open(multiplex.PluginServiceConn)
	if err != nil {
		return
	}

	client := api.NewPluginClient(ttrpc.NewClient(pluginConn))

	_, _ = client.Configure(
		t.Context(),
		&api.ConfigureRequest{
			RuntimeName:         "fake",
			RuntimeVersion:      "0.0.0",
			RegistrationTimeout: 5000,
			RequestTimeout:      2000,
		},
	)
}

// TestRunNRIRecoversFromDropBeforeConfigure reproduces a runtime connection
// that drops after RegisterPlugin but before Configure with the real NRI
// stub. The stub then waits for Configure forever; without the configure
// watchdog runNRI never reconnects.
func TestRunNRIRecoversFromDropBeforeConfigure(t *testing.T) {
	t.Parallel()

	// Unix socket paths are limited to 108 bytes, which t.TempDir paths
	// derived from long test names can exceed.
	dir, err := os.MkdirTemp("", "nri") //nolint:usetesting // see above
	testutil.AssertNoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	socketPath := filepath.Join(dir, "nri.sock")
	accepted := serveFakeNRIRuntime(t, socketPath, 1)

	plug := newDisabledPlugin(t)
	settings := testNRISettings()
	settings.socketPath = socketPath

	policy := testReconnectPolicy()
	policy.configureTimeout = 200 * time.Millisecond

	ctx, cancel := context.WithCancel(t.Context())
	errCh := make(chan error, 1)

	go func() {
		errCh <- runNRI(ctx, plug, settings, newNRIStub, noEnv, policy, newNRIConnection(time.Now()))
	}()

	waitFor(t, "connection after a drop before Configure", func() bool {
		return accepted.Load() >= 2 && plug.Connected()
	})

	cancel()

	select {
	case err := <-errCh:
		testutil.AssertNoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("runNRI did not return after cancellation")
	}
}

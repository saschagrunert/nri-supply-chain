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
	"encoding/json"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/plugin"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

func TestServeMetricsDisabled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	plug := newDisabledPlugin(t)

	err := serveMetrics(ctx, metrics.New(), "", plug)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestServeMetricsReadyz(t *testing.T) {
	t.Parallel()

	testPlug := newDisabledPlugin(t)
	addr := startMetricsServer(t, testPlug)

	assertProbeStatus(t, addr, "/readyz", http.StatusServiceUnavailable)
	assertProbeStatus(t, addr, "/healthz", http.StatusOK)

	_, configErr := testPlug.Configure(context.Background(), "", "cri-o", "1.32")
	if configErr != nil {
		t.Fatalf("configuring plugin: %v", configErr)
	}

	assertProbeStatus(t, addr, "/readyz", http.StatusOK)
	assertProbeStatus(t, addr, "/healthz", http.StatusOK)

	testPlug.SetDisconnected()

	assertProbeStatus(t, addr, "/healthz", http.StatusOK)
	assertProbeStatus(t, addr, "/readyz", http.StatusServiceUnavailable)
}

func TestServeMetricsReadyzVerifierNotReady(t *testing.T) {
	t.Parallel()

	// Create a plugin whose verifier is enabled but has no policies,
	// so VerifierReady returns false after connecting.
	policyDir := t.TempDir()

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = policyDir

	met := metrics.New()

	v, err := verifier.New(t.Context(), cfg, met, nil)
	if err != nil {
		t.Fatalf("creating verifier: %v", err)
	}

	testPlug := plugin.New(v, met, "", 30*time.Second, 5*time.Second, nil)

	// Connect the plugin so Connected() returns true.
	_, configErr := testPlug.Configure(context.Background(), "", "cri-o", "1.32")
	if configErr != nil {
		t.Fatalf("configuring plugin: %v", configErr)
	}

	addr := startMetricsServer(t, testPlug)

	// The plugin is connected but the verifier has no policies loaded,
	// so readyz should return 503 with a "not ready" reason.
	assertProbeStatus(t, addr, "/readyz", http.StatusServiceUnavailable)
}

func startMetricsServer(t *testing.T, plug *plugin.Plugin) string {
	t.Helper()

	listenCfg := net.ListenConfig{
		Control:   nil,
		KeepAlive: 0,
		KeepAliveConfig: net.KeepAliveConfig{
			Enable:   false,
			Idle:     0,
			Interval: 0,
			Count:    0,
		},
	}

	listener, err := listenCfg.Listen(
		context.Background(), "tcp", "127.0.0.1:0",
	)
	if err != nil {
		t.Fatalf("listening: %v", err)
	}

	addr := listener.Addr().String()
	met := metrics.New()

	mux := http.NewServeMux()
	mux.Handle("/metrics", met.Handler())
	registerHealthProbes(mux, plug)

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
	}

	ctx, cancel := context.WithCancel(context.Background())

	t.Cleanup(func() {
		cancel()

		_ = srv.Close()
	})

	go func() {
		_ = srv.Serve(listener)
	}()

	go shutdownOnCancel(ctx.Done(), srv)

	return addr
}

func TestServeMetricsStatusEndpoint(t *testing.T) {
	t.Parallel()

	testPlug := newDisabledPlugin(t)
	addr := startMetricsServer(t, testPlug)

	statusURL := "http://" + addr + "/status"

	var (
		resp *http.Response
		err  error
	)

	for range 50 {
		req, reqErr := http.NewRequestWithContext(
			context.Background(), http.MethodGet, statusURL, http.NoBody,
		)
		if reqErr != nil {
			t.Fatalf("creating request: %v", reqErr)
		}

		resp, err = http.DefaultClient.Do(req)
		if err == nil {
			break
		}

		time.Sleep(10 * time.Millisecond)
	}

	if err != nil {
		t.Fatalf("server did not start: %v", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", contentType)
	}

	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		t.Fatalf("reading body: %v", readErr)
	}

	var status types.StatusResponse

	jsonErr := json.Unmarshal(body, &status)
	if jsonErr != nil {
		t.Fatalf("decoding JSON: %v", jsonErr)
	}

	if status.Mode != string(config.ModeDisabled) {
		t.Errorf("mode = %q, want %q", status.Mode, config.ModeDisabled)
	}

	if status.Ready {
		t.Error("expected Ready = false before Configure")
	}

	if status.NRI.Connected {
		t.Error("expected NRI.Connected = false before Configure")
	}
}

func TestServeMetricsStatusEndpointConnected(t *testing.T) {
	t.Parallel()

	policyDir := t.TempDir()

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = policyDir

	met := metrics.New()

	v, err := verifier.New(t.Context(), cfg, met, nil)
	if err != nil {
		t.Fatalf("creating verifier: %v", err)
	}

	testPlug := plugin.New(v, met, "", 30*time.Second, 5*time.Second, nil)

	_, configErr := testPlug.Configure(
		context.Background(), "", "cri-o", "1.32",
	)
	if configErr != nil {
		t.Fatalf("configuring plugin: %v", configErr)
	}

	addr := startMetricsServer(t, testPlug)

	statusURL := "http://" + addr + "/status"

	var (
		resp   *http.Response
		reqErr error
	)

	for range 50 {
		req, newReqErr := http.NewRequestWithContext(
			context.Background(), http.MethodGet, statusURL, http.NoBody,
		)
		if newReqErr != nil {
			t.Fatalf("creating request: %v", newReqErr)
		}

		resp, reqErr = http.DefaultClient.Do(req)
		if reqErr == nil {
			break
		}

		time.Sleep(10 * time.Millisecond)
	}

	if reqErr != nil {
		t.Fatalf("server did not start: %v", reqErr)
	}

	defer func() { _ = resp.Body.Close() }()

	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		t.Fatalf("reading body: %v", readErr)
	}

	var status types.StatusResponse

	jsonErr := json.Unmarshal(body, &status)
	if jsonErr != nil {
		t.Fatalf("decoding JSON: %v", jsonErr)
	}

	if status.Mode != string(config.ModeWarn) {
		t.Errorf("mode = %q, want %q", status.Mode, config.ModeWarn)
	}

	if status.Ready {
		t.Error("expected Ready = false with no policies loaded")
	}

	if !status.NRI.Connected {
		t.Error("expected NRI.Connected = true after Configure")
	}

	if status.Policies.Source != string(config.PolicySourceLocal) {
		t.Errorf(
			"source = %q, want %q",
			status.Policies.Source, config.PolicySourceLocal,
		)
	}

	if status.Cache.MaxSize <= 0 {
		t.Errorf("expected positive cache max size, got %d", status.Cache.MaxSize)
	}

	if status.Cache.Size != 0 {
		t.Errorf("expected cache size 0, got %d", status.Cache.Size)
	}

	if len(status.CircuitBreakers) != 0 {
		t.Errorf(
			"expected empty circuit breakers, got %v",
			status.CircuitBreakers,
		)
	}
}

func assertProbeStatus(t *testing.T, addr, path string, wantStatus int) {
	t.Helper()

	probeURL := "http://" + addr + path

	var (
		resp *http.Response
		err  error
	)

	for range 50 {
		req, reqErr := http.NewRequestWithContext(
			context.Background(), http.MethodGet, probeURL, http.NoBody,
		)
		if reqErr != nil {
			t.Fatalf("creating request: %v", reqErr)
		}

		resp, err = http.DefaultClient.Do(req)
		if err == nil {
			break
		}

		time.Sleep(10 * time.Millisecond)
	}

	if err != nil {
		t.Fatalf("server did not start: %v", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != wantStatus {
		t.Errorf("%s: expected status %d, got %d", path, wantStatus, resp.StatusCode)
	}
}

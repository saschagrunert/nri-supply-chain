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
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
)

func TestServeMetricsRetriesBusyAddress(t *testing.T) {
	t.Parallel()

	listenCfg := net.ListenConfig{} //nolint:exhaustruct_v5 // zero-value config is valid

	blocker, err := listenCfg.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}

	addr := blocker.Addr().String()
	plug := newDisabledPlugin(t)

	ctx, cancel := context.WithCancel(t.Context())
	errCh := make(chan error, 1)

	go func() {
		errCh <- serveMetrics(ctx, metrics.New(), addr, plug, nil,
			listenRetryPolicy{initial: 5 * time.Millisecond, maximum: 10 * time.Millisecond, factor: listenRetryBackoffFactor})
	}()

	select {
	case err := <-errCh:
		t.Fatalf("serveMetrics must keep retrying a busy address, returned %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	_ = blocker.Close()

	deadline := time.After(5 * time.Second)

	for !healthzOK(t, addr) {
		select {
		case <-deadline:
			t.Fatal("metrics server did not start after the address was freed")
		case <-time.After(5 * time.Millisecond):
		}
	}

	cancel()

	err = <-errCh
	if err != nil {
		t.Fatalf("expected nil after cancellation, got %v", err)
	}
}

func TestServeMetricsReturnsOnCancelWhileAddressBusy(t *testing.T) {
	t.Parallel()

	listenCfg := net.ListenConfig{} //nolint:exhaustruct_v5 // zero-value config is valid

	blocker, err := listenCfg.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}

	t.Cleanup(func() { _ = blocker.Close() })

	plug := newDisabledPlugin(t)

	ctx, cancel := context.WithCancel(t.Context())
	errCh := make(chan error, 1)

	go func() {
		errCh <- serveMetrics(ctx, metrics.New(), blocker.Addr().String(), plug,
			nil, listenRetryPolicy{initial: time.Hour, maximum: time.Hour, factor: listenRetryBackoffFactor})
	}()

	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("expected nil, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveMetrics did not return after cancellation")
	}
}

func TestHealthzReportsLivenessFailure(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()

	var failing atomic.Bool

	registerHealthProbes(mux, newDisabledPlugin(t), func() error {
		if failing.Load() {
			return errNRIDisconnectedTooLong
		}

		return nil
	})

	check := func(want int) {
		t.Helper()

		recorder := httptest.NewRecorder()
		request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil)
		mux.ServeHTTP(recorder, request)

		if recorder.Code != want {
			t.Errorf("/healthz status = %d, want %d", recorder.Code, want)
		}
	}

	check(http.StatusOK)

	failing.Store(true)
	check(http.StatusServiceUnavailable)
}

// TestServeHealthIsSeparateFromMetrics checks that the dedicated health
// server answers the probes without exposing metrics, so probes keep working
// when the metrics port cannot be bound.
func TestServeHealthIsSeparateFromMetrics(t *testing.T) {
	t.Parallel()

	listenCfg := net.ListenConfig{} //nolint:exhaustruct_v5 // zero-value config is valid

	probe, err := listenCfg.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}

	addr := probe.Addr().String()
	_ = probe.Close()

	plug := newDisabledPlugin(t)

	ctx, cancel := context.WithCancel(t.Context())
	errCh := make(chan error, 1)

	go func() {
		errCh <- serveHealth(ctx, addr, plug, nil,
			listenRetryPolicy{initial: 5 * time.Millisecond, maximum: 10 * time.Millisecond, factor: listenRetryBackoffFactor})
	}()

	deadline := time.After(5 * time.Second)

	for !healthzOK(t, addr) {
		select {
		case <-deadline:
			t.Fatal("health server did not start")
		case <-time.After(5 * time.Millisecond):
		}
	}

	req, err := http.NewRequestWithContext(
		t.Context(), http.MethodGet, fmt.Sprintf("http://%s/metrics", addr), http.NoBody,
	)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("requesting /metrics: %v", err)
	}

	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected the health server not to serve metrics, got %d", resp.StatusCode)
	}

	cancel()

	err = <-errCh
	if err != nil {
		t.Fatalf("expected nil after cancellation, got %v", err)
	}
}

func healthzOK(t *testing.T, addr string) bool {
	t.Helper()

	req, err := http.NewRequestWithContext(
		t.Context(), http.MethodGet, fmt.Sprintf("http://%s/healthz", addr), http.NoBody,
	)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}

	_ = resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

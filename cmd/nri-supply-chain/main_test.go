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
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
)

func TestInitLogging(t *testing.T) { //nolint:paralleltest // modifies global slog default
	tests := []struct {
		name  string
		level string
		want  slog.Level
	}{
		{name: logLevelDebug, level: logLevelDebug, want: slog.LevelDebug},
		{name: logLevelInfo, level: logLevelInfo, want: slog.LevelInfo},
		{name: logLevelWarn, level: logLevelWarn, want: slog.LevelWarn},
		{name: logLevelError, level: logLevelError, want: slog.LevelError},
		{name: "unrecognized defaults to info", level: "bogus", want: slog.LevelInfo},
	}

	for _, test := range tests { //nolint:paralleltest // modifies global slog default
		t.Run(test.name, func(t *testing.T) {
			initLogging(test.level)

			handler := slog.Default().Handler()
			if !handler.Enabled(context.Background(), test.want) {
				t.Errorf("expected level %v to be enabled", test.want)
			}

			if test.want > slog.LevelDebug {
				belowLevel := test.want - 4
				if handler.Enabled(context.Background(), belowLevel) {
					t.Errorf("expected level %v to be disabled", belowLevel)
				}
			}
		})
	}
}

func TestSetupConfig(t *testing.T) {
	t.Parallel()

	t.Run("metricsAddr override", func(t *testing.T) {
		t.Parallel()

		opts := &options{
			configPath:  "",
			metricsAddr: ":9999",
			pluginName:  "",
			pluginIdx:   "",
			logLevel:    "",
			showVersion: false,
		}

		cfg, err := setupConfig(opts)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cfg.MetricsAddr != ":9999" {
			t.Errorf("expected :9999, got %s", cfg.MetricsAddr)
		}
	})

	t.Run("validation error", func(t *testing.T) {
		t.Parallel()

		configPath := filepath.Join(t.TempDir(), "config.toml")

		err := os.WriteFile(
			configPath,
			[]byte("verification = \"warn\"\npolicy_dir = \"/nonexistent\"\n"),
			0o600,
		)
		if err != nil {
			t.Fatalf("writing config: %v", err)
		}

		opts := &options{
			configPath:  configPath,
			metricsAddr: "",
			pluginName:  "",
			pluginIdx:   "",
			logLevel:    "",
			showVersion: false,
		}

		_, err = setupConfig(opts)
		if err == nil {
			t.Fatal("expected error for nonexistent policy dir")
		}
	})
}

func TestHandleShutdown(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	handleShutdown(ctx, cancel, sigCh)

	sigCh <- syscall.SIGTERM

	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("expected context to be cancelled after signal")
	}
}

func TestServeMetricsDisabled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ready := &atomic.Bool{}

	err := serveMetrics(ctx, metrics.New(), "", ready)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestServeMetricsReadyz(t *testing.T) {
	t.Parallel()

	addr := startMetricsServer(t)

	assertReadyzStatus(t, addr, http.StatusServiceUnavailable)

	testReady.Store(true)

	assertReadyzStatus(t, addr, http.StatusOK)
}

var testReady = &atomic.Bool{} //nolint:gochecknoglobals // test-only shared state

func startMetricsServer(t *testing.T) string {
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

	listener, err := listenCfg.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("finding free port: %v", err)
	}

	addr := listener.Addr().String()

	err = listener.Close()
	if err != nil {
		t.Fatalf("closing listener: %v", err)
	}

	testReady.Store(false)

	ctx, cancel := context.WithCancel(context.Background())

	t.Cleanup(cancel)

	go func() {
		_ = serveMetrics(ctx, metrics.New(), addr, testReady)
	}()

	return addr
}

func assertReadyzStatus(t *testing.T, addr string, wantStatus int) {
	t.Helper()

	readyzURL := "http://" + addr + "/readyz"

	var (
		resp *http.Response
		err  error
	)

	for range 50 {
		req, reqErr := http.NewRequestWithContext(
			context.Background(), http.MethodGet, readyzURL, http.NoBody,
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
		t.Errorf("expected status %d, got %d", wantStatus, resp.StatusCode)
	}
}

func TestLoadConfig(t *testing.T) {
	t.Parallel()

	t.Run("default config", func(t *testing.T) {
		t.Parallel()

		cfg, err := loadConfig("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cfg == nil {
			t.Fatal("expected config, got nil")
		}
	})

	t.Run("from file", func(t *testing.T) {
		t.Parallel()

		configPath := filepath.Join(t.TempDir(), "config.toml")

		err := os.WriteFile(
			configPath,
			[]byte("verification = \"warn\"\n"),
			0o600,
		)
		if err != nil {
			t.Fatalf("writing config: %v", err)
		}

		cfg, err := loadConfig(configPath)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cfg.Verification != "warn" {
			t.Errorf("expected warn, got %s", cfg.Verification)
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		t.Parallel()

		_, err := loadConfig("/nonexistent/config.toml")
		if err == nil {
			t.Fatal("expected error for nonexistent file")
		}
	})
}

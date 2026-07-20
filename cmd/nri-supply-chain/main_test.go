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
	"syscall"
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/plugin"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

func TestNewLogger(t *testing.T) {
	t.Parallel()

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

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			logger := newLogger(test.level)
			handler := logger.Handler()

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
			validate:    false,
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
			validate:    false,
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
	done := make(chan struct{})
	handleShutdown(ctx, cancel, sigCh, done)

	sigCh <- syscall.SIGTERM

	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("expected context to be cancelled after signal")
	}
}

func TestSetupReload(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	policyDir := filepath.Join(dir, "policies")

	err := os.Mkdir(policyDir, 0o750)
	if err != nil {
		t.Fatalf("creating policy dir: %v", err)
	}

	writeTestConfig(t, configPath, policyDir, "warn")

	cfg, err := config.LoadFromFile(configPath)
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}

	verif, err := verifier.New(cfg, metrics.New(), nil)
	if err != nil {
		t.Fatalf("creating verifier: %v", err)
	}

	if verif.Enforcing() {
		t.Fatal("expected warn mode initially")
	}

	ctx := t.Context()

	sigCh := make(chan os.Signal, 1)
	setupReload(ctx, configPath, verif, sigCh)

	writeTestConfig(t, configPath, policyDir, "enforce")

	sigCh <- syscall.SIGHUP

	deadline := time.After(2 * time.Second)

	for !verif.Enforcing() {
		select {
		case <-deadline:
			t.Fatal("verifier did not switch to enforce mode after SIGHUP")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func TestSetupReloadNoConfig(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()

	verif, err := verifier.New(cfg, metrics.New(), nil)
	if err != nil {
		t.Fatalf("creating verifier: %v", err)
	}

	ctx := t.Context()

	sigCh := make(chan os.Signal, 1)
	setupReload(ctx, "", verif, sigCh)

	sigCh <- syscall.SIGHUP

	time.Sleep(50 * time.Millisecond)

	if verif.Enforcing() {
		t.Fatal("expected warn mode to remain unchanged after no-op reload")
	}
}

func writeTestConfig(t *testing.T, path, policyDir, mode string) {
	t.Helper()

	data := "verification = \"" + mode + "\"\npolicy_dir = \"" + policyDir + "\"\n"

	err := os.WriteFile(path, []byte(data), 0o600)
	if err != nil {
		t.Fatalf("writing config: %v", err)
	}
}

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

func newDisabledPlugin(t *testing.T) *plugin.Plugin {
	t.Helper()

	cfg := config.DefaultConfig()
	met := metrics.New()

	v, err := verifier.New(cfg, met, nil)
	if err != nil {
		t.Fatalf("creating verifier: %v", err)
	}

	return plugin.New(v, met, "")
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

	listener, err := listenCfg.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("finding free port: %v", err)
	}

	addr := listener.Addr().String()

	err = listener.Close()
	if err != nil {
		t.Fatalf("closing listener: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	t.Cleanup(cancel)

	go func() {
		_ = serveMetrics(ctx, metrics.New(), addr, plug)
	}()

	return addr
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

func TestRunValidationDisabled(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()

	if code := runValidation(cfg); code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
}

func TestRunValidationValid(t *testing.T) {
	t.Parallel()

	policyDir := filepath.Join(t.TempDir(), "policies")

	err := os.MkdirAll(policyDir, 0o750)
	if err != nil {
		t.Fatalf("creating policy dir: %v", err)
	}

	writeValidationPolicy(t, policyDir, "default.json",
		`{"provenance": {"missingPolicy": "warn"}}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = policyDir

	if code := runValidation(cfg); code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
}

func TestRunValidationInvalidPolicy(t *testing.T) {
	t.Parallel()

	policyDir := filepath.Join(t.TempDir(), "policies")

	err := os.MkdirAll(policyDir, 0o750)
	if err != nil {
		t.Fatalf("creating policy dir: %v", err)
	}

	writeValidationPolicy(t, policyDir, "bad.json", `{invalid json}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = policyDir

	if code := runValidation(cfg); code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestRunValidationRuntimeFailure(t *testing.T) {
	t.Parallel()

	policyDir := filepath.Join(t.TempDir(), "policies")

	err := os.MkdirAll(policyDir, 0o750)
	if err != nil {
		t.Fatalf("creating policy dir: %v", err)
	}

	writeValidationPolicy(t, policyDir, "default.json",
		`{"trust":{"verifiers":[{"id":"test","key":"/nonexistent/key.pub"}]}}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.PolicyDir = policyDir

	if code := runValidation(cfg); code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func writeValidationPolicy(t *testing.T, dir, name, content string) {
	t.Helper()

	err := os.WriteFile(
		filepath.Join(dir, name), []byte(content), 0o600,
	)
	if err != nil {
		t.Fatalf("writing policy: %v", err)
	}
}

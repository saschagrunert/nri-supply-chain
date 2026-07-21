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
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/plugin"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

const (
	testConfigFile    = "test.toml"
	testNamespaceMain = "default"
)

//nolint:paralleltest // modifies package-level logLevelVar
func TestNewLogger(t *testing.T) {
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
			updateLogLevel(test.level)

			logger := newLogger()
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
			configPath:      "",
			metricsAddr:     ":9999",
			pluginName:      "",
			pluginIdx:       "",
			logLevel:        "",
			verifyImage:     "",
			verifyNamespace: "",
			showVersion:     false,
			validate:        false,
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
			configPath:      configPath,
			metricsAddr:     "",
			pluginName:      "",
			pluginIdx:       "",
			logLevel:        "",
			verifyImage:     "",
			verifyNamespace: "",
			showVersion:     false,
			validate:        false,
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
	setupReload(ctx, configPath, verif, sigCh, nil)

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
	setupReload(ctx, "", verif, sigCh, nil)

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

func TestServeMetricsReadyzVerifierNotReady(t *testing.T) {
	t.Parallel()

	// Create a plugin whose verifier is enabled but has no policies,
	// so VerifierReady returns false after connecting.
	policyDir := t.TempDir()

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = policyDir

	met := metrics.New()

	v, err := verifier.New(cfg, met, nil)
	if err != nil {
		t.Fatalf("creating verifier: %v", err)
	}

	testPlug := plugin.New(v, met, "")

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

		if cfg.Verification != config.ModeWarn {
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

func TestRunValidationEnforceValid(t *testing.T) {
	t.Parallel()

	policyDir := filepath.Join(t.TempDir(), "policies")

	err := os.MkdirAll(policyDir, 0o750)
	if err != nil {
		t.Fatalf("creating policy dir: %v", err)
	}

	writeValidationPolicy(t, policyDir, "default.json",
		`{"provenance": {"missingPolicy": "allow"}}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.PolicyDir = policyDir

	if code := runValidation(cfg); code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
}

func TestWarnValidationEnforceDefaults(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *config.Config
		policies map[string]*policy.Policy
	}{
		{
			name: "fetch failure policy warn",
			cfg: func() *config.Config {
				c := config.DefaultConfig()
				c.Verification = config.ModeEnforce
				c.FetchFailurePolicy = policy.ActionWarn

				return c
			}(),
			policies: map[string]*policy.Policy{},
		},
		{
			name: "fetch failure policy allow",
			cfg: func() *config.Config {
				c := config.DefaultConfig()
				c.Verification = config.ModeEnforce
				c.FetchFailurePolicy = policy.ActionAllow

				return c
			}(),
			policies: map[string]*policy.Policy{},
		},
		{
			name: "fetch failure policy deny",
			cfg: func() *config.Config {
				c := config.DefaultConfig()
				c.Verification = config.ModeEnforce
				c.FetchFailurePolicy = policy.ActionDeny

				return c
			}(),
			policies: map[string]*policy.Policy{},
		},
		{
			name: "provenance missing policy allow with default namespace",
			cfg: func() *config.Config {
				c := config.DefaultConfig()
				c.Verification = config.ModeEnforce
				c.FetchFailurePolicy = policy.ActionDeny

				return c
			}(),
			policies: map[string]*policy.Policy{
				"": {
					Provenance: &policy.ProvenancePolicy{
						MissingPolicy: policy.ActionAllow,
					},
				},
			},
		},
		{
			name: "provenance missing policy deny",
			cfg: func() *config.Config {
				c := config.DefaultConfig()
				c.Verification = config.ModeEnforce
				c.FetchFailurePolicy = policy.ActionDeny

				return c
			}(),
			policies: map[string]*policy.Policy{
				"prod": {
					Provenance: &policy.ProvenancePolicy{
						MissingPolicy: policy.ActionDeny,
					},
				},
			},
		},
		{
			name: "VEX missing policy allow with default namespace",
			cfg: func() *config.Config {
				c := config.DefaultConfig()
				c.Verification = config.ModeEnforce
				c.FetchFailurePolicy = policy.ActionDeny

				return c
			}(),
			policies: map[string]*policy.Policy{
				"": {
					Provenance: &policy.ProvenancePolicy{
						MissingPolicy: policy.ActionDeny,
					},
				},
			},
		},
		{
			name: "VEX missing policy deny",
			cfg: func() *config.Config {
				c := config.DefaultConfig()
				c.Verification = config.ModeEnforce
				c.FetchFailurePolicy = policy.ActionDeny

				return c
			}(),
			policies: map[string]*policy.Policy{
				"secure": {
					Provenance: &policy.ProvenancePolicy{
						MissingPolicy: policy.ActionDeny,
					},
					VEX: &policy.VEXPolicy{
						MissingPolicy: policy.ActionDeny,
					},
				},
			},
		},
		{
			name: "named namespace with all defaults",
			cfg: func() *config.Config {
				c := config.DefaultConfig()
				c.Verification = config.ModeEnforce

				return c
			}(),
			policies: map[string]*policy.Policy{
				"staging": {},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Should not panic for any combination.
			warnValidationEnforceDefaults(test.cfg, test.policies)
		})
	}
}

func TestSetupFileWatch(t *testing.T) {
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

	cleanup, _ := setupFileWatch(ctx, configPath, policyDir, verif)
	defer cleanup()

	writeTestConfig(t, configPath, policyDir, "enforce")

	deadline := time.After(3 * time.Second)

	for !verif.Enforcing() {
		select {
		case <-deadline:
			t.Fatal("verifier did not switch to enforce mode after file change")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func TestSetupFileWatchNoConfig(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()

	verif, err := verifier.New(cfg, metrics.New(), nil)
	if err != nil {
		t.Fatalf("creating verifier: %v", err)
	}

	cleanup, _ := setupFileWatch(t.Context(), "", "", verif)
	defer cleanup()

	if verif.Enforcing() {
		t.Fatal("expected disabled mode to remain unchanged")
	}
}

func TestIsReloadEvent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		op   fsnotify.Op
		want bool
	}{
		{name: "write", op: fsnotify.Write, want: true},
		{name: "create", op: fsnotify.Create, want: true},
		{name: "remove", op: fsnotify.Remove, want: true},
		{name: "rename", op: fsnotify.Rename, want: false},
		{name: "chmod", op: fsnotify.Chmod, want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			event := fsnotify.Event{
				Name: testConfigFile,
				Op:   test.op,
			}

			if got := isReloadEvent(event); got != test.want {
				t.Errorf("expected %v, got %v", test.want, got)
			}
		})
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

// --- outputVerifyResult tests ---

//nolint:paralleltest // captures os.Stdout
func TestOutputVerifyResultAllowed(t *testing.T) {
	checks := []checkEntry{
		{Type: "slsa_provenance", Passed: true, Status: "pass", Detail: "verified"},
	}

	out := captureVerifyOutput(
		t, "nginx:latest", "sha256:abc", testNamespaceMain, true, "verified", checks,
	)

	if out.Image != "nginx:latest" {
		t.Errorf("Image = %q, want %q", out.Image, "nginx:latest")
	}

	if out.Digest != "sha256:abc" {
		t.Errorf("Digest = %q, want %q", out.Digest, "sha256:abc")
	}

	if out.Namespace != testNamespaceMain {
		t.Errorf("Namespace = %q, want %q", out.Namespace, testNamespaceMain)
	}

	if !out.Allowed {
		t.Error("expected Allowed = true")
	}

	if out.Reason != "verified" {
		t.Errorf("Reason = %q, want %q", out.Reason, "verified")
	}

	if len(out.CheckResults) != 1 {
		t.Fatalf("CheckResults length = %d, want 1", len(out.CheckResults))
	}

	if out.CheckResults[0].Type != "slsa_provenance" {
		t.Errorf("CheckResults[0].Type = %q, want %q", out.CheckResults[0].Type, "slsa_provenance")
	}
}

//nolint:paralleltest // captures os.Stdout
func TestOutputVerifyResultDenied(t *testing.T) {
	out := captureVerifyOutput(t, "evil:latest", "sha256:bad", "prod", false, "failed checks", nil)

	if out.Allowed {
		t.Error("expected Allowed = false")
	}

	if out.Reason != "failed checks" {
		t.Errorf("Reason = %q, want %q", out.Reason, "failed checks")
	}

	if out.CheckResults != nil {
		t.Errorf("expected nil CheckResults, got %v", out.CheckResults)
	}
}

func captureVerifyOutput(
	t *testing.T,
	imageRef, digest, namespace string,
	allowed bool, reason string, checks []checkEntry,
) verifyOutput {
	t.Helper()

	origStdout := os.Stdout

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("creating pipe: %v", err)
	}

	os.Stdout = w

	outputVerifyResult(imageRef, digest, namespace, allowed, reason, checks)

	err = w.Close()
	if err != nil {
		os.Stdout = origStdout

		t.Fatalf("closing write pipe: %v", err)
	}

	os.Stdout = origStdout

	var buf bytes.Buffer

	_, err = io.Copy(&buf, r)
	if err != nil {
		t.Fatalf("reading pipe: %v", err)
	}

	var out verifyOutput

	err = json.Unmarshal(buf.Bytes(), &out)
	if err != nil {
		t.Fatalf("invalid JSON output: %v\nraw: %s", err, buf.String())
	}

	return out
}

// --- resolveDigest tests ---

func TestResolveDigestInvalidRef(t *testing.T) {
	t.Parallel()

	_, err := resolveDigest(":::invalid", 30*time.Second)
	if err == nil {
		t.Fatal("expected error for invalid image reference")
	}

	if !strings.Contains(err.Error(), "parsing image reference") {
		t.Errorf("error = %q, expected to contain 'parsing image reference'", err)
	}
}

func TestResolveDigestNetworkError(t *testing.T) {
	t.Parallel()

	// Use a closed server so connection is refused immediately.
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	addr := server.Listener.Addr().String()
	server.Close()

	_, err := resolveDigest(addr+"/test:latest", 30*time.Second)
	if err == nil {
		t.Fatal("expected error for unreachable registry")
	}

	if !strings.Contains(err.Error(), "resolving image digest") {
		t.Errorf("error = %q, expected to contain 'resolving image digest'", err)
	}
}

func TestResolveDigestSuccess(t *testing.T) {
	t.Parallel()

	regHandler := registry.New()
	server := httptest.NewServer(regHandler)

	t.Cleanup(server.Close)

	addr := strings.TrimPrefix(server.URL, "http://")
	imgRef := addr + "/test:latest"

	img, err := mutate.ConfigFile(empty.Image, nil)
	if err != nil {
		t.Fatalf("creating test image: %v", err)
	}

	err = crane.Push(img, imgRef, crane.Insecure)
	if err != nil {
		t.Fatalf("pushing test image: %v", err)
	}

	digest, err := resolveDigest(imgRef, 30*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.HasPrefix(digest, "sha256:") {
		t.Errorf("digest = %q, expected sha256: prefix", digest)
	}
}

// --- runVerify tests ---

func TestRunVerifyResolveDigestFails(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	opts := &options{
		configPath:      "",
		metricsAddr:     "",
		pluginName:      "",
		pluginIdx:       "",
		logLevel:        "",
		verifyImage:     ":::invalid-ref",
		verifyNamespace: testNamespaceMain,
		showVersion:     false,
		validate:        false,
	}

	code := runVerify(opts, cfg)
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
}

//nolint:paralleltest // captures os.Stdout
func TestRunVerifyDisabledAllowed(t *testing.T) {
	// Push image to in-memory registry, then verify with disabled mode.
	regHandler := registry.New()
	server := httptest.NewServer(regHandler)

	t.Cleanup(server.Close)

	addr := strings.TrimPrefix(server.URL, "http://")
	imgRef := addr + "/verify-test:latest"

	img, err := mutate.ConfigFile(empty.Image, nil)
	if err != nil {
		t.Fatalf("creating test image: %v", err)
	}

	err = crane.Push(img, imgRef, crane.Insecure)
	if err != nil {
		t.Fatalf("pushing test image: %v", err)
	}

	cfg := config.DefaultConfig()
	opts := &options{
		configPath:      "",
		metricsAddr:     "",
		pluginName:      "",
		pluginIdx:       "",
		logLevel:        "",
		verifyImage:     imgRef,
		verifyNamespace: testNamespaceMain,
		showVersion:     false,
		validate:        false,
	}

	out := captureRunVerify(t, opts, cfg)

	if !out.Allowed {
		t.Error("expected Allowed = true for disabled mode")
	}

	if out.Image != imgRef {
		t.Errorf("Image = %q, want %q", out.Image, imgRef)
	}
}

//nolint:paralleltest // captures os.Stdout
func TestRunVerifyEnforceDenied(t *testing.T) {
	// Push image to in-memory registry, then verify with enforce mode.
	regHandler := registry.New()
	server := httptest.NewServer(regHandler)

	t.Cleanup(server.Close)

	addr := strings.TrimPrefix(server.URL, "http://")
	imgRef := addr + "/deny-test:latest"

	img, err := mutate.ConfigFile(empty.Image, nil)
	if err != nil {
		t.Fatalf("creating test image: %v", err)
	}

	err = crane.Push(img, imgRef, crane.Insecure)
	if err != nil {
		t.Fatalf("pushing test image: %v", err)
	}

	policyDir := t.TempDir()
	writeValidationPolicy(t, policyDir, "default.json",
		`{"provenance": {"missingPolicy": "deny"}}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.PolicyDir = policyDir

	opts := &options{
		configPath:      "",
		metricsAddr:     "",
		pluginName:      "",
		pluginIdx:       "",
		logLevel:        "",
		verifyImage:     imgRef,
		verifyNamespace: testNamespaceMain,
		showVersion:     false,
		validate:        false,
	}

	out := captureRunVerify(t, opts, cfg)

	if out.Allowed {
		t.Error("expected Allowed = false for enforce mode with deny policy")
	}
}

func TestRunVerifyVerifierNewError(t *testing.T) {
	t.Parallel()

	// Create a policy dir with an invalid policy file so that
	// verifier.New fails when loading policies.
	policyDir := t.TempDir()
	writeValidationPolicy(t, policyDir, "bad.json", `{invalid json}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = policyDir

	opts := &options{
		configPath:      "",
		metricsAddr:     "",
		pluginName:      "",
		pluginIdx:       "",
		logLevel:        "",
		verifyImage:     "test:latest",
		verifyNamespace: testNamespaceMain,
		showVersion:     false,
		validate:        false,
	}

	code := runVerify(opts, cfg)
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
}

//nolint:paralleltest // captures os.Stdout
func TestRunVerifyWarnModeWithChecks(t *testing.T) {
	// In warn mode with a deny policy, the verifier returns check results
	// but allows the image. This exercises the CheckResults loop body.
	regHandler := registry.New()
	server := httptest.NewServer(regHandler)

	t.Cleanup(server.Close)

	addr := strings.TrimPrefix(server.URL, "http://")
	imgRef := addr + "/warn-test:latest"

	img, err := mutate.ConfigFile(empty.Image, nil)
	if err != nil {
		t.Fatalf("creating test image: %v", err)
	}

	err = crane.Push(img, imgRef, crane.Insecure)
	if err != nil {
		t.Fatalf("pushing test image: %v", err)
	}

	policyDir := t.TempDir()
	writeValidationPolicy(t, policyDir, "default.json",
		`{"provenance": {"missingPolicy": "deny"}}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = policyDir

	opts := &options{
		configPath:      "",
		metricsAddr:     "",
		pluginName:      "",
		pluginIdx:       "",
		logLevel:        "",
		verifyImage:     imgRef,
		verifyNamespace: testNamespaceMain,
		showVersion:     false,
		validate:        false,
	}

	out := captureRunVerify(t, opts, cfg)

	if !out.Allowed {
		t.Error("expected Allowed = true for warn mode")
	}

	if len(out.CheckResults) == 0 {
		t.Error("expected non-empty CheckResults for warn mode with deny policy")
	}
}

func captureRunVerify(t *testing.T, opts *options, cfg *config.Config) verifyOutput {
	t.Helper()

	origStdout := os.Stdout

	r, w, pErr := os.Pipe()
	if pErr != nil {
		t.Fatalf("creating pipe: %v", pErr)
	}

	os.Stdout = w

	_ = runVerify(opts, cfg)

	_ = w.Close()

	os.Stdout = origStdout

	var buf bytes.Buffer

	_, _ = io.Copy(&buf, r)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	lastJSON := findLastJSON(lines)

	if lastJSON == "" {
		t.Fatalf("no JSON found in output: %s", buf.String())
	}

	var out verifyOutput

	err := json.Unmarshal([]byte(lastJSON), &out)
	if err != nil {
		t.Fatalf("invalid JSON: %v\nraw: %s", err, lastJSON)
	}

	return out
}

func findLastJSON(lines []string) string {
	// outputVerifyResult writes a multi-line JSON object.
	// Collect lines starting from last '{' to matching '}'.
	var jsonLines []string

	depth := 0

	for _, line := range slices.Backward(lines) {
		for _, ch := range line {
			switch ch {
			case '}':
				depth++
			case '{':
				depth--
			}
		}

		jsonLines = append([]string{line}, jsonLines...)

		if depth == 0 && strings.Contains(line, "{") {
			break
		}
	}

	return strings.Join(jsonLines, "\n")
}

// --- setupSignals tests ---

func TestSetupSignals(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()

	verif, err := verifier.New(cfg, metrics.New(), nil)
	if err != nil {
		t.Fatalf("creating verifier: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cleanup := setupSignals(ctx, cancel, "", verif, cfg)
	cleanup()
}

func TestSetupSignalsWithConfig(t *testing.T) {
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cleanup := setupSignals(ctx, cancel, configPath, verif, cfg)
	cleanup()
}

// --- initLogging tests ---

//nolint:paralleltest // modifies package-level logLevelVar
func TestInitLogging(t *testing.T) {
	initLogging(logLevelDebug)

	if logLevelVar.Level() != slog.LevelDebug {
		t.Errorf("expected debug level, got %v", logLevelVar.Level())
	}

	initLogging("bogus")
}

// --- setupFileWatch error path tests ---

func TestSetupFileWatchNonexistentConfigPath(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()

	verif, err := verifier.New(cfg, metrics.New(), nil)
	if err != nil {
		t.Fatalf("creating verifier: %v", err)
	}

	// Passing a nonexistent config path causes watcher.Add to fail,
	// exercising the "Failed to watch config file" warning path.
	cleanup, _ := setupFileWatch(t.Context(), "/nonexistent/config.toml", "", verif)
	cleanup()
}

func TestSetupFileWatchPolicyDirWatchFailure(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	err := os.WriteFile(configPath, []byte("verification = \"disabled\"\n"), 0o600)
	if err != nil {
		t.Fatalf("writing config: %v", err)
	}

	cfg := config.DefaultConfig()

	verif, err := verifier.New(cfg, metrics.New(), nil)
	if err != nil {
		t.Fatalf("creating verifier: %v", err)
	}

	// Config path exists (watcher.Add succeeds), but policy dir does not,
	// exercising the "Failed to watch policy directory" warning path.
	cleanup, _ := setupFileWatch(t.Context(), configPath, "/nonexistent/policies", verif)
	cleanup()
}

// --- OCIFetcher rate-limit tests ---

func TestOCIFetcherWithRateLimit(t *testing.T) {
	t.Parallel()

	fetcher := attestation.NewOCIFetcher()
	fetcher.SetRateLimit(10.0)

	if fetcher == nil {
		t.Fatal("expected non-nil fetcher")
	}
}

// --- handleFileEvent tests ---

func TestHandleFileEventChmodIgnored(t *testing.T) {
	t.Parallel()

	event := fsnotify.Event{Name: testConfigFile, Op: fsnotify.Chmod}
	existingTimer := time.NewTimer(time.Hour)

	defer existingTimer.Stop()

	result := handleFileEvent(context.Background(), event, existingTimer, testConfigFile, nil, nil)

	if result != existingTimer {
		t.Error("expected chmod event to return same debounce timer unchanged")
	}
}

func TestHandleFileEventDebounceReplacement(t *testing.T) {
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

	// Create an existing debounce timer that should be stopped.
	oldTimer := time.NewTimer(time.Hour)
	defer oldTimer.Stop()

	event := fsnotify.Event{Name: configPath, Op: fsnotify.Write}
	newTimer := handleFileEvent(context.Background(), event, oldTimer, configPath, verif, nil)

	if newTimer == nil {
		t.Fatal("expected new timer, got nil")
	}

	if newTimer == oldTimer {
		t.Error("expected new timer to be different from old timer")
	}

	newTimer.Stop()
}

func TestHandleFileEventNilDebounce(t *testing.T) {
	t.Parallel()

	event := fsnotify.Event{Name: testConfigFile, Op: fsnotify.Write}
	result := handleFileEvent(context.Background(), event, nil, testConfigFile, nil, nil)

	if result == nil {
		t.Fatal("expected new timer, got nil")
	}

	result.Stop()
}

// --- runFileWatch tests ---

func TestRunFileWatchContextCancel(t *testing.T) {
	t.Parallel()

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatalf("creating watcher: %v", err)
	}

	defer func() { _ = watcher.Close() }()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	err = os.WriteFile(configPath, []byte("verification = \"disabled\"\n"), 0o600)
	if err != nil {
		t.Fatalf("writing config: %v", err)
	}

	err = watcher.Add(configPath)
	if err != nil {
		t.Fatalf("adding watch: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})

	go func() {
		runFileWatch(ctx, watcher, configPath, nil)
		close(done)
	}()

	// Write to trigger an event so a debounce timer exists, then cancel.
	err = os.WriteFile(configPath, []byte("verification = \"disabled\"\n# changed\n"), 0o600)
	if err != nil {
		t.Fatalf("writing config: %v", err)
	}

	// Give the event time to be received.
	time.Sleep(50 * time.Millisecond)

	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runFileWatch did not exit after context cancellation")
	}
}

func TestRunFileWatchChannelClosed(t *testing.T) {
	t.Parallel()

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatalf("creating watcher: %v", err)
	}

	done := make(chan struct{})

	go func() {
		runFileWatch(context.Background(), watcher, testConfigFile, nil)
		close(done)
	}()

	// Close the watcher to close channels, triggering the !ok return paths.
	err = watcher.Close()
	if err != nil {
		t.Fatalf("closing watcher: %v", err)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runFileWatch did not exit after watcher close")
	}
}

func TestRunFileWatchErrorChannel(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	err := os.WriteFile(configPath, []byte("verification = \"disabled\"\n"), 0o600)
	if err != nil {
		t.Fatalf("writing config: %v", err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatalf("creating watcher: %v", err)
	}

	err = watcher.Add(configPath)
	if err != nil {
		t.Fatalf("adding watch: %v", err)
	}

	ctx := t.Context()

	done := make(chan struct{})

	go func() {
		runFileWatch(ctx, watcher, configPath, nil)
		close(done)
	}()

	// Remove the watched file and then close the watcher to trigger error.
	err = os.Remove(configPath)
	if err != nil {
		t.Fatalf("removing config: %v", err)
	}

	// Give time for the remove event to be processed.
	time.Sleep(50 * time.Millisecond)

	// Close the watcher to end the loop.
	_ = watcher.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runFileWatch did not exit")
	}
}

// --- dynamic log level tests ---

//nolint:paralleltest // modifies package-level logLevelVar
func TestUpdateLogLevel(t *testing.T) {
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
			updateLogLevel(test.level)

			if logLevelVar.Level() != test.want {
				t.Errorf("expected level %v, got %v", test.want, logLevelVar.Level())
			}
		})
	}
}

//nolint:paralleltest // modifies package-level logLevelVar
func TestLogLevelDynamic(t *testing.T) {
	updateLogLevel(logLevelInfo)

	logger := newLogger()
	handler := logger.Handler()

	// Info should be enabled at info level.
	if !handler.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("expected info to be enabled at info level")
	}

	// Debug should be disabled at info level.
	if handler.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("expected debug to be disabled at info level")
	}

	// Change to debug level dynamically.
	updateLogLevel(logLevelDebug)

	// The same handler should now reflect the new level.
	if !handler.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("expected debug to be enabled after dynamic level change")
	}
}

//nolint:paralleltest // modifies package-level logLevelVar
func TestHandleReloadLogLevel(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	policyDir := filepath.Join(dir, "policies")

	err := os.Mkdir(policyDir, 0o750)
	if err != nil {
		t.Fatalf("creating policy dir: %v", err)
	}

	// Start with info level.
	updateLogLevel(logLevelInfo)

	// Write config with debug log level.
	data := "verification = \"warn\"\npolicy_dir = \"" + policyDir + "\"\nlog_level = \"debug\"\n"

	err = os.WriteFile(configPath, []byte(data), 0o600)
	if err != nil {
		t.Fatalf("writing config: %v", err)
	}

	cfg, err := config.LoadFromFile(configPath)
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}

	verif, err := verifier.New(cfg, metrics.New(), nil)
	if err != nil {
		t.Fatalf("creating verifier: %v", err)
	}

	handleReload(context.Background(), configPath, verif, nil)

	if logLevelVar.Level() != slog.LevelDebug {
		t.Errorf("expected log level DEBUG after reload, got %v", logLevelVar.Level())
	}
}

//nolint:paralleltest // modifies package-level logLevelVar
func TestHandleReloadNoLogLevel(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	policyDir := filepath.Join(dir, "policies")

	err := os.Mkdir(policyDir, 0o750)
	if err != nil {
		t.Fatalf("creating policy dir: %v", err)
	}

	// Set an explicit debug level.
	updateLogLevel(logLevelDebug)

	// Write config without log_level field.
	writeTestConfig(t, configPath, policyDir, "warn")

	cfg, err := config.LoadFromFile(configPath)
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}

	verif, err := verifier.New(cfg, metrics.New(), nil)
	if err != nil {
		t.Fatalf("creating verifier: %v", err)
	}

	handleReload(context.Background(), configPath, verif, nil)

	// Without log_level in config, the level should remain unchanged.
	if logLevelVar.Level() != slog.LevelDebug {
		t.Errorf("expected log level to remain DEBUG, got %v", logLevelVar.Level())
	}
}

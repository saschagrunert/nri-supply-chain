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
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/registry"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

const (
	testConfigFile     = "test.toml"
	testPrefixGHCR     = "ghcr.io"
	testMirrorInternal = "mirror.internal"
)

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

	met := metrics.New()

	verif, err := verifier.New(t.Context(), cfg, met, nil)
	if err != nil {
		t.Fatalf("creating verifier: %v", err)
	}

	if verif.Enforcing() {
		t.Fatal("expected warn mode initially")
	}

	ctx := t.Context()

	sigCh := make(chan os.Signal, 1)
	setupReload(ctx, configPath, verif, met, nil, sigCh, nil, &atomic.Value{}, &sync.Mutex{})

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
	met := metrics.New()

	verif, err := verifier.New(t.Context(), cfg, met, nil)
	if err != nil {
		t.Fatalf("creating verifier: %v", err)
	}

	ctx := t.Context()

	sigCh := make(chan os.Signal, 1)
	setupReload(ctx, "", verif, met, nil, sigCh, nil, &atomic.Value{}, &sync.Mutex{})

	sigCh <- syscall.SIGHUP

	time.Sleep(50 * time.Millisecond)

	if verif.Enforcing() {
		t.Fatal("expected warn mode to remain unchanged after no-op reload")
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

	met := metrics.New()

	verif, err := verifier.New(t.Context(), cfg, met, nil)
	if err != nil {
		t.Fatalf("creating verifier: %v", err)
	}

	if verif.Enforcing() {
		t.Fatal("expected warn mode initially")
	}

	ctx := t.Context()

	cleanup, _, _ := setupFileWatch(
		ctx, configPath, policyDir, "",
		config.OfflineModeDisabled, verif, met, nil,
		"", &sync.Mutex{},
	)
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
	met := metrics.New()

	verif, err := verifier.New(t.Context(), cfg, met, nil)
	if err != nil {
		t.Fatalf("creating verifier: %v", err)
	}

	cleanup, _, _ := setupFileWatch(
		t.Context(), "", "", "",
		config.OfflineModeDisabled, verif, met, nil,
		"", &sync.Mutex{},
	)
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
		{name: "rename", op: fsnotify.Rename, want: true},
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

func TestSetupSignals(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	met := metrics.New()

	verif, err := verifier.New(t.Context(), cfg, met, nil)
	if err != nil {
		t.Fatalf("creating verifier: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cleanup := setupSignals(ctx, cancel, "", verif, met, cfg, nil)
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

	met := metrics.New()

	verif, err := verifier.New(t.Context(), cfg, met, nil)
	if err != nil {
		t.Fatalf("creating verifier: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cleanup := setupSignals(ctx, cancel, configPath, verif, met, cfg, nil)
	cleanup()
}

func TestSetupFileWatchNonexistentConfigPath(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	met := metrics.New()

	verif, err := verifier.New(t.Context(), cfg, met, nil)
	if err != nil {
		t.Fatalf("creating verifier: %v", err)
	}

	cleanup, _, _ := setupFileWatch(
		t.Context(), "/nonexistent/config.toml", "", "",
		config.OfflineModeDisabled, verif, met, nil,
		"", &sync.Mutex{},
	)
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
	met := metrics.New()

	verif, err := verifier.New(t.Context(), cfg, met, nil)
	if err != nil {
		t.Fatalf("creating verifier: %v", err)
	}

	cleanup, _, _ := setupFileWatch(
		t.Context(), configPath, "/nonexistent/policies",
		"", config.OfflineModeDisabled, verif, met, nil,
		"", &sync.Mutex{},
	)
	cleanup()
}

func TestHandleFileEventChmodIgnored(t *testing.T) {
	t.Parallel()

	event := fsnotify.Event{Name: testConfigFile, Op: fsnotify.Chmod}
	existingTimer := time.NewTimer(time.Hour)

	defer existingTimer.Stop()

	cfgResult, feedResult := handleFileEvent(
		context.Background(),
		event,
		existingTimer,
		nil,
		testConfigFile,
		&atomic.Value{},
		nil,
		nil,
		nil,
		nil,
		&sync.Mutex{},
	)

	if cfgResult != existingTimer {
		t.Error("expected chmod event to return same debounce timer unchanged")
	}

	if feedResult != nil {
		t.Error("expected nil feed timer for chmod event")
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

	met := metrics.New()

	verif, err := verifier.New(t.Context(), cfg, met, nil)
	if err != nil {
		t.Fatalf("creating verifier: %v", err)
	}

	// Create an existing debounce timer that should be stopped.
	oldTimer := time.NewTimer(time.Hour)
	defer oldTimer.Stop()

	event := fsnotify.Event{Name: configPath, Op: fsnotify.Write}
	newTimer, _ := handleFileEvent(
		context.Background(),
		event,
		oldTimer,
		nil,
		configPath,
		&atomic.Value{},
		verif,
		met,
		nil,
		nil,
		&sync.Mutex{},
	)

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
	result, _ := handleFileEvent(
		context.Background(),
		event,
		nil,
		nil,
		testConfigFile,
		&atomic.Value{},
		nil,
		nil,
		nil,
		nil,
		&sync.Mutex{},
	)

	if result == nil {
		t.Fatal("expected new timer, got nil")
	}

	result.Stop()
}

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
		runFileWatch(ctx, watcher, configPath, &atomic.Value{}, nil, nil, nil, &sync.Mutex{})
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
		runFileWatch(
			context.Background(), watcher, testConfigFile, &atomic.Value{},
			nil, nil, nil, &sync.Mutex{},
		)
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
		runFileWatch(ctx, watcher, configPath, &atomic.Value{}, nil, nil, nil, &sync.Mutex{})
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

	met := metrics.New()

	verif, err := verifier.New(t.Context(), cfg, met, nil)
	if err != nil {
		t.Fatalf("creating verifier: %v", err)
	}

	handleReload(context.Background(), configPath, verif, met, nil, nil, &atomic.Value{})

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

	met := metrics.New()

	verif, err := verifier.New(t.Context(), cfg, met, nil)
	if err != nil {
		t.Fatalf("creating verifier: %v", err)
	}

	handleReload(context.Background(), configPath, verif, met, nil, nil, &atomic.Value{})

	// Without log_level in config, the level should remain unchanged.
	if logLevelVar.Level() != slog.LevelDebug {
		t.Errorf("expected log level to remain DEBUG, got %v", logLevelVar.Level())
	}
}

//nolint:paralleltest // modifies package-level logLevelVar
func TestHandleReloadUpdatesPluginRegistries(t *testing.T) {
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

	met := metrics.New()

	verif, err := verifier.New(t.Context(), cfg, met, nil)
	if err != nil {
		t.Fatalf("creating verifier: %v", err)
	}

	mock := &mockPluginReloader{
		cancelPrewarmCalled:          false,
		prewarmAfterReloadCalled:     false,
		transportCache:               nil,
		fetchTimeout:                 0,
		digestResolveTimeout:         0,
		remediationMode:              "",
		triggerReverifyCalled:        false,
		triggerFeedReverifyCalled:    false,
		triggerFeedReverifyLastPURLs: nil,
	}
	handleReload(context.Background(), configPath, verif, met, mock, nil, &atomic.Value{})

	if mock.transportCache != nil {
		t.Error("expected nil transport cache when no registries configured")
	}

	if mock.fetchTimeout != 30*time.Second {
		t.Errorf(
			"expected fetch timeout 30s, got %v",
			mock.fetchTimeout,
		)
	}

	if mock.digestResolveTimeout != 1*time.Second {
		t.Errorf(
			"expected digest resolve timeout 1s, got %v",
			mock.digestResolveTimeout,
		)
	}
}

//nolint:paralleltest // modifies package-level logLevelVar
func TestHandleReloadUpdatesPluginRegistriesNonEmpty(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	policyDir := filepath.Join(dir, "policies")

	err := os.Mkdir(policyDir, 0o750)
	if err != nil {
		t.Fatalf("creating policy dir: %v", err)
	}

	data := "verification = \"warn\"\npolicy_dir = \"" + policyDir + "\"\n" +
		"[[registries]]\nprefix = \"" + testPrefixGHCR + "\"\nmirror = \"" + testMirrorInternal + "\"\n"

	err = os.WriteFile(configPath, []byte(data), 0o600)
	if err != nil {
		t.Fatalf("writing config: %v", err)
	}

	cfg, err := config.LoadFromFile(configPath)
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}

	met := metrics.New()

	verif, err := verifier.New(t.Context(), cfg, met, nil)
	if err != nil {
		t.Fatalf("creating verifier: %v", err)
	}

	mock := &mockPluginReloader{ //nolint:exhaustruct_v5 // zero-value fields intentional
		transportCache: nil,
	}
	handleReload(context.Background(), configPath, verif, met, mock, nil, &atomic.Value{})

	if mock.transportCache == nil {
		t.Error("expected non-nil transport cache when registries configured")
	}
}

type mockPluginReloader struct {
	cancelPrewarmCalled          bool
	prewarmAfterReloadCalled     bool
	transportCache               *registry.TransportCache
	fetchTimeout                 time.Duration
	digestResolveTimeout         time.Duration
	remediationMode              config.RemediationMode
	triggerReverifyCalled        bool
	triggerFeedReverifyCalled    bool
	triggerFeedReverifyLastPURLs []string
}

func (m *mockPluginReloader) CancelPrewarm() {
	m.cancelPrewarmCalled = true
}

func (m *mockPluginReloader) PrewarmAfterReload(_ context.Context) {
	m.prewarmAfterReloadCalled = true
}

func (m *mockPluginReloader) SetFetchTimeout(d time.Duration) {
	m.fetchTimeout = d
}

func (m *mockPluginReloader) SetDigestResolveTimeout(d time.Duration) {
	m.digestResolveTimeout = d
}

func (m *mockPluginReloader) SetTransportCache(cache *registry.TransportCache) {
	m.transportCache = cache
}

func (m *mockPluginReloader) TransportCache() *registry.TransportCache {
	return m.transportCache
}

func (m *mockPluginReloader) SetRemediationMode(mode config.RemediationMode) {
	m.remediationMode = mode
}

func (m *mockPluginReloader) SetRemediationConfig(_ *config.RemediationConfig) {}

func (m *mockPluginReloader) TriggerReverify() {
	m.triggerReverifyCalled = true
}

func (m *mockPluginReloader) TriggerFeedReverify(purls []string) {
	m.triggerFeedReverifyCalled = true
	m.triggerFeedReverifyLastPURLs = purls
}

//nolint:paralleltest // mutates slog.SetDefault
func TestWarnNonReloadableChangesMetricsAddr(t *testing.T) {
	var buf bytes.Buffer

	prev := slog.Default()

	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	slog.SetDefault(slog.New(handler))

	t.Cleanup(func() { slog.SetDefault(prev) })

	current := config.DefaultConfig()
	proposed := config.DefaultConfig()
	proposed.MetricsAddr = "0.0.0.0:8080"

	warnNonReloadableChanges(current, proposed)

	output := buf.String()

	if !strings.Contains(output, "metrics_addr changed but requires restart") {
		t.Errorf("expected metrics_addr warning, got: %s", output)
	}
}

//nolint:paralleltest // mutates slog.SetDefault
func TestWarnNonReloadableChangesConfigVersion(t *testing.T) {
	var buf bytes.Buffer

	prev := slog.Default()

	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	slog.SetDefault(slog.New(handler))

	t.Cleanup(func() { slog.SetDefault(prev) })

	current := config.DefaultConfig()
	proposed := config.DefaultConfig()
	proposed.ConfigVersion = 2

	warnNonReloadableChanges(current, proposed)

	output := buf.String()

	if !strings.Contains(output, "config_version changed but requires restart") {
		t.Errorf("expected config_version warning, got: %s", output)
	}
}

//nolint:paralleltest // mutates slog.SetDefault
func TestWarnNonReloadableChangesNoWarningOnReloadableChange(t *testing.T) {
	var buf bytes.Buffer

	prev := slog.Default()

	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	slog.SetDefault(slog.New(handler))

	t.Cleanup(func() { slog.SetDefault(prev) })

	current := config.DefaultConfig()
	proposed := config.DefaultConfig()
	proposed.Verification = config.ModeEnforce

	warnNonReloadableChanges(current, proposed)

	output := buf.String()

	if strings.Contains(output, "requires restart") {
		t.Errorf("expected no non-reloadable warning for reloadable field change, got: %s", output)
	}
}

//nolint:paralleltest // mutates slog.SetDefault
func TestWarnNonReloadableChangesRemediationEnabled(t *testing.T) {
	var buf bytes.Buffer

	prev := slog.Default()

	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	slog.SetDefault(slog.New(handler))

	t.Cleanup(func() { slog.SetDefault(prev) })

	current := config.DefaultConfig()
	proposed := config.DefaultConfig()
	proposed.Remediation.Mode = config.RemediationModeWarn

	warnNonReloadableChanges(current, proposed)

	output := buf.String()

	if !strings.Contains(output, "remediation.mode enabled but requires restart") {
		t.Errorf("expected remediation enable warning, got: %s", output)
	}
}

func TestWarnNonReloadableChangesNilConfigs(t *testing.T) {
	t.Parallel()

	warnNonReloadableChanges(nil, config.DefaultConfig())
	warnNonReloadableChanges(config.DefaultConfig(), nil)
	warnNonReloadableChanges(nil, nil)
}

func TestUpdatePluginRegistries(t *testing.T) {
	t.Parallel()

	t.Run("non-empty registries sets cache", func(t *testing.T) {
		t.Parallel()

		mock := &mockPluginReloader{} //nolint:exhaustruct_v5 // zero-value fields intentional
		updatePluginRegistries(mock, []config.Registry{
			{
				Prefix: testPrefixGHCR, Mirror: testMirrorInternal,
				CACert: "", Insecure: false,
			},
		}, nil)

		if mock.transportCache == nil {
			t.Error("expected non-nil transport cache")
		}
	})

	t.Run("uses shared cache when provided", func(t *testing.T) {
		t.Parallel()

		shared := registry.NewTransportCache([]config.Registry{
			{
				Prefix: testPrefixGHCR, Mirror: testMirrorInternal,
				CACert: "", Insecure: false,
			},
		})
		mock := &mockPluginReloader{} //nolint:exhaustruct_v5 // zero-value fields intentional
		updatePluginRegistries(mock, shared.Registries(), shared)

		if mock.transportCache != shared {
			t.Error("expected plugin to use the shared transport cache")
		}
	})

	t.Run("clears cache when registries removed", func(t *testing.T) {
		t.Parallel()

		mock := &mockPluginReloader{ //nolint:exhaustruct_v5 // zero-value fields intentional
			transportCache: registry.NewTransportCache([]config.Registry{
				{
					Prefix: testPrefixGHCR, Mirror: testMirrorInternal,
					CACert: "", Insecure: false,
				},
			}),
		}
		updatePluginRegistries(mock, nil, nil)

		if mock.transportCache != nil {
			t.Error("expected nil transport cache after clearing registries")
		}
	})

	t.Run("ignores stale shared cache", func(t *testing.T) {
		t.Parallel()

		staleRegs := []config.Registry{
			{
				Prefix: "old.registry.io", Mirror: "",
				CACert: "", Insecure: false,
			},
		}
		staleShared := registry.NewTransportCache(staleRegs)
		newRegs := []config.Registry{
			{
				Prefix: "new.registry.io", Mirror: "",
				CACert: "", Insecure: false,
			},
		}
		mock := &mockPluginReloader{} //nolint:exhaustruct_v5 // zero-value fields intentional
		updatePluginRegistries(mock, newRegs, staleShared)

		if mock.transportCache == staleShared {
			t.Error("expected plugin to not use stale shared cache")
		}

		if mock.transportCache == nil {
			t.Fatal("expected a new transport cache to be created")
		}

		got := mock.transportCache.Registries()
		if len(got) != 1 || got[0].Prefix != "new.registry.io" {
			t.Errorf("expected new registries, got %v", got)
		}
	})

	t.Run("skips replacement when registries unchanged", func(t *testing.T) {
		t.Parallel()

		regs := []config.Registry{
			{
				Prefix: testPrefixGHCR, Mirror: testMirrorInternal,
				CACert: "", Insecure: false,
			},
		}
		original := registry.NewTransportCache(regs)
		mock := &mockPluginReloader{ //nolint:exhaustruct_v5 // zero-value fields intentional
			transportCache: original,
		}
		updatePluginRegistries(mock, regs, nil)

		if mock.transportCache != original {
			t.Error("expected transport cache to remain unchanged")
		}
	})
}

func TestUpdateWatchedPathsNilWatcher(t *testing.T) {
	t.Parallel()

	updateWatchedPaths(
		nil, "/some/config.toml", "/some/policies", "", config.OfflineModeDisabled, "", nil,
	)
}

func TestUpdateWatchedPathsSwapsDirectory(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	oldPolicyDir := filepath.Join(dir, "old-policies")
	newPolicyDir := filepath.Join(dir, "new-policies")

	err := os.Mkdir(oldPolicyDir, 0o750)
	if err != nil {
		t.Fatalf("creating dir: %v", err)
	}

	err = os.Mkdir(newPolicyDir, 0o750)
	if err != nil {
		t.Fatalf("creating dir: %v", err)
	}

	err = os.WriteFile(configPath, []byte("verification = \"disabled\"\n"), 0o600)
	if err != nil {
		t.Fatalf("writing config: %v", err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatalf("creating watcher: %v", err)
	}

	defer func() { _ = watcher.Close() }()

	err = watcher.Add(configPath)
	if err != nil {
		t.Fatalf("adding config watch: %v", err)
	}

	err = watcher.Add(oldPolicyDir)
	if err != nil {
		t.Fatalf("adding old policy dir watch: %v", err)
	}

	updateWatchedPaths(
		watcher, configPath, newPolicyDir, "", config.OfflineModeDisabled, "", &atomic.Value{},
	)

	watchList := watcher.WatchList()
	absNew, _ := filepath.Abs(newPolicyDir)

	if slices.Contains(watchList, oldPolicyDir) {
		t.Error("old policy directory should have been removed from watch list")
	}

	if !slices.Contains(watchList, absNew) {
		t.Errorf("new policy directory %s not found in watch list %v", absNew, watchList)
	}

	if !slices.Contains(watchList, configPath) {
		t.Error("config file should still be in watch list")
	}
}

func TestUpdateWatchedPathsEmptyNewDir(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	oldPolicyDir := filepath.Join(dir, "old-policies")

	err := os.Mkdir(oldPolicyDir, 0o750)
	if err != nil {
		t.Fatalf("creating dir: %v", err)
	}

	err = os.WriteFile(configPath, []byte("verification = \"disabled\"\n"), 0o600)
	if err != nil {
		t.Fatalf("writing config: %v", err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatalf("creating watcher: %v", err)
	}

	defer func() { _ = watcher.Close() }()

	err = watcher.Add(configPath)
	if err != nil {
		t.Fatalf("adding config watch: %v", err)
	}

	err = watcher.Add(oldPolicyDir)
	if err != nil {
		t.Fatalf("adding old policy dir watch: %v", err)
	}

	updateWatchedPaths(
		watcher, configPath, "", "", config.OfflineModeDisabled, "", &atomic.Value{},
	)

	if slices.Contains(watcher.WatchList(), oldPolicyDir) {
		t.Error("old policy directory should have been removed even with empty new policy dir")
	}
}

func TestUpdateWatchedPathsPreservesAttestationStore(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	policyDir := filepath.Join(dir, "policies")
	storeDir := filepath.Join(dir, "bundles")

	err := os.Mkdir(policyDir, 0o750)
	if err != nil {
		t.Fatalf("creating dir: %v", err)
	}

	err = os.Mkdir(storeDir, 0o750)
	if err != nil {
		t.Fatalf("creating dir: %v", err)
	}

	err = os.WriteFile(configPath, []byte("verification = \"disabled\"\n"), 0o600)
	if err != nil {
		t.Fatalf("writing config: %v", err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatalf("creating watcher: %v", err)
	}

	defer func() { _ = watcher.Close() }()

	for _, p := range []string{configPath, policyDir, storeDir} {
		addErr := watcher.Add(p)
		if addErr != nil {
			t.Fatalf("adding watch for %s: %v", p, addErr)
		}
	}

	updateWatchedPaths(
		watcher, configPath, policyDir, storeDir, config.OfflineModeOffline, "", nil,
	)

	absStore, _ := filepath.Abs(storeDir)
	if !slices.Contains(watcher.WatchList(), absStore) {
		t.Errorf("attestation store %s should be preserved in watch list %v",
			absStore, watcher.WatchList())
	}
}

func TestUpdateWatchedPathsRemovesStoreWhenDisabled(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	storeDir := filepath.Join(dir, "bundles")

	err := os.Mkdir(storeDir, 0o750)
	if err != nil {
		t.Fatalf("creating dir: %v", err)
	}

	err = os.WriteFile(configPath, []byte("verification = \"disabled\"\n"), 0o600)
	if err != nil {
		t.Fatalf("writing config: %v", err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatalf("creating watcher: %v", err)
	}

	defer func() { _ = watcher.Close() }()

	for _, p := range []string{configPath, storeDir} {
		addErr := watcher.Add(p)
		if addErr != nil {
			t.Fatalf("adding watch for %s: %v", p, addErr)
		}
	}

	updateWatchedPaths(
		watcher, configPath, "", storeDir, config.OfflineModeDisabled, "", nil,
	)

	absStore, _ := filepath.Abs(storeDir)
	if slices.Contains(watcher.WatchList(), absStore) {
		t.Error("attestation store should be removed when offline mode is disabled")
	}
}

func TestUpdateWatchedPathsPreservesFeedDir(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	policyDir := filepath.Join(dir, "policies")
	feedDir := filepath.Join(dir, "feeds")

	for _, d := range []string{policyDir, feedDir} {
		mkErr := os.Mkdir(d, 0o750)
		if mkErr != nil {
			t.Fatalf("creating dir: %v", mkErr)
		}
	}

	writeErr := os.WriteFile(
		configPath,
		[]byte("verification = \"disabled\"\n"),
		0o600,
	)
	if writeErr != nil {
		t.Fatalf("writing config: %v", writeErr)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatalf("creating watcher: %v", err)
	}

	defer func() { _ = watcher.Close() }()

	for _, p := range []string{configPath, policyDir, feedDir} {
		addErr := watcher.Add(p)
		if addErr != nil {
			t.Fatalf("adding watch %s: %v", p, addErr)
		}
	}

	updateWatchedPaths(
		watcher, configPath, policyDir, "", config.OfflineModeDisabled,
		feedDir, &atomic.Value{},
	)

	absFeed, _ := filepath.Abs(feedDir)
	if !slices.Contains(watcher.WatchList(), absFeed) {
		t.Errorf("feed directory %s should be preserved, watch list: %v",
			absFeed, watcher.WatchList())
	}
}

//nolint:paralleltest // mutates slog.SetDefault
func TestWarnNonReloadableChangesRemediationInterval(t *testing.T) {
	var buf bytes.Buffer

	prev := slog.Default()

	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	slog.SetDefault(slog.New(handler))

	t.Cleanup(func() { slog.SetDefault(prev) })

	current := config.DefaultConfig()
	current.Remediation.Mode = config.RemediationModeWarn
	current.Remediation.Interval = config.Duration{Duration: 30 * time.Second}

	proposed := config.DefaultConfig()
	proposed.Remediation.Mode = config.RemediationModeWarn
	proposed.Remediation.Interval = config.Duration{Duration: 60 * time.Second}

	warnNonReloadableChanges(current, proposed)

	output := buf.String()

	if !strings.Contains(output, "remediation.interval changed but requires restart") {
		t.Errorf("expected remediation.interval warning, got: %s", output)
	}
}

//nolint:paralleltest // mutates slog.SetDefault
func TestWarnNonReloadableChangesRemediationIntervalUnchanged(t *testing.T) {
	var buf bytes.Buffer

	prev := slog.Default()

	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	slog.SetDefault(slog.New(handler))

	t.Cleanup(func() { slog.SetDefault(prev) })

	current := config.DefaultConfig()
	current.Remediation.Mode = config.RemediationModeWarn
	current.Remediation.Interval = config.Duration{Duration: 30 * time.Second}

	proposed := config.DefaultConfig()
	proposed.Remediation.Mode = config.RemediationModeWarn
	proposed.Remediation.Interval = config.Duration{Duration: 30 * time.Second}

	warnNonReloadableChanges(current, proposed)

	output := buf.String()

	if strings.Contains(output, "remediation.interval") {
		t.Errorf("expected no interval warning for unchanged interval, got: %s", output)
	}
}

func TestHandleFeedEvent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	data := `{"id": "CVE-1", "affected": [{"package": {"purl": "pkg:golang/vuln@1.0"}}]}`

	err := os.WriteFile(filepath.Join(dir, "vuln.json"), []byte(data), 0o600)
	if err != nil {
		t.Fatalf("writing feed file: %v", err)
	}

	met := metrics.New()
	mock := &mockPluginReloader{} //nolint:exhaustruct_v5 // zero-value fields intentional

	handleFeedEvent(dir, met, mock)

	if !mock.triggerFeedReverifyCalled {
		t.Error("expected TriggerFeedReverify to be called")
	}

	if len(mock.triggerFeedReverifyLastPURLs) != 1 ||
		mock.triggerFeedReverifyLastPURLs[0] != "pkg:golang/vuln@1.0" {
		t.Errorf("expected [pkg:golang/vuln@1.0], got %v", mock.triggerFeedReverifyLastPURLs)
	}

	successCount := testutil.ToFloat64(
		met.FeedFilesProcessedTotal.WithLabelValues("success"),
	)

	if successCount != 1 {
		t.Errorf("expected 1 success metric, got %v", successCount)
	}
}

func TestHandleFeedEventNoPURLs(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	data := `{"id": "CVE-1", "affected": [{"package": {}}]}`

	err := os.WriteFile(filepath.Join(dir, "empty.json"), []byte(data), 0o600)
	if err != nil {
		t.Fatalf("writing feed file: %v", err)
	}

	met := metrics.New()
	mock := &mockPluginReloader{} //nolint:exhaustruct_v5 // zero-value fields intentional

	handleFeedEvent(dir, met, mock)

	if mock.triggerFeedReverifyCalled {
		t.Error("expected TriggerFeedReverify not to be called when no PURLs found")
	}
}

func TestHandleFeedEventNilPlugin(t *testing.T) {
	t.Parallel()

	handleFeedEvent(t.TempDir(), metrics.New(), nil)
}

func TestHandleFileEventFeedDebounce(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	feedDir := filepath.Join(dir, "feeds")

	err := os.Mkdir(feedDir, 0o750)
	if err != nil {
		t.Fatalf("creating feed dir: %v", err)
	}

	feedDirVal := &atomic.Value{}
	feedDirVal.Store(feedDir)

	event := fsnotify.Event{
		Name: filepath.Join(feedDir, "vuln.json"),
		Op:   fsnotify.Write,
	}

	cfgTimer, feedTimer := handleFileEvent(
		context.Background(),
		event,
		nil,
		nil,
		filepath.Join(dir, "config.toml"),
		feedDirVal,
		nil,
		nil,
		nil,
		nil,
		&sync.Mutex{},
	)

	if cfgTimer != nil {
		t.Error("expected nil config timer for feed event")
	}

	if feedTimer == nil {
		t.Fatal("expected non-nil feed timer")
	}

	feedTimer.Stop()
}

func TestHandleFileEventFeedDebounceReplacement(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	feedDir := filepath.Join(dir, "feeds")

	err := os.Mkdir(feedDir, 0o750)
	if err != nil {
		t.Fatalf("creating feed dir: %v", err)
	}

	feedDirVal := &atomic.Value{}
	feedDirVal.Store(feedDir)

	event := fsnotify.Event{
		Name: filepath.Join(feedDir, "vuln.json"),
		Op:   fsnotify.Create,
	}

	oldFeedTimer := time.NewTimer(time.Hour)
	defer oldFeedTimer.Stop()

	_, newFeedTimer := handleFileEvent(
		context.Background(),
		event,
		nil,
		oldFeedTimer,
		filepath.Join(dir, "config.toml"),
		feedDirVal,
		nil,
		nil,
		nil,
		nil,
		&sync.Mutex{},
	)

	if newFeedTimer == nil {
		t.Fatal("expected non-nil feed timer")
	}

	if newFeedTimer == oldFeedTimer {
		t.Error("expected new feed timer to replace old one")
	}

	newFeedTimer.Stop()
}

//nolint:paralleltest // modifies package-level logLevelVar
func TestHandleReloadPanicRecovery(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	// Write a valid config that passes LoadFromFile and ValidateRuntime.
	err := os.WriteFile(configPath, []byte("verification = \"disabled\"\n"), 0o600)
	if err != nil {
		t.Fatalf("writing config: %v", err)
	}

	met := metrics.New()

	errorsBefore := testutil.ToFloat64(met.ConfigReloadErrorsTotal)

	// Pass a nil verifier so that verif.Reload panics with a nil pointer dereference.
	// The deferred recover in handleReload should catch this.
	handleReload(context.Background(), configPath, nil, met, nil, nil, &atomic.Value{})

	errorsAfter := testutil.ToFloat64(met.ConfigReloadErrorsTotal)

	if errorsAfter != errorsBefore+1 {
		t.Errorf("expected config reload error counter to increment by 1, got delta %v",
			errorsAfter-errorsBefore)
	}
}

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
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

const testConfigFile = "test.toml"

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

	verif, err := verifier.New(cfg, met, nil)
	if err != nil {
		t.Fatalf("creating verifier: %v", err)
	}

	if verif.Enforcing() {
		t.Fatal("expected warn mode initially")
	}

	ctx := t.Context()

	sigCh := make(chan os.Signal, 1)
	setupReload(ctx, configPath, verif, met, sigCh, nil)

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

	verif, err := verifier.New(cfg, met, nil)
	if err != nil {
		t.Fatalf("creating verifier: %v", err)
	}

	ctx := t.Context()

	sigCh := make(chan os.Signal, 1)
	setupReload(ctx, "", verif, met, sigCh, nil)

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

	verif, err := verifier.New(cfg, met, nil)
	if err != nil {
		t.Fatalf("creating verifier: %v", err)
	}

	if verif.Enforcing() {
		t.Fatal("expected warn mode initially")
	}

	ctx := t.Context()

	cleanup, _ := setupFileWatch(ctx, configPath, policyDir, verif, met)
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

	verif, err := verifier.New(cfg, met, nil)
	if err != nil {
		t.Fatalf("creating verifier: %v", err)
	}

	cleanup, _ := setupFileWatch(t.Context(), "", "", verif, met)
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

func TestSetupSignals(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	met := metrics.New()

	verif, err := verifier.New(cfg, met, nil)
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

	verif, err := verifier.New(cfg, met, nil)
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

	verif, err := verifier.New(cfg, met, nil)
	if err != nil {
		t.Fatalf("creating verifier: %v", err)
	}

	cleanup, _ := setupFileWatch(t.Context(), "/nonexistent/config.toml", "", verif, met)
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

	verif, err := verifier.New(cfg, met, nil)
	if err != nil {
		t.Fatalf("creating verifier: %v", err)
	}

	cleanup, _ := setupFileWatch(t.Context(), configPath, "/nonexistent/policies", verif, met)
	cleanup()
}

func TestHandleFileEventChmodIgnored(t *testing.T) {
	t.Parallel()

	event := fsnotify.Event{Name: testConfigFile, Op: fsnotify.Chmod}
	existingTimer := time.NewTimer(time.Hour)

	defer existingTimer.Stop()

	result := handleFileEvent(
		context.Background(),
		event,
		existingTimer,
		testConfigFile,
		nil,
		nil,
		nil,
	)

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

	met := metrics.New()

	verif, err := verifier.New(cfg, met, nil)
	if err != nil {
		t.Fatalf("creating verifier: %v", err)
	}

	// Create an existing debounce timer that should be stopped.
	oldTimer := time.NewTimer(time.Hour)
	defer oldTimer.Stop()

	event := fsnotify.Event{Name: configPath, Op: fsnotify.Write}
	newTimer := handleFileEvent(context.Background(), event, oldTimer, configPath, verif, met, nil)

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
	result := handleFileEvent(context.Background(), event, nil, testConfigFile, nil, nil, nil)

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
		runFileWatch(ctx, watcher, configPath, nil, nil)
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
		runFileWatch(context.Background(), watcher, testConfigFile, nil, nil)
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
		runFileWatch(ctx, watcher, configPath, nil, nil)
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

	verif, err := verifier.New(cfg, met, nil)
	if err != nil {
		t.Fatalf("creating verifier: %v", err)
	}

	handleReload(context.Background(), configPath, verif, met, nil)

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

	verif, err := verifier.New(cfg, met, nil)
	if err != nil {
		t.Fatalf("creating verifier: %v", err)
	}

	handleReload(context.Background(), configPath, verif, met, nil)

	// Without log_level in config, the level should remain unchanged.
	if logLevelVar.Level() != slog.LevelDebug {
		t.Errorf("expected log level to remain DEBUG, got %v", logLevelVar.Level())
	}
}

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

package daemon //nolint:testpackage // tests use unexported daemon internals

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

type recordingStopper struct {
	ctx           context.Context //nolint:containedctx // records cancellation order in tests
	cancelledSeen atomic.Bool
	block         chan struct{}
}

func (s *recordingStopper) Stop() {
	s.cancelledSeen.Store(s.ctx.Err() != nil)

	if s.block != nil {
		<-s.block
	}
}

func TestShutdownCancelsBeforeStoppingVerifier(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	stopper := &recordingStopper{ctx: ctx} //nolint:exhaustruct_v5 // zero-value fields intentional

	var cleanedUp atomic.Bool

	shutdown(cancel, func() { cleanedUp.Store(true) }, stopper, time.Second)

	if !stopper.cancelledSeen.Load() {
		t.Error("expected the root context to be cancelled before verifier Stop")
	}

	if !cleanedUp.Load() {
		t.Error("expected signal cleanup to run")
	}
}

func TestShutdownBoundedByTimeout(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	stopper := &recordingStopper{ //nolint:exhaustruct_v5 // zero-value fields intentional
		ctx:   ctx,
		block: make(chan struct{}),
	}

	defer close(stopper.block)

	start := time.Now()

	shutdown(cancel, func() {}, stopper, 20*time.Millisecond)

	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("expected shutdown to give up after the timeout, took %v", elapsed)
	}
}

func newWatchTestVerifier(t *testing.T, configPath string) *verifier.Verifier {
	t.Helper()

	cfg, err := config.LoadFromFile(configPath)
	testutil.AssertNoError(t, err)

	verif, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)

	return verif
}

func waitForEnforcing(t *testing.T, verif *verifier.Verifier, want bool, step string) {
	t.Helper()

	deadline := time.After(5 * time.Second)

	for verif.Enforcing() != want {
		select {
		case <-deadline:
			t.Fatalf("%s: expected enforcing=%v", step, want)
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// TestFileWatchSurvivesAtomicRename replaces the config file with
// write-temp-and-rename several times. Watching the file itself lost the
// watch after the first rename.
func TestFileWatchSurvivesAtomicRename(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	policyDir := filepath.Join(dir, "policies")

	testutil.AssertNoError(t, os.Mkdir(policyDir, 0o750))
	writeTestConfig(t, configPath, policyDir, string(config.ModeWarn))

	verif := newWatchTestVerifier(t, configPath)

	cleanup, _, _ := setupFileWatch(
		t.Context(), configPath, policyDir, "",
		config.OfflineModeDisabled, verif, metrics.New(), nil,
		"", &sync.Mutex{},
	)
	defer cleanup()

	enforce, warn := string(config.ModeEnforce), string(config.ModeWarn)
	modes := []string{enforce, warn, enforce, warn}

	for idx, mode := range modes {
		tmpPath := filepath.Join(dir, fmt.Sprintf(".config.toml.tmp%d", idx))
		writeTestConfig(t, tmpPath, policyDir, mode)
		testutil.AssertNoError(t, os.Rename(tmpPath, configPath))

		waitForEnforcing(t, verif, mode == enforce, fmt.Sprintf("rename %d", idx))
	}
}

// TestFileWatchConfigMapSymlinkSwap mirrors a kubelet ConfigMap update:
// config.toml -> ..data/config.toml and "..data" is atomically re-pointed at
// a new timestamped directory.
func TestFileWatchConfigMapSymlinkSwap(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	mount := filepath.Join(root, "config")
	policyDir := filepath.Join(root, "policies")

	testutil.AssertNoError(t, os.Mkdir(mount, 0o750))
	testutil.AssertNoError(t, os.Mkdir(policyDir, 0o750))

	writeVersion := func(name, mode string) {
		versioned := filepath.Join(mount, name)
		testutil.AssertNoError(t, os.Mkdir(versioned, 0o750))
		writeTestConfig(t, filepath.Join(versioned, "config.toml"), policyDir, mode)
	}

	writeVersion("..v1", string(config.ModeWarn))
	testutil.AssertNoError(t, os.Symlink("..v1", filepath.Join(mount, configMapDataDir)))
	testutil.AssertNoError(t, os.Symlink(
		configMapDataDir+"/config.toml", filepath.Join(mount, "config.toml"),
	))

	configPath := filepath.Join(mount, "config.toml")
	verif := newWatchTestVerifier(t, configPath)

	cleanup, _, _ := setupFileWatch(
		t.Context(), configPath, policyDir, "",
		config.OfflineModeDisabled, verif, metrics.New(), nil,
		"", &sync.Mutex{},
	)
	defer cleanup()

	for idx, mode := range []string{string(config.ModeEnforce), string(config.ModeWarn)} {
		version := fmt.Sprintf("..v%d", idx+2)
		writeVersion(version, mode)

		tmpLink := filepath.Join(mount, "..data_tmp")
		testutil.AssertNoError(t, os.Symlink(version, tmpLink))
		testutil.AssertNoError(t, os.Rename(tmpLink, filepath.Join(mount, configMapDataDir)))

		waitForEnforcing(t, verif, mode == string(config.ModeEnforce), "swap "+version)
	}
}

func TestIsConfigDirNoise(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	policyDir := filepath.Join(dir, "policies")

	testutil.AssertNoError(t, os.Mkdir(policyDir, 0o750))
	writeTestConfig(t, configPath, policyDir, string(config.ModeWarn))

	verif := newWatchTestVerifier(t, configPath)

	tests := []struct {
		name  string
		event string
		want  bool
	}{
		{name: "config file", event: configPath, want: false},
		{name: "configmap data swap", event: filepath.Join(dir, configMapDataDir), want: false},
		{name: "editor swap file", event: filepath.Join(dir, ".config.toml.swp"), want: true},
		{name: "unrelated file", event: filepath.Join(dir, "notes.txt"), want: true},
		{name: "policy file", event: filepath.Join(policyDir, "default.json"), want: false},
		{name: "policy directory replaced", event: policyDir, want: false},
		{name: "staged policy directory", event: filepath.Join(dir, "policies.new"), want: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			event := fsnotify.Event{Name: tc.event, Op: fsnotify.Create}
			if got := isConfigDirNoise(event, configPath, verif); got != tc.want {
				t.Errorf("expected %v, got %v", tc.want, got)
			}
		})
	}
}

func TestIsConfigDirNoisePolicyDirIsConfigDir(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")

	writeTestConfig(t, configPath, dir, string(config.ModeWarn))

	verif := newWatchTestVerifier(t, configPath)
	event := fsnotify.Event{Name: filepath.Join(dir, "default.json"), Op: fsnotify.Write}

	if isConfigDirNoise(event, configPath, verif) {
		t.Error("expected policy changes in a shared config directory to trigger a reload")
	}
}

//nolint:paralleltest // mutates slog.SetDefault
func TestHandleFileEventIgnoresLogInConfigDir(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	policyDir := filepath.Join(dir, "policies")
	logPath := filepath.Join(dir, "plugin.log")

	testutil.AssertNoError(t, os.Mkdir(policyDir, 0o750))
	writeTestConfig(t, configPath, policyDir, string(config.ModeWarn))

	verif := newWatchTestVerifier(t, configPath)

	var buf bytes.Buffer

	previous := slog.Default()

	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	slog.SetDefault(slog.New(handler))
	t.Cleanup(func() { slog.SetDefault(previous) })

	event := fsnotify.Event{Name: logPath, Op: fsnotify.Write}

	cfgTimer, feedTimer := handleFileEvent(
		t.Context(), event, nil, nil, configPath, &atomic.Value{},
		verif, nil, nil, nil, &sync.Mutex{},
	)

	if cfgTimer != nil || feedTimer != nil {
		t.Error("expected a log file write next to the config file to be ignored")
	}

	// Logging the event would write to the log file and trigger the watcher
	// again, in an endless loop.
	if strings.Contains(buf.String(), logPath) {
		t.Errorf("expected no log output for the ignored event, got %q", buf.String())
	}
}

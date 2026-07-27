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
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

const (
	fileWatchDebounce = 500 * time.Millisecond
	panicExitCode     = 2
)

func setupSignals(
	ctx context.Context, cancel context.CancelFunc,
	configPath string, verif *verifier.Verifier,
	met *metrics.Metrics, cfg *config.Config,
	plug prewarmCanceller,
) func() {
	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)

	sigterm := make(chan os.Signal, 1)
	signal.Notify(sigterm, syscall.SIGINT, syscall.SIGTERM)

	done := make(chan struct{})

	cleanupWatch, watcher := setupFileWatch(ctx, configPath, cfg.PolicyDir, verif, met)
	setupReload(ctx, configPath, verif, met, sighup, watcher)
	handleShutdown(ctx, cancel, sigterm, done)

	return func() {
		signal.Stop(sighup)
		signal.Stop(sigterm)

		if plug != nil {
			plug.CancelPrewarm()
		}

		close(done)
		cleanupWatch()
	}
}

type prewarmCanceller interface {
	CancelPrewarm()
}

func setupReload(
	ctx context.Context, configPath string, verif *verifier.Verifier,
	met *metrics.Metrics, sigCh <-chan os.Signal, watcher *fsnotify.Watcher,
) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-sigCh:
			}

			handleReload(ctx, configPath, verif, met, watcher)
		}
	}()
}

func handleReload(
	ctx context.Context, configPath string,
	verif *verifier.Verifier, met *metrics.Metrics,
	watcher *fsnotify.Watcher,
) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("Recovered panic in reload handler",
				"error", r,
				"stack", string(debug.Stack()),
			)
			met.ConfigReloadErrorsTotal.Inc()
		}
	}()

	slog.Info("Reloading config")

	if configPath == "" {
		slog.Warn("No config file specified, skipping reload")

		return
	}

	newCfg, err := config.LoadFromFile(configPath)
	if err != nil {
		met.ConfigReloadErrorsTotal.Inc()
		slog.Error("Config reload failed", "error", err)

		return
	}

	if newCfg.Enabled() {
		err = newCfg.ValidateRuntime()
		if err != nil {
			met.ConfigReloadErrorsTotal.Inc()
			slog.Error("Config reload validation failed", "error", err)

			return
		}
	}

	if newCfg.LogLevel != "" {
		if parsed := parseLogLevel(newCfg.LogLevel); parsed != nil {
			current := logLevelVar.Level()

			if current != *parsed {
				logLevelVar.Set(*parsed)
				slog.Info("Log level changed", "from", current, "to", *parsed)
			}
		}
	}

	reloadErr := verif.Reload(ctx, newCfg)
	if reloadErr != nil {
		met.ConfigReloadErrorsTotal.Inc()
		slog.Error("Verifier reload failed", "error", reloadErr)
	} else {
		met.ConfigReloadsTotal.Inc()
		slog.Info("Config reloaded successfully")
		updatePolicyDirWatch(watcher, configPath, newCfg.PolicyDir)
	}
}

func updatePolicyDirWatch(watcher *fsnotify.Watcher, configPath, newPolicyDir string) {
	if watcher == nil {
		return
	}

	newAbsDir := ""

	if newPolicyDir != "" {
		abs, absErr := filepath.Abs(newPolicyDir)
		if absErr == nil {
			newAbsDir = abs
		}
	}

	// Remove any watched path that is not the config file or the new policy directory.
	for _, watched := range watcher.WatchList() {
		if watched == configPath || watched == newAbsDir {
			continue
		}

		removeErr := watcher.Remove(watched)
		if removeErr != nil {
			slog.Warn("Failed to unwatch old policy directory",
				"path", watched, "error", removeErr)
		} else {
			slog.Info("Removed old policy directory from file watcher",
				"path", watched)
		}
	}

	if newAbsDir == "" {
		return
	}

	// watcher.Add is a no-op for already-watched paths.
	addErr := watcher.Add(newAbsDir)
	if addErr != nil {
		slog.Warn("Failed to watch new policy directory",
			"path", newAbsDir, "error", addErr)
	} else {
		slog.Info("Added new policy directory to file watcher",
			"path", newAbsDir)
	}
}

func setupFileWatch(
	ctx context.Context, configPath, policyDir string,
	verif *verifier.Verifier, met *metrics.Metrics,
) (func(), *fsnotify.Watcher) {
	if configPath == "" {
		return func() {}, nil
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		slog.Warn("Failed to create file watcher, relying on SIGHUP", "error", err)

		return func() {}, nil
	}

	watchErr := watcher.Add(configPath)
	if watchErr != nil {
		slog.Warn("Failed to watch config file", "path", configPath, "error", watchErr)
	}

	if policyDir != "" {
		absDir, absErr := filepath.Abs(policyDir)
		if absErr == nil {
			watchErr = watcher.Add(absDir)
			if watchErr != nil {
				slog.Warn("Failed to watch policy directory",
					"path", absDir,
					"error", watchErr,
				)
			}
		}
	}

	go runFileWatch(ctx, watcher, configPath, verif, met)

	return func() {
		closeErr := watcher.Close()
		if closeErr != nil {
			slog.Warn("Failed to close file watcher", "error", closeErr)
		}
	}, watcher
}

func runFileWatch(
	ctx context.Context, watcher *fsnotify.Watcher,
	configPath string, verif *verifier.Verifier,
	met *metrics.Metrics,
) {
	var debounce *time.Timer

	for {
		select {
		case <-ctx.Done():
			if debounce != nil {
				debounce.Stop()
			}

			return

		case event, ok := <-watcher.Events:
			if !ok {
				slog.Warn("File watcher events channel closed")

				return
			}

			debounce = handleFileEvent(ctx, event, debounce, configPath, verif, met, watcher)

		case watchErr, ok := <-watcher.Errors:
			if !ok {
				slog.Warn("File watcher errors channel closed")

				return
			}

			slog.Warn("File watcher error", "error", watchErr)
		}
	}
}

func handleFileEvent(
	ctx context.Context, event fsnotify.Event,
	debounce *time.Timer, configPath string,
	verif *verifier.Verifier, met *metrics.Metrics,
	watcher *fsnotify.Watcher,
) *time.Timer {
	if !isReloadEvent(event) {
		return debounce
	}

	slog.Debug("File change detected", "file", event.Name, "op", event.Op)

	if debounce != nil {
		debounce.Stop()
	}

	return time.AfterFunc(fileWatchDebounce, func() {
		if ctx.Err() != nil {
			return
		}

		handleReload(ctx, configPath, verif, met, watcher)
	})
}

func isReloadEvent(event fsnotify.Event) bool {
	return event.Has(fsnotify.Write) ||
		event.Has(fsnotify.Create) ||
		event.Has(fsnotify.Remove)
}

func handleShutdown(
	ctx context.Context, cancel context.CancelFunc,
	sigCh <-chan os.Signal, done <-chan struct{},
) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("Recovered panic in shutdown handler", "error", r)
				os.Exit(panicExitCode)
			}
		}()

		select {
		case <-ctx.Done():
			return
		case <-sigCh:
		}

		slog.Info("Shutting down")
		cancel()

		select {
		case <-done:
		case <-sigCh:
			slog.Warn("Received second signal, forcing exit")
			os.Exit(1)
		}
	}()
}

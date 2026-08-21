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
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/feed"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/registry"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

const fileWatchDebounce = 500 * time.Millisecond

func setupSignals(
	ctx context.Context, cancel context.CancelFunc,
	configPath string, verif *verifier.Verifier,
	met *metrics.Metrics, cfg *config.Config,
	plug pluginReloader,
) func() {
	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)

	sigterm := make(chan os.Signal, 1)
	signal.Notify(sigterm, syscall.SIGINT, syscall.SIGTERM)

	done := make(chan struct{})

	var reloadMu sync.Mutex

	cleanupWatch, watcher, feedDirVal := setupFileWatch(
		ctx, configPath, cfg.PolicyDir, cfg.Offline.AttestationStore,
		cfg.Offline.Mode, verif, met, plug,
		cfg.Remediation.FeedDir, &reloadMu,
	)
	setupReload(ctx, configPath, verif, met, plug, sighup, watcher, feedDirVal, &reloadMu)
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

type pluginReloader interface {
	CancelPrewarm()
	PrewarmAfterReload(ctx context.Context)
	SetFetchTimeout(d time.Duration)
	SetDigestResolveTimeout(d time.Duration)
	SetTransportCache(tc *registry.TransportCache)
	TransportCache() *registry.TransportCache
	SetRemediationMode(mode config.RemediationMode)
	SetRemediationConfig(cfg *config.RemediationConfig)
	TriggerReverify()
	TriggerFeedReverify(purls []string)
}

func setupReload(
	ctx context.Context, configPath string, verif *verifier.Verifier,
	met *metrics.Metrics, plug pluginReloader,
	sigCh <-chan os.Signal, watcher *fsnotify.Watcher,
	feedDirVal *atomic.Value, reloadMu *sync.Mutex,
) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-sigCh:
			}

			reloadMu.Lock()
			handleReload(ctx, configPath, verif, met, plug, watcher, feedDirVal)
			reloadMu.Unlock()
		}
	}()
}

func handleReload( //nolint:funlen // sequential reload steps
	ctx context.Context, configPath string,
	verif *verifier.Verifier, met *metrics.Metrics,
	plug pluginReloader, watcher *fsnotify.Watcher,
	feedDirVal *atomic.Value,
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

	if !shouldUseConfigFile(configPath) {
		slog.Warn("No config file specified, skipping reload")

		return
	}

	newCfg, err := config.LoadFromFile(configPath)
	if err != nil {
		met.ConfigReloadErrorsTotal.Inc()
		slog.Error("Config reload failed", "error", err)

		return
	}

	err = newCfg.ValidateRuntime()
	if err != nil {
		met.ConfigReloadErrorsTotal.Inc()
		slog.Error("Config reload validation failed", "error", err)

		return
	}

	applyLogLevel(newCfg.LogLevel)
	newCfg.WarnInsecureRegistries()
	warnNonReloadableChanges(verif.CurrentConfig(), newCfg)

	reloadErr := verif.Reload(ctx, newCfg)
	if reloadErr != nil {
		met.ConfigReloadErrorsTotal.Inc()
		slog.Error("Verifier reload failed", "error", reloadErr)
	} else {
		met.ConfigReloadsTotal.Inc()
		slog.Info("Config reloaded successfully")
		updateWatchedPaths(watcher, configPath, newCfg.PolicyDir,
			newCfg.Offline.AttestationStore, newCfg.Offline.Mode,
			newCfg.Remediation.FeedDir, feedDirVal,
		)

		if plug != nil {
			plug.SetFetchTimeout(newCfg.FetchTimeout.Duration)
			plug.SetDigestResolveTimeout(newCfg.DigestResolveTimeout.Duration)
			updatePluginRegistries(plug, newCfg.Registries, verif.TransportCache())
			plug.SetRemediationMode(newCfg.Remediation.Mode)
			plug.SetRemediationConfig(&newCfg.Remediation)
			warnEvictDeferred(newCfg.Remediation.Mode)
			plug.PrewarmAfterReload(ctx)

			if newCfg.Remediation.Enabled() && newCfg.Remediation.Triggers.OnPolicyChange {
				plug.TriggerReverify()
			}
		}
	}
}

func warnNonReloadableChanges(current, proposed *config.Config) {
	if current == nil || proposed == nil {
		return
	}

	if current.MetricsAddr != proposed.MetricsAddr {
		slog.Warn("metrics_addr changed but requires restart to take effect",
			"current", current.MetricsAddr,
			"proposed", proposed.MetricsAddr,
		)
	}

	if current.ConfigVersion != proposed.ConfigVersion {
		slog.Warn("config_version changed but requires restart to take effect",
			"current", current.ConfigVersion,
			"proposed", proposed.ConfigVersion,
		)
	}

	if !current.Remediation.Enabled() && proposed.Remediation.Enabled() {
		slog.Warn("remediation.mode enabled but requires restart to take effect; "+
			"the continuous verifier goroutine is only started at startup",
			"proposed_mode", proposed.Remediation.Mode,
		)
	}

	if current.Remediation.Enabled() && proposed.Remediation.Enabled() &&
		current.Remediation.Interval != proposed.Remediation.Interval {
		slog.Warn("remediation.interval changed but requires restart to take effect",
			"current", current.Remediation.Interval.Duration,
			"proposed", proposed.Remediation.Interval.Duration,
		)
	}
}

func applyLogLevel(level string) {
	if level == "" {
		return
	}

	parsed := parseLogLevel(level)
	if parsed == nil {
		return
	}

	current := logLevelVar.Level()
	if current != *parsed {
		logLevelVar.Set(*parsed)
		slog.Info("Log level changed", "from", current, "to", *parsed)
	}
}

func updatePluginRegistries(
	plug pluginReloader, registries []config.Registry, shared *registry.TransportCache,
) {
	var oldRegistries []config.Registry

	if cache := plug.TransportCache(); cache != nil {
		oldRegistries = cache.Registries()
	}

	if !config.RegistriesChanged(oldRegistries, registries) {
		return
	}

	if shared != nil && !config.RegistriesChanged(shared.Registries(), registries) {
		plug.SetTransportCache(shared)
	} else {
		plug.SetTransportCache(registry.NewTransportCacheOrNil(registries))
	}
}

func updateWatchedPaths( //nolint:cyclop // sequential path management with feedDirVal update
	watcher *fsnotify.Watcher, configPath, newPolicyDir,
	attestationStore string, offlineMode config.OfflineMode,
	feedDir string, feedDirVal *atomic.Value,
) {
	if watcher == nil {
		return
	}

	keep := buildWatchSet(configPath, newPolicyDir, attestationStore, offlineMode, feedDir)

	if feedDirVal != nil {
		absFeedDir := ""

		if feedDir != "" {
			abs, absErr := filepath.Abs(feedDir)
			if absErr == nil {
				absFeedDir = abs
			}
		}

		feedDirVal.Store(absFeedDir)
	}

	for _, watched := range watcher.WatchList() {
		if keep[watched] {
			continue
		}

		removeErr := watcher.Remove(watched)
		if removeErr != nil {
			slog.Warn("Failed to unwatch old path",
				"path", watched, "error", removeErr)
		} else {
			slog.Info("Removed old path from file watcher",
				"path", watched)
		}
	}

	for path := range keep {
		if path == configPath {
			continue
		}

		addErr := watcher.Add(path)
		if addErr != nil {
			slog.Warn("Failed to watch path",
				"path", path, "error", addErr)
		}
	}
}

func buildWatchSet(
	configPath, policyDir, attestationStore string,
	offlineMode config.OfflineMode, feedDir string,
) map[string]bool {
	keep := map[string]bool{configPath: true}

	abs, err := filepath.Abs(policyDir)
	if policyDir != "" && err == nil {
		keep[abs] = true
	}

	abs, err = filepath.Abs(attestationStore)
	if offlineMode != config.OfflineModeDisabled && attestationStore != "" && err == nil {
		keep[abs] = true
	}

	abs, err = filepath.Abs(feedDir)
	if feedDir != "" && err == nil {
		keep[abs] = true
	}

	return keep
}

func setupFileWatch(
	ctx context.Context, configPath, policyDir, attestationStore string,
	offlineMode config.OfflineMode,
	verif *verifier.Verifier, met *metrics.Metrics,
	plug pluginReloader, feedDir string, reloadMu *sync.Mutex,
) (cleanup func(), watcher *fsnotify.Watcher, feedDirVal *atomic.Value) {
	feedDirVal = &atomic.Value{}

	if !shouldUseConfigFile(configPath) {
		return func() {}, nil, feedDirVal
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		slog.Warn("Failed to create file watcher, relying on SIGHUP", "error", err)

		return func() {}, nil, feedDirVal
	}

	addWatchPath(watcher, configPath, "config file")

	if policyDir != "" {
		addWatchPath(watcher, policyDir, "policy directory")
	}

	if offlineMode != config.OfflineModeDisabled && attestationStore != "" {
		addWatchPath(watcher, attestationStore, "attestation store")
	}

	absFeedDir := ""

	if feedDir != "" {
		abs, absErr := filepath.Abs(feedDir)
		if absErr == nil {
			absFeedDir = abs

			watchErr := watcher.Add(absFeedDir)
			if watchErr != nil {
				slog.Warn("Failed to watch feed directory",
					"path", absFeedDir,
					"error", watchErr,
				)

				absFeedDir = ""
			}
		}
	}

	feedDirVal.Store(absFeedDir)

	go runFileWatch(ctx, watcher, configPath, feedDirVal, verif, met, plug, reloadMu)

	return func() {
		closeErr := watcher.Close()
		if closeErr != nil {
			slog.Warn("Failed to close file watcher", "error", closeErr)
		}
	}, watcher, feedDirVal
}

func addWatchPath(watcher *fsnotify.Watcher, path, label string) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		slog.Warn("Failed to resolve absolute path for watch",
			"path", path, "label", label, "error", err)

		return
	}

	watchErr := watcher.Add(absPath)
	if watchErr != nil {
		slog.Warn("Failed to watch "+label, "path", absPath, "error", watchErr)
	}
}

func runFileWatch(
	ctx context.Context, watcher *fsnotify.Watcher,
	configPath string, feedDirVal *atomic.Value, verif *verifier.Verifier,
	met *metrics.Metrics, plug pluginReloader, reloadMu *sync.Mutex,
) {
	var configDebounce, feedDebounce *time.Timer

	for {
		select {
		case <-ctx.Done():
			if configDebounce != nil {
				configDebounce.Stop()
			}

			if feedDebounce != nil {
				feedDebounce.Stop()
			}

			return

		case event, ok := <-watcher.Events:
			if !ok {
				slog.Warn("File watcher events channel closed")

				return
			}

			configDebounce, feedDebounce = handleFileEvent(
				ctx, event, configDebounce, feedDebounce,
				configPath, feedDirVal, verif, met, plug, watcher, reloadMu,
			)

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
	configDebounce, feedDebounce *time.Timer,
	configPath string, feedDirVal *atomic.Value,
	verif *verifier.Verifier, met *metrics.Metrics,
	plug pluginReloader, watcher *fsnotify.Watcher,
	reloadMu *sync.Mutex,
) (newConfigDebounce, newFeedDebounce *time.Timer) {
	if !isReloadEvent(event) {
		return configDebounce, feedDebounce
	}

	slog.Debug("File change detected", "file", event.Name, "op", event.Op)

	feedDir, _ := feedDirVal.Load().(string)

	if feedDir != "" && strings.HasPrefix(event.Name, feedDir+"/") {
		if feedDebounce != nil {
			feedDebounce.Stop()
		}

		feedDebounce = time.AfterFunc(fileWatchDebounce, func() {
			if ctx.Err() != nil {
				return
			}

			currentFeedDir, _ := feedDirVal.Load().(string)
			if currentFeedDir != "" {
				handleFeedEvent(currentFeedDir, met, plug)
			}
		})

		return configDebounce, feedDebounce
	}

	if configDebounce != nil {
		configDebounce.Stop()
	}

	configDebounce = time.AfterFunc(fileWatchDebounce, func() {
		if ctx.Err() != nil {
			return
		}

		reloadMu.Lock()
		handleReload(ctx, configPath, verif, met, plug, watcher, feedDirVal)
		reloadMu.Unlock()
	})

	return configDebounce, feedDebounce
}

func handleFeedEvent(feedDir string, met *metrics.Metrics, plug pluginReloader) {
	if plug == nil {
		return
	}

	purls, successCount, errorCount := feed.ParseDir(feedDir)

	met.FeedFilesProcessedTotal.WithLabelValues("success").Add(float64(successCount))
	met.FeedFilesProcessedTotal.WithLabelValues("error").Add(float64(errorCount))

	if len(purls) > 0 {
		slog.Info("Feed directory updated",
			"purls", len(purls),
			"files_ok", successCount,
			"files_err", errorCount,
		)

		plug.TriggerFeedReverify(purls)
	}
}

func isReloadEvent(event fsnotify.Event) bool {
	return event.Has(fsnotify.Write) ||
		event.Has(fsnotify.Create) ||
		event.Has(fsnotify.Remove) ||
		event.Has(fsnotify.Rename)
}

func handleShutdown(
	ctx context.Context, cancel context.CancelFunc,
	sigCh <-chan os.Signal, done <-chan struct{},
) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("Recovered panic in shutdown handler", "error", r)
				os.Exit(exitError)
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
			os.Exit(exitError)
		}
	}()
}

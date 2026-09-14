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

const (
	fileWatchDebounce = 500 * time.Millisecond

	// configMapDataDir is the symlink Kubernetes atomically swaps when a
	// ConfigMap or Secret volume is updated. Its rename is the only event in
	// the mount directory when a projected key changes.
	configMapDataDir = "..data"
)

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

func handleReload(
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
			applyPluginSettings(ctx, newCfg, verif, plug)
		}
	}
}

// applyPluginSettings applies the plugin-side settings of a reloaded
// configuration (a config file reload or a configuration passed by the
// runtime) after the verifier has been reloaded.
func applyPluginSettings(
	ctx context.Context, cfg *config.Config, verif *verifier.Verifier, plug pluginReloader,
) {
	plug.SetFetchTimeout(cfg.FetchTimeout.Duration)
	plug.SetDigestResolveTimeout(cfg.DigestResolveTimeout.Duration)
	updatePluginRegistries(plug, cfg.Registries, verif.TransportCache())
	plug.SetRemediationMode(cfg.Remediation.Mode)
	plug.SetRemediationConfig(&cfg.Remediation)
	warnEvictDeferred(cfg.Remediation.Mode)
	plug.PrewarmAfterReload(ctx)

	if cfg.Remediation.Enabled() && cfg.Remediation.Triggers.OnPolicyChange {
		plug.TriggerReverify()
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

func updateWatchedPaths(
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
	keep := map[string]bool{}

	if dir := configWatchDir(configPath); dir != "" {
		keep[dir] = true
	}

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

	// Watch the directory rather than the file: editors and config
	// management replace files with a rename, and Kubernetes swaps the
	// "..data" symlink, both of which drop an inotify watch on the file.
	if dir := configWatchDir(configPath); dir != "" {
		addWatchPath(watcher, dir, "config directory")
	}

	if policyDir != "" {
		addWatchPath(watcher, policyDir, "policy directory")
	}

	if offlineMode != config.OfflineModeDisabled && attestationStore != "" {
		addWatchPath(watcher, attestationStore, "attestation store")
	}

	feedDirVal.Store(addFeedDirWatch(watcher, feedDir))

	go runFileWatch(ctx, watcher, configPath, feedDirVal, verif, met, plug, reloadMu)

	return func() {
		closeErr := watcher.Close()
		if closeErr != nil {
			slog.Warn("Failed to close file watcher", "error", closeErr)
		}
	}, watcher, feedDirVal
}

// addFeedDirWatch watches the feed directory and returns its absolute path,
// or an empty string if it is unset or cannot be watched.
func addFeedDirWatch(watcher *fsnotify.Watcher, feedDir string) string {
	if feedDir == "" {
		return ""
	}

	absFeedDir, err := filepath.Abs(feedDir)
	if err != nil {
		return ""
	}

	watchErr := watcher.Add(absFeedDir)
	if watchErr != nil {
		slog.Warn("Failed to watch feed directory",
			"path", absFeedDir,
			"error", watchErr,
		)

		return ""
	}

	return absFeedDir
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

	feedDir, _ := feedDirVal.Load().(string)

	if feedDir != "" && strings.HasPrefix(event.Name, feedDir+"/") {
		slog.Debug("Feed file change detected", "file", event.Name, "op", event.Op)

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

	// Filter before logging: the config directory may also hold the plugin's
	// own log file, and logging its write events would feed back into the
	// watcher forever.
	if isConfigDirNoise(event, configPath, verif) {
		return configDebounce, feedDebounce
	}

	slog.Debug("File change detected", "file", event.Name, "op", event.Op)

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

// configWatchDir returns the absolute directory containing the config file,
// or an empty string if it cannot be resolved.
func configWatchDir(configPath string) string {
	if configPath == "" {
		return ""
	}

	abs, err := filepath.Abs(configPath)
	if err != nil {
		return ""
	}

	return filepath.Dir(abs)
}

// isConfigDirNoise reports whether event concerns an unrelated file in the
// config file's directory. The directory is watched instead of the file, so
// only the config file itself and the Kubernetes "..data" symlink swap
// trigger a reload, unless the directory is, or contains, a watched
// directory. Replacing a watched directory (for example with a rename) drops
// its watch, and the reload adds it again.
func isConfigDirNoise(
	event fsnotify.Event, configPath string, verif *verifier.Verifier,
) bool {
	configDir := configWatchDir(configPath)
	if configDir == "" || filepath.Dir(event.Name) != configDir {
		return false
	}

	switch filepath.Base(event.Name) {
	case filepath.Base(configPath), configMapDataDir:
		return false
	}

	if verif == nil {
		return true
	}

	cfg := verif.CurrentConfig()
	if cfg == nil {
		return true
	}

	for _, dir := range []string{cfg.PolicyDir, cfg.Offline.AttestationStore, cfg.Remediation.FeedDir} {
		if watchedDirAffected(dir, configDir, event.Name) {
			return false
		}
	}

	return true
}

// watchedDirAffected reports whether a change to path in configDir concerns
// the watched directory dir: dir is configDir itself, path, or below path.
func watchedDirAffected(dir, configDir, path string) bool {
	if dir == "" {
		return false
	}

	abs, err := filepath.Abs(dir)
	if err != nil {
		return false
	}

	return abs == configDir || abs == path ||
		strings.HasPrefix(abs, path+string(filepath.Separator))
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

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

// Package main provides the entry point for the NRI supply chain verification plugin.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/containerd/nri/pkg/stub"
	"github.com/fsnotify/fsnotify"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	crremote "github.com/google/go-containerregistry/pkg/v1/remote"
	"golang.org/x/sync/errgroup"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/plugin"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

var version = "0.1.3"

// ErrNoPlatformMatch indicates that no image in a manifest list matches the current platform.
var ErrNoPlatformMatch = errors.New("no matching platform image in manifest list")

var logLevelVar slog.LevelVar //nolint:gochecknoglobals // shared between initLogging and reload

const (
	readHeaderTimeout   = 10 * time.Second
	shutdownGracePeriod = 5 * time.Second
	fileWatchDebounce   = 500 * time.Millisecond
	panicExitCode       = 2

	logLevelDebug = "debug"
	logLevelInfo  = "info"
	logLevelWarn  = "warn"
	logLevelError = "error"
)

type options struct {
	configPath      string
	metricsAddr     string
	pluginName      string
	pluginIdx       string
	logLevel        string
	verifyImage     string
	verifyNamespace string
	showVersion     bool
	validate        bool
}

type verifyOutput struct {
	Image        string       `json:"image"`
	Digest       string       `json:"digest"`
	Namespace    string       `json:"namespace"`
	Allowed      bool         `json:"allowed"`
	Reason       string       `json:"reason,omitempty"`
	CheckResults []checkEntry `json:"checkResults,omitempty"`
}

type checkEntry struct {
	Type   string `json:"type"`
	Passed bool   `json:"passed"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

func main() {
	os.Exit(run())
}

func run() int {
	opts := parseFlags()

	if opts.showVersion {
		_, _ = fmt.Fprintln(os.Stdout, "nri-supply-chain v"+version)

		return 0
	}

	initLogging(opts.logLevel)

	cfg, err := setupConfig(&opts)
	if err != nil {
		slog.Error("Setup failed", "error", err)

		return 1
	}

	if cfg.LogLevel != "" {
		updateLogLevel(cfg.LogLevel)
	}

	if opts.validate {
		return runValidation(cfg)
	}

	if opts.verifyImage != "" {
		return runVerify(&opts, cfg)
	}

	met := metrics.New()

	var fetcher attestation.Fetcher
	if cfg.Enabled() {
		fetcher = verifier.NewFetcher(cfg)
	}

	verif, err := verifier.New(cfg, met, fetcher)
	if err != nil {
		slog.Error("Failed to create verifier", "error", err)

		return 1
	}

	plug := plugin.New(verif, met, opts.configPath, cfg.FetchTimeout.Duration)
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	cleanupSignals := setupSignals(ctx, cancel, opts.configPath, verif, cfg)
	defer cleanupSignals()

	err = runPlugin(ctx, plug, met, cfg.MetricsAddr, &opts, cancel)
	if err != nil {
		slog.Error("Plugin exited with error", "error", err)

		return 1
	}

	return 0
}

func setupSignals(
	ctx context.Context, cancel context.CancelFunc,
	configPath string, verif *verifier.Verifier,
	cfg *config.Config,
) func() {
	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)

	sigterm := make(chan os.Signal, 1)
	signal.Notify(sigterm, syscall.SIGINT, syscall.SIGTERM)

	done := make(chan struct{})

	cleanupWatch, watcher := setupFileWatch(ctx, configPath, cfg.PolicyDir, verif)
	setupReload(ctx, configPath, verif, sighup, watcher)
	handleShutdown(ctx, cancel, sigterm, done)

	return func() {
		signal.Stop(sighup)
		signal.Stop(sigterm)
		close(done)
		cleanupWatch()
	}
}

func parseFlags() options {
	configPath := flag.String("config", "", "path to TOML config file")
	metricsAddr := flag.String("metrics-addr", "", "metrics HTTP listen address (overrides config)")
	pluginName := flag.String("plugin-name", "supply-chain", "NRI plugin name")
	pluginIdx := flag.String("plugin-idx", "10", "NRI plugin index")
	logLevel := flag.String("log-level", logLevelInfo, "log level (debug, info, warn, error)")
	showVersion := flag.Bool("version", false, "print version and exit")
	validate := flag.Bool("validate", false, "validate config and policies, then exit")
	verifyImage := flag.String("verify-image", "", "verify an image and exit")
	verifyNamespace := flag.String("verify-namespace", "default", "namespace for verification")

	flag.Parse()

	return options{
		configPath:      *configPath,
		metricsAddr:     *metricsAddr,
		pluginName:      *pluginName,
		pluginIdx:       *pluginIdx,
		logLevel:        *logLevel,
		verifyImage:     *verifyImage,
		verifyNamespace: *verifyNamespace,
		showVersion:     *showVersion,
		validate:        *validate,
	}
}

func setupConfig(opts *options) (*config.Config, error) {
	cfg, err := loadConfig(opts.configPath)
	if err != nil {
		return nil, err
	}

	if opts.metricsAddr != "" {
		cfg.MetricsAddr = opts.metricsAddr
	}

	if cfg.Enabled() {
		err = cfg.ValidateRuntime()
		if err != nil {
			return nil, fmt.Errorf("runtime validation: %w", err)
		}
	}

	return cfg, nil
}

func runValidation(cfg *config.Config) int {
	if !cfg.Enabled() {
		slog.Info("Validation passed (verification disabled)")

		return 0
	}

	policies, err := policy.LoadAll(cfg.PolicyDir)
	if err != nil {
		slog.Error("Policy validation failed", "error", err)

		return 1
	}

	for ns, pol := range policies {
		label := ns
		if label == "" {
			label = "default"
		}

		err = pol.ValidateRuntime()
		if err != nil {
			slog.Error("Policy runtime validation failed",
				"policy", label,
				"error", err,
			)

			return 1
		}

		if cfg.Verification == config.ModeEnforce {
			err = pol.ValidateEnforce()
			if err != nil {
				slog.Error("Policy enforce validation failed",
					"policy", label,
					"error", err,
				)

				return 1
			}
		}
	}

	verifier.WarnEnforceDefaults(cfg, policies)

	slog.Info("Validation passed",
		"mode", cfg.Verification,
		"policies", len(policies),
	)

	return 0
}

func loadConfig(path string) (*config.Config, error) {
	if path != "" {
		cfg, err := config.LoadFromFile(path)
		if err != nil {
			return nil, fmt.Errorf("loading config file: %w", err)
		}

		return cfg, nil
	}

	return config.DefaultConfig(), nil
}

func initLogging(level string) {
	updateLogLevel(level)
	slog.SetDefault(newLogger())

	if parseLogLevel(level) == nil {
		slog.Warn("Unrecognized log level, defaulting to info", "level", level)
	}
}

func updateLogLevel(level string) {
	logLevel := slog.LevelInfo

	if parsed := parseLogLevel(level); parsed != nil {
		logLevel = *parsed
	}

	logLevelVar.Set(logLevel)
}

func parseLogLevel(level string) *slog.Level {
	var parsed slog.Level

	switch level {
	case logLevelDebug:
		parsed = slog.LevelDebug
	case logLevelInfo:
		parsed = slog.LevelInfo
	case logLevelWarn:
		parsed = slog.LevelWarn
	case logLevelError:
		parsed = slog.LevelError
	default:
		return nil
	}

	return &parsed
}

func newLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: &logLevelVar,
	}))
}

func runPlugin(
	ctx context.Context, plug *plugin.Plugin, met *metrics.Metrics,
	metricsAddr string, opts *options, cancel context.CancelFunc,
) error {
	nriStub, err := stub.New(plug,
		stub.WithPluginName(opts.pluginName),
		stub.WithPluginIdx(opts.pluginIdx),
		stub.WithOnClose(func() {
			slog.Error("NRI connection lost")
			plug.SetDisconnected()
			cancel()
		}),
	)
	if err != nil {
		return fmt.Errorf("creating NRI stub: %w", err)
	}

	group, gctx := errgroup.WithContext(ctx)

	group.Go(func() error {
		slog.Info("Starting NRI plugin",
			"name", opts.pluginName, "index", opts.pluginIdx,
		)

		runErr := nriStub.Run(gctx)
		if runErr != nil {
			return fmt.Errorf("NRI plugin: %w", runErr)
		}

		return nil
	})

	group.Go(func() error {
		return serveMetrics(gctx, met, metricsAddr, plug)
	})

	err = group.Wait()
	if err != nil {
		return fmt.Errorf("plugin services: %w", err)
	}

	return nil
}

func setupReload(
	ctx context.Context, configPath string, verif *verifier.Verifier,
	sigCh <-chan os.Signal, watcher *fsnotify.Watcher,
) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-sigCh:
			}

			handleReload(ctx, configPath, verif, watcher)
		}
	}()
}

func handleReload(
	ctx context.Context, configPath string,
	verif *verifier.Verifier, watcher *fsnotify.Watcher,
) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("Recovered panic in reload handler", "error", r)
		}
	}()

	slog.Info("Reloading config")

	if configPath == "" {
		slog.Warn("No config file specified, skipping reload")

		return
	}

	newCfg, err := config.LoadFromFile(configPath)
	if err != nil {
		slog.Error("Config reload failed", "error", err)

		return
	}

	if newCfg.Enabled() {
		err = newCfg.ValidateRuntime()
		if err != nil {
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
		slog.Error("Verifier reload failed", "error", reloadErr)
	} else {
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

func runVerify(opts *options, cfg *config.Config) int {
	imageRef := opts.verifyImage
	namespace := opts.verifyNamespace

	if !cfg.Enabled() {
		slog.Error("--verify-image requires verification to be enabled")

		return 1
	}

	met := metrics.New()
	fetcher := verifier.NewFetcher(cfg)

	verif, err := verifier.New(cfg, met, fetcher)
	if err != nil {
		slog.Error("Failed to create verifier", "error", err)

		return 1
	}

	resolved, err := resolveDigest(imageRef, cfg.FetchTimeout.Duration)
	if err != nil {
		slog.Error("Failed to resolve image digest", "image", imageRef, "error", err)

		return 1
	}

	digest := resolved.digest

	result, err := verif.Verify(
		context.Background(), imageRef, digest, resolved.indexDigest, namespace,
	)
	if err != nil {
		slog.Error("Verification failed", "image", imageRef, "error", err)
	}

	checks := convertCheckResults(result)

	if err != nil {
		outputVerifyResult(imageRef, digest, namespace, false, err.Error(), checks)

		return 1
	}

	outputVerifyResult(imageRef, digest, namespace, result.Allowed, result.Reason, checks)

	if !result.Allowed {
		return 1
	}

	return 0
}

func convertCheckResults(result *types.Result) []checkEntry {
	if result == nil {
		return nil
	}

	checks := make([]checkEntry, 0, len(result.CheckResults))

	for _, cr := range result.CheckResults {
		checks = append(checks, checkEntry{
			Type:   cr.Type,
			Passed: cr.Passed,
			Status: cr.Status,
			Detail: cr.Detail,
		})
	}

	return checks
}

type resolvedDigest struct {
	digest      string
	indexDigest string
}

func resolveDigest(imageRef string, timeout time.Duration) (resolvedDigest, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return resolvedDigest{}, fmt.Errorf("parsing image reference: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	desc, err := crremote.Get(ref, crremote.WithContext(ctx))
	if err != nil {
		return resolvedDigest{}, fmt.Errorf("resolving image digest: %w", err)
	}

	if desc.MediaType.IsIndex() {
		platformDigest, indexErr := resolveIndexDigest(desc)
		if indexErr != nil {
			return resolvedDigest{}, indexErr
		}

		return resolvedDigest{
			digest:      platformDigest,
			indexDigest: desc.Digest.String(),
		}, nil
	}

	return resolvedDigest{digest: desc.Digest.String(), indexDigest: ""}, nil
}

func resolveIndexDigest(desc *crremote.Descriptor) (string, error) {
	idx, err := desc.ImageIndex()
	if err != nil {
		return "", fmt.Errorf("reading image index: %w", err)
	}

	manifest, err := idx.IndexManifest()
	if err != nil {
		return "", fmt.Errorf("reading index manifest: %w", err)
	}

	platform := v1.Platform{
		Architecture: runtime.GOARCH,
		OS:           runtime.GOOS,
	}

	for i := range manifest.Manifests {
		entry := &manifest.Manifests[i]

		if entry.Platform != nil && entry.Platform.Satisfies(platform) {
			slog.Debug("Resolved manifest list to platform image",
				"platform", platform.String(),
				"digest", entry.Digest.String(),
			)

			return entry.Digest.String(), nil
		}
	}

	return "", fmt.Errorf("%w for %s/%s", ErrNoPlatformMatch, runtime.GOOS, runtime.GOARCH)
}

func outputVerifyResult(
	imageRef, digest, namespace string,
	allowed bool, reason string, checks []checkEntry,
) {
	out := verifyOutput{
		Image:        imageRef,
		Digest:       digest,
		Namespace:    namespace,
		Allowed:      allowed,
		Reason:       reason,
		CheckResults: checks,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")

	encErr := enc.Encode(out)
	if encErr != nil {
		slog.Error("Failed to encode verify output", "error", encErr)
	}
}

func setupFileWatch(
	ctx context.Context, configPath, policyDir string,
	verif *verifier.Verifier,
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

	go runFileWatch(ctx, watcher, configPath, verif)

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
				return
			}

			debounce = handleFileEvent(ctx, event, debounce, configPath, verif, watcher)

		case watchErr, ok := <-watcher.Errors:
			if !ok {
				return
			}

			slog.Warn("File watcher error", "error", watchErr)
		}
	}
}

func handleFileEvent(
	ctx context.Context, event fsnotify.Event,
	debounce *time.Timer, configPath string,
	verif *verifier.Verifier, watcher *fsnotify.Watcher,
) *time.Timer {
	if !isReloadEvent(event) {
		return debounce
	}

	slog.Debug("File change detected", "file", event.Name, "op", event.Op)

	if debounce != nil {
		debounce.Stop()
	}

	return time.AfterFunc(fileWatchDebounce, func() {
		handleReload(ctx, configPath, verif, watcher)
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

func serveMetrics(
	ctx context.Context, met *metrics.Metrics, addr string,
	plug *plugin.Plugin,
) error {
	if addr == "" {
		slog.Info("Metrics server disabled (no address configured)")
		<-ctx.Done()

		return nil
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", met.Handler())
	registerHealthProbes(mux, plug)

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
	}

	//nolint:gosec,contextcheck // parent ctx is already cancelled; fresh context is intentional
	go shutdownOnCancel(ctx.Done(), srv)

	slog.Info("Starting metrics and health server", "addr", addr)

	err := srv.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("metrics server: %w", err)
	}

	return nil
}

func shutdownOnCancel(done <-chan struct{}, srv *http.Server) {
	<-done

	shutdownCtx, shutdownCancel := context.WithTimeout(
		context.Background(), shutdownGracePeriod,
	)
	defer shutdownCancel()

	shutdownErr := srv.Shutdown(shutdownCtx)
	if shutdownErr != nil {
		slog.Error("Failed to shutdown metrics server", "error", shutdownErr)
	}
}

func registerHealthProbes(mux *http.ServeMux, plug *plugin.Plugin) {
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("ok"))
	})

	mux.HandleFunc("/readyz", func(writer http.ResponseWriter, _ *http.Request) {
		if !plug.Connected() {
			writer.WriteHeader(http.StatusServiceUnavailable)
			_, _ = writer.Write([]byte("not ready: NRI not connected"))

			return
		}

		if ready, reason := plug.VerifierReady(); !ready {
			writer.WriteHeader(http.StatusServiceUnavailable)
			_, _ = writer.Write([]byte("not ready: " + reason))

			return
		}

		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("ok"))
	})
}

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
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/containerd/nri/pkg/stub"
	"golang.org/x/sync/errgroup"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/plugin"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

var version = "0.1.0"

const (
	readHeaderTimeout   = 10 * time.Second
	shutdownGracePeriod = 5 * time.Second

	logLevelDebug = "debug"
	logLevelInfo  = "info"
	logLevelWarn  = "warn"
	logLevelError = "error"
)

type options struct {
	configPath  string
	metricsAddr string
	pluginName  string
	pluginIdx   string
	logLevel    string
	showVersion bool
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

	met := metrics.New()

	var fetcher attestation.Fetcher
	if cfg.Enabled() {
		fetcher = createFetcher()
	}

	verif, err := verifier.New(cfg, met, fetcher)
	if err != nil {
		slog.Error("Failed to create verifier", "error", err)

		return 1
	}

	plug := plugin.New(verif, met, opts.configPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)

	defer signal.Stop(sighup)

	sigterm := make(chan os.Signal, 1)
	signal.Notify(sigterm, syscall.SIGINT, syscall.SIGTERM)

	defer signal.Stop(sigterm)

	setupReload(ctx, opts.configPath, verif, sighup)
	handleShutdown(ctx, cancel, sigterm)

	err = runPlugin(ctx, plug, met, cfg.MetricsAddr, &opts, cancel)
	if err != nil {
		slog.Error("Plugin exited with error", "error", err)

		return 1
	}

	return 0
}

func parseFlags() options {
	configPath := flag.String("config", "", "path to TOML config file")
	metricsAddr := flag.String("metrics-addr", "", "metrics HTTP listen address (overrides config)")
	pluginName := flag.String("plugin-name", "supply-chain", "NRI plugin name")
	pluginIdx := flag.String("plugin-idx", "10", "NRI plugin index")
	logLevel := flag.String("log-level", logLevelInfo, "log level (debug, info, warn, error)")
	showVersion := flag.Bool("version", false, "print version and exit")

	flag.Parse()

	return options{
		configPath:  *configPath,
		metricsAddr: *metricsAddr,
		pluginName:  *pluginName,
		pluginIdx:   *pluginIdx,
		logLevel:    *logLevel,
		showVersion: *showVersion,
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

func createFetcher() *attestation.OCIFetcher {
	ociFetcher := attestation.NewOCIFetcher()

	warmErr := ociFetcher.Warm(context.Background())
	if warmErr != nil {
		slog.Warn(
			"Failed to pre-warm Sigstore trusted root",
			"error", warmErr,
		)
	}

	return ociFetcher
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
	var logLevel slog.Level

	var warnInvalid bool

	switch level {
	case logLevelDebug:
		logLevel = slog.LevelDebug
	case logLevelInfo:
		logLevel = slog.LevelInfo
	case logLevelWarn:
		logLevel = slog.LevelWarn
	case logLevelError:
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
		warnInvalid = true
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
	})))

	if warnInvalid {
		slog.Warn("Unrecognized log level, defaulting to info", "level", level)
	}
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
	sigCh <-chan os.Signal,
) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-sigCh:
			}

			slog.Info("Received SIGHUP, reloading config")

			if configPath == "" {
				slog.Warn("No config file specified, skipping reload")

				continue
			}

			newCfg, err := config.LoadFromFile(configPath)
			if err != nil {
				slog.Error("Config reload failed", "error", err)

				continue
			}

			if newCfg.Enabled() {
				err = newCfg.ValidateRuntime()
				if err != nil {
					slog.Error("Config reload validation failed", "error", err)

					continue
				}
			}

			reloadErr := verif.Reload(ctx, newCfg)
			if reloadErr != nil {
				slog.Error("Verifier reload failed", "error", reloadErr)
			} else {
				slog.Info("Config reloaded successfully")
			}
		}
	}()
}

func handleShutdown(ctx context.Context, cancel context.CancelFunc, sigCh <-chan os.Signal) {
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-sigCh:
		}

		slog.Info("Shutting down")
		cancel()
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

	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("ok"))
	})

	mux.HandleFunc("/readyz", func(writer http.ResponseWriter, _ *http.Request) {
		if !plug.Connected() {
			writer.WriteHeader(http.StatusServiceUnavailable)
			_, _ = writer.Write([]byte("not ready"))

			return
		}

		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("ok"))
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
	}

	go func() { //nolint:gosec // ctx is cancelled at this point; fresh context is intentional
		<-ctx.Done()

		shutdownCtx, shutdownCancel := context.WithTimeout(
			context.Background(), shutdownGracePeriod,
		)
		defer shutdownCancel()

		//nolint:contextcheck // ctx is already cancelled here
		shutdownErr := srv.Shutdown(shutdownCtx)
		if shutdownErr != nil {
			slog.Error("Failed to shutdown metrics server", "error", shutdownErr)
		}
	}()

	slog.Info("Starting metrics and health server", "addr", addr)

	err := srv.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("metrics server: %w", err)
	}

	return nil
}

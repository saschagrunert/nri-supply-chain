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

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/plugin"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

const (
	version           = "0.1.0"
	readHeaderTimeout = 10 * time.Second
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

	verif, err := verifier.New(cfg, met)
	if err != nil {
		slog.Error("Failed to create verifier", "error", err)

		return 1
	}

	plug := plugin.New(verif, opts.configPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	setupReload(opts.configPath, verif)
	handleShutdown(cancel)

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
	logLevel := flag.String("log-level", "info", "log level (debug, info, warn, error)")
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

	switch level {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
	})))
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
			cancel()
		}),
	)
	if err != nil {
		return fmt.Errorf("creating NRI stub: %w", err)
	}

	plug.SetStub(nriStub)

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
		return serveMetrics(gctx, met, metricsAddr)
	})

	err = group.Wait()
	if err != nil {
		return fmt.Errorf("plugin services: %w", err)
	}

	return nil
}

func setupReload(configPath string, verif *verifier.Verifier) {
	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)

	go func() {
		for range sighup {
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

			reloadErr := verif.Reload(newCfg)
			if reloadErr != nil {
				slog.Error("Verifier reload failed", "error", reloadErr)
			} else {
				slog.Info("Config reloaded successfully")
			}
		}
	}()
}

func handleShutdown(cancel context.CancelFunc) {
	sigterm := make(chan os.Signal, 1)
	signal.Notify(sigterm, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigterm
		slog.Info("Shutting down")
		cancel()
	}()
}

func serveMetrics(ctx context.Context, met *metrics.Metrics, addr string) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", met.Handler())

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
	}

	go func() {
		<-ctx.Done()

		closeErr := srv.Close()
		if closeErr != nil {
			slog.Error("Failed to close metrics server", "error", closeErr)
		}
	}()

	slog.Info("Starting metrics server", "addr", addr)

	err := srv.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("metrics server: %w", err)
	}

	return nil
}

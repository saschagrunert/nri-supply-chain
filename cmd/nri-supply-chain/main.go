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
	"flag"
	"fmt"
	"log/slog"
	"os"
	"runtime"

	"github.com/containerd/nri/pkg/stub"
	"golang.org/x/sync/errgroup"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/plugin"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

var version = "0.1.5"

var logLevelVar slog.LevelVar //nolint:gochecknoglobals // shared between initLogging and reload

const (
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
	jsonSchema      string
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

	if opts.jsonSchema != "" {
		return printJSONSchema(opts.jsonSchema)
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

	return startPlugin(&opts, cfg)
}

func startPlugin(opts *options, cfg *config.Config) int {
	met := metrics.New()
	met.SetBuildInfo(version, runtime.Version())

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

	cleanupSignals := setupSignals(ctx, cancel, opts.configPath, verif, met, cfg, plug)
	defer cleanupSignals()

	err = runPlugin(ctx, plug, met, cfg.MetricsAddr, opts, cancel)
	if err != nil {
		slog.Error("Plugin exited with error", "error", err)

		return 1
	}

	return 0
}

func parseFlags() options {
	return parseFlagsFrom(os.Args[1:])
}

func parseFlagsFrom(args []string) options {
	flagSet := flag.NewFlagSet("nri-supply-chain", flag.ExitOnError)

	configPath := flagSet.String("config", "", "path to TOML config file")
	metricsAddr := flagSet.String(
		"metrics-addr", "", "metrics HTTP listen address (overrides config)",
	)
	pluginName := flagSet.String("plugin-name", "supply-chain", "NRI plugin name")
	pluginIdx := flagSet.String("plugin-idx", "10", "NRI plugin index")
	logLevel := flagSet.String("log-level", logLevelInfo, "log level (debug, info, warn, error)")
	showVersion := flagSet.Bool("version", false, "print version and exit")
	validate := flagSet.Bool("validate", false, "validate config and policies, then exit")
	verifyImage := flagSet.String("verify-image", "", "verify an image and exit")
	verifyNamespace := flagSet.String("verify-namespace", "default", "namespace for verification")
	jsonSchema := flagSet.String(
		"json-schema", "",
		"print JSON Schema and exit (policy, result)",
	)

	_ = flagSet.Parse(args)

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
		jsonSchema:      *jsonSchema,
	}
}

func setupConfig(opts *options) (*config.Config, error) {
	cfg, err := loadConfig(opts.configPath)
	if err != nil {
		return nil, err
	}

	if opts.metricsAddr != "" {
		cfg.MetricsAddr = opts.metricsAddr

		err = cfg.Validate()
		if err != nil {
			return nil, fmt.Errorf("validating config with --metrics-addr override: %w", err)
		}
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

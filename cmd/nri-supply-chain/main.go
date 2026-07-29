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
	exitSuccess = 0
	exitDenied  = 1
	exitError   = 2

	logLevelDebug = "debug"
	logLevelInfo  = "info"
	logLevelWarn  = "warn"
	logLevelError = "error"

	outputFormatTable = "table"
	outputFormatJSON  = "json"
)

type options struct {
	configPath      string
	metricsAddr     string
	pluginName      string
	pluginIdx       string
	logLevel        string
	verifyImage     string
	verifyNamespace string
	outputFormat    string
	showVersion     bool
	validate        bool
	jsonSchema      string
}

func main() {
	os.Exit(run())
}

func run() int {
	opts, err := parseFlags()
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitSuccess
		}

		slog.Error("Failed to parse flags", "error", err)

		return exitError
	}

	if opts.showVersion {
		_, _ = fmt.Fprintln(os.Stdout, "nri-supply-chain v"+version)

		return exitSuccess
	}

	if opts.jsonSchema != "" {
		return printJSONSchema(opts.jsonSchema)
	}

	cfg, err := setupConfig(&opts)
	if err != nil {
		slog.Error("Setup failed", "error", err)

		return exitError
	}

	cliMode := opts.verifyImage != "" || opts.validate
	initLogging(effectiveLogLevel(opts.logLevel, cfg.LogLevel), cliMode)

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

	ctx, cancel := context.WithCancel(context.Background())

	slog.Info("Effective configuration",
		"mode", cfg.Verification,
		"policy_dir", cfg.PolicyDir,
		"cache_ttl", cfg.CacheTTL.Duration,
		"cache_failure_ttl", cfg.CacheFailureTTL.Duration,
		"fetch_timeout", cfg.FetchTimeout.Duration,
		"fetch_rate_limit", cfg.FetchRateLimit,
		"fetch_failure_policy", cfg.FetchFailurePolicy,
		"circuit_breaker_threshold", cfg.CircuitBreakerThreshold,
		"circuit_breaker_cooldown", cfg.CircuitBreakerCooldown.Duration,
		"metrics_addr", cfg.MetricsAddr,
	)

	var fetcher attestation.Fetcher

	if cfg.Enabled() {
		var err error

		fetcher, err = verifier.NewFetcher(ctx, cfg)
		if err != nil {
			slog.Error("Failed to create fetcher", "error", err)
			cancel()

			return exitError
		}
	}

	verif, err := verifier.New(cfg, met, fetcher)
	if err != nil {
		slog.Error("Failed to create verifier", "error", err)
		cancel()

		return exitError
	}

	defer cancel()
	defer verif.Stop()

	plug := plugin.New(verif, met, opts.configPath, cfg.FetchTimeout.Duration)

	cleanupSignals := setupSignals(ctx, cancel, opts.configPath, verif, met, cfg, plug)
	defer cleanupSignals()

	err = runPlugin(ctx, plug, met, cfg.MetricsAddr, opts, cancel)
	if err != nil {
		slog.Error("Plugin exited with error", "error", err)

		return exitError
	}

	return exitSuccess
}

func parseFlags() (options, error) {
	return parseFlagsFrom(os.Args[1:])
}

func parseFlagsFrom(args []string) (options, error) {
	flagSet := flag.NewFlagSet("nri-supply-chain", flag.ContinueOnError)

	var opts options

	registerFlags(flagSet, &opts)

	err := flagSet.Parse(args)
	if err != nil {
		return options{}, fmt.Errorf("parsing flags: %w", err)
	}

	return opts, nil
}

func registerFlags(flagSet *flag.FlagSet, opts *options) {
	flagSet.StringVar(&opts.configPath, "config", "", "path to TOML config file")
	flagSet.StringVar(
		&opts.metricsAddr,
		"metrics-addr",
		"",
		"metrics HTTP listen address (overrides config)",
	)
	flagSet.StringVar(&opts.pluginName, "plugin-name", "supply-chain", "NRI plugin name")
	flagSet.StringVar(&opts.pluginIdx, "plugin-idx", "10", "NRI plugin index")
	flagSet.StringVar(
		&opts.logLevel, "log-level", "",
		"log level: debug, info, warn, error (default: info)",
	)
	flagSet.BoolVar(&opts.showVersion, "version", false, "print version and exit")
	flagSet.BoolVar(&opts.validate, "validate", false, "validate config and policies, then exit")
	flagSet.StringVar(&opts.verifyImage, "verify-image", "", "verify an image and exit")
	flagSet.StringVar(
		&opts.verifyNamespace,
		"verify-namespace",
		verifier.DefaultPolicyLabel,
		"namespace for verification",
	)
	flagSet.StringVar(
		&opts.outputFormat,
		"output",
		outputFormatTable,
		"output format for --verify-image (table, json)",
	)
	flagSet.StringVar(
		&opts.jsonSchema, "json-schema", "",
		"print JSON Schema and exit (policy, result)",
	)
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

		return exitSuccess
	}

	policies, err := policy.LoadAll(cfg.PolicyDir)
	if err != nil {
		slog.Error("Policy validation failed", "error", err)

		return exitError
	}

	var errs []error

	for ns, pol := range policies {
		label := ns
		if label == "" {
			label = verifier.DefaultPolicyLabel
		}

		err := pol.ValidateRuntime()
		if err != nil {
			errs = append(errs, fmt.Errorf("policy %q: %w", label, err))
		}

		if cfg.Verification == config.ModeEnforce {
			err = pol.ValidateEnforce()
			if err != nil {
				errs = append(errs, fmt.Errorf("policy %q: %w", label, err))
			}
		}
	}

	if len(errs) > 0 {
		slog.Error("Validation failed", "error", errors.Join(errs...))

		return exitError
	}

	verifier.WarnEnforceDefaults(cfg, policies)

	slog.Info("Validation passed",
		"mode", cfg.Verification,
		"policies", len(policies),
	)

	return exitSuccess
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

func effectiveLogLevel(flagLevel, configLevel string) string {
	if flagLevel != "" {
		return flagLevel
	}

	if configLevel != "" {
		return configLevel
	}

	return logLevelInfo
}

func initLogging(level string, cliMode bool) {
	updateLogLevel(level)
	slog.SetDefault(newLogger(cliMode))

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

func newLogger(cliMode bool) *slog.Logger {
	if cliMode {
		return slog.New(newCLIHandler(os.Stderr, &logLevelVar))
	}

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

		return nriStub.Run(gctx)
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

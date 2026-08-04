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
	"fmt"
	"log/slog"
	"os"
	"runtime"

	"github.com/containerd/nri/pkg/stub"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/plugin"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/registry"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

var version = "v0.2.0"

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

	defaultConfigPath = "/etc/nri-supply-chain/config.toml"

	cmdVersion    = "version"
	cmdVerify     = "verify"
	cmdValidate   = "validate"
	cmdJSONSchema = "json-schema"
)

var (
	errExitNonZero       = errors.New("non-zero exit")
	errMissingSchemaType = errors.New("requires a schema type: policy, result")
)

func main() {
	os.Exit(execute())
}

func execute() int {
	initLogging(logLevelInfo, true)

	err := newRootCmd().Execute()
	if err != nil {
		if !errors.Is(err, errExitNonZero) {
			slog.Error(err.Error())
		}

		return exitError
	}

	return exitSuccess
}

func newRootCmd() *cobra.Command {
	var (
		configPath string
		logLevel   string
		pluginName string
		pluginIdx  string
	)

	root := &cobra.Command{
		Use:           "nri-supply-chain",
		Short:         "NRI Supply Chain Plugin",
		Version:       version,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.SilenceUsage = true

			cfg, err := setupConfig(configPath)
			if err != nil {
				slog.Error("Setup failed", "error", err)

				return errExitNonZero
			}

			initLogging(effectiveLogLevel(logLevel, cfg.LogLevel), false)

			code := startPlugin(configPath, pluginName, pluginIdx, cfg)
			if code != 0 {
				return errExitNonZero
			}

			return nil
		},
	}

	root.CompletionOptions.DisableDefaultCmd = true
	root.SetVersionTemplate("nri-supply-chain {{.Version}}\n")

	root.PersistentFlags().StringVarP(&configPath, "config", "c",
		defaultConfigPath, "path to TOML config file")
	root.PersistentFlags().StringVarP(&logLevel, "log-level", "l", "",
		"log level: debug, info, warn, error (default: info)")

	root.Flags().StringVar(&pluginName, "plugin-name", "supply-chain",
		"NRI plugin name")
	root.Flags().StringVar(&pluginIdx, "plugin-idx", "10",
		"NRI plugin index")

	root.AddCommand(
		newVerifyCmd(&configPath, &logLevel),
		newValidateCmd(&configPath, &logLevel),
		newVersionCmd(),
		newJSONSchemaCmd(),
	)

	return root
}

func newVerifyCmd(configPath, logLevel *string) *cobra.Command {
	var (
		namespace    string
		outputFormat string
	)

	cmd := &cobra.Command{
		Use:   cmdVerify + " <image> [<image>...]",
		Short: "Verify one or more images",
		Long: "Verify one or more container images against configured policies.\n\n" +
			"Pass one or more image references as positional arguments.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true

			cfg, err := setupConfig(*configPath)
			if err != nil {
				slog.Error("Setup failed", "error", err)

				return errExitNonZero
			}

			initLogging(effectiveLogLevel(*logLevel, cfg.LogLevel), true)

			slog.Info("Using config", "path", *configPath)

			code := runVerifyCmd(args, namespace, outputFormat, cfg)
			if code != 0 {
				return errExitNonZero
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&namespace, "namespace", "n",
		policy.DefaultPolicyLabel, "namespace for verification")
	cmd.Flags().StringVarP(&outputFormat, "output", "o",
		outputFormatTable, "output format: table, json")

	return cmd
}

func runVerifyCmd(
	args []string, namespace, outputFormat string,
	cfg *config.Config,
) int {
	if len(args) == 1 {
		return runVerify(args[0], namespace, outputFormat, cfg)
	}

	return runVerifyBatch(args, namespace, outputFormat, cfg)
}

func newValidateCmd(configPath, logLevel *string) *cobra.Command {
	return &cobra.Command{
		Use:   cmdValidate,
		Short: "Validate config and policies",
		Long: "Validate the configuration file and all policy files.\n\n" +
			"Loads the config, checks policy syntax, and in enforce mode\n" +
			"verifies that trust roots and key files are accessible.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.SilenceUsage = true

			cfg, err := setupConfig(*configPath)
			if err != nil {
				slog.Error("Setup failed", "error", err)

				return errExitNonZero
			}

			initLogging(effectiveLogLevel(*logLevel, cfg.LogLevel), true)

			slog.Info("Using config", "path", *configPath)

			code := runValidation(cfg)
			if code != 0 {
				return errExitNonZero
			}

			return nil
		},
	}
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   cmdVersion,
		Short: "Print the version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "nri-supply-chain "+version)

			return nil
		},
	}
}

func newJSONSchemaCmd() *cobra.Command {
	return &cobra.Command{
		Use:   cmdJSONSchema + " <type>",
		Short: "Print JSON Schema for a given type",
		Long: "Print the JSON Schema definition for a given type.\n\n" +
			"Available types:\n" +
			"  policy   Policy configuration file schema\n" +
			"  result   Verification result output schema",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errMissingSchemaType
			}

			if len(args) > 1 {
				//nolint:err113 // dynamic arg count
				return fmt.Errorf("accepts 1 arg, received %d", len(args))
			}

			return nil
		},
		ValidArgs: []string{schemaPolicy, schemaResult},
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true

			code := printJSONSchema(args[0])
			if code != 0 {
				return errExitNonZero
			}

			return nil
		},
	}
}

func logEffectiveConfig(configPath string, cfg *config.Config) {
	attrs := []any{
		"config", configPath,
		"mode", cfg.Verification,
		"policy_dir", cfg.PolicyDir,
		"cache_ttl", cfg.CacheTTL.Duration,
		"cache_failure_ttl", cfg.CacheFailureTTL.Duration,
		"fetch_timeout", cfg.FetchTimeout.Duration,
		"digest_resolve_timeout", cfg.DigestResolveTimeout.Duration,
		"fetch_rate_limit", cfg.FetchRateLimit,
		"fetch_failure_policy", cfg.FetchFailurePolicy,
		"circuit_breaker_threshold", cfg.CircuitBreakerThreshold,
		"circuit_breaker_cooldown", cfg.CircuitBreakerCooldown.Duration,
		"metrics_addr", cfg.MetricsAddr,
	}

	if cfg.Policy.Source == config.PolicySourceOCI {
		attrs = append(attrs,
			"policy_source", cfg.Policy.Source,
			"policy_oci_ref", cfg.Policy.OCIRef,
			"policy_poll_interval", cfg.Policy.PollInterval.Duration,
		)
	}

	slog.Info("Effective configuration", attrs...)
}

func startPlugin(
	configPath, pluginName, pluginIdx string, cfg *config.Config,
) int {
	met := metrics.New()
	met.SetBuildInfo(version, runtime.Version())

	ctx, cancel := context.WithCancel(context.Background())

	logEffectiveConfig(configPath, cfg)

	cfg.WarnInsecureRegistries()

	transportCache := registry.NewTransportCacheOrNil(cfg.Registries)

	verif, err := createVerifier(ctx, cfg, met, transportCache)
	if err != nil {
		slog.Error("Startup failed", "error", err)

		if transportCache != nil {
			transportCache.CloseIdleConnections()
		}

		cancel()

		return exitError
	}

	defer cancel()
	defer verif.Stop()

	plug := plugin.New(
		verif, met, configPath,
		cfg.FetchTimeout.Duration, cfg.DigestResolveTimeout.Duration,
		transportCache,
	)

	cleanupSignals := setupSignals(ctx, cancel, configPath, verif, met, cfg, plug)
	defer cleanupSignals()

	err = runPlugin(ctx, plug, met, cfg.MetricsAddr, pluginName, pluginIdx, cancel)
	if err != nil {
		slog.Error("Plugin exited with error", "error", err)

		return exitError
	}

	return exitSuccess
}

func createVerifier(
	ctx context.Context,
	cfg *config.Config,
	met *metrics.Metrics,
	transportCache *registry.TransportCache,
) (*verifier.Verifier, error) {
	var fetcher attestation.Fetcher

	if cfg.Enabled() {
		var err error

		fetcher, err = verifier.NewFetcher(ctx, cfg, transportCache)
		if err != nil {
			return nil, fmt.Errorf("creating fetcher: %w", err)
		}
	}

	verif, err := verifier.New(ctx, cfg, met, fetcher)
	if err != nil {
		return nil, fmt.Errorf("creating verifier: %w", err)
	}

	return verif, nil
}

func setupConfig(configPath string) (*config.Config, error) {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return nil, err
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

	policies, err := loadPoliciesForValidation(cfg)
	if err != nil {
		slog.Error("Policy validation failed", "error", err)

		return exitError
	}

	var errs []error

	for ns, pol := range policies {
		label := ns
		if label == "" {
			label = policy.DefaultPolicyLabel
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

func loadPoliciesForValidation(cfg *config.Config) (map[string]*policy.Policy, error) {
	if cfg.Policy.Source != config.PolicySourceOCI {
		policies, err := policy.LoadAll(cfg.PolicyDir)
		if err != nil {
			return nil, fmt.Errorf("loading policies: %w", err)
		}

		return policies, nil
	}

	transportCache := registry.NewTransportCacheOrNil(cfg.Registries)
	fetcher := policy.NewOCIFetcher(transportCache)

	ctx, cancel := context.WithTimeout(context.Background(), cfg.FetchTimeout.Duration)
	defer cancel()

	result, err := fetcher.FetchFromOCI(ctx, cfg.Policy.OCIRef)
	if err != nil {
		return nil, fmt.Errorf("loading OCI policies: %w", err)
	}

	slog.Info("Loaded policies from OCI artifact",
		"oci_ref", cfg.Policy.OCIRef,
		"digest", result.Digest,
		"count", len(result.Policies),
	)

	return result.Policies, nil
}

func shouldUseConfigFile(path string) bool {
	if path == "" {
		return false
	}

	if path == defaultConfigPath {
		_, err := os.Stat(path)

		return !os.IsNotExist(err)
	}

	return true
}

func loadConfig(path string) (*config.Config, error) {
	if path == defaultConfigPath {
		_, statErr := os.Stat(path)
		if statErr != nil {
			if os.IsNotExist(statErr) {
				return config.DefaultConfig(), nil
			}

			return nil, fmt.Errorf("checking config file: %w", statErr)
		}
	}

	cfg, err := config.LoadFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("loading config file: %w", err)
	}

	return cfg, nil
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
	metricsAddr, pluginName, pluginIdx string, cancel context.CancelFunc,
) error {
	nriStub, err := stub.New(plug,
		stub.WithPluginName(pluginName),
		stub.WithPluginIdx(pluginIdx),
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
			"name", pluginName, "index", pluginIdx,
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

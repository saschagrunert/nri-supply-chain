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
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"

	"github.com/containerd/nri/pkg/api"
	"github.com/spf13/cobra"
)

var version = "v0.6.0"

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
	outputFormatQuiet = "quiet"

	defaultConfigPath = "/etc/nri-supply-chain/config.toml"

	cmdVersion    = "version"
	cmdVerify     = "verify"
	cmdPreview    = "preview"
	cmdValidate   = "validate"
	cmdJSONSchema = "json-schema"
)

var (
	errExitNonZero       = errors.New("non-zero exit")
	errMissingSchemaType = errors.New("requires a schema type: policy, result, config")
	errTooManyArgs       = errors.New("accepts 1 arg")
)

// exitCodeError carries a process exit code out of a cobra command. It wraps
// errExitNonZero so callers that only check for a non-zero exit keep working.
type exitCodeError struct {
	code int
}

func (e *exitCodeError) Error() string {
	return "exit code " + strconv.Itoa(e.code)
}

func (e *exitCodeError) Unwrap() error {
	return errExitNonZero
}

// exitWith converts a command exit code into the error returned from a cobra
// RunE function: nil for exitSuccess, otherwise an exitCodeError.
func exitWith(code int) error {
	if code == exitSuccess {
		return nil
	}

	return &exitCodeError{code: code}
}

func main() {
	os.Exit(execute())
}

func execute() int {
	initLogging(logLevelInfo, true)

	return exitCodeFor(newRootCmd().Execute())
}

// exitCodeFor maps a command error to the process exit code: exitCodeError
// carries its own code (for example exitDenied), any other error is
// exitError.
func exitCodeFor(err error) int {
	if err == nil {
		return exitSuccess
	}

	if codeErr, ok := errors.AsType[*exitCodeError](err); ok {
		return codeErr.code
	}

	if !errors.Is(err, errExitNonZero) {
		slog.Error(err.Error())
	}

	return exitError
}

func newRootCmd() *cobra.Command { //nolint:funlen // cobra command setup
	var (
		configPath string
		logLevel   string
		settings   nriSettings
	)

	root := &cobra.Command{
		Use:   "nri-supply-chain",
		Short: "NRI Supply Chain Plugin",
		Long: "NRI plugin for supply chain attestation verification at the\n" +
			"container runtime level.\n\n" +
			"Exit codes:\n" +
			"  0  success (verification passed)\n" +
			"  1  denied (verification failed)\n" +
			"  2  error (configuration, network, or internal error)",
		Version:       version,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.SilenceUsage = true

			servePath := serveConfigPath(configPath, cmd.Flags().Changed("config"))

			cfg, err := setupServeConfig(servePath)
			if err != nil {
				slog.Error("Setup failed", "error", err)

				return errExitNonZero
			}

			initLogging(effectiveLogLevel(logLevel, cfg.LogLevel), false)

			if servePath == "" {
				slog.Info("No config file, using the configuration passed by the runtime")
			}

			return exitWith(startPlugin(servePath, settings, cfg))
		},
	}

	root.CompletionOptions.HiddenDefaultCmd = false
	root.SetVersionTemplate("nri-supply-chain {{.Version}}\n")
	// Define the version flag without cobra's default -v shorthand, which
	// means --verbose on the verify subcommand.
	root.Flags().Bool("version", false, "print the version")

	root.PersistentFlags().StringVarP(&configPath, "config", "c",
		defaultConfigPath, "path to TOML config file (the plugin uses the configuration "+
			"passed by the runtime when empty, or when unset and the default file does not exist)")
	root.PersistentFlags().StringVarP(&logLevel, "log-level", "l", "",
		"log level: debug, info, warn, error (default: info)")

	root.Flags().StringVar(&settings.pluginName, "plugin-name", "supply-chain",
		"NRI plugin name (ignored when the runtime sets NRI_PLUGIN_NAME)")
	root.Flags().StringVar(&settings.pluginIdx, "plugin-idx", "10",
		"NRI plugin index (ignored when the runtime sets NRI_PLUGIN_IDX)")
	root.Flags().StringVar(&settings.socketPath, "nri-socket", "",
		"path to the NRI runtime socket (default: "+api.DefaultSocketPath+")")
	root.Flags().DurationVar(&settings.disconnectTimeout, "nri-disconnect-timeout",
		defaultNRIDisconnectTimeout,
		"report unhealthy on /healthz after the NRI connection has been down this long "+
			"while the NRI socket exists (0 disables)")
	root.Flags().StringVar(&settings.healthAddr, "health-addr", "",
		"address of a dedicated server for /healthz, /readyz and /status, so probes do not "+
			"depend on the metrics port (empty: serve them only on metrics_addr)")

	root.AddCommand(
		newVerifyCmd(&configPath, &logLevel),
		newPreviewCmd(&configPath, &logLevel),
		newValidateCmd(&configPath, &logLevel),
		newEffectivePolicyCmd(&configPath, &logLevel),
		newInspectCmd(&configPath, &logLevel),
		newBundleCmd(&configPath, &logLevel),
		newVersionCmd(),
		newJSONSchemaCmd(),
	)

	return root
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

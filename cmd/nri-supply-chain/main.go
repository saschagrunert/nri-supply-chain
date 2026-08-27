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

	"github.com/spf13/cobra"
)

var version = "v0.5.0"

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

func newRootCmd() *cobra.Command { //nolint:funlen // cobra command setup
	var (
		configPath string
		logLevel   string
		pluginName string
		pluginIdx  string
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

	root.CompletionOptions.HiddenDefaultCmd = false
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

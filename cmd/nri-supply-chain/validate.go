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
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/registry"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

var errConfigNotFound = errors.New("config file not found")

func newValidateCmd(configPath, logLevel *string) *cobra.Command {
	var allowMissingConfig bool

	cmd := &cobra.Command{
		Use:   cmdValidate,
		Short: "Validate config and policies",
		Long: "Validate the configuration file and all policy files.\n\n" +
			"Loads the config, checks policy syntax, and verifies that trust\n" +
			"roots and key files are accessible. Policies are validated even\n" +
			"when verification is disabled, so they can be checked before\n" +
			"switching to warn or enforce mode.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.SilenceUsage = true

			err := requireConfigFile(*configPath, allowMissingConfig)
			if err != nil {
				slog.Error("Setup failed", "error", err)

				return errExitNonZero
			}

			cfg, err := loadConfig(*configPath)
			if err != nil {
				slog.Error("Setup failed", "error", err)

				return errExitNonZero
			}

			initLogging(effectiveLogLevel(*logLevel, cfg.LogLevel), true)

			slog.Debug("Using config", "path", *configPath)

			return exitWith(runValidation(cfg))
		},
	}

	cmd.Flags().BoolVar(&allowMissingConfig, "allow-missing-config", false,
		"validate the built-in defaults when the default config file does not exist")

	return cmd
}

// requireConfigFile returns an error when the default config file does not
// exist, unless allowMissing is set. Without this check validate would
// silently pass by validating the built-in defaults.
func requireConfigFile(path string, allowMissing bool) error {
	if allowMissing || path != defaultConfigPath {
		return nil
	}

	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return fmt.Errorf(
			"%w: %q (pass --config or --allow-missing-config)", errConfigNotFound, path,
		)
	}

	return nil
}

func runValidation(cfg *config.Config) int {
	if !cfg.Enabled() && !policiesConfigured(cfg) {
		slog.Info("Validation passed (verification disabled, no policies configured)")

		return exitSuccess
	}

	err := cfg.ValidateRuntime()
	if err != nil {
		slog.Error("Config validation failed", "error", err)

		return exitError
	}

	policies, err := loadPoliciesForValidation(cfg)
	if err != nil {
		slog.Error("Policy validation failed", "error", err)

		return exitError
	}

	errs := validatePolicies(cfg, policies)
	if len(errs) > 0 {
		for _, e := range errs {
			slog.Error("Validation failed", "error", e)
		}

		return exitError
	}

	if cfg.Enabled() {
		verifier.WarnEnforceDefaults(context.Background(), cfg, policies)
		verifier.WarnWarnModeDefaults(context.Background(), cfg, policies)
	}

	slog.Info("Validation passed",
		"mode", cfg.Verification,
		"policies", len(policies),
	)

	return exitSuccess
}

// policiesConfigured reports whether a disabled config has local policies to
// validate. OCI policies are only fetched when verification is enabled, so a
// disabled config does not require registry access to validate.
func policiesConfigured(cfg *config.Config) bool {
	if cfg.Policy.Source == config.PolicySourceOCI {
		return false
	}

	if cfg.PolicyDir == "" {
		return false
	}

	_, err := os.Stat(cfg.PolicyDir)

	return err == nil
}

func validatePolicies(cfg *config.Config, policies map[string]*policy.Policy) []error {
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

		switch cfg.Verification {
		case config.ModeEnforce:
			err = pol.ValidateEnforce()
			if err != nil {
				errs = append(errs, fmt.Errorf("policy %q: %w", label, err))
			}
		case config.ModeDisabled:
			// A policy mode stricter than a disabled global mode is
			// ignored: the plugin only warns so that disabling
			// verification always works, but validate reports it.
			if pol.Mode != "" && pol.Mode != config.ModeDisabled {
				errs = append(errs, fmt.Errorf(
					"policy %q: %w: sets mode %q",
					label, verifier.ErrPolicyModeWhileDisabled, pol.Mode,
				))
			}
		case config.ModeWarn:
		}
	}

	return errs
}

func loadPoliciesForValidation(cfg *config.Config) (map[string]*policy.Policy, error) {
	policies, digest, err := loadPolicies(cfg)
	if err != nil {
		return nil, err
	}

	if cfg.Policy.Source == config.PolicySourceOCI {
		slog.Info("Loaded policies from OCI artifact",
			"oci_ref", cfg.Policy.OCIRef,
			"digest", digest,
			"count", len(policies),
		)
	}

	return policies, nil
}

func loadPolicies(
	cfg *config.Config,
) (policies map[string]*policy.Policy, digest string, err error) {
	if cfg.Policy.Source != config.PolicySourceOCI {
		policies, err = policy.LoadAll(cfg.PolicyDir)
		if err != nil {
			return nil, "", fmt.Errorf("loading policies: %w", err)
		}

		return policies, "", nil
	}

	transportCache := registry.NewTransportCacheOrNil(cfg.Registries)
	fetcher := policy.NewOCIFetcher(transportCache)

	ctx, cancel := context.WithTimeout(context.Background(), cfg.FetchTimeout.Duration)
	defer cancel()

	result, err := fetcher.FetchFromOCI(ctx, cfg.Policy.OCIRef)
	if err != nil {
		return nil, "", fmt.Errorf("loading OCI policies: %w", err)
	}

	return result.Policies, result.Digest, nil
}

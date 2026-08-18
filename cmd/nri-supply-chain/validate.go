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
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/registry"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

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

			slog.Debug("Using config", "path", *configPath)

			code := runValidation(cfg)
			if code != 0 {
				return errExitNonZero
			}

			return nil
		},
	}
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
		for _, e := range errs {
			slog.Error("Validation failed", "error", e)
		}

		return exitError
	}

	verifier.WarnEnforceDefaults(context.Background(), cfg, policies)
	verifier.WarnWarnModeDefaults(context.Background(), cfg, policies)

	slog.Info("Validation passed",
		"mode", cfg.Verification,
		"policies", len(policies),
	)

	return exitSuccess
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

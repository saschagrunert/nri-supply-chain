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
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

const (
	cmdEffectivePolicy    = "effective-policy"
	policySourceDefault   = "default"
	policySourceNamespace = "namespace"
)

type effectivePolicyOutput struct {
	Namespace    string         `json:"namespace"`
	Image        string         `json:"image,omitempty"`
	Mode         string         `json:"mode"`
	Source       string         `json:"source"`
	RuleIndex    int            `json:"ruleIndex"`
	RulePatterns []string       `json:"rulePatterns,omitempty"`
	Policy       *policy.Policy `json:"policy"`
}

func newEffectivePolicyCmd(configPath, logLevel *string) *cobra.Command {
	var (
		namespace    string
		image        string
		outputFormat string
	)

	cmd := &cobra.Command{
		Use:   cmdEffectivePolicy,
		Short: "Show the effective policy for a namespace",
		Long: "Show the resolved policy that applies to a namespace after\n" +
			"inheritance from the default policy. When --image is specified,\n" +
			"the first matching image rule is applied on top.",
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

			code := runEffectivePolicy(os.Stdout, namespace, image, outputFormat, cfg)
			if code != 0 {
				return errExitNonZero
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&namespace, "namespace", "n",
		policy.DefaultPolicyLabel, "namespace to resolve")
	cmd.Flags().StringVarP(&image, "image", "i",
		"", "image reference to match against rules")
	cmd.Flags().StringVarP(&outputFormat, "output", "o",
		outputFormatJSON, "output format: table, json")

	return cmd
}

func runEffectivePolicy(
	writer io.Writer, namespace, image, outputFormat string, cfg *config.Config,
) int {
	if outputFormat != outputFormatTable && outputFormat != outputFormatJSON {
		slog.Error("Invalid output format", "format", outputFormat)

		return exitError
	}

	policies, _, err := loadPolicies(cfg)
	if err != nil {
		slog.Error("Failed to load policies", "error", err)

		return exitError
	}

	pol, source := resolveNamespacePolicy(policies, namespace)
	if pol == nil {
		slog.Error("No policy found", "namespace", namespace)

		return exitError
	}

	out := buildEffectivePolicyOutput(namespace, image, source, pol, cfg)

	if outputFormat == outputFormatTable {
		return outputEffectivePolicyTable(writer, out)
	}

	enc := json.NewEncoder(writer)
	enc.SetIndent("", "  ")

	err = enc.Encode(out)
	if err != nil {
		slog.Error("Failed to write output", "error", err)

		return exitError
	}

	return exitSuccess
}

func outputEffectivePolicyTable(writer io.Writer, out *effectivePolicyOutput) int {
	_, _ = fmt.Fprintf(writer, "%s  %s\n", colorBold.Sprint("Namespace:"), out.Namespace)
	_, _ = fmt.Fprintf(writer, "%s       %s\n", colorBold.Sprint("Mode:"), colorMode(out.Mode))
	_, _ = fmt.Fprintf(writer, "%s     %s\n", colorBold.Sprint("Source:"), out.Source)

	if out.Image != "" {
		_, _ = fmt.Fprintf(writer, "%s      %s\n", colorBold.Sprint("Image:"), out.Image)
	}

	if out.RuleIndex >= 0 {
		_, _ = fmt.Fprintf(writer, "%s %d\n",
			colorBold.Sprint("Rule index:"), out.RuleIndex)
		_, _ = fmt.Fprintf(writer, "%s   %s\n",
			colorBold.Sprint("Patterns:"), strings.Join(out.RulePatterns, ", "))
	}

	return exitSuccess
}

func resolveNamespacePolicy(
	policies map[string]*policy.Policy, namespace string,
) (pol *policy.Policy, source string) {
	nsKey := namespace
	if nsKey == policy.DefaultPolicyLabel {
		nsKey = ""
	}

	pol = policies[nsKey]
	source = policySourceNamespace

	if pol == nil {
		pol = policies[""]
		source = policySourceDefault
	} else if nsKey == "" {
		source = policySourceDefault
	}

	return pol, source
}

func buildEffectivePolicyOutput(
	namespace, image, source string,
	pol *policy.Policy, cfg *config.Config,
) *effectivePolicyOutput {
	effectiveMode := pol.EffectiveMode(cfg.Verification)

	out := &effectivePolicyOutput{
		Namespace:    namespace,
		Image:        image,
		Mode:         string(effectiveMode),
		Source:       source,
		RuleIndex:    -1,
		RulePatterns: nil,
		Policy:       pol,
	}

	if image != "" {
		resolved, ruleIdx := verifier.ResolveImagePolicy(
			context.Background(), pol, image,
		)
		out.Policy = resolved
		out.RuleIndex = ruleIdx

		if ruleIdx >= 0 && ruleIdx < len(pol.Rules) {
			out.RulePatterns = pol.Rules[ruleIdx].Images
		}
	}

	return out
}

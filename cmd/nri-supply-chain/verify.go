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
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/fileutil"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/registry"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

func newVerifyCmd( //nolint:funlen // cobra command setup
	configPath, logLevel *string,
) *cobra.Command {
	var (
		namespace     string
		outputFormat  string
		verbose       bool
		previewPolicy string
	)

	cmd := &cobra.Command{
		Use:   cmdVerify + " <image> [<image>...]",
		Short: "Verify one or more images",
		Long: "Verify one or more container images against configured policies.\n\n" +
			"Pass one or more image references as positional arguments.\n" +
			"Use --verbose to show step-by-step diagnostic output.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true

			cfg, err := setupConfig(*configPath)
			if err != nil {
				slog.Error("Setup failed", "error", err)

				return errExitNonZero
			}

			level := effectiveLogLevel(*logLevel, cfg.LogLevel)
			if verbose {
				level = logLevelDebug
			}

			initLogging(level, true)

			slog.Debug("Using config", "path", *configPath)

			if previewPolicy != "" {
				tmpDir, cleanupErr := setupPreviewPolicyDir(previewPolicy, namespace)
				if cleanupErr != nil {
					slog.Error("Failed to set up preview policy", "error", cleanupErr)

					return errExitNonZero
				}

				defer func() { _ = os.RemoveAll(tmpDir) }()

				cfg.PolicyDir = tmpDir
			}

			if verbose {
				logVerbosePreamble(cmd.ErrOrStderr(), args, namespace, cfg)
			}

			code := runVerifyCmd(args, namespace, outputFormat, cfg, previewPolicy)
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
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false,
		"show step-by-step diagnostic output")
	cmd.Flags().StringVar(&previewPolicy, "preview-policy", "",
		"path to a policy JSON file to use instead of the configured policies (dry-run)")

	return cmd
}

func runVerifyCmd(
	args []string, namespace, outputFormat string,
	cfg *config.Config, previewPolicy string,
) int {
	if len(args) == 1 {
		return runVerify(args[0], namespace, outputFormat, cfg, previewPolicy)
	}

	return runVerifyBatch(args, namespace, outputFormat, cfg, previewPolicy)
}

type verifyOutput struct {
	Image         string              `json:"image"`
	Digest        string              `json:"digest"`
	Namespace     string              `json:"namespace"`
	PolicyFile    string              `json:"-"`
	Mode          string              `json:"-"`
	PreviewPolicy string              `json:"previewPolicy,omitempty"`
	Allowed       bool                `json:"allowed"`
	Reason        string              `json:"reason,omitempty"`
	CheckResults  []types.CheckResult `json:"checkResults,omitempty"`
}

type resolvedDigest struct {
	digest      string
	indexDigest string
}

func runVerify(
	imageRef, namespace, outputFormat string, cfg *config.Config, previewPolicy string,
) int {
	return runVerifyTo(os.Stdout, imageRef, namespace, outputFormat, cfg, previewPolicy)
}

func runVerifyTo(
	writer io.Writer,
	imageRef, namespace, outputFormat string, cfg *config.Config, previewPolicy string,
) int {
	return withVerifier(writer, outputFormat, cfg, func(
		ctx context.Context, w io.Writer, v *verifier.Verifier, c *registry.TransportCache,
	) int {
		return executeVerify(ctx, w, imageRef, namespace, outputFormat, cfg, v, c, previewPolicy)
	})
}

func executeVerify(
	ctx context.Context, writer io.Writer,
	imageRef, namespace, outputFormat string,
	cfg *config.Config, verif *verifier.Verifier,
	cache *registry.TransportCache, previewPolicy string,
) int {
	policyFile := resolvePolicyFile(cfg.PolicyDir, namespace)

	resolved, err := resolveDigest(ctx, imageRef, cfg.FetchTimeout.Duration, cache)
	if err != nil {
		slog.Error("Failed to resolve image digest", "image", imageRef, "error", err)

		return exitError
	}

	result, err := verif.Verify(
		ctx, imageRef, resolved.digest, resolved.indexDigest, namespace, "",
	)
	out := newVerifyOutput(imageRef, resolved.digest, namespace, policyFile)
	out.Mode = string(verif.EffectiveModeForNamespace(namespace))
	out.PreviewPolicy = previewPolicy
	out.CheckResults = checksFrom(result)

	if err != nil {
		slog.Error("Verification failed", "image", imageRef, "error", err)

		out.Reason = err.Error()

		outErr := outputVerifyResult(writer, outputFormat, out)
		if outErr != nil {
			slog.Error("Failed to write output", "error", outErr)
		}

		return exitCodeForVerifyError(err)
	}

	out.Allowed = result.Allowed
	out.Reason = result.Reason

	outErr := outputVerifyResult(writer, outputFormat, out)
	if outErr != nil {
		slog.Error("Failed to write output", "error", outErr)

		return exitError
	}

	if !result.Allowed {
		return exitDenied
	}

	return exitSuccess
}

func runVerifyBatch(
	images []string, namespace, outputFormat string, cfg *config.Config, previewPolicy string,
) int {
	return runVerifyBatchTo(os.Stdout, images, namespace, outputFormat, cfg, previewPolicy)
}

func runVerifyBatchTo(
	writer io.Writer,
	images []string, namespace, outputFormat string, cfg *config.Config, previewPolicy string,
) int {
	return withVerifier(writer, outputFormat, cfg, func(
		ctx context.Context, w io.Writer, v *verifier.Verifier, c *registry.TransportCache,
	) int {
		return executeBatchVerify(ctx, w, images, namespace, outputFormat, cfg, v, c, previewPolicy)
	})
}

func withVerifier(
	writer io.Writer, outputFormat string, cfg *config.Config,
	execute func(context.Context, io.Writer, *verifier.Verifier, *registry.TransportCache) int,
) int {
	if outputFormat != outputFormatTable && outputFormat != outputFormatJSON {
		slog.Error("Invalid output format", "format", outputFormat)

		return exitError
	}

	if !cfg.Enabled() {
		slog.Error(
			"verify requires verification to be enabled" +
				" (set verification = \"warn\" or \"enforce\" in the config file)",
		)

		return exitError
	}

	cfg.WarnInsecureRegistries()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cache := registry.NewTransportCacheOrNil(cfg.Registries)

	verif, err := newVerifier(ctx, cfg, cache)
	if err != nil {
		slog.Error("Failed to create verifier", "error", err)

		return exitError
	}

	defer verif.Stop()

	return execute(ctx, writer, verif, cache)
}

func executeBatchVerify(
	ctx context.Context, writer io.Writer,
	images []string, namespace, outputFormat string,
	cfg *config.Config, verif *verifier.Verifier,
	cache *registry.TransportCache, previewPolicy string,
) int {
	results := make([]*verifyOutput, 0, len(images))
	worstCode := exitSuccess

	for _, imageRef := range images {
		if ctx.Err() != nil {
			slog.Error("Batch verification interrupted", "error", ctx.Err())

			return exitError
		}

		code, out := verifySingleImage(ctx, imageRef, namespace, cfg, verif, cache, previewPolicy)
		results = append(results, out)

		if code > worstCode {
			worstCode = code
		}
	}

	outErr := outputBatchResults(writer, outputFormat, results)
	if outErr != nil {
		slog.Error("Failed to write output", "error", outErr)

		return exitError
	}

	return worstCode
}

func verifySingleImage(
	ctx context.Context, imageRef, namespace string,
	cfg *config.Config, verif *verifier.Verifier,
	cache *registry.TransportCache, previewPolicy string,
) (int, *verifyOutput) {
	policyFile := resolvePolicyFile(cfg.PolicyDir, namespace)

	resolved, err := resolveDigest(ctx, imageRef, cfg.FetchTimeout.Duration, cache)
	if err != nil {
		slog.Error("Failed to resolve image digest", "image", imageRef, "error", err)

		out := newVerifyOutput(imageRef, "", namespace, policyFile)
		out.Mode = string(verif.EffectiveModeForNamespace(namespace))
		out.PreviewPolicy = previewPolicy
		out.Reason = err.Error()

		return exitCodeForVerifyError(err), out
	}

	result, err := verif.Verify(
		ctx, imageRef, resolved.digest, resolved.indexDigest, namespace, "",
	)
	out := newVerifyOutput(imageRef, resolved.digest, namespace, policyFile)
	out.Mode = string(verif.EffectiveModeForNamespace(namespace))
	out.PreviewPolicy = previewPolicy
	out.CheckResults = checksFrom(result)

	if err != nil {
		slog.Error("Verification failed", "image", imageRef, "error", err)

		out.Reason = err.Error()

		return exitCodeForVerifyError(err), out
	}

	out.Allowed = result.Allowed
	out.Reason = result.Reason

	if !result.Allowed {
		return exitDenied, out
	}

	return exitSuccess, out
}

func outputBatchResults(writer io.Writer, format string, results []*verifyOutput) error {
	switch format {
	case outputFormatJSON:
		return outputBatchJSON(writer, results)
	default:
		return outputBatchTable(writer, results)
	}
}

func outputBatchJSON(writer io.Writer, results []*verifyOutput) error {
	enc := json.NewEncoder(writer)
	enc.SetIndent("", "  ")

	err := enc.Encode(results)
	if err != nil {
		return fmt.Errorf("encoding batch JSON output: %w", err)
	}

	return nil
}

func outputBatchTable(writer io.Writer, results []*verifyOutput) error {
	for i, out := range results {
		if i > 0 {
			_, _ = fmt.Fprintln(writer)
		}

		err := outputVerifyTable(writer, out)
		if err != nil {
			return err
		}
	}

	return nil
}

func exitCodeForVerifyError(err error) int {
	if errors.Is(err, verifier.ErrVerificationFailed) {
		return exitDenied
	}

	return exitError
}

func newVerifier(
	ctx context.Context, cfg *config.Config, cache *registry.TransportCache,
) (*verifier.Verifier, error) {
	met := metrics.New()

	fetcher, err := verifier.NewFetcher(ctx, cfg, cache)
	if err != nil {
		return nil, fmt.Errorf("creating fetcher: %w", err)
	}

	v, err := verifier.New(ctx, cfg, met, fetcher)
	if err != nil {
		return nil, fmt.Errorf("creating verifier: %w", err)
	}

	return v, nil
}

func resolveDigest(
	parent context.Context, imageRef string, timeout time.Duration,
	cache *registry.TransportCache,
) (resolvedDigest, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	digest, indexDigest, _, err := registry.ResolveWithRegistries(ctx, imageRef, cache)
	if err != nil {
		return resolvedDigest{}, fmt.Errorf("resolving digest: %w", err)
	}

	return resolvedDigest{digest: digest, indexDigest: indexDigest}, nil
}

func checksFrom(result *types.Result) []types.CheckResult {
	if result != nil {
		return result.CheckResults
	}

	return nil
}

func resolvePolicyFile(policyDir, namespace string) string {
	nsFile := filepath.Join(policyDir, filepath.Base(namespace)+".json")

	_, err := os.Stat(nsFile)
	if err == nil {
		return nsFile
	}

	slog.Debug("Namespace policy not found, falling back to default",
		"namespace", namespace, "tried", nsFile)

	return filepath.Join(policyDir, "default.json")
}

func newVerifyOutput(
	imageRef, digest, namespace, policyFile string,
) *verifyOutput {
	return &verifyOutput{
		Image:         imageRef,
		Digest:        digest,
		Namespace:     namespace,
		PolicyFile:    policyFile,
		Mode:          "",
		PreviewPolicy: "",
		Allowed:       false,
		Reason:        "",
		CheckResults:  nil,
	}
}

func outputVerifyResult(writer io.Writer, format string, out *verifyOutput) error {
	switch format {
	case outputFormatJSON:
		return outputVerifyJSON(writer, out)
	default:
		return outputVerifyTable(writer, out)
	}
}

func outputVerifyJSON(writer io.Writer, out *verifyOutput) error {
	enc := json.NewEncoder(writer)
	enc.SetIndent("", "  ")

	err := enc.Encode(out)
	if err != nil {
		return fmt.Errorf("encoding JSON output: %w", err)
	}

	return nil
}

//nolint:gochecknoglobals // reusable color formatters
var (
	colorGreen  = color.New(color.FgGreen, color.Bold)
	colorRed    = color.New(color.FgRed, color.Bold)
	colorYellow = color.New(color.FgYellow)
	colorBold   = color.New(color.Bold)
	colorItalic = color.New(color.Italic)
)

func outputVerifyTable(writer io.Writer, out *verifyOutput) error {
	if out.PreviewPolicy != "" {
		_, _ = fmt.Fprintf(
			writer,
			"%s %s\n",
			colorYellow.Sprint(
				"Preview:",
			),
			out.PreviewPolicy+" (dry-run, not using configured policies)",
		)
	}

	_, _ = fmt.Fprintf(writer, "%s %s\n", colorBold.Sprint("Image:"), out.Image)
	_, _ = fmt.Fprintf(writer, "%s %s\n", colorBold.Sprint("Digest:"), out.Digest)
	_, _ = fmt.Fprintf(writer, "%s %s\n",
		colorBold.Sprint("Namespace:"), colorItalic.Sprint(out.Namespace))
	_, _ = fmt.Fprintf(writer, "%s %s\n", colorBold.Sprint("Policy:"), out.PolicyFile)
	_, _ = fmt.Fprintf(writer, "%s %s\n", colorBold.Sprint("Mode:"), colorMode(out.Mode))

	resultText := colorGreen.Sprint("ALLOWED")

	if !out.Allowed {
		resultText = colorRed.Sprint("DENIED")
	}

	_, _ = fmt.Fprintf(writer, "%s %s\n", colorBold.Sprint("Result:"), resultText)

	if out.Reason != "" {
		_, _ = fmt.Fprintf(writer, "%s %s\n", colorBold.Sprint("Reason:"), out.Reason)
	}

	if len(out.CheckResults) == 0 {
		return nil
	}

	_, _ = fmt.Fprintln(writer)

	return renderCheckTable(writer, out.CheckResults)
}

func renderCheckTable(writer io.Writer, checks []types.CheckResult) error {
	table := newBorderlessTable(writer, []string{"Type", "Status", "Detail"})

	for _, check := range checks {
		detail := check.Detail
		if detail == "" {
			detail = "-"
		}

		status := colorStatus(check.Status)

		err := table.Append([]string{
			strings.ToUpper(string(check.Type)),
			status,
			detail,
		})
		if err != nil {
			return fmt.Errorf("appending table row: %w", err)
		}
	}

	err := table.Render()
	if err != nil {
		return fmt.Errorf("rendering table: %w", err)
	}

	return nil
}

func logVerbosePreamble(
	writer io.Writer, images []string, namespace string, cfg *config.Config,
) {
	mode := colorMode(string(cfg.Verification))
	_, _ = fmt.Fprintf(writer, "%s %s\n", colorBold.Sprint("Mode:"), mode)
	_, _ = fmt.Fprintf(writer, "%s %s\n",
		colorBold.Sprint("Policy dir:"), cfg.PolicyDir)
	_, _ = fmt.Fprintf(writer, "%s %s\n",
		colorBold.Sprint("Namespace:"), colorItalic.Sprint(namespace))
	_, _ = fmt.Fprintf(writer, "%s %v\n",
		colorBold.Sprint("Fetch timeout:"), cfg.FetchTimeout.Duration)
	_, _ = fmt.Fprintf(writer, "%s %s\n",
		colorBold.Sprint("Fetch failure policy:"),
		string(cfg.FetchFailurePolicy))
	_, _ = fmt.Fprintf(writer, "%s %v\n",
		colorBold.Sprint("Verification timeout:"),
		cfg.VerificationTimeout.Duration)
	_, _ = fmt.Fprintf(writer, "%s %s\n",
		colorBold.Sprint("Images:"), strings.Join(images, ", "))
	_, _ = fmt.Fprintln(writer)
}

func colorMode(mode string) string {
	switch config.VerificationMode(mode) {
	case config.ModeWarn:
		return colorYellow.Sprint(mode)
	case config.ModeEnforce:
		return colorRed.Sprint(mode)
	case config.ModeDisabled:
		return mode
	}

	return mode
}

func setupPreviewPolicyDir(previewPolicyPath, namespace string) (string, error) {
	data, err := fileutil.ReadLimited(previewPolicyPath, fileutil.MaxCredentialFileSize)
	if err != nil {
		return "", fmt.Errorf("reading preview policy %q: %w", previewPolicyPath, err)
	}

	tmpDir, err := os.MkdirTemp("", "nri-supply-chain-preview-*")
	if err != nil {
		return "", fmt.Errorf("creating temp dir: %w", err)
	}

	filename := filepath.Base(namespace) + ".json"
	if namespace == policy.DefaultPolicyLabel {
		filename = "default.json"
	}

	//nolint:mnd // permission is intentional
	err = os.WriteFile(filepath.Join(tmpDir, filename), data, 0o600)
	if err != nil {
		_ = os.RemoveAll(tmpDir)

		return "", fmt.Errorf("writing preview policy: %w", err)
	}

	return tmpDir, nil
}

func colorStatus(status types.CheckStatus) string {
	switch status {
	case types.StatusPass:
		return colorGreen.Sprint(string(status))
	case types.StatusWarn:
		return colorYellow.Sprint(string(status))
	case types.StatusFail:
		return colorRed.Sprint(string(status))
	default:
		return string(status)
	}
}

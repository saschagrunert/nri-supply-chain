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
	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/tw"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/registry"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

type verifyOutput struct {
	Image        string              `json:"image"`
	Digest       string              `json:"digest"`
	Namespace    string              `json:"namespace"`
	PolicyFile   string              `json:"-"`
	Mode         string              `json:"-"`
	Allowed      bool                `json:"allowed"`
	Reason       string              `json:"reason,omitempty"`
	CheckResults []types.CheckResult `json:"checkResults,omitempty"`
}

type resolvedDigest struct {
	digest      string
	indexDigest string
}

func runVerify(
	imageRef, namespace, outputFormat string, cfg *config.Config,
) int {
	return runVerifyTo(os.Stdout, imageRef, namespace, outputFormat, cfg)
}

func runVerifyTo(
	writer io.Writer,
	imageRef, namespace, outputFormat string, cfg *config.Config,
) int {
	if outputFormat != outputFormatTable && outputFormat != outputFormatJSON {
		slog.Error("Invalid output format", "format", outputFormat)

		return exitError
	}

	if !cfg.Enabled() {
		slog.Error("verify requires verification to be enabled")

		return exitError
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	verif, err := newVerifier(ctx, cfg)
	if err != nil {
		slog.Error("Failed to create verifier", "error", err)

		return exitError
	}

	defer verif.Stop()

	return executeVerify(ctx, writer, imageRef, namespace, outputFormat, cfg, verif)
}

func executeVerify(
	ctx context.Context, writer io.Writer,
	imageRef, namespace, outputFormat string,
	cfg *config.Config, verif *verifier.Verifier,
) int {
	policyFile := resolvePolicyFile(cfg.PolicyDir, namespace)

	resolved, err := resolveDigest(ctx, imageRef, cfg.FetchTimeout.Duration)
	if err != nil {
		slog.Error("Failed to resolve image digest", "image", imageRef, "error", err)

		return exitError
	}

	result, err := verif.Verify(
		ctx, imageRef, resolved.digest, resolved.indexDigest, namespace,
	)
	out := newVerifyOutput(imageRef, resolved.digest, namespace, policyFile)
	out.Mode = string(verif.EffectiveModeForNamespace(namespace))
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
	images []string, namespace, outputFormat string, cfg *config.Config,
) int {
	return runVerifyBatchTo(os.Stdout, images, namespace, outputFormat, cfg)
}

func runVerifyBatchTo(
	writer io.Writer,
	images []string, namespace, outputFormat string, cfg *config.Config,
) int {
	if outputFormat != outputFormatTable && outputFormat != outputFormatJSON {
		slog.Error("Invalid output format", "format", outputFormat)

		return exitError
	}

	if !cfg.Enabled() {
		slog.Error("verify requires verification to be enabled")

		return exitError
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	verif, err := newVerifier(ctx, cfg)
	if err != nil {
		slog.Error("Failed to create verifier", "error", err)

		return exitError
	}

	defer verif.Stop()

	return executeBatchVerify(ctx, writer, images, namespace, outputFormat, cfg, verif)
}

func executeBatchVerify(
	ctx context.Context, writer io.Writer,
	images []string, namespace, outputFormat string,
	cfg *config.Config, verif *verifier.Verifier,
) int {
	results := make([]*verifyOutput, 0, len(images))
	worstCode := exitSuccess

	for _, imageRef := range images {
		if ctx.Err() != nil {
			slog.Error("Batch verification interrupted", "error", ctx.Err())

			return exitError
		}

		code, out := verifySingleImage(ctx, imageRef, namespace, cfg, verif)
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
) (int, *verifyOutput) {
	policyFile := resolvePolicyFile(cfg.PolicyDir, namespace)

	resolved, err := resolveDigest(ctx, imageRef, cfg.FetchTimeout.Duration)
	if err != nil {
		slog.Error("Failed to resolve image digest", "image", imageRef, "error", err)

		out := newVerifyOutput(imageRef, "", namespace, policyFile)
		out.Mode = string(verif.EffectiveModeForNamespace(namespace))
		out.Reason = err.Error()

		return exitCodeForVerifyError(err), out
	}

	result, err := verif.Verify(
		ctx, imageRef, resolved.digest, resolved.indexDigest, namespace,
	)
	out := newVerifyOutput(imageRef, resolved.digest, namespace, policyFile)
	out.Mode = string(verif.EffectiveModeForNamespace(namespace))
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
	ctx context.Context, cfg *config.Config,
) (*verifier.Verifier, error) {
	met := metrics.New()

	fetcher, err := verifier.NewFetcher(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("creating fetcher: %w", err)
	}

	v, err := verifier.New(cfg, met, fetcher)
	if err != nil {
		return nil, fmt.Errorf("creating verifier: %w", err)
	}

	return v, nil
}

func resolveDigest(
	parent context.Context, imageRef string, timeout time.Duration,
) (resolvedDigest, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	digest, indexDigest, err := registry.ResolveWithDefaultKeychain(ctx, imageRef)
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
	nsFile := filepath.Join(policyDir, namespace+".json")

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
		Image:        imageRef,
		Digest:       digest,
		Namespace:    namespace,
		PolicyFile:   policyFile,
		Mode:         "",
		Allowed:      false,
		Reason:       "",
		CheckResults: nil,
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
	padding := tw.Padding{Left: "", Right: "   "}

	table := tablewriter.NewTable(writer,
		tablewriter.WithHeader([]string{"Type", "Status", "Detail"}),
		tablewriter.WithHeaderAlignment(tw.AlignLeft),
		tablewriter.WithRowAlignment(tw.AlignLeft),
		tablewriter.WithRowAutoWrap(tw.WrapNone),
		tablewriter.WithPadding(padding),
		tablewriter.WithRendition(tw.Rendition{
			Borders: tw.Border{
				Left: tw.Off, Right: tw.Off, Top: tw.Off, Bottom: tw.Off,
			},
			Settings: tw.Settings{
				Separators: tw.Separators{
					BetweenColumns: tw.Off,
					ShowHeader:     tw.Off,
				},
				Lines: tw.Lines{
					ShowHeaderLine: tw.Off,
					ShowTop:        tw.Off,
					ShowBottom:     tw.Off,
				},
			},
		}),
	)

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

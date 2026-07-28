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
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"

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

func runVerify(opts *options, cfg *config.Config) int {
	return runVerifyTo(os.Stdout, opts, cfg)
}

func runVerifyTo(writer io.Writer, opts *options, cfg *config.Config) int {
	if opts.outputFormat != outputFormatTable && opts.outputFormat != outputFormatJSON {
		slog.Error("Invalid output format", "format", opts.outputFormat)

		return 1
	}

	if !cfg.Enabled() {
		slog.Error("--verify-image requires verification to be enabled")

		return 1
	}

	imageRef := opts.verifyImage
	namespace := opts.verifyNamespace
	policyFile := resolvePolicyFile(cfg.PolicyDir, namespace)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	verif, err := newVerifier(ctx, cfg)
	if err != nil {
		slog.Error("Failed to create verifier", "error", err)

		return 1
	}

	defer verif.Stop()

	resolved, err := resolveDigest(ctx, imageRef, cfg.FetchTimeout.Duration)
	if err != nil {
		slog.Error("Failed to resolve image digest", "image", imageRef, "error", err)

		return 1
	}

	result, err := verif.Verify(
		ctx, imageRef, resolved.digest, resolved.indexDigest, namespace,
	)
	out := newVerifyOutput(imageRef, resolved.digest, namespace, policyFile, cfg)
	out.CheckResults = checksFrom(result)

	if err != nil {
		slog.Error("Verification failed", "image", imageRef, "error", err)

		out.Reason = err.Error()
		outputVerifyResult(writer, opts.outputFormat, out)

		return 1
	}

	out.Allowed = result.Allowed
	out.Reason = result.Reason
	outputVerifyResult(writer, opts.outputFormat, out)

	if !result.Allowed {
		return 1
	}

	return 0
}

func newVerifier(
	ctx context.Context, cfg *config.Config,
) (*verifier.Verifier, error) {
	met := metrics.New()
	fetcher := verifier.NewFetcher(ctx, cfg)

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
	imageRef, digest, namespace, policyFile string, cfg *config.Config,
) *verifyOutput {
	return &verifyOutput{
		Image:        imageRef,
		Digest:       digest,
		Namespace:    namespace,
		PolicyFile:   policyFile,
		Mode:         string(cfg.Verification),
		Allowed:      false,
		Reason:       "",
		CheckResults: nil,
	}
}

func outputVerifyResult(writer io.Writer, format string, out *verifyOutput) {
	switch format {
	case outputFormatJSON:
		outputVerifyJSON(writer, out)
	default:
		outputVerifyTable(writer, out)
	}
}

func outputVerifyJSON(writer io.Writer, out *verifyOutput) {
	enc := json.NewEncoder(writer)
	enc.SetIndent("", "  ")

	encErr := enc.Encode(out)
	if encErr != nil {
		slog.Error("Failed to encode verify output", "error", encErr)
	}
}

//nolint:gochecknoglobals // reusable color formatters
var (
	colorGreen  = color.New(color.FgGreen, color.Bold)
	colorRed    = color.New(color.FgRed, color.Bold)
	colorYellow = color.New(color.FgYellow)
	colorBold   = color.New(color.Bold)
	colorItalic = color.New(color.Italic)
)

func outputVerifyTable(writer io.Writer, out *verifyOutput) {
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
		return
	}

	_, _ = fmt.Fprintln(writer)

	renderCheckTable(writer, out.CheckResults)
}

func renderCheckTable(writer io.Writer, checks []types.CheckResult) {
	table := tablewriter.NewWriter(writer)
	table.SetHeader([]string{"Type", "Status", "Detail"})
	table.SetAutoWrapText(false)
	table.SetBorder(false)
	table.SetColumnSeparator("")
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetHeaderLine(false)
	table.SetTablePadding("   ")
	table.SetNoWhiteSpace(true)

	for _, check := range checks {
		detail := check.Detail
		if detail == "" {
			detail = "-"
		}

		status := colorStatus(check.Status)

		table.Append([]string{
			strings.ToUpper(string(check.Type)),
			status,
			detail,
		})
	}

	table.Render()
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

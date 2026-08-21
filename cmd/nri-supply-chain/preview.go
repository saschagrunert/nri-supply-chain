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
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/registry"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

func newPreviewCmd(configPath, logLevel *string) *cobra.Command {
	var (
		namespace     string
		outputFormat  string
		imagesFile    string
		comparePolicy string
	)

	cmd := &cobra.Command{
		Use:   cmdPreview + " [<image>...]",
		Short: "Preview policy verification without blocking",
		Long: "Preview policy verification against a set of images to assess\n" +
			"the impact of policy changes before enabling enforce mode.\n\n" +
			"Images can be passed as positional arguments and/or via --images-file.\n" +
			"Use --compare-policy to diff results between two policy sets.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true

			return runPreviewCmd(
				configPath, logLevel, args, namespace, outputFormat,
				imagesFile, comparePolicy,
			)
		},
	}

	cmd.Flags().StringVarP(&namespace, "namespace", "n",
		policy.DefaultPolicyLabel, "namespace for policy resolution")
	cmd.Flags().StringVarP(&outputFormat, "output", "o",
		outputFormatTable, "output format: table, json")
	cmd.Flags().StringVar(&imagesFile, "images-file", "",
		"file containing image references (one per line)")
	cmd.Flags().StringVar(&comparePolicy, "compare-policy", "",
		"path to alternative policy directory for side-by-side comparison")

	return cmd
}

func runPreviewCmd(
	configPath, logLevel *string,
	args []string, namespace, outputFormat, imagesFile, comparePolicy string,
) error {
	images, err := loadImages(args, imagesFile)
	if err != nil {
		slog.Error("Failed to load images", "error", err)

		return errExitNonZero
	}

	if len(images) == 0 {
		slog.Error("No images specified; pass images as arguments or use --images-file")

		return errExitNonZero
	}

	cfg, err := setupConfig(*configPath)
	if err != nil {
		slog.Error("Setup failed", "error", err)

		return errExitNonZero
	}

	level := effectiveLogLevel(*logLevel, cfg.LogLevel)
	initLogging(level, true)

	code := runPreview(
		os.Stdout, images, namespace, outputFormat, comparePolicy, cfg,
	)
	if code != exitSuccess {
		return errExitNonZero
	}

	return nil
}

func loadImages(args []string, imagesFile string) ([]string, error) {
	images := append([]string{}, args...)

	if imagesFile != "" {
		fileImages, err := readImagesFile(imagesFile)
		if err != nil {
			return nil, err
		}

		images = append(images, fileImages...)
	}

	return deduplicateImages(images), nil
}

func deduplicateImages(images []string) []string {
	seen := make(map[string]struct{}, len(images))
	result := make([]string, 0, len(images))

	for _, img := range images {
		if _, exists := seen[img]; exists {
			continue
		}

		seen[img] = struct{}{}

		result = append(result, img)
	}

	return result
}

func readImagesFile(path string) ([]string, error) {
	cleanPath := filepath.Clean(path)

	file, err := os.Open(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("opening images file: %w", err)
	}

	defer func() {
		closeErr := file.Close()
		if closeErr != nil {
			slog.Warn("Failed to close images file", "error", closeErr)
		}
	}()

	var images []string

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			images = append(images, line)
		}
	}

	scanErr := scanner.Err()
	if scanErr != nil {
		return nil, fmt.Errorf("reading images file: %w", scanErr)
	}

	return images, nil
}

func runPreview(
	writer io.Writer,
	images []string, namespace, outputFormat, comparePolicy string,
	cfg *config.Config,
) int {
	if comparePolicy != "" {
		return runPreviewDiff(writer, images, namespace, outputFormat, comparePolicy, cfg)
	}

	return withVerifier(writer, outputFormat, cfg, func(
		ctx context.Context, w io.Writer, v *verifier.Verifier, c *registry.TransportCache,
	) int {
		return executePreview(ctx, w, images, namespace, outputFormat, cfg, v, c)
	})
}

func executePreview(
	ctx context.Context, writer io.Writer,
	images []string, namespace, outputFormat string,
	cfg *config.Config, verif *verifier.Verifier,
	cache *registry.TransportCache,
) int {
	results := previewImages(ctx, images, namespace, cfg, verif, cache)
	summary := aggregateResults(results)
	suggestions := generateSuggestions(summary)

	out := &previewOutput{
		Images:      results,
		Summary:     summary,
		Suggestions: suggestions,
	}

	outErr := outputPreviewResult(writer, outputFormat, out)
	if outErr != nil {
		slog.Error("Failed to write output", "error", outErr)

		return exitError
	}

	return exitSuccess
}

func previewImages(
	ctx context.Context,
	images []string, namespace string,
	cfg *config.Config, verif *verifier.Verifier,
	cache *registry.TransportCache,
) []*verifyOutput {
	results := make([]*verifyOutput, 0, len(images))

	for _, imageRef := range images {
		if ctx.Err() != nil {
			slog.Error("Preview interrupted", "error", ctx.Err())

			break
		}

		_, out := verifySingleImage(ctx, imageRef, namespace, cfg, verif, cache, "")
		results = append(results, out)
	}

	return results
}

type previewOutput struct {
	Images      []*verifyOutput `json:"images"`
	Summary     previewSummary  `json:"summary"`
	Suggestions []string        `json:"suggestions,omitempty"`
}

type previewSummary struct {
	Total   int                     `json:"total"`
	Allowed int                     `json:"allowed"`
	Denied  int                     `json:"denied"`
	Errors  int                     `json:"errors"`
	Checks  map[string]checkSummary `json:"checks"`
}

type checkSummary struct {
	Pass int `json:"pass"`
	Warn int `json:"warn"`
	Fail int `json:"fail"`
}

func aggregateResults(results []*verifyOutput) previewSummary {
	summary := previewSummary{
		Total:   len(results),
		Allowed: 0,
		Denied:  0,
		Errors:  0,
		Checks:  make(map[string]checkSummary),
	}

	for _, out := range results {
		classifyResult(&summary, out)
	}

	return summary
}

func classifyResult(summary *previewSummary, out *verifyOutput) {
	switch {
	case out.Digest == "" && out.Reason != "":
		summary.Errors++
	case out.Allowed:
		summary.Allowed++
	default:
		summary.Denied++
	}

	for _, check := range out.CheckResults {
		checkName := string(check.Type)
		entry := summary.Checks[checkName]

		incrementCheckSummary(&entry, check.Status)

		summary.Checks[checkName] = entry
	}
}

func incrementCheckSummary(entry *checkSummary, status types.CheckStatus) {
	switch status {
	case types.StatusPass:
		entry.Pass++
	case types.StatusWarn:
		entry.Warn++
	case types.StatusFail:
		entry.Fail++
	}
}

func generateSuggestions(summary previewSummary) []string {
	if summary.Total == 0 {
		return nil
	}

	// Exclude errored images from the denominator: they have no check results,
	// so including them would inflate the count and suppress valid suggestions.
	verified := summary.Total - summary.Errors

	var suggestions []string

	for _, checkType := range types.AttestationCheckTypes {
		checkName := string(checkType)

		entry, exists := summary.Checks[checkName]
		if !exists {
			continue
		}

		suggestions = appendSuggestion(suggestions, checkName, entry, verified)
	}

	if summary.Denied > 0 && summary.Allowed > 0 {
		suggestions = append(suggestions, fmt.Sprintf(
			"%d/%d images would be denied; review failing checks before enabling enforce mode",
			summary.Denied, verified,
		))
	}

	if summary.Denied == 0 && summary.Errors == 0 && summary.Allowed == verified && verified > 0 {
		suggestions = append(suggestions,
			"All images pass; this policy set is safe to promote to enforce mode",
		)
	}

	return suggestions
}

func appendSuggestion(
	suggestions []string, checkName string, entry checkSummary, total int,
) []string {
	allPass := total > 0 && entry.Pass == total && entry.Fail == 0 && entry.Warn == 0

	if allPass {
		suggestions = append(suggestions, fmt.Sprintf(
			"All %d images pass %s; consider setting %s.missingPolicy=deny",
			total, strings.ToUpper(checkName), checkName,
		))
	}

	if entry.Fail > 0 {
		suggestions = append(suggestions, fmt.Sprintf(
			"%d/%d images fail %s checks",
			entry.Fail, total, strings.ToUpper(checkName),
		))
	}

	return suggestions
}

func outputPreviewResult(writer io.Writer, format string, out *previewOutput) error {
	switch format {
	case outputFormatJSON:
		return outputPreviewJSON(writer, out)
	default:
		return outputPreviewTable(writer, out)
	}
}

func outputPreviewJSON(writer io.Writer, out *previewOutput) error {
	enc := json.NewEncoder(writer)
	enc.SetIndent("", "  ")

	encErr := enc.Encode(out)
	if encErr != nil {
		return fmt.Errorf("encoding preview JSON output: %w", encErr)
	}

	return nil
}

func outputPreviewTable(writer io.Writer, out *previewOutput) error {
	err := renderPreviewSummary(writer, out)
	if err != nil {
		return err
	}

	if len(out.Suggestions) > 0 {
		_, _ = fmt.Fprintf(writer, "\n%s\n", colorBold.Sprint("Suggestions:"))

		for _, suggestion := range out.Suggestions {
			_, _ = fmt.Fprintf(writer, "  - %s\n", suggestion)
		}
	}

	_, _ = fmt.Fprintln(writer)

	for idx, img := range out.Images {
		if idx > 0 {
			_, _ = fmt.Fprintln(writer)
		}

		tableErr := outputVerifyTable(writer, img)
		if tableErr != nil {
			return tableErr
		}
	}

	return nil
}

func renderPreviewSummary(writer io.Writer, out *previewOutput) error {
	_, _ = fmt.Fprintf(writer, "%s\n", colorBold.Sprint("Preview Summary"))
	_, _ = fmt.Fprintf(writer, "%s %d\n", colorBold.Sprint("Total:"), out.Summary.Total)
	_, _ = fmt.Fprintf(writer, "%s %s\n",
		colorBold.Sprint("Allowed:"), colorGreen.Sprint(out.Summary.Allowed))
	_, _ = fmt.Fprintf(writer, "%s %s\n",
		colorBold.Sprint("Denied:"), formatDenied(out.Summary.Denied))

	if out.Summary.Errors > 0 {
		_, _ = fmt.Fprintf(writer, "%s %s\n",
			colorBold.Sprint("Errors:"), colorRed.Sprint(out.Summary.Errors))
	}

	if len(out.Summary.Checks) > 0 {
		_, _ = fmt.Fprintln(writer)

		return renderCheckSummaryTable(writer, out.Summary.Checks)
	}

	return nil
}

func formatDenied(denied int) string {
	if denied > 0 {
		return colorRed.Sprint(denied)
	}

	return colorGreen.Sprint(denied)
}

func renderCheckSummaryTable(
	writer io.Writer, checks map[string]checkSummary,
) error {
	table := newBorderlessTable(writer, []string{"Check", "Pass", "Warn", "Fail"})

	for _, checkType := range types.AttestationCheckTypes {
		checkName := string(checkType)

		entry, exists := checks[checkName]
		if !exists {
			continue
		}

		appendErr := table.Append([]string{
			strings.ToUpper(checkName),
			colorGreen.Sprint(entry.Pass),
			colorYellow.Sprint(entry.Warn),
			formatFailCount(entry.Fail),
		})
		if appendErr != nil {
			return fmt.Errorf("appending check summary row: %w", appendErr)
		}
	}

	renderErr := table.Render()
	if renderErr != nil {
		return fmt.Errorf("rendering check summary table: %w", renderErr)
	}

	return nil
}

func formatFailCount(count int) string {
	if count > 0 {
		return colorRed.Sprint(count)
	}

	return strconv.Itoa(count)
}

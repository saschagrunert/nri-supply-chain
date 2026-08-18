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
	"slices"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/registry"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

type previewDiffOutput struct {
	Images  []previewDiffImage `json:"images"`
	Summary previewDiffSummary `json:"summary"`
}

type previewDiffImage struct {
	Image    string       `json:"image"`
	Changed  bool         `json:"changed"`
	Current  verifyOutput `json:"current"`
	Proposed verifyOutput `json:"proposed"`
}

type previewDiffSummary struct {
	Total     int `json:"total"`
	Changed   int `json:"changed"`
	Unchanged int `json:"unchanged"`
	NewDenied int `json:"newDenied"`
	NewAllow  int `json:"newAllow"`
}

func runPreviewDiff(
	writer io.Writer,
	images []string, namespace, outputFormat, comparePolicyDir string,
	cfg *config.Config,
) int {
	return withVerifier(writer, outputFormat, cfg, func(
		ctx context.Context, w io.Writer,
		currentVerif *verifier.Verifier, cache *registry.TransportCache,
	) int {
		return executeDiff(
			ctx, w, images, namespace, outputFormat, comparePolicyDir,
			cfg, currentVerif, cache,
		)
	})
}

func executeDiff(
	ctx context.Context, writer io.Writer,
	images []string, namespace, outputFormat, comparePolicyDir string,
	cfg *config.Config, currentVerif *verifier.Verifier,
	cache *registry.TransportCache,
) int {
	currentResults := previewImages(ctx, images, namespace, cfg, currentVerif, cache)

	if ctx.Err() != nil {
		slog.Error("Context cancelled before proposed policy preview", "error", ctx.Err())

		return exitError
	}

	proposedResults, err := runProposedPreview(
		ctx, images, namespace, comparePolicyDir, cfg, cache,
	)
	if err != nil {
		slog.Error("Failed to create verifier for proposed policy", "error", err)

		return exitError
	}

	if ctx.Err() != nil {
		slog.Error("Context cancelled during proposed policy preview", "error", ctx.Err())

		return exitError
	}

	out := buildDiffOutput(currentResults, proposedResults)

	outErr := outputDiffResult(writer, outputFormat, out)
	if outErr != nil {
		slog.Error("Failed to write diff output", "error", outErr)

		return exitError
	}

	return exitSuccess
}

func runProposedPreview(
	ctx context.Context,
	images []string, namespace, comparePolicyDir string,
	cfg *config.Config, cache *registry.TransportCache,
) ([]*verifyOutput, error) {
	proposedCfg := *cfg
	proposedCfg.PolicyDir = comparePolicyDir
	proposedCfg.Registries = slices.Clone(cfg.Registries)

	proposedVerif, err := newVerifier(ctx, &proposedCfg, cache)
	if err != nil {
		return nil, fmt.Errorf("creating proposed verifier: %w", err)
	}

	defer proposedVerif.Stop()

	return previewImages(ctx, images, namespace, &proposedCfg, proposedVerif, cache), nil
}

func buildDiffOutput(
	current, proposed []*verifyOutput,
) *previewDiffOutput {
	count := min(len(current), len(proposed))

	if len(current) != len(proposed) {
		slog.Warn("Result set length mismatch in diff; trailing images dropped",
			"current", len(current), "proposed", len(proposed))
	}

	out := &previewDiffOutput{
		Images: make([]previewDiffImage, 0, count),
		Summary: previewDiffSummary{
			Total:     count,
			Changed:   0,
			Unchanged: 0,
			NewDenied: 0,
			NewAllow:  0,
		},
	}

	for idx := range count {
		//nolint:gosec // idx bounded by min(len(current), len(proposed))
		diff := buildDiffImage(current[idx], proposed[idx])
		out.Images = append(out.Images, diff)
		updateDiffSummary(&out.Summary, &diff)
	}

	return out
}

func buildDiffImage(current, proposed *verifyOutput) previewDiffImage {
	changed := current.Allowed != proposed.Allowed || checkStatusesChanged(current, proposed)

	return previewDiffImage{
		Image:    current.Image,
		Changed:  changed,
		Current:  *current,
		Proposed: *proposed,
	}
}

func checkStatusesChanged(current, proposed *verifyOutput) bool {
	if len(current.CheckResults) != len(proposed.CheckResults) {
		return true
	}

	statusMap := make(map[types.CheckType]types.CheckStatus, len(current.CheckResults))

	for idx := range current.CheckResults {
		checkType := current.CheckResults[idx].Type

		if _, exists := statusMap[checkType]; exists {
			return true
		}

		statusMap[checkType] = current.CheckResults[idx].Status
	}

	seen := make(map[types.CheckType]struct{}, len(proposed.CheckResults))

	for idx := range proposed.CheckResults {
		check := &proposed.CheckResults[idx]

		if _, duplicate := seen[check.Type]; duplicate {
			return true
		}

		seen[check.Type] = struct{}{}

		currentStatus, exists := statusMap[check.Type]
		if !exists || currentStatus != check.Status {
			return true
		}
	}

	return false
}

func updateDiffSummary(summary *previewDiffSummary, diff *previewDiffImage) {
	if diff.Changed {
		summary.Changed++

		if diff.Current.Allowed && !diff.Proposed.Allowed {
			summary.NewDenied++
		}

		if !diff.Current.Allowed && diff.Proposed.Allowed {
			summary.NewAllow++
		}
	} else {
		summary.Unchanged++
	}
}

func outputDiffResult(writer io.Writer, format string, out *previewDiffOutput) error {
	switch format {
	case outputFormatJSON:
		return outputDiffJSON(writer, out)
	default:
		return outputDiffTable(writer, out)
	}
}

func outputDiffJSON(writer io.Writer, out *previewDiffOutput) error {
	enc := json.NewEncoder(writer)
	enc.SetIndent("", "  ")

	encErr := enc.Encode(out)
	if encErr != nil {
		return fmt.Errorf("encoding diff JSON output: %w", encErr)
	}

	return nil
}

func outputDiffTable(writer io.Writer, out *previewDiffOutput) error {
	_, _ = fmt.Fprintf(writer, "%s\n", colorBold.Sprint("Policy Diff Summary"))
	_, _ = fmt.Fprintf(writer, "%s %d\n", colorBold.Sprint("Total:"), out.Summary.Total)
	_, _ = fmt.Fprintf(writer, "%s %d\n", colorBold.Sprint("Changed:"), out.Summary.Changed)
	_, _ = fmt.Fprintf(writer, "%s %d\n", colorBold.Sprint("Unchanged:"), out.Summary.Unchanged)

	if out.Summary.NewDenied > 0 {
		_, _ = fmt.Fprintf(writer, "%s %s\n",
			colorBold.Sprint("Newly denied:"), colorRed.Sprint(out.Summary.NewDenied))
	}

	if out.Summary.NewAllow > 0 {
		_, _ = fmt.Fprintf(writer, "%s %s\n",
			colorBold.Sprint("Newly allowed:"), colorGreen.Sprint(out.Summary.NewAllow))
	}

	if out.Summary.Changed == 0 {
		_, _ = fmt.Fprintf(writer, "\n%s\n",
			colorGreen.Sprint("No policy impact: all images produce the same result"))

		return nil
	}

	_, _ = fmt.Fprintln(writer)

	return renderDiffTable(writer, out.Images)
}

func renderDiffTable(writer io.Writer, images []previewDiffImage) error {
	table := newBorderlessTable(writer, []string{"Image", "Current", "Proposed", "Impact"})

	for idx := range images {
		diff := &images[idx]

		if !diff.Changed {
			continue
		}

		appendErr := table.Append([]string{
			diff.Image,
			formatAllowed(diff.Current.Allowed),
			formatAllowed(diff.Proposed.Allowed),
			diffImpact(diff.Current.Allowed, diff.Proposed.Allowed),
		})
		if appendErr != nil {
			return fmt.Errorf("appending diff row: %w", appendErr)
		}
	}

	renderErr := table.Render()
	if renderErr != nil {
		return fmt.Errorf("rendering diff table: %w", renderErr)
	}

	return nil
}

func formatAllowed(allowed bool) string {
	if allowed {
		return colorGreen.Sprint("ALLOWED")
	}

	return colorRed.Sprint("DENIED")
}

func diffImpact(currentAllowed, proposedAllowed bool) string {
	switch {
	case currentAllowed && !proposedAllowed:
		return colorRed.Sprint("WOULD BE DENIED")
	case !currentAllowed && proposedAllowed:
		return colorGreen.Sprint("WOULD BE ALLOWED")
	default:
		return "-"
	}
}

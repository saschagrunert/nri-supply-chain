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
	"strings"
	"syscall"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/spf13/cobra"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/registry"
)

const cmdInspect = "inspect"

type inspectOutput struct {
	Image        string               `json:"image"`
	Digest       string               `json:"digest"`
	Attestations []inspectAttestation `json:"attestations"`
}

type inspectAttestation struct {
	PredicateType string `json:"predicateType"`
	SignatureType string `json:"signatureType"`
	Digest        string `json:"digest,omitempty"`
}

func newInspectCmd(configPath, logLevel *string) *cobra.Command {
	var outputFormat string

	cmd := &cobra.Command{
		Use:   cmdInspect + " <image>",
		Short: "List attestations attached to an image",
		Long: "Discover and list all attestations attached to a container image.\n\n" +
			"This command fetches attestations from the registry and displays\n" +
			"their predicate types and signature types without verifying them\n" +
			"against any policy.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true

			cfg, err := setupConfig(*configPath)
			if err != nil {
				slog.Error("Setup failed", "error", err)

				return errExitNonZero
			}

			initLogging(effectiveLogLevel(*logLevel, cfg.LogLevel), true)

			slog.Info("Using config", "path", *configPath)

			code := runInspect(os.Stdout, args[0], outputFormat, cfg)
			if code != 0 {
				return errExitNonZero
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&outputFormat, "output", "o",
		outputFormatTable, "output format: table, json")

	return cmd
}

func runInspect(
	writer io.Writer, imageRef, outputFormat string, cfg *config.Config,
) int {
	if outputFormat != outputFormatTable && outputFormat != outputFormatJSON {
		slog.Error("Invalid output format", "format", outputFormat)

		return exitError
	}

	cfg.WarnInsecureRegistries()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cache := registry.NewTransportCacheOrNil(cfg.Registries)

	resolved, err := resolveDigest(ctx, imageRef, cfg.FetchTimeout.Duration, cache)
	if err != nil {
		slog.Error("Failed to resolve image digest", "image", imageRef, "error", err)

		return exitError
	}

	fetcher := newInspectFetcher(cache, cfg)

	attestations, err := fetchInspectAttestations(
		ctx, fetcher, imageRef, resolved.digest, resolved.indexDigest, cfg,
	)
	if err != nil {
		slog.Error("Failed to fetch attestations", "image", imageRef, "error", err)

		return exitError
	}

	out := &inspectOutput{
		Image:        imageRef,
		Digest:       resolved.digest,
		Attestations: buildInspectAttestations(attestations),
	}

	err = outputInspectResult(writer, outputFormat, out)
	if err != nil {
		slog.Error("Failed to write output", "error", err)

		return exitError
	}

	return exitSuccess
}

func newInspectFetcher(
	cache *registry.TransportCache, cfg *config.Config,
) *attestation.OCIFetcher {
	fetcher := attestation.NewOCIFetcherWithVerifier(
		func(_ context.Context, bundleBytes []byte, _ *attestation.FetchOptions) ([]byte, error) {
			return attestation.ExtractBundlePayload(bundleBytes)
		},
	)

	if cache != nil {
		fetcher.SetTransportCache(cache)
	}

	fetcher.SetMaxAttestationSize(cfg.MaxAttestationSize)

	return fetcher
}

func fetchInspectAttestations(
	ctx context.Context, fetcher *attestation.OCIFetcher,
	imageRef, digest, indexDigest string,
	cfg *config.Config,
) ([]attestation.VerifiedAttestation, error) {
	parsedRef, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("parsing image reference: %w", err)
	}

	opts := &attestation.FetchOptions{
		Timeout:   cfg.FetchTimeout.Duration,
		Digest:    digest,
		ParsedRef: parsedRef,
	}

	if indexDigest != "" {
		indexOpts := &attestation.FetchOptions{
			Timeout:   cfg.FetchTimeout.Duration,
			Digest:    indexDigest,
			ParsedRef: parsedRef,
		}

		atts, fetchErr := fetcher.Fetch(ctx, imageRef, indexOpts)
		if fetchErr == nil && len(atts) > 0 {
			return atts, nil
		}

		if fetchErr != nil {
			slog.Debug("Index digest fetch failed, falling back to platform digest",
				"indexDigest", indexDigest,
				"platformDigest", digest,
				"error", fetchErr,
			)
		} else {
			slog.Debug("No attestations on index digest, falling back to platform digest",
				"indexDigest", indexDigest,
				"platformDigest", digest,
			)
		}
	}

	atts, err := fetcher.Fetch(ctx, imageRef, opts)
	if err != nil {
		return nil, fmt.Errorf("fetching attestations: %w", err)
	}

	return atts, nil
}

func buildInspectAttestations(
	atts []attestation.VerifiedAttestation,
) []inspectAttestation {
	result := make([]inspectAttestation, 0, len(atts))

	for idx := range atts {
		result = append(result, inspectAttestation{
			PredicateType: atts[idx].PredicateType,
			SignatureType: string(atts[idx].SignatureType),
			Digest:        atts[idx].Digest,
		})
	}

	return result
}

func outputInspectResult(writer io.Writer, format string, out *inspectOutput) error {
	switch format {
	case outputFormatJSON:
		return outputInspectJSON(writer, out)
	default:
		return outputInspectTable(writer, out)
	}
}

func outputInspectJSON(writer io.Writer, out *inspectOutput) error {
	enc := json.NewEncoder(writer)
	enc.SetIndent("", "  ")

	err := enc.Encode(out)
	if err != nil {
		return fmt.Errorf("encoding JSON output: %w", err)
	}

	return nil
}

func outputInspectTable(writer io.Writer, out *inspectOutput) error {
	_, _ = fmt.Fprintf(writer, "%s %s\n", colorBold.Sprint("Image:"), out.Image)
	_, _ = fmt.Fprintf(writer, "%s %s\n", colorBold.Sprint("Digest:"), out.Digest)
	_, _ = fmt.Fprintf(writer, "%s %d\n",
		colorBold.Sprint("Attestations:"), len(out.Attestations))

	if len(out.Attestations) == 0 {
		return nil
	}

	_, _ = fmt.Fprintln(writer)

	return renderInspectTable(writer, out.Attestations)
}

func renderInspectTable(writer io.Writer, atts []inspectAttestation) error {
	table := newBorderlessTable(writer, []string{"Predicate Type", "Signature", "Digest"})

	for _, att := range atts {
		digest := att.Digest
		if digest == "" {
			digest = "-"
		}

		predicate := shortenPredicateType(att.PredicateType)

		err := table.Append([]string{predicate, att.SignatureType, digest})
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

//nolint:gochecknoglobals // read-only lookup table
var knownPredicateTypes = map[string]string{
	attestation.PredicateSLSAProvenanceV1:  "slsa-provenance-v1",
	attestation.PredicateSLSAProvenanceV02: "slsa-provenance-v0.2",
	attestation.PredicateVSA:               "vsa",
	attestation.PredicateOpenVEX:           "openvex",
	attestation.PredicateSPDX:              "spdx",
	attestation.PredicateCycloneDX:         "cyclonedx",
	attestation.PredicateSCAI:              "scai",
	attestation.PredicateSLSASourceV1:      "slsa-source-v1",
	attestation.PredicateBuildEnv:          "build-env",
	attestation.PredicateVulnScan:          "vulns-v0.1",
	attestation.PredicateVulnScanV02:       "vulns-v0.2",
	attestation.PredicateTestResult:        "test-result",
	attestation.PredicateRelease:           "release",
	attestation.PredicateRuntimeTrace:      "runtime-trace",
	attestation.PredicateCosignSignature:   "cosign-signature",
}

func shortenPredicateType(predicateType string) string {
	if short, ok := knownPredicateTypes[predicateType]; ok {
		return short
	}

	if after, ok := strings.CutPrefix(predicateType, "https://"); ok {
		return after
	}

	return predicateType
}

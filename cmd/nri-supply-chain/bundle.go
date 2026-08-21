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
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/spf13/cobra"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/bundle"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/registry"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

const cmdBundle = "bundle"

func newBundleCmd(configPath, logLevel *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   cmdBundle,
		Short: "Manage offline attestation bundles",
		Long: "Create, inspect, verify, and import portable attestation bundles\n" +
			"for air-gapped environments.",
	}

	cmd.AddCommand(
		newBundleCreateCmd(configPath, logLevel),
		newBundleInspectCmd(),
		newBundleVerifyCmd(),
		newBundleImportCmd(),
	)

	return cmd
}

func newBundleCreateCmd(configPath, logLevel *string) *cobra.Command {
	var (
		images      []string
		outputPath  string
		signKey     string
		fromPolicy  string
		trustedRoot string
		revocation  []string
	)

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create an attestation bundle from registry images",
		Long: "Fetch attestations from OCI registries and package them into\n" +
			"a portable bundle for transfer to air-gapped environments.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runBundleCreateCmd(
				cmd, configPath, logLevel,
				&images, outputPath, signKey, fromPolicy,
				trustedRoot, revocation,
			)
		},
	}

	cmd.Flags().StringArrayVar(&images, "image", nil,
		"image reference to include (can be specified multiple times)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "",
		"output file path for the bundle tar.gz")
	cmd.Flags().StringVar(&signKey, "sign-key", "",
		"path to private key PEM for signing the bundle")
	cmd.Flags().StringVar(&fromPolicy, "from-policy", "",
		"path to policy file to extract image references from")
	cmd.Flags().StringVar(&trustedRoot, "trusted-root", "",
		"path to trusted root JSON to embed in the bundle")
	cmd.Flags().StringArrayVar(&revocation, "revocation", nil,
		"path to CRL or TSA file to embed (can be specified multiple times)")

	return cmd
}

func runBundleCreateCmd(
	cmd *cobra.Command, configPath, logLevel *string,
	images *[]string, outputPath, signKey, fromPolicy string,
	trustedRootPath string, revocationPaths []string,
) error {
	cmd.SilenceUsage = true

	cfg, err := setupConfig(*configPath)
	if err != nil {
		slog.Error("Setup failed", "error", err)

		return errExitNonZero
	}

	initLogging(effectiveLogLevel(*logLevel, cfg.LogLevel), true)

	if fromPolicy != "" {
		policyImages, loadErr := imagesFromPolicy(fromPolicy)
		if loadErr != nil {
			slog.Error("Failed to load images from policy", "error", loadErr)

			return errExitNonZero
		}

		*images = append(*images, policyImages...)
	}

	if len(*images) == 0 {
		slog.Error("At least one --image or --from-policy is required")

		return errExitNonZero
	}

	if outputPath == "" {
		slog.Error("--output is required")

		return errExitNonZero
	}

	code := runBundleCreate(
		cmd.Context(), *images, outputPath, signKey, cfg,
		trustedRootPath, revocationPaths,
	)
	if code != 0 {
		return errExitNonZero
	}

	return nil
}

func newBundleInspectCmd() *cobra.Command {
	var outputFormat string

	cmd := &cobra.Command{
		Use:   "inspect <store-path>",
		Short: "Show contents of an attestation bundle",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true

			code := runBundleInspect(os.Stdout, args[0], outputFormat)
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

func newBundleVerifyCmd() *cobra.Command {
	var (
		keyPath string
		maxAge  string
	)

	cmd := &cobra.Command{
		Use:   "verify <store-path>",
		Short: "Verify bundle integrity, signature, and expiry",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true

			code := runBundleVerify(args[0], keyPath, maxAge)
			if code != 0 {
				return errExitNonZero
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&keyPath, "key", "",
		"path to public key PEM for signature verification")
	cmd.Flags().StringVar(&maxAge, "max-age", "",
		"maximum acceptable bundle age (e.g. 720h, 24h)")

	return cmd
}

func runBundleVerify(storePath, keyPath, maxAge string) int {
	store, err := bundle.OpenStore(storePath)
	if err != nil {
		slog.Error("Failed to open bundle", "error", err)

		return exitError
	}

	manifest := store.Manifest()

	printBundleSummary(manifest)

	integrityErr := bundle.VerifyBlobIntegrity(store)
	if integrityErr != nil {
		slog.Error("Blob integrity check failed", "error", integrityErr)

		return exitError
	}

	_, _ = fmt.Fprintln(os.Stdout, "Blob integrity: OK")

	if verifySignature(manifest, keyPath) != exitSuccess {
		return exitError
	}

	if verifyExpiry(manifest, maxAge) != exitSuccess {
		return exitError
	}

	_, _ = fmt.Fprintln(os.Stdout, "\nBundle verification passed.")

	return exitSuccess
}

func printBundleSummary(manifest *bundle.Manifest) {
	_, _ = fmt.Fprintf(os.Stdout, "Bundle version: %d\n", manifest.Version)
	_, _ = fmt.Fprintf(
		os.Stdout, "Created: %s\n",
		manifest.CreatedAt.Format("2006-01-02 15:04:05 UTC"),
	)
	_, _ = fmt.Fprintf(os.Stdout, "Images: %d\n", len(manifest.Images))
	_, _ = fmt.Fprintf(
		os.Stdout, "Trusted root: %v\n", manifest.TrustedRoot != nil,
	)
	_, _ = fmt.Fprintf(os.Stdout, "Signed: %v\n", manifest.Signature != nil)

	if manifest.Signature != nil {
		_, _ = fmt.Fprintf(
			os.Stdout, "Signature algorithm: %s\n",
			manifest.Signature.Algorithm,
		)
		_, _ = fmt.Fprintf(
			os.Stdout, "Signature key hint: %s\n",
			manifest.Signature.KeyHint,
		)
	}
}

func verifySignature(manifest *bundle.Manifest, keyPath string) int {
	if keyPath == "" {
		return exitSuccess
	}

	if manifest.Signature == nil {
		slog.Error("Bundle is not signed but --key was provided")

		return exitError
	}

	sigErr := bundle.VerifyManifestSignature(manifest, keyPath)
	if sigErr != nil {
		slog.Error("Signature verification failed", "error", sigErr)

		return exitError
	}

	_, _ = fmt.Fprintln(os.Stdout, "Signature: OK")

	return exitSuccess
}

func verifyExpiry(manifest *bundle.Manifest, maxAge string) int {
	var maxAgeDuration time.Duration

	if maxAge != "" {
		parsed, err := time.ParseDuration(maxAge)
		if err != nil {
			slog.Error("Invalid --max-age value", "error", err)

			return exitError
		}

		maxAgeDuration = parsed
	}

	expiryPolicy := bundle.ExpiryAllow
	if maxAgeDuration > 0 {
		expiryPolicy = bundle.ExpiryDeny
	}

	staleness := bundle.CheckStaleness(
		manifest, maxAgeDuration, expiryPolicy,
	)
	_, _ = fmt.Fprintf(
		os.Stdout, "Age: %s\n", staleness.Age.Round(time.Second),
	)

	if staleness.Stale && !staleness.Allowed {
		slog.Error("Bundle is expired",
			"age", staleness.Age.Round(time.Second),
			"maxAge", staleness.MaxAge,
		)

		return exitError
	}

	return exitSuccess
}

func newBundleImportCmd() *cobra.Command {
	var (
		storePath string
		keyPath   string
	)

	cmd := &cobra.Command{
		Use:   "import <bundle.tar.gz>",
		Short: "Import a bundle into the local attestation store",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true

			if storePath == "" {
				slog.Error("--store is required")

				return errExitNonZero
			}

			importErr := bundle.Import(args[0], storePath, keyPath)
			if importErr != nil {
				slog.Error("Import failed", "error", importErr)

				return errExitNonZero
			}

			if keyPath != "" {
				slog.Info("Signature verified")
			}

			_, _ = fmt.Fprintf(os.Stdout, "Bundle imported to %s\n", storePath)

			return nil
		},
	}

	cmd.Flags().StringVar(&storePath, "store", "",
		"path to the local attestation store directory")
	cmd.Flags().StringVar(&keyPath, "key", "",
		"path to public key PEM for signature verification during import")

	return cmd
}

func runBundleCreate(
	ctx context.Context,
	images []string,
	outputPath, signKey string,
	cfg *config.Config,
	trustedRootPath string, revocationPaths []string,
) int {
	createOpts, err := buildCreateOptions(
		ctx, images, outputPath, signKey, cfg,
		trustedRootPath, revocationPaths,
	)
	if err != nil {
		slog.Error("Bundle setup failed", "error", err)

		return exitError
	}

	createErr := bundle.Create(ctx, createOpts)
	if createErr != nil {
		slog.Error("Bundle creation failed", "error", createErr)

		return exitError
	}

	slog.Info("Bundle created", "output", outputPath, "images", len(images))

	return exitSuccess
}

func buildCreateOptions(
	ctx context.Context,
	images []string,
	outputPath, signKey string,
	cfg *config.Config,
	trustedRootPath string, revocationPaths []string,
) (*bundle.CreateOptions, error) {
	cache := registry.NewTransportCacheOrNil(cfg.Registries)

	fetcher, err := verifier.NewFetcher(ctx, cfg, cache)
	if err != nil {
		return nil, fmt.Errorf("creating fetcher: %w", err)
	}

	trustedRoots, err := loadBundleTrustedRoots(
		trustedRootPath, fetcher,
	)
	if err != nil {
		return nil, fmt.Errorf("loading trusted root: %w", err)
	}

	revData, err := loadBundleRevocationData(revocationPaths)
	if err != nil {
		return nil, fmt.Errorf("loading revocation data: %w", err)
	}

	fetchOpts, err := fetchOptsFromPolicy(cfg.PolicyDir)
	if err != nil {
		return nil, fmt.Errorf("loading trust config from policy: %w", err)
	}

	authOpt := registry.AuthOption()

	return &bundle.CreateOptions{
		Images:         images,
		OutputPath:     outputPath,
		Fetcher:        fetcher,
		FetchOptions:   fetchOpts,
		TrustedRoots:   trustedRoots,
		SigningKeyPath: signKey,
		ResolveDigest: func(
			ctx context.Context, imageRef string,
		) (string, string, error) {
			return registry.ResolveImageDigest(ctx, imageRef, authOpt)
		},
		RevocationData: revData,
	}, nil
}

func fetchOptsFromPolicy(policyDir string) (*attestation.FetchOptions, error) {
	if policyDir == "" {
		return &attestation.FetchOptions{}, nil
	}

	defaultPolicyPath := filepath.Join(policyDir, "default.json")

	pol, err := policy.Load(defaultPolicyPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &attestation.FetchOptions{}, nil
		}

		return nil, fmt.Errorf("loading default policy: %w", err)
	}

	opts := &attestation.FetchOptions{}

	if pol.Trust == nil {
		return opts, nil
	}

	opts.TrustedIssuers = pol.Trust.Issuers
	opts.SANPatterns = pol.Trust.SANPatterns

	totalKeys := 0
	for idx := range pol.Trust.Verifiers {
		totalKeys += len(pol.Trust.Verifiers[idx].Keys)
	}

	keys := make([]attestation.TrustedKeyRef, 0, totalKeys)

	for idx := range pol.Trust.Verifiers {
		for _, keyPath := range pol.Trust.Verifiers[idx].Keys {
			keys = append(keys, attestation.TrustedKeyRef{
				Path:      keyPath,
				NotBefore: pol.Trust.Verifiers[idx].NotBeforeTime,
				NotAfter:  pol.Trust.Verifiers[idx].NotAfterTime,
			})
		}
	}

	opts.TrustedKeys = keys

	return opts, nil
}

func runBundleInspect(writer io.Writer, storePath, outputFormat string) int {
	result, err := bundle.Inspect(storePath)
	if err != nil {
		slog.Error("Inspection failed", "error", err)

		return exitError
	}

	switch outputFormat {
	case outputFormatJSON:
		enc := json.NewEncoder(writer)
		enc.SetIndent("", "  ")

		encErr := enc.Encode(result)
		if encErr != nil {
			slog.Error("JSON encoding failed", "error", encErr)

			return exitError
		}

	default:
		tabW := tabwriter.NewWriter(writer, 0, 4, 2, ' ', 0) //nolint:mnd // tabwriter formatting
		_, _ = fmt.Fprintf(tabW,
			"VERSION\tCREATED\tAGE\tIMAGES\tATTESTATIONS\tTRUSTED ROOT\tSIGNED\n")
		_, _ = fmt.Fprintf(tabW, "%d\t%s\t%s\t%d\t%d\t%v\t%v\n",
			result.Version,
			result.CreatedAt.Format("2006-01-02 15:04:05"),
			result.Age.Duration().Round(time.Second),
			result.ImageCount,
			result.AttestationCount,
			result.TrustedRoot,
			result.Signed,
		)

		for _, img := range result.Images {
			_, _ = fmt.Fprintf(tabW, "\n")
			_, _ = fmt.Fprintf(tabW, "  Digest: %s\n", img.Digest)

			for _, ref := range img.Refs {
				_, _ = fmt.Fprintf(tabW, "  Ref: %s\n", ref)
			}

			for _, att := range img.Attestations {
				_, _ = fmt.Fprintf(tabW, "  - %s (%s, %d bytes)\n",
					att.PredicateType, att.SignatureType, att.Size)
			}
		}

		_ = tabW.Flush()
	}

	return exitSuccess
}

func imagesFromPolicy(policyPath string) ([]string, error) {
	pol, err := policy.Load(policyPath)
	if err != nil {
		return nil, fmt.Errorf("loading policy %s: %w", policyPath, err)
	}

	seen := make(map[string]bool)

	var refs []string

	for _, pattern := range pol.Include {
		if isConcreteImageRef(pattern) && !seen[pattern] {
			seen[pattern] = true
			refs = append(refs, pattern)
		}
	}

	for i := range pol.Rules {
		for _, pattern := range pol.Rules[i].Images {
			if isConcreteImageRef(pattern) && !seen[pattern] {
				seen[pattern] = true
				refs = append(refs, pattern)
			}
		}
	}

	return refs, nil
}

func isConcreteImageRef(pattern string) bool {
	return !strings.ContainsAny(pattern, "*?[")
}

func loadBundleTrustedRoots(
	trustedRootPath string, fetcher attestation.Fetcher,
) ([]*root.TrustedRoot, error) {
	if trustedRootPath != "" {
		data, err := os.ReadFile(trustedRootPath) //nolint:gosec // user CLI flag
		if err != nil {
			return nil, fmt.Errorf("reading trusted root %s: %w", trustedRootPath, err)
		}

		tr, err := root.NewTrustedRootFromJSON(data)
		if err != nil {
			return nil, fmt.Errorf("parsing trusted root %s: %w", trustedRootPath, err)
		}

		return []*root.TrustedRoot{tr}, nil
	}

	ociFetcher := extractOCIFetcher(fetcher)
	if ociFetcher != nil {
		tr := ociFetcher.CachedTrustedRoot()
		if tr != nil {
			slog.Info("Embedding cached Sigstore trusted root into bundle")

			return []*root.TrustedRoot{tr}, nil
		}
	}

	slog.Warn("No trusted root available to embed in bundle; " +
		"use --trusted-root to supply one")

	return nil, nil
}

func loadBundleRevocationData(
	revocationPaths []string,
) ([]bundle.RevocationData, error) {
	if len(revocationPaths) == 0 {
		return nil, nil
	}

	revData := make([]bundle.RevocationData, 0, len(revocationPaths))

	for _, revPath := range revocationPaths {
		data, err := os.ReadFile(revPath) //nolint:gosec // user CLI flag
		if err != nil {
			return nil, fmt.Errorf("reading revocation data %s: %w", revPath, err)
		}

		revData = append(revData, bundle.RevocationData{
			Type: revocationTypeFromPath(revPath),
			Data: data,
		})
	}

	return revData, nil
}

func revocationTypeFromPath(path string) string {
	if strings.HasSuffix(path, ".pem") || strings.HasSuffix(path, ".crl") {
		return "crl"
	}

	return "tsa"
}

func extractOCIFetcher(fetcher attestation.Fetcher) *attestation.OCIFetcher {
	if ociFetcher, ok := fetcher.(*attestation.OCIFetcher); ok {
		return ociFetcher
	}

	if fb, ok := fetcher.(*bundle.FallbackFetcher); ok {
		return fb.OCIFetcher()
	}

	return nil
}

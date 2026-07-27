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
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/registry"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

type verifyOutput struct {
	Image        string       `json:"image"`
	Digest       string       `json:"digest"`
	Namespace    string       `json:"namespace"`
	Allowed      bool         `json:"allowed"`
	Reason       string       `json:"reason,omitempty"`
	CheckResults []checkEntry `json:"checkResults,omitempty"`
}

type checkEntry struct {
	Type   string `json:"type"`
	Passed bool   `json:"passed"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type resolvedDigest struct {
	digest      string
	indexDigest string
}

func runVerify(opts *options, cfg *config.Config) int {
	return runVerifyTo(os.Stdout, opts, cfg)
}

func runVerifyTo(writer io.Writer, opts *options, cfg *config.Config) int {
	imageRef := opts.verifyImage
	namespace := opts.verifyNamespace

	if !cfg.Enabled() {
		slog.Error("--verify-image requires verification to be enabled")

		return 1
	}

	met := metrics.New()
	fetcher := verifier.NewFetcher(cfg)

	verif, err := verifier.New(cfg, met, fetcher)
	if err != nil {
		slog.Error("Failed to create verifier", "error", err)

		return 1
	}

	resolved, err := resolveDigest(imageRef, cfg.FetchTimeout.Duration)
	if err != nil {
		slog.Error("Failed to resolve image digest", "image", imageRef, "error", err)

		return 1
	}

	digest := resolved.digest

	result, err := verif.Verify(
		context.Background(), imageRef, digest, resolved.indexDigest, namespace,
	)
	if err != nil {
		slog.Error("Verification failed", "image", imageRef, "error", err)
	}

	checks := convertCheckResults(result)

	if err != nil {
		outputVerifyResult(writer, imageRef, digest, namespace, false, err.Error(), checks)

		return 1
	}

	outputVerifyResult(
		writer, imageRef, digest, namespace, result.Allowed, result.Reason, checks,
	)

	if !result.Allowed {
		return 1
	}

	return 0
}

func convertCheckResults(result *types.Result) []checkEntry {
	if result == nil {
		return nil
	}

	checks := make([]checkEntry, 0, len(result.CheckResults))

	for _, cr := range result.CheckResults {
		checks = append(checks, checkEntry{
			Type:   string(cr.Type),
			Passed: cr.Passed,
			Status: string(cr.Status),
			Detail: cr.Detail,
		})
	}

	return checks
}

func resolveDigest(imageRef string, timeout time.Duration) (resolvedDigest, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	digest, indexDigest, err := registry.ResolveWithDefaultKeychain(ctx, imageRef)
	if err != nil {
		return resolvedDigest{}, fmt.Errorf("resolving digest: %w", err)
	}

	return resolvedDigest{digest: digest, indexDigest: indexDigest}, nil
}

func outputVerifyResult(
	writer io.Writer,
	imageRef, digest, namespace string,
	allowed bool, reason string, checks []checkEntry,
) {
	out := verifyOutput{
		Image:        imageRef,
		Digest:       digest,
		Namespace:    namespace,
		Allowed:      allowed,
		Reason:       reason,
		CheckResults: checks,
	}

	enc := json.NewEncoder(writer)
	enc.SetIndent("", "  ")

	encErr := enc.Encode(out)
	if encErr != nil {
		slog.Error("Failed to encode verify output", "error", encErr)
	}
}

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
	"syscall"
	"time"

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
	imageRef := opts.verifyImage
	namespace := opts.verifyNamespace

	if !cfg.Enabled() {
		slog.Error("--verify-image requires verification to be enabled")

		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	met := metrics.New()
	fetcher := verifier.NewFetcher(ctx, cfg)

	verif, err := verifier.New(cfg, met, fetcher)
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

	digest := resolved.digest

	result, err := verif.Verify(
		ctx, imageRef, digest, resolved.indexDigest, namespace,
	)

	var checks []types.CheckResult
	if result != nil {
		checks = result.CheckResults
	}

	if err != nil {
		slog.Error("Verification failed", "image", imageRef, "error", err)
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

func outputVerifyResult(
	writer io.Writer,
	imageRef, digest, namespace string,
	allowed bool, reason string, checks []types.CheckResult,
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

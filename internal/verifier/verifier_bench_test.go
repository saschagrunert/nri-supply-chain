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

package verifier_test

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

const benchmarkDigest = "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4" +
	"e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

func benchSuppressLogs(b *testing.B) {
	b.Helper()

	prev := slog.Default()

	slog.SetDefault(slog.New(slog.DiscardHandler))

	b.Cleanup(func() { slog.SetDefault(prev) })
}

func benchWritePolicy(b *testing.B, dir, name, content string) {
	b.Helper()

	err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600)
	if err != nil {
		b.Fatalf("writing policy: %v", err)
	}
}

func BenchmarkVerifyCacheHit(b *testing.B) {
	dir := b.TempDir()
	benchWritePolicy(b, dir, "default.json", `{}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir
	cfg.CacheTTL = config.Duration{Duration: time.Hour}

	verif, err := verifier.New(b.Context(), cfg, metrics.New(), nil)
	if err != nil {
		b.Fatalf("creating verifier: %v", err)
	}

	ctx := context.Background()

	_, err = verif.Verify(ctx, "nginx:latest", benchmarkDigest, "", "default")
	if err != nil {
		b.Fatalf("initial verify: %v", err)
	}

	b.ResetTimer()

	for range b.N {
		_, err = verif.Verify(
			ctx, "nginx:latest", benchmarkDigest, "", "default",
		)
		if err != nil {
			b.Fatalf("verify: %v", err)
		}
	}
}

func BenchmarkVerifyCacheHitParallel(b *testing.B) {
	dir := b.TempDir()
	benchWritePolicy(b, dir, "default.json", `{}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir
	cfg.CacheTTL = config.Duration{Duration: time.Hour}

	verif, err := verifier.New(b.Context(), cfg, metrics.New(), nil)
	if err != nil {
		b.Fatalf("creating verifier: %v", err)
	}

	ctx := context.Background()

	_, err = verif.Verify(ctx, "nginx:latest", benchmarkDigest, "", "default")
	if err != nil {
		b.Fatalf("initial verify: %v", err)
	}

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, verifyErr := verif.Verify(ctx, "nginx:latest", benchmarkDigest, "", "default")
			if verifyErr != nil {
				b.Errorf("verify: %v", verifyErr)

				return
			}
		}
	})
}

func BenchmarkVerifyE2EWithMockFetcher(b *testing.B) {
	benchSuppressLogs(b)

	dir := b.TempDir()
	benchWritePolicy(b, dir, "default.json", policyTrustRunnerJSON)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.PolicyDir = dir
	cfg.CacheTTL = config.Duration{Duration: 0}

	slsaPayload := validSLSAPayload(b)

	fetcher := &mockFetcher{
		attestations: []attestation.VerifiedAttestation{
			{
				PredicateType: attestation.PredicateSLSAProvenanceV1,
				Payload:       slsaPayload,
				Digest:        benchmarkDigest,
			},
		},
		err: nil,
	}

	verif, err := verifier.New(b.Context(), cfg, metrics.New(), fetcher)
	if err != nil {
		b.Fatalf("creating verifier: %v", err)
	}

	ctx := context.Background()

	b.ResetTimer()

	for range b.N {
		_, err = verif.Verify(ctx, "nginx:latest", benchmarkDigest, "", "default")
		if err != nil {
			b.Fatalf("verify: %v", err)
		}
	}
}

func BenchmarkVerifyE2EParallel(b *testing.B) {
	benchSuppressLogs(b)

	dir := b.TempDir()
	benchWritePolicy(b, dir, "default.json", policyTrustRunnerJSON)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.PolicyDir = dir
	cfg.CacheTTL = config.Duration{Duration: 0}

	slsaPayload := validSLSAPayload(b)

	fetcher := &mockFetcher{
		attestations: []attestation.VerifiedAttestation{
			{
				PredicateType: attestation.PredicateSLSAProvenanceV1,
				Payload:       slsaPayload,
				Digest:        benchmarkDigest,
			},
		},
		err: nil,
	}

	verif, err := verifier.New(b.Context(), cfg, metrics.New(), fetcher)
	if err != nil {
		b.Fatalf("creating verifier: %v", err)
	}

	ctx := context.Background()

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, verifyErr := verif.Verify(ctx, "nginx:latest", benchmarkDigest, "", "default")
			if verifyErr != nil {
				b.Errorf("verify: %v", verifyErr)

				return
			}
		}
	})
}

func BenchmarkVerifyE2EMultipleImages(b *testing.B) {
	benchSuppressLogs(b)

	dir := b.TempDir()
	benchWritePolicy(b, dir, "default.json", policyTrustRunnerJSON)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.PolicyDir = dir
	cfg.CacheTTL = config.Duration{Duration: 0}

	slsaPayload := validSLSAPayload(b)

	fetcher := &mockFetcher{
		attestations: []attestation.VerifiedAttestation{
			{
				PredicateType: attestation.PredicateSLSAProvenanceV1,
				Payload:       slsaPayload,
				Digest:        benchmarkDigest,
			},
		},
		err: nil,
	}

	verif, err := verifier.New(b.Context(), cfg, metrics.New(), fetcher)
	if err != nil {
		b.Fatalf("creating verifier: %v", err)
	}

	ctx := context.Background()

	b.ResetTimer()

	for i := range b.N {
		image := fmt.Sprintf("nginx-%d:latest", i%100)

		_, err = verif.Verify(ctx, image, benchmarkDigest, "", "default")
		if err != nil {
			b.Fatalf("verify: %v", err)
		}
	}
}

func BenchmarkVerifyDisabled(b *testing.B) {
	cfg := config.DefaultConfig()

	verif, err := verifier.New(b.Context(), cfg, metrics.New(), nil)
	if err != nil {
		b.Fatalf("creating verifier: %v", err)
	}

	ctx := context.Background()

	b.ResetTimer()

	for range b.N {
		_, err = verif.Verify(
			ctx, "nginx:latest", benchmarkDigest, "", "default",
		)
		if err != nil {
			b.Fatalf("verify: %v", err)
		}
	}
}

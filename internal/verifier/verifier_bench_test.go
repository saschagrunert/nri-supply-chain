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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

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

	verif, err := verifier.New(cfg, metrics.New(), nil)
	if err != nil {
		b.Fatalf("creating verifier: %v", err)
	}

	ctx := context.Background()

	_, err = verif.Verify(ctx, "nginx:latest", "sha256:abc123", "", "default")
	if err != nil {
		b.Fatalf("initial verify: %v", err)
	}

	b.ResetTimer()

	for range b.N {
		_, err = verif.Verify(ctx, "nginx:latest", "sha256:abc123", "", "default")
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

	verif, err := verifier.New(cfg, metrics.New(), nil)
	if err != nil {
		b.Fatalf("creating verifier: %v", err)
	}

	ctx := context.Background()

	_, err = verif.Verify(ctx, "nginx:latest", "sha256:abc123", "", "default")
	if err != nil {
		b.Fatalf("initial verify: %v", err)
	}

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, verifyErr := verif.Verify(ctx, "nginx:latest", "sha256:abc123", "", "default")
			if verifyErr != nil {
				b.Errorf("verify: %v", verifyErr)

				return
			}
		}
	})
}

func BenchmarkVerifyDisabled(b *testing.B) {
	cfg := config.DefaultConfig()

	verif, err := verifier.New(cfg, metrics.New(), nil)
	if err != nil {
		b.Fatalf("creating verifier: %v", err)
	}

	ctx := context.Background()

	b.ResetTimer()

	for range b.N {
		_, err = verif.Verify(ctx, "nginx:latest", "sha256:abc123", "", "default")
		if err != nil {
			b.Fatalf("verify: %v", err)
		}
	}
}

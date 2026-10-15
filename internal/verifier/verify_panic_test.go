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
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

// panickingFetcher panics on every fetch, like a parser tripping over a
// malformed registry payload.
type panickingFetcher struct {
	calls atomic.Int32
}

func (f *panickingFetcher) Fetch(
	_ context.Context, _ string, _ *attestation.FetchOptions,
) ([]attestation.VerifiedAttestation, error) {
	f.calls.Add(1)

	panic("malformed payload")
}

// TestVerifyRecoversPanicOutsideChecks checks that a panic outside a single
// check denies the image in enforce mode, admits it unverified in warn mode,
// is not cached, and does not leave the registry circuit breaker half-open.
func TestVerifyRecoversPanicOutsideChecks(t *testing.T) {
	t.Parallel()

	for _, mode := range []config.VerificationMode{config.ModeEnforce, config.ModeWarn} {
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()

			fetcher := &panickingFetcher{calls: atomic.Int32{}}

			cfg := config.DefaultConfig()
			cfg.Verification = mode
			cfg.CircuitBreakerThreshold = 1

			verif, _ := newHardeningVerifier(t, cfg, fetcher,
				map[string]string{testDefaultPolicy: testSLSADenyPolicy})

			digest := "sha256:" + strings.Repeat("a", 64)

			for call := range 2 {
				result, err := verif.Verify(context.Background(),
					newRequest(testHardeningImage, digest, "", "default", ""))

				if mode == config.ModeEnforce {
					if !errors.Is(err, verifier.ErrVerificationPanic) {
						t.Fatalf("call %d: expected a panic error, got %v", call, err)
					}

					continue
				}

				testutil.AssertNoError(t, err)

				if !result.Allowed || result.Verified {
					t.Fatalf("call %d: expected an unverified admission, got %+v", call, result)
				}

				if len(result.CheckResults) == 0 ||
					result.CheckResults[0].Type != types.CheckTypeInternal {
					t.Fatalf("call %d: expected an internal check result, got %+v",
						call, result.CheckResults)
				}
			}

			if got := fetcher.calls.Load(); got != 2 {
				t.Errorf("expected the failed verification not to be cached, got %d fetches", got)
			}

			if state := verif.Status().CircuitBreakers["ghcr.io"]; state != "closed" {
				t.Errorf("expected the breaker to stay closed, got %q", state)
			}
		})
	}
}

// TestVerifyPanicCountsAdmissionsOnly checks that a panicked verification
// counts as an internal failure for admissions only, not for background
// verifications.
func TestVerifyPanicCountsAdmissionsOnly(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce

	verif, met := newHardeningVerifier(t, cfg, &panickingFetcher{calls: atomic.Int32{}},
		map[string]string{testDefaultPolicy: testSLSADenyPolicy})

	digest := "sha256:" + strings.Repeat("b", 64)
	internalFailures := func() float64 {
		return promtestutil.ToFloat64(met.VerificationTotal.WithLabelValues(
			string(types.CheckTypeInternal), string(types.StatusFail), "default",
		))
	}

	_, err := verif.Verify(types.WithVerifyOrigin(context.Background(), types.OriginPrewarm),
		newRequest(testHardeningImage, digest, "", "default", ""))
	if !errors.Is(err, verifier.ErrVerificationPanic) {
		t.Fatalf("expected a panic error, got %v", err)
	}

	if got := internalFailures(); got != 0 {
		t.Errorf("expected no admission failure for pre-warming, got %v", got)
	}

	_, err = verif.Verify(context.Background(),
		newRequest(testHardeningImage, digest, "", "default", ""))
	if !errors.Is(err, verifier.ErrVerificationPanic) {
		t.Fatalf("expected a panic error, got %v", err)
	}

	if got := internalFailures(); got != 1 {
		t.Errorf("expected one admission failure, got %v", got)
	}
}

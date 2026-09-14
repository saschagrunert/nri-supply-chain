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
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/v1/remote/transport"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

const testIndexDigest = "sha256:bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222"

// legFetcher returns a scripted outcome per fetched digest.
type legFetcher struct {
	attestations map[string][]attestation.VerifiedAttestation
	errs         map[string]error
}

func (f *legFetcher) Fetch(
	_ context.Context, _ string, opts *attestation.FetchOptions,
) ([]attestation.VerifiedAttestation, error) {
	return f.attestations[opts.Digest], f.errs[opts.Digest]
}

func errUntrustedBundles() error {
	return fmt.Errorf(
		"%w: all referrer bundles failed verification",
		attestation.ErrVerificationFailed,
	)
}

func TestVerifyFetchFailureIsNotVerified(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn

	verif, _ := newHardeningVerifier(t, cfg, newScriptedFetcher(connectionError()),
		map[string]string{testDefaultPolicy: `{}`})

	result, err := verif.Verify(context.Background(),
		newRequest(testHardeningImage, testFetchDigest, "", "default", ""))
	testutil.AssertNoError(t, err)

	if !result.Allowed {
		t.Fatalf("expected warn mode to admit a fetch failure, got %q", result.Reason)
	}

	if result.Verified {
		t.Error("expected a result without fetched attestations not to be verified")
	}

	if !result.Incomplete() {
		t.Error("expected a result without fetched attestations to be incomplete")
	}
}

func TestVerifyAttestationVerificationFailureIsNotIncomplete(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn

	verif, _ := newHardeningVerifier(t, cfg, newScriptedFetcher(errUntrustedBundles()),
		map[string]string{testDefaultPolicy: testSLSADenyPolicy})

	result, err := verif.Verify(context.Background(),
		newRequest(testHardeningImage, testFetchDigest, "", "default", ""))
	testutil.AssertNoError(t, err)

	if result.Verified || result.Incomplete() {
		t.Errorf("expected a completed, failed verification, got verified=%v incomplete=%v",
			result.Verified, result.Incomplete())
	}
}

func TestVerifyIndexLegVerificationFailureWithPlatformTransportFailure(t *testing.T) {
	t.Parallel()

	fetcher := &legFetcher{
		attestations: nil,
		errs: map[string]error{
			testIndexDigest: errUntrustedBundles(),
			testFetchDigest: connectionError(),
		},
	}

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.FetchFailurePolicy = types.ActionAllow
	cfg.FetchFailurePolicyExplicit = true
	cfg.CircuitBreakerThreshold = 1

	verif, _ := newHardeningVerifier(t, cfg, fetcher, map[string]string{testDefaultPolicy: `{}`})

	_, err := verif.Verify(context.Background(),
		newRequest(testHardeningImage, testFetchDigest, testIndexDigest, "default", ""))
	if err != nil {
		t.Fatalf(
			"expected the platform transport failure to follow fetch_failure_policy, got %v",
			err,
		)
	}

	if state := verif.Status().CircuitBreakers["ghcr.io"]; state != "open" {
		t.Errorf("expected the transport failure to trip the breaker, got state %q", state)
	}
}

func TestVerifyIndexLegTransportFailureWithPlatformVerificationFailure(t *testing.T) {
	t.Parallel()

	fetcher := &legFetcher{
		attestations: nil,
		errs: map[string]error{
			testIndexDigest: connectionError(),
			testFetchDigest: errUntrustedBundles(),
		},
	}

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.FetchFailurePolicy = types.ActionAllow
	cfg.FetchFailurePolicyExplicit = true
	cfg.CircuitBreakerThreshold = 1

	verif, _ := newHardeningVerifier(t, cfg, fetcher,
		map[string]string{testDefaultPolicy: testSLSADenyPolicy})

	result, err := verif.Verify(context.Background(),
		newRequest(testHardeningImage, testFetchDigest, testIndexDigest, "default", ""))
	if err != nil {
		t.Fatalf("expected the transport failure to follow fetch_failure_policy (allow), got %v",
			err)
	}

	if !result.Incomplete() || result.Verified {
		t.Errorf("expected an incomplete, unverified result, got incomplete=%v verified=%v",
			result.Incomplete(), result.Verified)
	}

	if state := verif.Status().CircuitBreakers["ghcr.io"]; state != "open" {
		t.Errorf("expected the index transport failure to trip the breaker, got state %q", state)
	}
}

func TestVerifyIndexLegErrorWithPlatformAttestations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		indexErr error
		wantDeny bool
	}{
		{
			name: "incomplete index set denies",
			indexErr: fmt.Errorf("%w: %w: 51 referrers exceed the per-image limits",
				attestation.ErrVerificationFailed, attestation.ErrIncompleteAttestationSet),
			wantDeny: true,
		},
		{
			name:     "registry error follows fetch_failure_policy",
			indexErr: &transport.Error{StatusCode: http.StatusForbidden},
			wantDeny: true,
		},
		{
			name:     "unverified index attestations are ignored",
			indexErr: errUntrustedBundles(),
			wantDeny: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fetcher := &legFetcher{
				attestations: map[string][]attestation.VerifiedAttestation{
					testFetchDigest: {{
						PredicateType: attestation.PredicateCosignSignature,
						Digest:        testFetchDigest,
					}},
				},
				errs: map[string]error{testIndexDigest: test.indexErr},
			}

			cfg := config.DefaultConfig()
			cfg.Verification = config.ModeEnforce
			cfg.FetchFailurePolicy = types.ActionDeny
			cfg.FetchFailurePolicyExplicit = true

			verif, _ := newHardeningVerifier(t, cfg, fetcher,
				map[string]string{testDefaultPolicy: `{}`})

			_, err := verif.Verify(context.Background(),
				newRequest(testHardeningImage, testFetchDigest, testIndexDigest, "default", ""))
			if denied := errors.Is(err, verifier.ErrVerificationFailed); denied != test.wantDeny {
				t.Errorf("denied = %v, want %v (error: %v)", denied, test.wantDeny, err)
			}
		})
	}
}

func TestVerifyTransportFailureNotBypassedByUnverifiedAttestations(t *testing.T) {
	t.Parallel()

	fetcher := &legFetcher{
		attestations: nil,
		errs: map[string]error{
			testIndexDigest: connectionError(),
			testFetchDigest: errUntrustedBundles(),
		},
	}

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.FetchFailurePolicy = types.ActionDeny
	cfg.FetchFailurePolicyExplicit = true

	verif, _ := newHardeningVerifier(t, cfg, fetcher,
		map[string]string{testDefaultPolicy: `{}`})

	_, err := verif.Verify(context.Background(),
		newRequest(testHardeningImage, testFetchDigest, testIndexDigest, "default", ""))
	if !errors.Is(err, verifier.ErrVerificationFailed) {
		t.Fatalf(
			"expected fetch_failure_policy deny to deny despite unverified attestations, got %v",
			err,
		)
	}
}

// blockingFetcher blocks every fetch until release is closed.
type blockingFetcher struct {
	release chan struct{}
}

func (f *blockingFetcher) Fetch(
	ctx context.Context, _ string, _ *attestation.FetchOptions,
) ([]attestation.VerifiedAttestation, error) {
	select {
	case <-f.release:
		return nil, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("blocked fetch: %w", ctx.Err())
	}
}

func TestVerifyJoiningLongRunningVerificationFailsFast(t *testing.T) {
	t.Parallel()

	const budget = 100 * time.Millisecond

	fetcher := &blockingFetcher{release: make(chan struct{})}

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.AdmissionTimeout = config.Duration{Duration: budget}

	verif, _ := newHardeningVerifier(t, cfg, fetcher, map[string]string{testDefaultPolicy: `{}`})
	t.Cleanup(func() { close(fetcher.release) })

	req := newRequest(testHardeningImage, testFetchDigest, "", "default", "")

	first, cancelFirst := context.WithTimeout(context.Background(), budget)
	defer cancelFirst()

	_, err := verif.Verify(first, req)
	if err == nil {
		t.Fatal("expected the first admission to time out")
	}

	time.Sleep(20 * time.Millisecond)

	second, cancelSecond := context.WithTimeout(context.Background(), budget)
	defer cancelSecond()

	start := time.Now()
	_, err = verif.Verify(second, req)
	elapsed := time.Since(start)

	if elapsed > budget/2 {
		t.Errorf("expected joining a long-running verification to fail fast, took %s", elapsed)
	}

	if !errors.Is(err, verifier.ErrVerificationInProgress) {
		t.Errorf("expected ErrVerificationInProgress, got %v", err)
	}
}

func TestVerifyEmptyDigestRequiresDigestWhenVerificationNeeded(t *testing.T) {
	t.Parallel()

	fetcher := newScriptedFetcher(nil)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn

	verif, _ := newHardeningVerifier(t, cfg, fetcher, map[string]string{
		testDefaultPolicy: `{"exclude": ["docker.io/library/excluded:*"]}`,
	})

	_, err := verif.Verify(context.Background(),
		newRequest(testHardeningImage, "", "", "default", ""))
	if !errors.Is(err, types.ErrDigestRequired) {
		t.Fatalf("expected ErrDigestRequired for an image that needs verification, got %v", err)
	}

	result, err := verif.Verify(context.Background(),
		newRequest("docker.io/library/excluded:v1", "", "", "default", ""))
	testutil.AssertNoError(t, err)

	if !result.Allowed {
		t.Errorf(
			"expected an excluded image to be admitted without a digest, got %q",
			result.Reason,
		)
	}

	if got := fetcher.calls.Load(); got != 0 {
		t.Errorf("expected no fetch without a digest, got %d", got)
	}
}

func TestBuilderKeysOnlyTrustedForProvenance(t *testing.T) {
	t.Parallel()

	builderKey := createTempKeyFile(t, t.TempDir())
	verifierKey := filepath.Join(t.TempDir(), "verifier.pub")
	createTempKeyFileAt(t, verifierKey)

	sbomSignedBy := func(keyPath string) *scriptedFetcher {
		fetcher := newScriptedFetcher(nil)
		fetcher.attestations = []attestation.VerifiedAttestation{{
			PredicateType: attestation.PredicateSPDX,
			Payload:       validSBOMPayload(t),
			Digest:        testFetchDigest,
			Signer: attestation.SignerIdentity{
				KeyPath: keyPath, KeyPaths: []string{keyPath}, Issuer: "", SAN: "",
			},
		}}

		return fetcher
	}

	policyJSON := `{
		"trust": {
			"builders": [{"id": "` + testBuilderRunner + `", "keys": ["` + builderKey + `"]}],
			"verifiers": [{"id": "https://example.com/verifier", "keys": ["` + verifierKey + `"]}]
		},
		"sbom": {"missingPolicy": "deny"}
	}`

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce

	builderSigned, _ := newHardeningVerifier(
		t, cfg, sbomSignedBy(builderKey), map[string]string{testDefaultPolicy: policyJSON},
	)

	_, err := builderSigned.Verify(context.Background(),
		newRequest(testHardeningImage, testFetchDigest, "", "default", ""))
	if !errors.Is(err, verifier.ErrVerificationFailed) {
		t.Errorf("expected an SBOM signed with a builder key to be ignored, got %v", err)
	}

	verifierCfg := config.DefaultConfig()
	verifierCfg.Verification = config.ModeEnforce

	verifierSigned, _ := newHardeningVerifier(
		t, verifierCfg, sbomSignedBy(verifierKey), map[string]string{testDefaultPolicy: policyJSON},
	)

	result, err := verifierSigned.Verify(context.Background(),
		newRequest(testHardeningImage, testFetchDigest, "", "default", ""))
	if err != nil {
		t.Fatalf("expected an SBOM signed with a verifier key to be accepted, got %v", err)
	}

	if !result.Verified {
		t.Errorf("expected the verifier-signed SBOM to verify, got %q", result.Reason)
	}
}

func TestVSAShortCircuitKeepsGUACResult(t *testing.T) {
	t.Parallel()

	keyPath := createTempKeyFile(t, t.TempDir())

	pol := &policy.Policy{}
	pol.Trust = &policy.TrustPolicy{
		Verifiers: []policy.TrustedVerifier{{
			ID: "https://example.com/verifier", Keys: []string{keyPath},
		}},
	}

	vsaAtts := []attestation.VerifiedAttestation{{
		PredicateType: attestation.PredicateVSA,
		Payload:       validVSAPayload(t, "PASSED"),
		Digest:        testFetchDigest,
		Signer: attestation.SignerIdentity{
			KeyPath: keyPath, KeyPaths: []string{keyPath}, Issuer: "", SAN: "",
		},
	}}

	guacResult := types.PassResult(types.CheckTypeGUAC, "GUAC data available")

	result := verifier.ExportRunVSAAndParallelChecks(
		context.Background(), vsaAtts, pol, metrics.New(),
		"nginx:latest", testFetchDigest, guacResult,
	)

	if len(result.CheckResults) == 0 || result.CheckResults[0].Type != types.CheckTypeVSA {
		t.Fatalf("expected the VSA short-circuit path, got %+v", result.CheckResults)
	}

	for idx := range result.CheckResults {
		if result.CheckResults[idx].Type == types.CheckTypeGUAC {
			return
		}
	}

	t.Errorf("expected the GUAC result on a VSA-accelerated image, got %+v", result.CheckResults)
}

func createTempKeyFileAt(t *testing.T, path string) {
	t.Helper()

	err := os.WriteFile(path, []byte("placeholder-key"), 0o600)
	if err != nil {
		t.Fatalf("creating temp key file: %v", err)
	}
}

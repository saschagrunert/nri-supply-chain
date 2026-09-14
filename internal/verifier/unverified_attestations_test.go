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
	"testing"

	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

const testSLSADenyPolicy = `{"slsa":{"missingPolicy":"deny"}}`

func findCheck(result *types.Result, checkType types.CheckType) *types.CheckResult {
	if result == nil {
		return nil
	}

	for idx := range result.CheckResults {
		if result.CheckResults[idx].Type == checkType {
			return &result.CheckResults[idx]
		}
	}

	return nil
}

func TestVerifyUnverifiedAttestationsAreTreatedAsMissing(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.CircuitBreakerThreshold = 1

	verif, met := newHardeningVerifier(t, cfg, newScriptedFetcher(errUntrustedBundles()),
		map[string]string{testDefaultPolicy: `{}`})

	result, err := verif.Verify(context.Background(),
		newRequest(testHardeningImage, testFetchDigest, "", "default", ""))
	if err != nil {
		t.Fatalf("expected permissive missing policies to admit an image whose "+
			"attestations did not verify, got %v", err)
	}

	check := findCheck(result, types.CheckTypeAttestation)
	if check == nil || check.Status != types.StatusWarn {
		t.Fatalf("expected a warn attestation check, got %+v", result.CheckResults)
	}

	if findCheck(result, types.CheckTypeFetch) != nil || result.Incomplete() {
		t.Error("expected unverified attestations not to follow fetch_failure_policy")
	}

	if trips := promtestutil.CollectAndCount(met.CircuitBreakerTripsTotal); trips != 0 {
		t.Errorf("expected unverified attestations not to trip the breaker, got %d", trips)
	}
}

func TestVerifyUnverifiedAttestationsApplyMissingPolicy(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.FetchFailurePolicy = types.ActionAllow
	cfg.FetchFailurePolicyExplicit = true

	verif, _ := newHardeningVerifier(t, cfg, newScriptedFetcher(errUntrustedBundles()),
		map[string]string{testDefaultPolicy: testSLSADenyPolicy})

	result, err := verif.Verify(context.Background(),
		newRequest(testHardeningImage, testFetchDigest, "", "default", ""))
	if !errors.Is(err, verifier.ErrVerificationFailed) {
		t.Fatalf("expected slsa.missingPolicy deny to deny, got %v", err)
	}

	if check := findCheck(result, types.CheckTypeSLSA); check == nil || check.Passed {
		t.Errorf("expected a failing slsa missing check, got %+v", result)
	}

	if findCheck(result, types.CheckTypeAttestation) == nil {
		t.Errorf("expected the unverified attestations to be reported, got %+v", result)
	}
}

func TestVerifyIncompleteAttestationSetDenies(t *testing.T) {
	t.Parallel()

	fetcher := newScriptedFetcher(fmt.Errorf(
		"%w: %w: 51 referrers exceed the per-image limits",
		attestation.ErrVerificationFailed, attestation.ErrIncompleteAttestationSet,
	))

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.FetchFailurePolicy = types.ActionAllow
	cfg.FetchFailurePolicyExplicit = true

	verif, _ := newHardeningVerifier(t, cfg, fetcher, map[string]string{testDefaultPolicy: `{}`})

	_, err := verif.Verify(context.Background(),
		newRequest(testHardeningImage, testFetchDigest, "", "default", ""))
	if !errors.Is(err, verifier.ErrVerificationFailed) {
		t.Fatalf("expected an incomplete attestation set to deny, got %v", err)
	}
}

func TestVerifyIndexTransportFailureWithEmptyPlatformIsIncomplete(t *testing.T) {
	t.Parallel()

	fetcher := &legFetcher{
		attestations: nil,
		errs:         map[string]error{testIndexDigest: connectionError()},
	}

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.FetchFailurePolicy = types.ActionAllow
	cfg.FetchFailurePolicyExplicit = true

	verif, _ := newHardeningVerifier(t, cfg, fetcher,
		map[string]string{testDefaultPolicy: testSLSADenyPolicy})

	result, err := verif.Verify(context.Background(),
		newRequest(testHardeningImage, testFetchDigest, testIndexDigest, "default", ""))
	if err != nil {
		t.Fatalf("expected the index transport failure to follow fetch_failure_policy, got %v", err)
	}

	if !result.Incomplete() || result.Verified {
		t.Errorf("expected an incomplete, unverified result, got incomplete=%v verified=%v",
			result.Incomplete(), result.Verified)
	}
}

func TestVerifyUnverifiedIndexAttestationsWithEmptyPlatform(t *testing.T) {
	t.Parallel()

	fetcher := &legFetcher{
		attestations: nil,
		errs:         map[string]error{testIndexDigest: errUntrustedBundles()},
	}

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce

	verif, _ := newHardeningVerifier(t, cfg, fetcher,
		map[string]string{testDefaultPolicy: testSLSADenyPolicy})

	result, err := verif.Verify(context.Background(),
		newRequest(testHardeningImage, testFetchDigest, testIndexDigest, "default", ""))
	if !errors.Is(err, verifier.ErrVerificationFailed) {
		t.Fatalf("expected slsa.missingPolicy deny to deny, got %v", err)
	}

	if findCheck(result, types.CheckTypeAttestation) == nil {
		t.Errorf("expected the unverified index attestations to be reported, got %+v", result)
	}
}

func TestJunkNotationSignatureDoesNotDenyWithoutPolicy(t *testing.T) {
	t.Parallel()

	fetcher := &mockFetcher{
		attestations: []attestation.VerifiedAttestation{
			{
				SignatureType: attestation.SignatureTypeNotation,
				Payload:       []byte("junk-signature"),
				Digest:        testFetchDigest,
				Signer: attestation.SignerIdentity{
					KeyPath: "", KeyPaths: nil, Issuer: "", SAN: "",
				},
			},
		},
		err: nil,
	}

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce

	verif, _ := newHardeningVerifier(t, cfg, fetcher,
		map[string]string{testDefaultPolicy: `{}`})

	result, err := verif.Verify(context.Background(),
		newRequest(testHardeningImage, testFetchDigest, "", "default", ""))
	if err != nil {
		t.Fatalf("expected a junk Notation signature not to deny when Notation is "+
			"not configured in the policy, got %v", err)
	}

	check := findCheck(result, types.CheckTypeNotation)
	if check == nil {
		t.Fatal("expected a Notation check result")
	}

	if !check.Missing {
		t.Error("expected the Notation check to be marked as missing when no policy section exists")
	}
}

func TestScopeBuilderKeysUsesAllMatchedKeyPaths(t *testing.T) {
	t.Parallel()

	const (
		builderKey  = "/etc/keys/builder.pub"
		verifierKey = "/etc/keys/verifier.pub"
	)

	pol := &policy.Policy{}
	pol.Trust = &policy.TrustPolicy{
		Builders: []policy.TrustedBuilder{{
			ID: "https://builder", MaxLevel: 3, Keys: []string{builderKey}, Identities: nil,
		}},
		Verifiers: []policy.TrustedVerifier{{
			ID: "https://verifier", Keys: []string{verifierKey},
		}},
	}

	vex := func(keyPath string, keyPaths ...string) attestation.VerifiedAttestation {
		return attestation.VerifiedAttestation{
			PredicateType: attestation.PredicateOpenVEX,
			Signer: attestation.SignerIdentity{
				KeyPath: keyPath, KeyPaths: keyPaths, Issuer: "", SAN: "",
			},
		}
	}

	tests := []struct {
		name string
		att  attestation.VerifiedAttestation
		keep bool
	}{
		{"builder key only", vex(builderKey, builderKey), false},
		{"builder key without key paths", vex(builderKey), false},
		{"same key at builder and verifier paths", vex(builderKey, builderKey, verifierKey), true},
		{"verifier key", vex(verifierKey, verifierKey), true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			kept := verifier.ExportScopeBuilderKeys(
				[]attestation.VerifiedAttestation{test.att}, pol,
			)
			if got := len(kept) == 1; got != test.keep {
				t.Errorf("kept = %v, want %v", got, test.keep)
			}
		})
	}
}

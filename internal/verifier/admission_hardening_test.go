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
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

const (
	testHardeningImage = "ghcr.io/org/app:v1"
	testHardeningNS    = "prod"
	testDefaultPolicy  = "default.json"
)

var errNotFound = errors.New("manifest unknown")

// scriptedFetcher returns a fixed result and counts calls.
type scriptedFetcher struct {
	calls        atomic.Int32
	attestations []attestation.VerifiedAttestation
	err          error
}

func (f *scriptedFetcher) Fetch(
	_ context.Context, _ string, _ *attestation.FetchOptions,
) ([]attestation.VerifiedAttestation, error) {
	f.calls.Add(1)

	return f.attestations, f.err
}

func newScriptedFetcher(err error) *scriptedFetcher {
	return &scriptedFetcher{calls: atomic.Int32{}, attestations: nil, err: err}
}

// connectionError returns a registry connection error, which counts toward
// the circuit breaker.
func connectionError() error {
	return &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: errRegistryUnavail}
}

func newHardeningVerifier(
	t *testing.T, cfg *config.Config, fetcher attestation.Fetcher, policies map[string]string,
) (*verifier.Verifier, *metrics.Metrics) {
	t.Helper()

	dir := t.TempDir()
	for file, content := range policies {
		testutil.WritePolicy(t, dir, file, content)
	}

	cfg.PolicyDir = dir
	met := metrics.New()

	verif, err := verifier.New(t.Context(), cfg, met, fetcher)
	testutil.AssertNoError(t, err)
	t.Cleanup(verif.Stop)

	return verif, met
}

func TestShouldVerify(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn

	verif, _ := newHardeningVerifier(t, cfg, nil, map[string]string{
		testDefaultPolicy: `{"exclude": ["ghcr.io/org/excluded:*"]}`,
		"prod.json":       `{"include": ["ghcr.io/org/**"]}`,
	})

	tests := []struct {
		name      string
		namespace string
		imageRef  string
		want      bool
	}{
		{"default policy verifies", "default", "docker.io/library/nginx:latest", true},
		{"excluded image skipped", "default", "ghcr.io/org/excluded:v1", false},
		{"included image verified", testHardeningNS, testHardeningImage, true},
		{"not included image skipped", testHardeningNS, "docker.io/library/nginx:latest", false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, reason := verif.ShouldVerify(context.Background(), test.namespace, test.imageRef)
			if got != test.want {
				t.Errorf("ShouldVerify = %v (%s), want %v", got, reason, test.want)
			}

			if !got && reason == "" {
				t.Error("expected a reason when verification is skipped")
			}
		})
	}
}

func TestShouldVerifyDisabled(t *testing.T) {
	t.Parallel()

	verif, err := verifier.New(t.Context(), config.DefaultConfig(), metrics.New(), nil)
	testutil.AssertNoError(t, err)
	t.Cleanup(verif.Stop)

	if got, _ := verif.ShouldVerify(context.Background(), "default", testHardeningImage); got {
		t.Error("expected no verification while verification is disabled")
	}
}

func TestVerifyReportsVerifiedAndModeInWarn(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn

	verif, _ := newHardeningVerifier(t, cfg, newScriptedFetcher(nil), map[string]string{
		testDefaultPolicy: `{"slsa": {"missingPolicy": "deny"}}`,
	})

	result, err := verif.Verify(context.Background(),
		newRequest(testHardeningImage, testFetchDigest, "", "default", ""))
	testutil.AssertNoError(t, err)

	if !result.Allowed || result.Verified {
		t.Errorf("expected admitted but not verified, got allowed=%v verified=%v",
			result.Allowed, result.Verified)
	}

	if result.Mode != string(config.ModeWarn) {
		t.Errorf("expected mode warn, got %q", result.Mode)
	}
}

func TestVerifyNamespaceEnforceDeniesFetchFailure(t *testing.T) {
	t.Parallel()

	fetcher := newScriptedFetcher(connectionError())

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn

	verif, _ := newHardeningVerifier(t, cfg, fetcher, map[string]string{
		testDefaultPolicy: `{}`,
		"prod.json":       `{"mode": "enforce"}`,
	})

	_, err := verif.Verify(context.Background(),
		newRequest(testHardeningImage, testFetchDigest, "", testHardeningNS, ""))
	if !errors.Is(err, verifier.ErrVerificationFailed) {
		t.Fatalf("expected enforce namespace to deny on fetch failure, got %v", err)
	}

	result, err := verif.Verify(context.Background(),
		newRequest(testHardeningImage, testFetchDigest, "", "default", ""))
	testutil.AssertNoError(t, err)

	if !result.Allowed {
		t.Error("expected warn namespace to keep the warn fetch failure policy")
	}
}

// TestVerifyAttestationVerificationFailureIgnoresFetchPolicy checks that
// attestations failing verification apply the missing policies instead of a
// lenient fetch_failure_policy, and never trip the circuit breaker.
func TestVerifyAttestationVerificationFailureIgnoresFetchPolicy(t *testing.T) {
	t.Parallel()

	fetcher := newScriptedFetcher(
		fmt.Errorf(
			"%w: all referrer bundles failed verification",
			attestation.ErrVerificationFailed,
		),
	)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.FetchFailurePolicy = types.ActionWarn
	cfg.FetchFailurePolicyExplicit = true
	cfg.CircuitBreakerThreshold = 1
	cfg.CacheTTL = config.Duration{Duration: 0}
	cfg.CacheFailureTTL = config.Duration{Duration: 0}

	verif, met := newHardeningVerifier(t, cfg, fetcher,
		map[string]string{testDefaultPolicy: `{"slsa":{"missingPolicy":"deny"}}`})

	for call := range 3 {
		digest := "sha256:" + strings.Repeat(string("abc"[call]), 64)

		_, err := verif.Verify(context.Background(),
			newRequest(testHardeningImage, digest, "", "default", ""))
		if !errors.Is(err, verifier.ErrVerificationFailed) {
			t.Fatalf("call %d: expected verification failure to deny, got %v", call, err)
		}
	}

	if got := fetcher.calls.Load(); got != 3 {
		t.Errorf("expected every request to reach the registry, got %d fetches", got)
	}

	if trips := promtestutil.CollectAndCount(met.CircuitBreakerTripsTotal); trips != 0 {
		t.Errorf(
			"expected verification failures not to trip the breaker, got %d trip series",
			trips,
		)
	}
}

func TestVerifyNonTransportErrorsDoNotTripBreaker(t *testing.T) {
	t.Parallel()

	fetcher := newScriptedFetcher(errNotFound)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.CircuitBreakerThreshold = 1
	cfg.CacheTTL = config.Duration{Duration: 0}
	cfg.CacheFailureTTL = config.Duration{Duration: 0}

	verif, _ := newHardeningVerifier(t, cfg, fetcher, map[string]string{testDefaultPolicy: `{}`})

	for call := range 3 {
		digest := "sha256:" + strings.Repeat(string("def"[call]), 64)

		_, err := verif.Verify(context.Background(),
			newRequest(testHardeningImage, digest, "", "default", ""))
		testutil.AssertNoError(t, err)
	}

	if got := fetcher.calls.Load(); got != 3 {
		t.Errorf("expected the breaker to stay closed, got %d fetches", got)
	}

	if state := verif.Status().CircuitBreakers["ghcr.io"]; state != "closed" {
		t.Errorf("expected closed breaker, got %q", state)
	}
}

func TestVerifyEmptyDigestRejectedWithoutBreaker(t *testing.T) {
	t.Parallel()

	fetcher := newScriptedFetcher(nil)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.CircuitBreakerThreshold = 1

	verif, _ := newHardeningVerifier(t, cfg, fetcher, map[string]string{testDefaultPolicy: `{}`})

	_, err := verif.Verify(
		context.Background(),
		newRequest(testHardeningImage, "", "", "default", ""),
	)
	if !errors.Is(err, types.ErrDigestRequired) {
		t.Fatalf("expected empty digest to be rejected, got %v", err)
	}

	if got := fetcher.calls.Load(); got != 0 {
		t.Errorf("expected no fetch for an empty digest, got %d", got)
	}

	if _, tracked := verif.Status().CircuitBreakers["ghcr.io"]; tracked {
		t.Error("expected no circuit breaker activity for an empty digest")
	}
}

func TestVerifyBreakerOpenResultNotCached(t *testing.T) {
	t.Parallel()

	fetcher := newScriptedFetcher(connectionError())

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.CircuitBreakerThreshold = 1
	cfg.CircuitBreakerCooldown = config.Duration{Duration: 50 * time.Millisecond}

	verif, _ := newHardeningVerifier(t, cfg, fetcher, map[string]string{testDefaultPolicy: `{}`})

	first := "sha256:" + strings.Repeat("1", 64)
	second := "sha256:" + strings.Repeat("2", 64)

	// Trip the breaker, then get a breaker-open result for another digest.
	_, err := verif.Verify(
		context.Background(),
		newRequest(testHardeningImage, first, "", "default", ""),
	)
	testutil.AssertNoError(t, err)

	_, err = verif.Verify(
		context.Background(),
		newRequest(testHardeningImage, second, "", "default", ""),
	)
	testutil.AssertNoError(t, err)

	if got := fetcher.calls.Load(); got != 1 {
		t.Fatalf("expected the open breaker to skip the fetch, got %d fetches", got)
	}

	time.Sleep(100 * time.Millisecond)

	fetcher.err = nil

	result, err := verif.Verify(
		context.Background(),
		newRequest(testHardeningImage, second, "", "default", ""),
	)
	testutil.AssertNoError(t, err)

	if got := fetcher.calls.Load(); got != 2 {
		t.Errorf("expected a fresh fetch after the cooldown, got %d fetches", got)
	}

	if strings.Contains(result.Reason, "circuit breaker open") {
		t.Errorf("expected no cached breaker-open result, got %q", result.Reason)
	}
}

func TestInvalidateCacheRemovesImageAndRuleKeys(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn

	verif, met := newHardeningVerifier(t, cfg, newScriptedFetcher(nil), map[string]string{
		testDefaultPolicy: `{"rules": [{"images": ["ghcr.io/org/**"], "slsa": {"missingPolicy": "warn"}}]}`,
	})

	req := newRequest(testHardeningImage, testFetchDigest, "", "default", "")

	for range 2 {
		_, err := verif.Verify(context.Background(), req)
		testutil.AssertNoError(t, err)
	}

	if hits := promtestutil.ToFloat64(met.CacheHitsTotal); hits != 1 {
		t.Fatalf("expected one cache hit before invalidation, got %v", hits)
	}

	verif.InvalidateCache(testFetchDigest, "default")

	_, err := verif.Verify(context.Background(), req)
	testutil.AssertNoError(t, err)

	if misses := promtestutil.ToFloat64(met.CacheMissesTotal); misses != 2 {
		t.Errorf("expected a cache miss after invalidation, got %v misses", misses)
	}
}

func TestCacheKeyIncludesImageReference(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn

	fetcher := newScriptedFetcher(nil)
	verif, _ := newHardeningVerifier(t, cfg, fetcher, map[string]string{testDefaultPolicy: `{}`})

	for _, imageRef := range []string{"ghcr.io/org/app:v1", "ghcr.io/other/app:v1"} {
		_, err := verif.Verify(
			context.Background(),
			newRequest(imageRef, testFetchDigest, "", "default", ""),
		)
		testutil.AssertNoError(t, err)
	}

	if got := fetcher.calls.Load(); got != 2 {
		t.Errorf("expected separate results per image reference, got %d fetches", got)
	}
}

func TestReloadKeyRotationInvalidatesCache(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "verifier.pub")
	testutil.AssertNoError(t, os.WriteFile(keyPath, []byte("old-key"), 0o600))

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn

	verif, _ := newHardeningVerifier(t, cfg, newScriptedFetcher(nil), map[string]string{
		testDefaultPolicy: `{"trust": {"verifiers": [{"id": "https://example.com/v", "keys": ["` +
			keyPath + `"]}]}}`,
	})

	reloadCfg := *verif.CurrentConfig()

	testutil.AssertNoError(t, verif.Reload(context.Background(), &reloadCfg))

	unchanged := verif.ExportGeneration()

	testutil.AssertNoError(t, verif.Reload(context.Background(), &reloadCfg))

	if got := verif.ExportGeneration(); got != unchanged {
		t.Errorf(
			"expected an unchanged reload to keep the cache generation, got %d want %d",
			got,
			unchanged,
		)
	}

	testutil.AssertNoError(t, os.WriteFile(keyPath, []byte("rotated-key"), 0o600))
	testutil.AssertNoError(t, verif.Reload(context.Background(), &reloadCfg))

	if got := verif.ExportGeneration(); got == unchanged {
		t.Error("expected key rotation to invalidate cached results")
	}
}

func TestStopRejectsNewVerifications(t *testing.T) {
	t.Parallel()

	verif, err := verifier.New(t.Context(), config.DefaultConfig(), metrics.New(), nil)
	testutil.AssertNoError(t, err)

	if !verif.ExportFlightsBegin() {
		t.Fatal("expected a verification to begin before stop")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()

	verif.StopContext(ctx)

	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("expected StopContext to be bounded, took %s", elapsed)
	}

	if verif.ExportFlightsBegin() {
		t.Error("expected no verification to begin after stop")
	}

	verif.ExportFlightsEnd()
}

func TestIsTransportFailure(t *testing.T) {
	t.Parallel()

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	tests := []struct {
		name string
		ctx  context.Context //nolint:containedctx // table test input
		err  error
		want bool
	}{
		{"nil", context.Background(), nil, false},
		{"plain error", context.Background(), errNotFound, false},
		{
			"connection error",
			context.Background(),
			&net.OpError{
				Op:     "dial",
				Net:    "tcp",
				Source: nil,
				Addr:   nil,
				Err:    errRegistryUnavail,
			},
			true,
		},
		{
			"server error", context.Background(),
			&transport.Error{StatusCode: http.StatusBadGateway, Errors: nil, Request: nil}, true,
		},
		{
			"rate limited",
			context.Background(),
			&transport.Error{
				StatusCode: http.StatusTooManyRequests,
				Errors:     nil,
				Request:    nil,
			},
			true,
		},
		{
			"not found", context.Background(),
			&transport.Error{StatusCode: http.StatusNotFound, Errors: nil, Request: nil}, false,
		},
		{"timeout", context.Background(), context.DeadlineExceeded, true},
		{"shutdown", cancelled, context.DeadlineExceeded, false},
		{
			"verification failure",
			context.Background(),
			fmt.Errorf(
				"%w: %w",
				attestation.ErrVerificationFailed,
				context.DeadlineExceeded,
			),
			false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := verifier.ExportIsTransportFailure(test.ctx, test.err); got != test.want {
				t.Errorf("isTransportFailure = %v, want %v", got, test.want)
			}
		})
	}
}

func TestBindBuilderSigner(t *testing.T) {
	t.Parallel()

	const (
		builderKey = "/etc/keys/builder.pub"
		issuer     = "https://token.actions.githubusercontent.com"
	)

	bound := policy.TrustedBuilder{
		ID: testBuilderRunner, MaxLevel: 3, Keys: []string{builderKey},
		Identities: []policy.TrustedIdentity{{
			Issuer: issuer, SANPattern: "https://github.com/slsa-framework/**",
		}},
	}
	unbound := policy.TrustedBuilder{
		ID: testBuilderRunner, MaxLevel: 3, Keys: nil, Identities: nil,
	}

	tests := []struct {
		name    string
		signer  attestation.SignerIdentity
		matched []policy.TrustedBuilder
		wantErr bool
	}{
		{
			"bound key matches",
			attestation.SignerIdentity{
				KeyPath: builderKey, KeyPaths: []string{builderKey}, Issuer: "", SAN: "",
			},
			[]policy.TrustedBuilder{bound},
			false,
		},
		{
			"bound identity matches",
			attestation.SignerIdentity{
				KeyPath:  "",
				KeyPaths: nil,
				Issuer:   issuer,
				SAN:      "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/b.yml@refs/tags/v2",
			},
			[]policy.TrustedBuilder{bound},
			false,
		},
		{
			"bound builder other signer",
			attestation.SignerIdentity{
				KeyPath:  "",
				KeyPaths: nil,
				Issuer:   issuer,
				SAN:      "https://github.com/attacker/repo/.github/workflows/b.yml@refs/heads/main",
			},
			[]policy.TrustedBuilder{bound},
			true,
		},
		{"unbound builder accepts any signer", attestation.SignerIdentity{
			KeyPath: "/other.pub", KeyPaths: []string{"/other.pub"}, Issuer: "", SAN: "",
		}, []policy.TrustedBuilder{unbound}, false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			att := &attestation.VerifiedAttestation{
				Signer: test.signer,
			}

			err := verifier.ExportBindBuilderSigner(att, test.matched)
			if (err != nil) != test.wantErr {
				t.Fatalf("expected error=%v, got %v", test.wantErr, err)
			}

			if err != nil && !errors.Is(err, verifier.ErrBuilderSignerMismatch) {
				t.Errorf("expected ErrBuilderSignerMismatch, got %v", err)
			}
		})
	}
}

func TestCheckRegistry(t *testing.T) {
	t.Parallel()

	checkTypes := verifier.ExportCheckSpecTypes()
	want := []types.CheckType{
		types.CheckTypeSLSA,
		types.CheckTypeVEX,
		types.CheckTypeNotation,
		types.CheckTypeSBOM,
		types.CheckTypeSCAI,
		types.CheckTypeSource,
		types.CheckTypeBuildEnv,
		types.CheckTypeVulnScan,
		types.CheckTypeTestResult,
		types.CheckTypeRelease,
		types.CheckTypeRuntimeTrace,
		types.CheckTypeScorecard,
	}

	if fmt.Sprint(checkTypes) != fmt.Sprint(want) {
		t.Errorf("unexpected check order %v, want %v", checkTypes, want)
	}

	cyclone := verifier.ExportPredicateCheckTypes(attestation.PredicateCycloneDX)
	if fmt.Sprint(
		cyclone,
	) != fmt.Sprint(
		[]types.CheckType{types.CheckTypeVEX, types.CheckTypeSBOM},
	) {
		t.Errorf("expected CycloneDX to feed VEX and SBOM, got %v", cyclone)
	}

	if vsaBins := verifier.ExportPredicateCheckTypes(attestation.PredicateVSA); len(vsaBins) != 1 {
		t.Errorf("expected VSA predicate binned once, got %v", vsaBins)
	}
}

func TestVSAShortCircuitStillRunsCEL(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keyPath := createTempKeyFile(t, dir)

	fetcher := &mockFetcher{
		attestations: []attestation.VerifiedAttestation{{
			PredicateType: attestation.PredicateVSA,
			Payload:       validVSAPayload(t, "PASSED"),
			Digest:        testFetchDigest,
			Signer: attestation.SignerIdentity{
				KeyPath: keyPath, KeyPaths: []string{keyPath}, Issuer: "", SAN: "",
			},
		}},
		err: nil,
	}

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn

	verif, _ := newHardeningVerifier(t, cfg, fetcher, map[string]string{
		testDefaultPolicy: `{
			"trust": {"verifiers": [{"id": "https://example.com/verifier", "keys": ["` + keyPath + `"]}]},
			"cel": {"rules": [{"require": "slsa.present == true", "message": "provenance required"}]}
		}`,
	})

	result, err := verif.Verify(
		context.Background(),
		newRequest("nginx:latest", testFetchDigest, "", "default", ""),
	)
	testutil.AssertNoError(t, err)

	if result.Verified {
		t.Error("expected CEL to evaluate on a VSA-accelerated image and fail")
	}

	if !strings.Contains(result.Reason, "provenance required") {
		t.Errorf("expected CEL failure in reason, got %q", result.Reason)
	}

	// The VSA must have short-circuited the direct checks: the result holds
	// the passing VSA and the CEL check, and no direct check results.
	checkTypes := make([]types.CheckType, 0, len(result.CheckResults))
	for idx := range result.CheckResults {
		checkTypes = append(checkTypes, result.CheckResults[idx].Type)
	}

	if len(result.CheckResults) != 2 ||
		result.CheckResults[0].Type != types.CheckTypeVSA || !result.CheckResults[0].Passed ||
		result.CheckResults[1].Type != types.CheckTypeCEL {
		t.Errorf("expected the VSA short-circuit path (vsa pass, cel), got %v", checkTypes)
	}
}

func TestReadyReportsStaleOCIPolicies(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn

	verif, _ := newHardeningVerifier(t, cfg, nil, map[string]string{testDefaultPolicy: `{}`})

	verif.ExportInstallPoller("ghcr.io/org/policies:v1", time.Millisecond)

	time.Sleep(10 * time.Millisecond)

	ready, reason := verif.Ready()
	if ready || !strings.Contains(reason, "not refreshed") {
		t.Errorf("expected not ready for stale OCI policies, got ready=%v reason=%q", ready, reason)
	}

	fresh, _ := newHardeningVerifier(t, cfg, nil, map[string]string{testDefaultPolicy: `{}`})
	fresh.ExportInstallPoller("ghcr.io/org/policies:v1", time.Hour)

	if ready, reason := fresh.Ready(); !ready {
		t.Errorf("expected ready within max staleness, got %q", reason)
	}
}

func TestOCIRollbackSeedFollowsReference(t *testing.T) {
	t.Parallel()

	verif, err := verifier.New(t.Context(), config.DefaultConfig(), metrics.New(), nil)
	testutil.AssertNoError(t, err)
	t.Cleanup(verif.Stop)

	const ociRef = "ghcr.io/org/policies:v1"

	created := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	verif.ExportInstallPoller(ociRef, 0).SeedNewestCreated(created)

	if got := verif.ExportOCIRollbackSeed(ociRef); !got.Equal(created) {
		t.Errorf("expected rollback seed %s, got %s", created, got)
	}

	if got := verif.ExportOCIRollbackSeed("ghcr.io/org/other:v1"); !got.IsZero() {
		t.Errorf("expected no rollback seed for another reference, got %s", got)
	}
}

func TestFetchOptionsForPolicyIncludesBuilderKeys(t *testing.T) {
	t.Parallel()

	pol := &policy.Policy{}
	pol.Trust = &policy.TrustPolicy{
		Verifiers: []policy.TrustedVerifier{{
			ID: "https://example.com/v", Keys: []string{"/keys/verifier.pub"},
		}},
		Builders: []policy.TrustedBuilder{{
			ID: testBuilderRunner, Keys: []string{"/keys/builder.pub"},
		}},
	}

	opts := verifier.FetchOptionsForPolicy(pol)

	paths := make([]string, 0, len(opts.TrustedKeys))
	for _, key := range opts.TrustedKeys {
		paths = append(paths, key.Path)
	}

	if fmt.Sprint(paths) != fmt.Sprint([]string{"/keys/verifier.pub", "/keys/builder.pub"}) {
		t.Errorf("expected verifier and builder keys, got %v", paths)
	}
}

func TestFetchOptionsForPolicyBoundsBuilderKeySharedWithVerifier(t *testing.T) {
	t.Parallel()

	const keyPath = "/keys/shared.pub"

	revoked := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	defaultPol := &policy.Policy{}
	defaultPol.Trust = &policy.TrustPolicy{
		Verifiers: []policy.TrustedVerifier{{
			ID: "https://example.com/v", Keys: []string{keyPath}, NotAfterTime: revoked,
		}},
	}

	// Each document is valid on its own, but the merged policy trusts the
	// same key path as a verifier and as a builder.
	namespacePol := &policy.Policy{}
	namespacePol.Trust = &policy.TrustPolicy{
		Builders: []policy.TrustedBuilder{{ID: testBuilderRunner, Keys: []string{keyPath}}},
	}

	opts := verifier.FetchOptionsForPolicy(policy.MergeWithDefault(namespacePol, defaultPol))

	if len(opts.TrustedKeys) != 1 || !opts.TrustedKeys[0].NotAfter.Equal(revoked) {
		t.Errorf("expected the shared key only with the verifier window ending %s, got %+v",
			revoked, opts.TrustedKeys)
	}
}

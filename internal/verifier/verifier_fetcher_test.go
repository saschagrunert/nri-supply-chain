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
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	openvex "github.com/openvex/go-vex/pkg/vex"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/slsa"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
	"github.com/saschagrunert/nri-supply-chain/internal/vsa"
)

const (
	testFetchDigest       = "sha256:abc123"
	testDefaultNamespace  = "default"
	testInTotoStatementV1 = "https://in-toto.io/Statement/v1"
	testOpenVEXPredicate  = "https://openvex.dev/ns"
	policyTrustRunnerJSON = `{
	"trust": {"builders": [{"id": "https://github.com/actions/runner", "maxLevel": 2}]}
}`
)

var (
	errMockFetch       = errors.New("mock fetch error")
	errRegistryUnavail = errors.New("registry unavailable")
)

type mockFetcher struct {
	attestations []attestation.VerifiedAttestation
	err          error
}

func (m *mockFetcher) Fetch(
	_ context.Context,
	_, _ string,
	_ *attestation.FetchOptions,
) ([]attestation.VerifiedAttestation, error) {
	return m.attestations, m.err
}

func marshalJSON(t *testing.T, val any) []byte {
	t.Helper()

	data, err := json.Marshal(val)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}

	return data
}

func validSLSAPayload(t *testing.T) []byte {
	t.Helper()

	stmt := slsa.Statement{
		Type: testInTotoStatementV1,
		Subject: []slsa.Subject{
			{
				Name:   "nginx",
				Digest: map[string]string{"sha256": "abc123"},
			},
		},
		PredicateType: attestation.PredicateSLSAProvenanceV1,
		Predicate: slsa.ProvenancePredicate{
			BuildDefinition: slsa.BuildDefinition{
				BuildType: "https://actions.github.io/buildtypes/workflow/v1",
				ExternalParameters: map[string]any{
					"source": "github.com/example/repo",
				},
				InternalParameters: map[string]any{},
			},
			RunDetails: slsa.RunDetails{
				Builder: slsa.Builder{
					ID: "https://github.com/actions/runner",
				},
				Metadata: slsa.Metadata{
					InvocationID: "run-123",
				},
			},
		},
	}

	return marshalJSON(t, stmt)
}

func validVSAPayload(t *testing.T, result string) []byte {
	t.Helper()

	stmt := vsa.Statement{
		Type:          testInTotoStatementV1,
		PredicateType: "https://slsa.dev/verification_summary/v1",
		Predicate: vsa.Predicate{
			Verifier: vsa.Verifier{
				ID: "https://example.com/verifier",
			},
			TimeVerified:       time.Now().UTC().Format(time.RFC3339),
			ResourceURI:        "index.docker.io/library/nginx@" + testFetchDigest,
			Policy:             vsa.Policy{URI: "https://example.com/policy"},
			VerificationResult: result,
			VerifiedLevels:     []string{"SLSA_BUILD_LEVEL_3"},
			SLSAVersion:        "1.0",
		},
	}

	return marshalJSON(t, stmt)
}

func validVEXPayload(t *testing.T, status openvex.Status) []byte {
	t.Helper()

	doc := openvex.VEX{
		Metadata: openvex.Metadata{
			Context: "https://openvex.dev/ns/v0.2.0",
			ID:      "https://openvex.dev/docs/example/vex-test",
		},
		Statements: []openvex.Statement{
			{
				Vulnerability: openvex.Vulnerability{Name: "CVE-2024-1234"},
				Products: []openvex.Product{
					{Component: openvex.Component{ID: testFetchDigest}},
				},
				Status: status,
			},
		},
	}

	predBytes := marshalJSON(t, doc)

	// Wrap in in-toto format with a subject so that VEX subject binding
	// does not reject the payload when a digest is available.
	wrapper := struct {
		Type    string `json:"_type"` //nolint:tagliatelle // In-toto spec field name.
		Subject []struct {
			Name   string            `json:"name"`
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
		PredicateType string          `json:"predicateType"`
		Predicate     json.RawMessage `json:"predicate"`
	}{
		Type: testInTotoStatementV1,
		Subject: []struct {
			Name   string            `json:"name"`
			Digest map[string]string `json:"digest"`
		}{
			{
				Name:   "nginx",
				Digest: map[string]string{"sha256": testFetchDigest[len("sha256:"):]},
			},
		},
		PredicateType: testOpenVEXPredicate,
		Predicate:     predBytes,
	}

	return marshalJSON(t, wrapper)
}

func TestVerifyWithFetcher(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		policyJSON         string
		mode               string
		fetcher            *mockFetcher
		fetchFailurePolicy string
		setupPayloads      func(t *testing.T, fetcher *mockFetcher)
		wantAllowed        bool
		wantErr            error
		wantCheckLen       int
	}{
		{
			name:       "SLSA pass",
			policyJSON: policyTrustRunnerJSON,
			mode:       config.ModeEnforce,
			fetcher: &mockFetcher{
				attestations: []attestation.VerifiedAttestation{
					{
						PredicateType: attestation.PredicateSLSAProvenanceV1,
						Payload:       nil,
						Digest:        testFetchDigest,
					},
				},
				err: nil,
			},
			fetchFailurePolicy: "",
			setupPayloads: func(t *testing.T, fetcher *mockFetcher) {
				t.Helper()

				fetcher.attestations[0].Payload = validSLSAPayload(t)
			},
			wantAllowed:  true,
			wantErr:      nil,
			wantCheckLen: 0,
		},
		{
			name: "SLSA missing deny",
			policyJSON: `{
				"trust": {"builders": [{"id": "https://github.com/actions/runner", "maxLevel": 2}]},
				"provenance": {"missingPolicy": "deny"}
			}`,
			mode: config.ModeEnforce,
			fetcher: &mockFetcher{
				attestations: []attestation.VerifiedAttestation{},
				err:          nil,
			},
			fetchFailurePolicy: "",
			setupPayloads:      nil,
			wantAllowed:        false,
			wantErr:            verifier.ErrVerificationFailed,
			wantCheckLen:       0,
		},
		{
			name: "VSA passed skips SLSA",
			policyJSON: `{
				"trust": {
					"builders": [{"id": "https://github.com/actions/runner", "maxLevel": 2}],
					"verifiers": [{"id": "https://example.com/verifier", "key": "/etc/keys/v.pub"}]
				},
				"provenance": {"missingPolicy": "deny"}
			}`,
			mode: config.ModeEnforce,
			fetcher: &mockFetcher{
				attestations: []attestation.VerifiedAttestation{
					{
						PredicateType: attestation.PredicateVSA,
						Payload:       nil,
						Digest:        testFetchDigest,
					},
				},
				err: nil,
			},
			fetchFailurePolicy: "",
			setupPayloads: func(t *testing.T, fetcher *mockFetcher) {
				t.Helper()

				fetcher.attestations[0].Payload = validVSAPayload(t, vsa.ResultPassed)
			},
			wantAllowed:  true,
			wantErr:      nil,
			wantCheckLen: 1,
		},
		{
			name: "VSA failed hard reject",
			policyJSON: `{
				"trust": {"verifiers": [{"id": "https://example.com/verifier", "key": "/etc/keys/v.pub"}]}
			}`,
			mode: config.ModeEnforce,
			fetcher: &mockFetcher{
				attestations: []attestation.VerifiedAttestation{
					{
						PredicateType: attestation.PredicateVSA,
						Payload:       nil,
						Digest:        testFetchDigest,
					},
				},
				err: nil,
			},
			fetchFailurePolicy: "",
			setupPayloads: func(t *testing.T, fetcher *mockFetcher) {
				t.Helper()

				fetcher.attestations[0].Payload = validVSAPayload(t, vsa.ResultFailed)
			},
			wantAllowed:  false,
			wantErr:      verifier.ErrVerificationFailed,
			wantCheckLen: 0,
		},
		{
			name: "VSA untrusted falls through to SLSA",
			policyJSON: `{
				"trust": {
					"builders": [{"id": "https://github.com/actions/runner", "maxLevel": 2}],
					"verifiers": [{"id": "https://other-verifier.example.com", "key": "/etc/keys/v.pub"}]
				}
			}`,
			mode: config.ModeEnforce,
			fetcher: &mockFetcher{
				attestations: []attestation.VerifiedAttestation{
					{
						PredicateType: attestation.PredicateVSA,
						Payload:       nil,
						Digest:        testFetchDigest,
					},
					{
						PredicateType: attestation.PredicateSLSAProvenanceV1,
						Payload:       nil,
						Digest:        testFetchDigest,
					},
				},
				err: nil,
			},
			fetchFailurePolicy: "",
			setupPayloads: func(t *testing.T, fetcher *mockFetcher) {
				t.Helper()

				fetcher.attestations[0].Payload = validVSAPayload(t, vsa.ResultPassed)
				fetcher.attestations[1].Payload = validSLSAPayload(t)
			},
			wantAllowed:  true,
			wantErr:      nil,
			wantCheckLen: 0,
		},
		{
			name: "VSA parse error falls through",
			policyJSON: `{
				"trust": {
					"builders": [{"id": "https://github.com/actions/runner", "maxLevel": 2}],
					"verifiers": [{"id": "https://example.com/verifier", "key": "/etc/keys/v.pub"}]
				}
			}`,
			mode: config.ModeEnforce,
			fetcher: &mockFetcher{
				attestations: []attestation.VerifiedAttestation{
					{
						PredicateType: attestation.PredicateVSA,
						Payload:       []byte("invalid json"),
						Digest:        testFetchDigest,
					},
					{
						PredicateType: attestation.PredicateSLSAProvenanceV1,
						Payload:       nil,
						Digest:        testFetchDigest,
					},
				},
				err: nil,
			},
			fetchFailurePolicy: "",
			setupPayloads: func(t *testing.T, fetcher *mockFetcher) {
				t.Helper()

				fetcher.attestations[1].Payload = validSLSAPayload(t)
			},
			wantAllowed:  true,
			wantErr:      nil,
			wantCheckLen: 0,
		},
		{
			name:       "fetch error allow policy",
			policyJSON: `{}`,
			mode:       config.ModeEnforce,
			fetcher: &mockFetcher{
				attestations: nil,
				err:          errMockFetch,
			},
			fetchFailurePolicy: policy.ActionAllow,
			setupPayloads:      nil,
			wantAllowed:        true,
			wantErr:            nil,
			wantCheckLen:       0,
		},
		{
			name:       "fetch error deny policy",
			policyJSON: `{}`,
			mode:       config.ModeEnforce,
			fetcher: &mockFetcher{
				attestations: nil,
				err:          errMockFetch,
			},
			fetchFailurePolicy: policy.ActionDeny,
			setupPayloads:      nil,
			wantAllowed:        false,
			wantErr:            verifier.ErrVerificationFailed,
			wantCheckLen:       0,
		},
		{
			name:       "fetch error warn policy",
			policyJSON: `{}`,
			mode:       config.ModeEnforce,
			fetcher: &mockFetcher{
				attestations: nil,
				err:          errMockFetch,
			},
			fetchFailurePolicy: policy.ActionWarn,
			setupPayloads:      nil,
			wantAllowed:        true,
			wantErr:            nil,
			wantCheckLen:       0,
		},
		{
			name: "empty attestations deny policies",
			policyJSON: `{
				"trust": {"builders": [{"id": "test", "maxLevel": 2}]},
				"provenance": {"missingPolicy": "deny"},
				"vex": {"missingPolicy": "deny"}
			}`,
			mode: config.ModeEnforce,
			fetcher: &mockFetcher{
				attestations: []attestation.VerifiedAttestation{},
				err:          nil,
			},
			fetchFailurePolicy: "",
			setupPayloads:      nil,
			wantAllowed:        false,
			wantErr:            verifier.ErrVerificationFailed,
			wantCheckLen:       0,
		},
		{
			name: "no fetcher nil fallback",
			policyJSON: `{
				"provenance": {"missingPolicy": "allow"}
			}`,
			mode:               config.ModeEnforce,
			fetcher:            nil,
			fetchFailurePolicy: "",
			setupPayloads:      nil,
			wantAllowed:        true,
			wantErr:            nil,
			wantCheckLen:       0,
		},
		{
			name:       "parallel SLSA and VEX",
			policyJSON: policyTrustRunnerJSON,
			mode:       config.ModeEnforce,
			fetcher: &mockFetcher{
				attestations: []attestation.VerifiedAttestation{
					{
						PredicateType: attestation.PredicateSLSAProvenanceV1,
						Payload:       nil,
						Digest:        testFetchDigest,
					},
				},
				err: nil,
			},
			fetchFailurePolicy: "",
			setupPayloads: func(t *testing.T, fetcher *mockFetcher) {
				t.Helper()

				fetcher.attestations[0].Payload = validSLSAPayload(t)
			},
			wantAllowed:  true,
			wantErr:      nil,
			wantCheckLen: 0,
		},
		{
			name: "VEX not affected passes",
			policyJSON: `{
				"trust": {"builders": [{"id": "https://github.com/actions/runner", "maxLevel": 2}]},
				"vex": {"missingPolicy": "deny"}
			}`,
			mode: config.ModeEnforce,
			fetcher: &mockFetcher{
				attestations: []attestation.VerifiedAttestation{
					{
						PredicateType: attestation.PredicateSLSAProvenanceV1,
						Payload:       nil,
						Digest:        testFetchDigest,
					},
					{
						PredicateType: attestation.PredicateOpenVEX,
						Payload:       nil,
						Digest:        testFetchDigest,
					},
				},
				err: nil,
			},
			fetchFailurePolicy: "",
			setupPayloads: func(t *testing.T, fetcher *mockFetcher) {
				t.Helper()

				fetcher.attestations[0].Payload = validSLSAPayload(t)
				fetcher.attestations[1].Payload = validVEXPayload(
					t, openvex.StatusNotAffected,
				)
			},
			wantAllowed:  true,
			wantErr:      nil,
			wantCheckLen: 0,
		},
		{
			name:       "VEX affected fails",
			policyJSON: policyTrustRunnerJSON,
			mode:       config.ModeEnforce,
			fetcher: &mockFetcher{
				attestations: []attestation.VerifiedAttestation{
					{
						PredicateType: attestation.PredicateSLSAProvenanceV1,
						Payload:       nil,
						Digest:        testFetchDigest,
					},
					{
						PredicateType: attestation.PredicateOpenVEX,
						Payload:       nil,
						Digest:        testFetchDigest,
					},
				},
				err: nil,
			},
			fetchFailurePolicy: "",
			setupPayloads: func(t *testing.T, fetcher *mockFetcher) {
				t.Helper()

				fetcher.attestations[0].Payload = validSLSAPayload(t)
				fetcher.attestations[1].Payload = validVEXPayload(
					t, openvex.StatusAffected,
				)
			},
			wantAllowed:  false,
			wantErr:      verifier.ErrVerificationFailed,
			wantCheckLen: 0,
		},
		{
			name: "VEX parse error fails",
			policyJSON: `{
				"trust": {"builders": [{"id": "https://github.com/actions/runner", "maxLevel": 2}]},
				"vex": {"missingPolicy": "allow"}
			}`,
			mode: config.ModeEnforce,
			fetcher: &mockFetcher{
				attestations: []attestation.VerifiedAttestation{
					{
						PredicateType: attestation.PredicateSLSAProvenanceV1,
						Payload:       nil,
						Digest:        testFetchDigest,
					},
					{
						PredicateType: attestation.PredicateOpenVEX,
						Payload:       []byte("invalid json"),
						Digest:        testFetchDigest,
					},
				},
				err: nil,
			},
			fetchFailurePolicy: "",
			setupPayloads: func(t *testing.T, fetcher *mockFetcher) {
				t.Helper()

				fetcher.attestations[0].Payload = validSLSAPayload(t)
			},
			wantAllowed:  false,
			wantErr:      verifier.ErrVerificationFailed,
			wantCheckLen: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()

			policyJSON := test.policyJSON
			if strings.Contains(policyJSON, "/etc/keys/v.pub") {
				keyPath := createTempKeyFile(t, dir)
				policyJSON = strings.ReplaceAll(policyJSON, "/etc/keys/v.pub", keyPath)
			}

			writePolicy(t, dir, "default.json", policyJSON)

			cfg := config.DefaultConfig()
			cfg.Verification = test.mode
			cfg.PolicyDir = dir

			if test.fetchFailurePolicy != "" {
				cfg.FetchFailurePolicy = test.fetchFailurePolicy
			}

			var fetcher attestation.Fetcher

			if test.fetcher != nil {
				if test.setupPayloads != nil {
					test.setupPayloads(t, test.fetcher)
				}

				fetcher = test.fetcher
			}

			verif, err := verifier.New(cfg, metrics.New(), fetcher)
			assertNoError(t, err)

			result, err := verif.Verify(
				context.Background(), "nginx:latest", testFetchDigest, testDefaultNamespace,
			)

			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) {
					t.Errorf("expected error %v, got %v", test.wantErr, err)
				}

				return
			}

			assertNoError(t, err)

			if result.Allowed != test.wantAllowed {
				t.Errorf("expected allowed=%v, got allowed=%v (reason: %s)",
					test.wantAllowed, result.Allowed, result.Reason)
			}

			if test.wantCheckLen > 0 && len(result.CheckResults) != test.wantCheckLen {
				t.Errorf("expected %d check results, got %d",
					test.wantCheckLen, len(result.CheckResults))
			}
		})
	}
}

func createTempKeyFile(t *testing.T, dir string) string {
	t.Helper()

	keyPath := filepath.Join(dir, "verifier.pub")

	err := os.WriteFile(keyPath, []byte("placeholder-key"), 0o600)
	if err != nil {
		t.Fatalf("creating temp key file: %v", err)
	}

	return keyPath
}

func TestVerifyCacheFailureTTL(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePolicy(t, dir, "default.json", `{
		"trust": {"builders": [{"id": "test", "maxLevel": 2}]},
		"provenance": {"missingPolicy": "deny"}
	}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir
	cfg.CacheTTL = config.Duration{Duration: time.Hour}
	cfg.CacheFailureTTL = config.Duration{Duration: 10 * time.Millisecond}

	verif, err := verifier.New(cfg, metrics.New(), nil)
	assertNoError(t, err)

	// First call: provenance missing with deny policy triggers a failure result.
	// In warn mode it's allowed, but the underlying result has failures,
	// so it should be cached with the short failure TTL.
	result1, err := verif.Verify(
		context.Background(), "nginx:latest", "sha256:failttl", "default",
	)
	assertNoError(t, err)

	if !result1.Allowed {
		t.Fatal("expected allowed=true in warn mode")
	}

	// Wait for the failure TTL to expire.
	time.Sleep(20 * time.Millisecond)

	// Second call: cache should have expired due to the short failure TTL.
	// The result should still be computed fresh (same outcome in this case).
	result2, err := verif.Verify(
		context.Background(), "nginx:latest", "sha256:failttl", "default",
	)
	assertNoError(t, err)

	if !result2.Allowed {
		t.Fatal("expected allowed=true in warn mode on second call")
	}
}

type countingFetcher struct {
	calls atomic.Int32
	delay time.Duration
}

func (f *countingFetcher) Fetch(
	_ context.Context,
	_, _ string,
	_ *attestation.FetchOptions,
) ([]attestation.VerifiedAttestation, error) {
	f.calls.Add(1)
	time.Sleep(f.delay)

	return nil, nil
}

type failingFetcher struct {
	calls atomic.Int32
}

func (f *failingFetcher) Fetch(
	_ context.Context,
	_, _ string,
	_ *attestation.FetchOptions,
) ([]attestation.VerifiedAttestation, error) {
	f.calls.Add(1)

	return nil, errRegistryUnavail
}

func TestVerifyConcurrentSameDigest(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePolicy(t, dir, "default.json", `{}`)

	fetcher := &countingFetcher{
		calls: atomic.Int32{},
		delay: 10 * time.Millisecond,
	}

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir
	cfg.CacheTTL = config.Duration{Duration: 0}

	ver, err := verifier.New(cfg, metrics.New(), fetcher)
	assertNoError(t, err)

	const goroutines = 10

	digest := "sha256:" + strings.Repeat("a", 64)
	imageRef := testDockerNginx
	namespace := testDefaultNamespace

	var waitGroup sync.WaitGroup

	for range goroutines {
		waitGroup.Go(func() {
			_, verifyErr := ver.Verify(
				context.Background(), imageRef, digest, namespace,
			)
			if verifyErr != nil {
				t.Errorf("unexpected error: %v", verifyErr)
			}
		})
	}

	waitGroup.Wait()

	if got := fetcher.calls.Load(); got != 1 {
		t.Errorf("expected 1 fetch call (singleflight dedup), got %d", got)
	}
}

func TestVerifyCircuitBreakerIntegration(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePolicy(t, dir, "default.json", `{}`)

	fetcher := &failingFetcher{calls: atomic.Int32{}}

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir
	cfg.CacheTTL = config.Duration{Duration: 0}
	cfg.CircuitBreakerThreshold = 3
	cfg.CircuitBreakerCooldown = config.Duration{Duration: 100 * time.Millisecond}

	ver, err := verifier.New(cfg, metrics.New(), fetcher)
	assertNoError(t, err)

	imageRef := testDockerNginx
	digest := "sha256:" + strings.Repeat("b", 64)
	namespace := testDefaultNamespace

	// Trip the circuit breaker with 3 failures.
	for call := range 3 {
		result, verifyErr := ver.Verify(
			context.Background(), imageRef, digest, namespace,
		)
		assertNoError(t, verifyErr)

		if !result.Allowed {
			t.Errorf("call %d: expected allowed=true in warn mode, got false", call+1)
		}
	}

	if got := fetcher.calls.Load(); got != 3 {
		t.Fatalf("expected 3 fetch calls before breaker trip, got %d", got)
	}

	// 4th call: circuit breaker is open, fetch should be skipped.
	result, err := ver.Verify(
		context.Background(), imageRef, digest, namespace,
	)
	assertNoError(t, err)

	if !result.Allowed {
		t.Error("expected allowed=true in warn mode with open breaker")
	}

	if !strings.Contains(result.Reason, "circuit breaker") {
		t.Errorf("expected reason to mention circuit breaker, got %q", result.Reason)
	}

	if got := fetcher.calls.Load(); got != 3 {
		t.Errorf("expected no additional fetch calls after breaker trip, got %d total", got)
	}

	// Wait for cooldown to expire, then verify the breaker allows a probe.
	time.Sleep(150 * time.Millisecond)

	_, err = ver.Verify(
		context.Background(), imageRef, digest, namespace,
	)
	assertNoError(t, err)

	if got := fetcher.calls.Load(); got != 4 {
		t.Errorf("expected 1 probe call after cooldown, got %d total", got)
	}
}

func TestVerifyCircuitBreakerMetric(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePolicy(t, dir, "default.json", `{}`)

	fetcher := &failingFetcher{calls: atomic.Int32{}}

	met := metrics.New()

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir
	cfg.CacheTTL = config.Duration{Duration: 0}
	cfg.CircuitBreakerThreshold = 2
	cfg.CircuitBreakerCooldown = config.Duration{Duration: 100 * time.Millisecond}

	ver, err := verifier.New(cfg, met, fetcher)
	assertNoError(t, err)

	imageRef := testDockerNginx
	namespace := testDefaultNamespace

	// Trip the circuit breaker with 2 failures (threshold=2).
	for call := range 2 {
		digest := "sha256:" + strings.Repeat(string("0123456789abcdef"[call%16]), 64)

		_, err := ver.Verify(context.Background(), imageRef, digest, namespace)
		assertNoError(t, err)
	}

	// Verify the circuit breaker trips metric was incremented.
	tripCount := testutil.ToFloat64(met.CircuitBreakerTripsTotal)
	if tripCount < 1 {
		t.Errorf("expected circuit breaker trips metric >= 1, got %v", tripCount)
	}

	// 3rd call: circuit breaker is open, fetch should be skipped.
	digest := "sha256:" + strings.Repeat("c", 64)

	result, err := ver.Verify(context.Background(), imageRef, digest, namespace)
	assertNoError(t, err)

	if !result.Allowed {
		t.Error("expected allowed=true in warn mode with open breaker")
	}

	if !strings.Contains(result.Reason, "circuit breaker") {
		t.Errorf("expected reason to mention circuit breaker, got %q", result.Reason)
	}

	if got := fetcher.calls.Load(); got != 2 {
		t.Errorf("expected no fetch calls after breaker trip, got %d total", got)
	}

	// Wait for cooldown, verify the breaker allows a probe.
	time.Sleep(150 * time.Millisecond)

	digest = "sha256:" + strings.Repeat("d", 64)

	_, err = ver.Verify(context.Background(), imageRef, digest, namespace)
	assertNoError(t, err)

	if got := fetcher.calls.Load(); got != 3 {
		t.Errorf("expected 1 probe call after cooldown, got %d total", got)
	}
}

func TestVerifyConcurrentWithReloadModeSwitch(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePolicy(t, dir, "default.json", `{}`)

	fetcher := &countingFetcher{
		calls: atomic.Int32{},
		delay: time.Millisecond,
	}

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir
	cfg.CacheTTL = config.Duration{Duration: 0}

	ver, err := verifier.New(cfg, metrics.New(), fetcher)
	assertNoError(t, err)

	const (
		numVerifiers = 20
		numReloaders = 5
	)

	var waitGroup sync.WaitGroup

	for idx := range numVerifiers {
		waitGroup.Go(func() {
			hexChar := string("0123456789abcdef"[idx%16])
			digest := "sha256:" + strings.Repeat(hexChar, 64)

			for range 10 {
				_, verifyErr := ver.Verify(
					context.Background(), testDockerNginx,
					digest, testDefaultNamespace,
				)
				if verifyErr != nil && !errors.Is(verifyErr, verifier.ErrVerificationFailed) {
					t.Errorf("unexpected verify error: %v", verifyErr)
				}
			}
		})
	}

	modes := [2]string{config.ModeWarn, config.ModeEnforce}

	for idx := range numReloaders {
		waitGroup.Go(func() {
			for range 10 {
				reloadCfg := config.DefaultConfig()
				reloadCfg.PolicyDir = dir
				reloadCfg.CacheTTL = config.Duration{Duration: 0}
				reloadCfg.Verification = modes[idx%2]

				reloadErr := ver.Reload(context.Background(), reloadCfg)
				if reloadErr != nil {
					t.Errorf("unexpected reload error: %v", reloadErr)
				}
			}
		})
	}

	waitGroup.Wait()
}

func TestVerifyConcurrentWithReload(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePolicy(t, dir, "default.json", `{}`)

	fetcher := &countingFetcher{
		calls: atomic.Int32{},
		delay: time.Millisecond,
	}

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir
	cfg.CacheTTL = config.Duration{Duration: 0}

	ver, err := verifier.New(cfg, metrics.New(), fetcher)
	assertNoError(t, err)

	const (
		verifiers = 20
		reloaders = 5
	)

	var waitGroup sync.WaitGroup

	for idx := range verifiers {
		waitGroup.Go(func() {
			hexChar := string("0123456789abcdef"[idx%16])
			digest := "sha256:" + strings.Repeat(hexChar, 64)

			for range 10 {
				_, verifyErr := ver.Verify(
					context.Background(), testDockerNginx,
					digest, testDefaultNamespace,
				)
				if verifyErr != nil {
					t.Errorf("unexpected verify error: %v", verifyErr)
				}
			}
		})
	}

	for range reloaders {
		waitGroup.Go(func() {
			for range 10 {
				reloadCfg := config.DefaultConfig()
				reloadCfg.Verification = config.ModeWarn
				reloadCfg.PolicyDir = dir
				reloadCfg.CacheTTL = config.Duration{Duration: 0}

				reloadErr := ver.Reload(context.Background(), reloadCfg)
				if reloadErr != nil {
					t.Errorf("unexpected reload error: %v", reloadErr)
				}
			}
		})
	}

	waitGroup.Wait()
}

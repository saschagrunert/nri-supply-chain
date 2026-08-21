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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/guac"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

var errTestGUAC = errors.New("test GUAC error")

const (
	testGUACImage      = "test-image:latest"
	testGUACDigest     = "sha256:abc123"
	testGUACCheckVuln  = "certify_vuln"
	testGUACMaxDeps    = 5
	testGUACBreakerCap = 5
	testGUACTimeout    = 5 * time.Second
)

func TestApplyGUACFallbackAllow(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Guac.FallbackPolicy = types.ActionAllow
	met := metrics.New()

	state := verifier.ExportNewGUACSnapshot(cfg, met, nil, nil)
	result := verifier.ExportApplyGUACFallback(
		state, testGUACImage, errTestGUAC,
	)

	if result != nil {
		t.Error("allow fallback should return nil result")
	}
}

func TestApplyGUACFallbackDeny(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Guac.FallbackPolicy = types.ActionDeny
	met := metrics.New()

	state := verifier.ExportNewGUACSnapshot(cfg, met, nil, nil)
	result := verifier.ExportApplyGUACFallback(
		state, testGUACImage, errTestGUAC,
	)

	if result == nil {
		t.Fatal("deny fallback should return a result")
	}

	testutil.AssertEqual(t, false, result.Passed)
	testutil.AssertEqual(t, types.StatusFail, result.Status)
	testutil.AssertContains(t, result.Detail, "GUAC query failed")
	testutil.AssertContains(t, result.Detail, testGUACImage)
}

func TestApplyGUACFallbackWarn(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Guac.FallbackPolicy = types.ActionWarn
	met := metrics.New()

	state := verifier.ExportNewGUACSnapshot(cfg, met, nil, nil)
	result := verifier.ExportApplyGUACFallback(
		state, testGUACImage, errTestGUAC,
	)

	if result == nil {
		t.Fatal("warn fallback should return a result")
	}

	testutil.AssertEqual(t, true, result.Passed)
	testutil.AssertEqual(t, types.StatusWarn, result.Status)
	testutil.AssertContains(t, result.Detail, "GUAC query failed")
}

func TestApplyGUACFallbackDefaultIsWarn(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Guac.FallbackPolicy = ""
	met := metrics.New()

	state := verifier.ExportNewGUACSnapshot(cfg, met, nil, nil)
	result := verifier.ExportApplyGUACFallback(
		state, "img", errTestGUAC,
	)

	if result == nil {
		t.Fatal("default fallback should return a result (warn)")
	}

	testutil.AssertEqual(t, true, result.Passed)
	testutil.AssertEqual(t, types.StatusWarn, result.Status)
}

func TestFetchGUACDataCircuitBreakerOpen(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Guac.FallbackPolicy = types.ActionWarn
	met := metrics.New()

	breaker := attestation.NewCircuitBreaker(1, time.Minute)
	breaker.RecordFailure()

	state := verifier.ExportNewGUACSnapshot(cfg, met, nil, breaker)
	result := verifier.ExportFetchGUACData(
		context.Background(), state, testGUACDigest, testGUACImage,
	)

	if result == nil {
		t.Fatal("should return fallback result when circuit breaker is open")
	}

	testutil.AssertEqual(t, types.StatusWarn, result.Status)
	testutil.AssertContains(t, result.Detail, "GUAC query failed")
}

func newTestGUACServer(handler http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(handler)
}

func TestFetchGUACDataSuccessRecordsBreaker(t *testing.T) {
	t.Parallel()

	srv := newTestGUACServer(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"vulnerabilities": []any{},
		})
	})
	defer srv.Close()

	client, err := guac.NewClient(srv.URL, "", "", testGUACTimeout)
	testutil.AssertNoError(t, err)

	cfg := config.DefaultConfig()
	cfg.Guac.Checks = []string{testGUACCheckVuln}
	cfg.Guac.MaxDependencies = testGUACMaxDeps
	cfg.Guac.FallbackPolicy = types.ActionWarn
	met := metrics.New()

	breaker := attestation.NewCircuitBreaker(testGUACBreakerCap, time.Minute)

	state := verifier.ExportNewGUACSnapshot(cfg, met, client, breaker)
	result := verifier.ExportFetchGUACData(
		context.Background(), state, testGUACDigest, testGUACImage,
	)

	if result == nil {
		t.Fatal("successful GUAC query should return a result")
	}

	testutil.AssertEqual(t, true, result.Passed)
}

func TestFetchGUACDataFailureRecordsBreakerAndFallback(t *testing.T) {
	t.Parallel()

	srv := newTestGUACServer(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal error"))
	})
	defer srv.Close()

	client, err := guac.NewClient(srv.URL, "", "", testGUACTimeout)
	testutil.AssertNoError(t, err)

	cfg := config.DefaultConfig()
	cfg.Guac.Checks = []string{testGUACCheckVuln}
	cfg.Guac.MaxDependencies = testGUACMaxDeps
	cfg.Guac.FallbackPolicy = types.ActionDeny
	met := metrics.New()

	breaker := attestation.NewCircuitBreaker(testGUACBreakerCap, time.Minute)

	state := verifier.ExportNewGUACSnapshot(cfg, met, client, breaker)
	result := verifier.ExportFetchGUACData(
		context.Background(), state, testGUACDigest, testGUACImage,
	)

	if result == nil {
		t.Fatal("failed GUAC query with deny fallback should return a result")
	}

	testutil.AssertEqual(t, false, result.Passed)
}

func TestTimedFetchGUACDataRecordsMetrics(t *testing.T) {
	t.Parallel()

	srv := newTestGUACServer(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"vulnerabilities": []any{},
		})
	})
	defer srv.Close()

	client, err := guac.NewClient(srv.URL, "", "", testGUACTimeout)
	testutil.AssertNoError(t, err)

	cfg := config.DefaultConfig()
	cfg.Guac.Checks = []string{testGUACCheckVuln}
	cfg.Guac.MaxDependencies = testGUACMaxDeps
	cfg.Guac.FallbackPolicy = types.ActionWarn
	met := metrics.New()

	state := verifier.ExportNewGUACSnapshot(cfg, met, client, nil)
	result := verifier.ExportTimedFetchGUACData(
		context.Background(), state, "sha256:def456", "timed-image:v1",
	)

	if result == nil {
		t.Fatal("timed fetch should return a result")
	}

	testutil.AssertEqual(t, true, result.Passed)
}

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

package metrics_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
)

func TestNewMetrics(t *testing.T) {
	t.Parallel()

	met := metrics.New()

	if met.VerificationTotal == nil {
		t.Error("expected VerificationTotal to be set")
	}

	if met.VerificationDuration == nil {
		t.Error("expected VerificationDuration to be set")
	}

	if met.CacheHitsTotal == nil {
		t.Error("expected CacheHitsTotal to be set")
	}

	if met.CacheMissesTotal == nil {
		t.Error("expected CacheMissesTotal to be set")
	}

	if met.CacheEntriesTotal == nil {
		t.Error("expected CacheEntriesTotal to be set")
	}

	if met.FetchErrorsTotal == nil {
		t.Error("expected FetchErrorsTotal to be set")
	}

	if met.InflightDedupTotal == nil {
		t.Error("expected InflightDedupTotal to be set")
	}

	if met.VerificationSkippedTotal == nil {
		t.Error("expected VerificationSkippedTotal to be set")
	}
}

func TestMetricsHandler(t *testing.T) {
	t.Parallel()

	met := metrics.New()
	handler := met.Handler()

	if handler == nil {
		t.Fatal("expected non-nil handler")
	}

	met.CacheHitsTotal.Inc()
	met.CacheMissesTotal.Inc()
	met.VerificationTotal.WithLabelValues("slsa", "pass", "default").Inc()

	recorder := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(
		context.Background(), http.MethodGet, "/metrics", http.NoBody,
	)
	handler.ServeHTTP(recorder, req)

	resp := recorder.Result()

	defer func() {
		closeErr := resp.Body.Close()
		if closeErr != nil {
			t.Fatalf("closing response body: %v", closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response body: %v", err)
	}

	bodyStr := string(body)

	for _, expected := range []string{
		"nri_supply_chain_cache_hits_total",
		"nri_supply_chain_cache_misses_total",
		"nri_supply_chain_cache_entries",
		"nri_supply_chain_verification_total",
		"nri_supply_chain_inflight_dedup_total",
		"process_cpu_seconds_total",
		"go_goroutines",
	} {
		if !strings.Contains(bodyStr, expected) {
			t.Errorf("expected %q in metrics output", expected)
		}
	}
}

func TestMetricsIncrement(t *testing.T) {
	t.Parallel()

	met := metrics.New()

	met.CacheHitsTotal.Inc()
	met.CacheHitsTotal.Inc()
	met.CacheMissesTotal.Inc()
	met.CacheEntriesTotal.Set(42)
	met.InflightDedupTotal.Inc()
	met.TrustedRootStaleTotal.Inc()
	met.CacheFailureHitsTotal.Inc()
	met.FetchErrorsTotal.WithLabelValues("attestation", "ghcr.io").Inc()
	met.CircuitBreakerTripsTotal.WithLabelValues("ghcr.io").Inc()
	met.VerificationTotal.WithLabelValues("slsa", "pass", "default").Inc()
	met.VerificationTotal.WithLabelValues("vex", "fail", "production").Inc()
	met.VerificationDuration.WithLabelValues("slsa").Observe(0.5)
	met.VerificationSkippedTotal.WithLabelValues("excluded", "default").Inc()

	recorder := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(
		context.Background(), http.MethodGet, "/metrics", http.NoBody,
	)
	met.Handler().ServeHTTP(recorder, req)

	resp := recorder.Result()

	defer func() {
		closeErr := resp.Body.Close()
		if closeErr != nil {
			t.Fatalf("closing response body: %v", closeErr)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response body: %v", err)
	}

	bodyStr := string(body)

	for _, expected := range []string{
		`nri_supply_chain_cache_hits_total 2`,
		`nri_supply_chain_cache_misses_total 1`,
		`nri_supply_chain_cache_entries 42`,
		`nri_supply_chain_inflight_dedup_total 1`,
		`nri_supply_chain_trusted_root_stale_total 1`,
		`nri_supply_chain_cache_failure_hits_total 1`,
		`nri_supply_chain_fetch_errors_total{registry="ghcr.io",type="attestation"} 1`,
		`nri_supply_chain_circuit_breaker_trips_total{registry="ghcr.io"} 1`,
		`nri_supply_chain_verification_total{namespace="default",result="pass",type="slsa"} 1`,
		`nri_supply_chain_verification_total{namespace="production",result="fail",type="vex"} 1`,
		`nri_supply_chain_verification_skipped_total{namespace="default",reason="excluded"} 1`,
	} {
		if !strings.Contains(bodyStr, expected) {
			t.Errorf("expected %q in metrics output", expected)
		}
	}
}

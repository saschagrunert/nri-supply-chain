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
	met.VerificationTotal.WithLabelValues("slsa_provenance", "pass").Inc()

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
	} {
		if !strings.Contains(bodyStr, expected) {
			t.Errorf("expected %q in metrics output", expected)
		}
	}
}

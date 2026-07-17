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

// Package metrics provides Prometheus metrics for supply chain verification.
package metrics

import (
	"net/http"
	"slices"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	namespace = "nri_supply_chain"
	labelType = "type"

	bucketFetchMid     = 15
	bucketFetchTimeout = 30
)

// Metrics holds Prometheus metrics for supply chain verification.
type Metrics struct {
	// VerificationTotal counts verification attempts by type and result.
	VerificationTotal *prometheus.CounterVec
	// VerificationDuration measures verification latency by type.
	VerificationDuration *prometheus.HistogramVec
	// VerificationSkippedTotal counts containers allowed without verification.
	VerificationSkippedTotal *prometheus.CounterVec
	// CacheHitsTotal counts cache hits for verification results.
	CacheHitsTotal prometheus.Counter
	// CacheMissesTotal counts cache misses for verification results.
	CacheMissesTotal prometheus.Counter
	// CacheEntriesTotal reports the current number of cached entries.
	CacheEntriesTotal prometheus.Gauge
	// FetchErrorsTotal counts attestation fetch errors by type.
	FetchErrorsTotal *prometheus.CounterVec
	// InflightDedupTotal counts deduplicated inflight verifications.
	InflightDedupTotal prometheus.Counter
	// CircuitBreakerTripsTotal counts how many times the circuit breaker opened.
	CircuitBreakerTripsTotal prometheus.Counter
	registry                 *prometheus.Registry
}

// New creates and registers all supply chain verification metrics.
func New() *Metrics {
	met := &Metrics{
		VerificationTotal:        newVerificationTotal(),
		VerificationDuration:     newVerificationDuration(),
		VerificationSkippedTotal: newVerificationSkipped(),
		CacheHitsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "cache_hits_total",
			Help:      "Total number of verification cache hits.",
		}),
		CacheMissesTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "cache_misses_total",
			Help:      "Total number of verification cache misses.",
		}),
		CacheEntriesTotal: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "cache_entries",
			Help:      "Current number of entries in the verification cache.",
		}),
		FetchErrorsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "fetch_errors_total",
				Help:      "Total number of attestation fetch errors.",
			},
			[]string{labelType},
		),
		InflightDedupTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "inflight_dedup_total",
			Help:      "Total number of deduplicated inflight verifications.",
		}),
		CircuitBreakerTripsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "circuit_breaker_trips_total",
			Help:      "Total number of times the fetch circuit breaker opened.",
		}),
		registry: prometheus.NewRegistry(),
	}

	met.register()

	return met
}

func newVerificationTotal() *prometheus.CounterVec {
	return prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "verification_total",
			Help:      "Total number of supply chain verification attempts.",
		},
		[]string{labelType, "result"},
	)
}

func newVerificationDuration() *prometheus.HistogramVec {
	return prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "verification_duration_seconds",
			Help:      "Duration of supply chain verification in seconds.",
			Buckets: sortedBuckets(
				slices.Clone(prometheus.DefBuckets),
				bucketFetchMid, bucketFetchTimeout,
			),
		},
		[]string{labelType},
	)
}

func newVerificationSkipped() *prometheus.CounterVec {
	return prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "verification_skipped_total",
			Help:      "Total number of containers allowed without verification.",
		},
		[]string{"reason"},
	)
}

// Handler returns the Prometheus HTTP handler for the registered metrics.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

func sortedBuckets(base []float64, extra ...float64) []float64 {
	base = append(base, extra...)
	slices.Sort(base)

	return base
}

func (m *Metrics) register() {
	m.registry.MustRegister(
		m.VerificationTotal,
		m.VerificationDuration,
		m.VerificationSkippedTotal,
		m.CacheHitsTotal,
		m.CacheMissesTotal,
		m.CacheEntriesTotal,
		m.FetchErrorsTotal,
		m.InflightDedupTotal,
		m.CircuitBreakerTripsTotal,
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{
			PidFn:        nil,
			Namespace:    "",
			ReportErrors: false,
		}),
		collectors.NewGoCollector(),
	)
}

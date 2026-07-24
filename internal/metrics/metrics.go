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
	namespace      = "nri_supply_chain"
	labelType      = "type"
	labelResult    = "result"
	labelNamespace = "namespace"
	labelRegistry  = "registry"

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
	CircuitBreakerTripsTotal *prometheus.CounterVec
	// TrustedRootStaleTotal counts how many times a stale trusted root was served.
	TrustedRootStaleTotal prometheus.Counter
	// CacheFailureHitsTotal counts cache hits that returned a previously cached failure result.
	CacheFailureHitsTotal prometheus.Counter
	// CacheEvictionsTotal counts cache entry evictions.
	CacheEvictionsTotal prometheus.Counter
	// BuildInfo exposes version and Go metadata as a constant gauge.
	BuildInfo *prometheus.GaugeVec
	// ConfigReloadsTotal counts successful configuration reloads.
	ConfigReloadsTotal prometheus.Counter
	// ConfigReloadErrorsTotal counts failed configuration reloads.
	ConfigReloadErrorsTotal prometheus.Counter
	registry                *prometheus.Registry
}

// New creates and registers all supply chain verification metrics.
//
//nolint:funlen // flat metric registration
func New() *Metrics {
	met := &Metrics{
		VerificationTotal:        newVerificationTotal(),
		VerificationDuration:     newVerificationDuration(),
		VerificationSkippedTotal: newVerificationSkipped(),
		CacheHitsTotal: newCounter(
			"cache_hits_total",
			"Total number of verification cache hits.",
		),
		CacheMissesTotal: newCounter(
			"cache_misses_total",
			"Total number of verification cache misses.",
		),
		CacheEntriesTotal: newGauge(
			"cache_entries",
			"Current number of entries in the verification cache.",
		),
		FetchErrorsTotal: newCounterVec(
			"fetch_errors_total",
			"Total number of attestation fetch errors.",
			labelType,
			labelRegistry,
		),
		InflightDedupTotal: newCounter(
			"inflight_dedup_total",
			"Total number of deduplicated inflight verifications.",
		),
		CircuitBreakerTripsTotal: newCounterVec(
			"circuit_breaker_trips_total",
			"Total number of times the fetch circuit breaker opened.",
			labelRegistry,
		),
		TrustedRootStaleTotal: newCounter(
			"trusted_root_stale_total",
			"Total number of times a stale trusted root was served from cache.",
		),
		CacheFailureHitsTotal: newCounter(
			"cache_failure_hits_total",
			"Total number of cache hits that returned a previously cached failure result.",
		),
		CacheEvictionsTotal: newCounter(
			"cache_evictions_total",
			"Total number of cache entry evictions.",
		),
		BuildInfo: newGaugeVec(
			"build_info",
			"Build and version information.",
			"version",
			"goversion",
		),
		ConfigReloadsTotal: newCounter(
			"config_reloads_total",
			"Total number of successful configuration reloads.",
		),
		ConfigReloadErrorsTotal: newCounter(
			"config_reload_errors_total",
			"Total number of failed configuration reloads.",
		),
		registry: prometheus.NewRegistry(),
	}

	met.register()

	return met
}

//nolint:ireturn // prometheus API returns interface
func newCounter(name, help string) prometheus.Counter {
	return prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      name,
		Help:      help,
	})
}

func newCounterVec(name, help string, labels ...string) *prometheus.CounterVec {
	return prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      name,
			Help:      help,
		},
		labels,
	)
}

//nolint:ireturn // prometheus API returns interface
func newGauge(name, help string) prometheus.Gauge {
	return prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      name,
		Help:      help,
	})
}

func newGaugeVec(name, help string, labels ...string) *prometheus.GaugeVec {
	return prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      name,
			Help:      help,
		},
		labels,
	)
}

func newVerificationTotal() *prometheus.CounterVec {
	return prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "verification_total",
			Help:      "Total number of supply chain verification attempts.",
		},
		[]string{labelType, labelResult, labelNamespace},
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
		[]string{"reason", labelNamespace},
	)
}

// SetBuildInfo sets the build info gauge with the given version and Go version.
func (m *Metrics) SetBuildInfo(version, goVersion string) {
	m.BuildInfo.WithLabelValues(version, goVersion).Set(1)
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
		m.TrustedRootStaleTotal,
		m.CacheFailureHitsTotal,
		m.CacheEvictionsTotal,
		m.BuildInfo,
		m.ConfigReloadsTotal,
		m.ConfigReloadErrorsTotal,
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{
			PidFn:        nil,
			Namespace:    "",
			ReportErrors: false,
		}),
		collectors.NewGoCollector(),
	)
}

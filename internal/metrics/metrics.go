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

	bucketPrewarmShort   = 1
	bucketPrewarmMedLow  = 5
	bucketPrewarmMed     = 10
	bucketPrewarmMedHigh = 30
	bucketPrewarmLong    = 60
	bucketPrewarmLonger  = 120
	bucketPrewarmMax     = 300

	bucketLifetimeStart = 0.5
	bucketLifetimeBase  = 2
	bucketLifetimeCount = 21
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
	// TrustedRootFallbackTotal counts fallback events: stale cache or pre-seeded root.
	TrustedRootFallbackTotal prometheus.Counter
	// CacheFailureHitsTotal counts cache hits that returned a previously cached failure result.
	CacheFailureHitsTotal prometheus.Counter
	// CacheEvictionsTotal counts cache entry evictions by reason (expired, capacity).
	CacheEvictionsTotal *prometheus.CounterVec
	// BuildInfo exposes version and Go metadata as a constant gauge.
	BuildInfo *prometheus.GaugeVec
	// ConfigReloadsTotal counts successful configuration reloads.
	ConfigReloadsTotal prometheus.Counter
	// ConfigReloadErrorsTotal counts failed configuration reloads.
	ConfigReloadErrorsTotal prometheus.Counter
	// VerificationInterruptedTotal counts verifications interrupted by context cancellation.
	VerificationInterruptedTotal prometheus.Counter
	// FetchDuration measures attestation fetch latency by registry.
	FetchDuration *prometheus.HistogramVec
	// PrewarmDurationSeconds measures cache pre-warming duration.
	PrewarmDurationSeconds *prometheus.HistogramVec
	// MirrorFallbackTotal counts mirror fallback events by registry and type.
	MirrorFallbackTotal *prometheus.CounterVec
	// ContainerLifetime measures the duration between container creation and removal.
	ContainerLifetime *prometheus.HistogramVec
	// PolicyReloadsTotal counts OCI policy update events.
	PolicyReloadsTotal prometheus.Counter
	// CELEvaluationDuration measures CEL rule evaluation latency.
	CELEvaluationDuration prometheus.Histogram
	// GUACQueryDuration measures GUAC query latency by check type.
	GUACQueryDuration *prometheus.HistogramVec
	// BundleStalenessTotal counts bundle staleness events by policy (allow, warn, deny).
	BundleStalenessTotal *prometheus.CounterVec
	// BundleVerificationsTotal counts bundle verification attempts by result (success, failure).
	BundleVerificationsTotal *prometheus.CounterVec
	// BundleAgeSeconds reports the current age of the active bundle in seconds.
	BundleAgeSeconds prometheus.Gauge
	// BundleImageCount reports the number of images in the active bundle.
	BundleImageCount prometheus.Gauge
	// ReverificationTotal counts re-verification attempts by namespace and result.
	ReverificationTotal *prometheus.CounterVec
	// ReverificationDuration measures single-container re-verification latency.
	ReverificationDuration *prometheus.HistogramVec
	// TrackedContainers reports the number of containers by verification state.
	TrackedContainers *prometheus.GaugeVec
	// RemediationActionsTotal counts remediation actions by type and namespace.
	RemediationActionsTotal *prometheus.CounterVec
	// RemediationErrorsTotal counts failed UpdateContainers calls.
	RemediationErrorsTotal *prometheus.CounterVec
	// FeedFilesProcessedTotal counts vulnerability feed files processed.
	FeedFilesProcessedTotal *prometheus.CounterVec
	// ContinuousVerifierLastRun is the unix timestamp of the last completed cycle.
	ContinuousVerifierLastRun prometheus.Gauge
	// CreateContainerDuration measures end-to-end NRI CreateContainer hook latency.
	CreateContainerDuration *prometheus.HistogramVec
	// HostSemOverflowTotal counts per-host semaphore overflow events.
	HostSemOverflowTotal prometheus.Counter
	registry             *prometheus.Registry
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
		TrustedRootFallbackTotal: newCounter(
			"trusted_root_fallback_total",
			"Total number of trusted root fallback events (stale cache or pre-seeded root).",
		),
		CacheFailureHitsTotal: newCounter(
			"cache_failure_hits_total",
			"Total number of cache hits that returned a previously cached failure result.",
		),
		CacheEvictionsTotal: newCounterVec(
			"cache_evictions_total",
			"Total number of cache entry evictions.",
			"reason",
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
		VerificationInterruptedTotal: newCounter(
			"verification_interrupted_total",
			"Total number of verifications interrupted by context cancellation.",
		),
		FetchDuration:          newFetchDuration(),
		PrewarmDurationSeconds: newPrewarmDuration(),
		MirrorFallbackTotal: newCounterVec(
			"mirror_fallback_total",
			"Total number of mirror fallback events.",
			labelRegistry,
			labelType,
		),
		ContainerLifetime: newContainerLifetime(),
		PolicyReloadsTotal: newCounter(
			"policy_reloads_total",
			"Total number of OCI policy update events.",
		),
		CELEvaluationDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "cel_evaluation_duration_seconds",
			Help:      "Duration of CEL rule evaluation in seconds.",
			Buckets:   prometheus.DefBuckets,
		}),
		GUACQueryDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "guac_query_duration_seconds",
				Help:      "Duration of GUAC API queries in seconds.",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{labelType},
		),
		BundleStalenessTotal: newCounterVec(
			"bundle_staleness_total",
			"Total number of bundle staleness events.",
			"policy",
		),
		BundleVerificationsTotal: newCounterVec(
			"bundle_verifications_total",
			"Total number of bundle verification attempts.",
			labelResult,
		),
		BundleAgeSeconds: newGauge(
			"bundle_age_seconds",
			"Current age of the active attestation bundle in seconds.",
		),
		BundleImageCount: newGauge(
			"bundle_image_count",
			"Number of images in the active attestation bundle.",
		),
		ReverificationTotal: newCounterVec(
			"reverification_total",
			"Total number of container re-verifications.",
			labelNamespace, labelResult,
		),
		ReverificationDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "reverification_duration_seconds",
				Help:      "Duration of single container re-verification in seconds.",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{labelNamespace},
		),
		TrackedContainers: newGaugeVec(
			"tracked_containers",
			"Number of containers tracked by verification state.",
			"state",
		),
		RemediationActionsTotal: newCounterVec(
			"remediation_actions_total",
			"Total number of remediation actions taken.",
			"action", labelNamespace,
		),
		RemediationErrorsTotal: newCounterVec(
			"remediation_errors_total",
			"Total number of failed remediation UpdateContainers calls.",
			"action",
		),
		FeedFilesProcessedTotal: newCounterVec(
			"feed_files_processed_total",
			"Total number of vulnerability feed files processed.",
			labelResult,
		),
		ContinuousVerifierLastRun: newGauge(
			"continuous_verifier_last_run",
			"Unix timestamp of the last completed continuous verification cycle.",
		),
		CreateContainerDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "create_container_duration_seconds",
				Help:      "End-to-end duration of the NRI CreateContainer hook in seconds.",
				Buckets: sortedBuckets(
					slices.Clone(prometheus.DefBuckets),
					bucketFetchMid, bucketFetchTimeout,
				),
			},
			[]string{labelNamespace, labelResult},
		),
		HostSemOverflowTotal: newCounter(
			"host_sem_overflow_total",
			"Total number of per-host semaphore overflow events.",
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

func newFetchDuration() *prometheus.HistogramVec {
	return prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "fetch_duration_seconds",
			Help:      "Duration of attestation fetches from OCI registries in seconds.",
			Buckets: sortedBuckets(
				slices.Clone(prometheus.DefBuckets),
				bucketFetchMid, bucketFetchTimeout,
			),
		},
		[]string{labelRegistry},
	)
}

func newPrewarmDuration() *prometheus.HistogramVec {
	return prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "prewarm_duration_seconds",
			Help:      "Duration of cache pre-warming in seconds.",
			Buckets: []float64{
				bucketPrewarmShort, bucketPrewarmMedLow, bucketPrewarmMed,
				bucketPrewarmMedHigh, bucketPrewarmLong, bucketPrewarmLonger,
				bucketPrewarmMax,
			},
		},
		[]string{labelResult},
	)
}

func newContainerLifetime() *prometheus.HistogramVec {
	return prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "container_lifetime_seconds",
			Help:      "Duration between container creation and removal in seconds.",
			Buckets: prometheus.ExponentialBuckets(
				bucketLifetimeStart, bucketLifetimeBase, bucketLifetimeCount,
			),
		},
		[]string{labelNamespace},
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
		m.TrustedRootFallbackTotal,
		m.CacheFailureHitsTotal,
		m.CacheEvictionsTotal,
		m.BuildInfo,
		m.ConfigReloadsTotal,
		m.ConfigReloadErrorsTotal,
		m.VerificationInterruptedTotal,
		m.FetchDuration,
		m.PrewarmDurationSeconds,
		m.MirrorFallbackTotal,
		m.ContainerLifetime,
		m.PolicyReloadsTotal,
		m.CELEvaluationDuration,
		m.GUACQueryDuration,
		m.BundleStalenessTotal,
		m.BundleVerificationsTotal,
		m.BundleAgeSeconds,
		m.BundleImageCount,
		m.ReverificationTotal,
		m.ReverificationDuration,
		m.TrackedContainers,
		m.RemediationActionsTotal,
		m.RemediationErrorsTotal,
		m.FeedFilesProcessedTotal,
		m.ContinuousVerifierLastRun,
		m.CreateContainerDuration,
		m.HostSemOverflowTotal,
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{
			PidFn:        nil,
			Namespace:    "",
			ReportErrors: false,
		}),
		collectors.NewGoCollector(),
	)
}

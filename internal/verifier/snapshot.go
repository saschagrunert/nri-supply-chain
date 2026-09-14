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

package verifier

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/cache"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/guac"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
)

// snapshot is an immutable view of everything a verification needs. It is
// replaced atomically on config reload and OCI policy updates.
type snapshot struct {
	// generation identifies the result cache instance. It changes whenever
	// cached results may no longer be valid (policy, trust material or cache
	// affecting config changes) and is part of the singleflight key so no
	// request joins a verification started under an older generation.
	generation       uint64
	config           *config.Config
	policies         map[string]*policy.Policy
	policyHashes     map[string]string
	trust            trustFingerprint
	fetcherBasis     fetcherBasis
	cache            *cache.Cache
	metrics          *metrics.Metrics
	fetcher          attestation.Fetcher
	circuitBreakers  *attestation.CircuitBreakerRegistry
	fetchSem         *semaphore.Weighted
	hostSem          *hostSemMap
	auditLogger      *slog.Logger
	auditLogFile     *os.File
	allowlistDigests map[string]struct{}
	guacClient       *guac.Client
	guacBreaker      *attestation.CircuitBreaker
}

// snapshotInput carries the parts of the next snapshot that are always
// provided by the caller.
type snapshotInput struct {
	config       *config.Config
	policies     map[string]*policy.Policy
	policyHashes map[string]string
	trust        trustFingerprint
	fetcher      attestation.Fetcher
	fetcherBasis fetcherBasis
	metrics      *metrics.Metrics
}

// fetcherBasis is the config and Sigstore trust material the fetcher was
// built with. A reload with verification disabled and an OCI policy update
// keep the fetcher but store a new config and trust fingerprint, so a later
// reload decides whether to rebuild the fetcher against its basis instead.
type fetcherBasis struct {
	config   *config.Config
	sigstore string
}

// buildSnapshot assembles the next snapshot. Without a previous snapshot
// every component is created and creation errors are returned. Otherwise
// components are reused unless what they depend on changed:
//
//   - result cache: replaced, with a new generation, when policies, trust
//     material or cache affecting config fields changed
//   - per-host semaphores and verification helper caches (PEM keys, SAN
//     warnings, Notation verifiers, globs): reset when policies or trust
//     material changed
//   - circuit breakers: replaced when threshold or cooldown changed
//   - GUAC client: replaced when its transport settings changed; the
//     previous client is kept when creating the new one fails
//   - audit logger: replaced when the path changed; falls back to the
//     default logger when the new file cannot be opened
//   - fetch semaphore: always reused
//
// Replaced components of prev are released by retireSnapshot once the new
// snapshot is published.
func (v *Verifier) buildSnapshot(
	ctx context.Context, prev *snapshot, input *snapshotInput,
) (*snapshot, error) {
	if prev == nil {
		return v.newSnapshot(input)
	}

	cfg := input.config

	policiesChanged := !policyHashesEqual(prev.policyHashes, input.policyHashes) ||
		prev.trust != input.trust

	next := &snapshot{
		generation:       prev.generation,
		config:           cfg,
		policies:         input.policies,
		policyHashes:     maps.Clone(input.policyHashes),
		trust:            input.trust,
		fetcherBasis:     input.fetcherBasis,
		cache:            prev.cache,
		metrics:          input.metrics,
		fetcher:          input.fetcher,
		circuitBreakers:  reuseCircuitBreakers(prev, cfg),
		fetchSem:         prev.fetchSem,
		hostSem:          prev.hostSem,
		auditLogger:      prev.auditLogger,
		auditLogFile:     prev.auditLogFile,
		allowlistDigests: buildAllowlistMap(cfg.AllowlistDigests),
		guacClient:       prev.guacClient,
		guacBreaker:      prev.guacBreaker,
	}

	if policiesChanged || cacheAffectingFieldsChanged(prev.config, cfg) {
		next.cache = newResultCache(cfg, input.metrics)
		next.generation = v.generation.Add(1)
	}

	if policiesChanged {
		resetVerificationCaches()

		next.hostSem = newHostSemMap(input.metrics)
	}

	guacClient, guacBreaker, err := reloadGUACClient(prev, cfg)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to reload GUAC client, keeping previous", "error", err)
	} else {
		next.guacClient, next.guacBreaker = guacClient, guacBreaker
	}

	next.auditLogger, next.auditLogFile = reloadAuditLogger(ctx, prev, cfg)

	return next, nil
}

func (v *Verifier) newSnapshot(input *snapshotInput) (*snapshot, error) {
	cfg := input.config

	auditLogger, auditLogFile, err := openAuditLogger(cfg.AuditLog)
	if err != nil {
		return nil, fmt.Errorf("opening audit log: %w", err)
	}

	snap := &snapshot{
		generation:   v.generation.Add(1),
		config:       cfg,
		policies:     input.policies,
		policyHashes: maps.Clone(input.policyHashes),
		trust:        input.trust,
		fetcherBasis: input.fetcherBasis,
		cache:        newResultCache(cfg, input.metrics),
		metrics:      input.metrics,
		fetcher:      input.fetcher,
		circuitBreakers: attestation.NewCircuitBreakerRegistry(
			cfg.CircuitBreakerThreshold, cfg.CircuitBreakerCooldown.Duration,
		),
		fetchSem:         semaphore.NewWeighted(maxConcurrentFetches),
		hostSem:          newHostSemMap(input.metrics),
		auditLogger:      auditLogger,
		auditLogFile:     auditLogFile,
		allowlistDigests: buildAllowlistMap(cfg.AllowlistDigests),
		guacClient:       nil,
		guacBreaker:      nil,
	}

	if cfg.Guac.Enabled() {
		guacClient, err := newGUACClient(cfg)
		if err != nil {
			closeAuditLogFile(auditLogFile)
			snap.cache.Stop()

			return nil, err
		}

		snap.guacClient = guacClient
		snap.guacBreaker = attestation.NewCircuitBreaker(
			cfg.CircuitBreakerThreshold, cfg.CircuitBreakerCooldown.Duration,
		)
	}

	return snap, nil
}

// retireSnapshot releases the components of prev that next no longer uses.
// The audit log file is closed after a grace period so verifications still
// holding prev can finish their writes.
func retireSnapshot(prev, next *snapshot) {
	if prev == nil {
		return
	}

	if prev.cache != next.cache {
		prev.cache.Stop()
	}

	if prev.guacClient != nil && prev.guacClient != next.guacClient {
		prev.guacClient.Close()
	}

	if prev.auditLogFile != nil && prev.auditLogFile != next.auditLogFile {
		oldFile := prev.auditLogFile

		time.AfterFunc(prev.config.VerificationTimeout.Duration, func() {
			closeAuditLogFile(oldFile)
		})
	}
}

func newResultCache(cfg *config.Config, met *metrics.Metrics) *cache.Cache {
	return cache.NewWithGauge(
		cfg.CacheTTL.Duration, cfg.CacheMaxEntries,
		met.CacheEntriesTotal, met.CacheEvictionsTotal,
	)
}

func newHostSemMap(met *metrics.Metrics) *hostSemMap {
	return &hostSemMap{
		m: sync.Map{}, count: atomic.Int64{},
		onOverflow: func() { met.HostSemOverflowTotal.Inc() },
	}
}

func newGUACClient(cfg *config.Config) (*guac.Client, error) {
	client, err := guac.NewClient(
		cfg.Guac.Endpoint,
		cfg.Guac.AuthTokenPath,
		cfg.Guac.CACertPath,
		cfg.Guac.Timeout.Duration,
	)
	if err != nil {
		return nil, fmt.Errorf("creating GUAC client: %w", err)
	}

	return client, nil
}

// reuseCircuitBreakers returns the existing circuit breaker registry if
// settings are unchanged, or creates a new one. Preserving the registry across
// reloads prevents a burst of retries to failing registries.
func reuseCircuitBreakers(prev *snapshot, cfg *config.Config) *attestation.CircuitBreakerRegistry {
	if prev.circuitBreakers != nil &&
		prev.config.CircuitBreakerThreshold == cfg.CircuitBreakerThreshold &&
		prev.config.CircuitBreakerCooldown.Duration == cfg.CircuitBreakerCooldown.Duration {
		return prev.circuitBreakers
	}

	return attestation.NewCircuitBreakerRegistry(
		cfg.CircuitBreakerThreshold,
		cfg.CircuitBreakerCooldown.Duration,
	)
}

// flightTracker counts running singleflight verifications so Stop can wait
// for them. Unlike a sync.WaitGroup it never races an increment with a
// concurrent wait: once closed, no new verification starts.
type flightTracker struct {
	mu     sync.Mutex
	active int
	closed bool
	idle   chan struct{}
}

// begin registers a running verification. It returns false when the tracker
// was closed by Stop; the caller must not start the verification then.
func (t *flightTracker) begin() bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return false
	}

	t.active++

	return true
}

// end marks a verification registered by begin as finished.
func (t *flightTracker) end() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.active--

	if t.active == 0 && t.idle != nil {
		close(t.idle)
		t.idle = nil
	}
}

// wait blocks until no verification is running or done is closed, returning
// false on the latter. With closeTracker set, no new verification can begin
// afterwards.
func (t *flightTracker) wait(done <-chan struct{}, closeTracker bool) bool {
	t.mu.Lock()

	if closeTracker {
		t.closed = true
	}

	if t.active == 0 {
		t.mu.Unlock()

		return true
	}

	if t.idle == nil {
		t.idle = make(chan struct{})
	}

	idle := t.idle

	t.mu.Unlock()

	select {
	case <-idle:
		return true
	case <-done:
		return false
	}
}

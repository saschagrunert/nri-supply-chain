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
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
)

// maxStalenessCheckInterval bounds how often the OCI policy staleness gauge
// is refreshed.
const maxStalenessCheckInterval = 30 * time.Second

// policyPoller bundles the OCI policy poller with the fetcher it uses and the
// goroutine that reports policy staleness.
type policyPoller struct {
	poller        *policy.Poller
	fetcher       *policy.OCIFetcher
	ociRef        string
	maxStaleness  time.Duration
	checkInterval time.Duration
	cancel        context.CancelFunc
	done          chan struct{}
}

func (v *Verifier) startPoller(
	ctx context.Context,
	policyFetcher *policy.OCIFetcher,
	cfg *config.Config,
	ociDigest string,
) {
	if policyFetcher == nil {
		slog.WarnContext(ctx, "No policy fetcher available; not starting poller")

		return
	}

	pollerInstance := policy.NewPoller(
		policyFetcher,
		cfg.Policy.OCIRef,
		cfg.Policy.PollInterval.Duration,
		func(policies map[string]*policy.Policy) error {
			return v.onPolicyUpdate(ctx, policies)
		},
	)

	pollerInstance.SetCachedDigest(ociDigest)

	v.runPoller(ctx, &policyPoller{
		poller:        pollerInstance,
		fetcher:       policyFetcher,
		ociRef:        cfg.Policy.OCIRef,
		maxStaleness:  cfg.Policy.OCIMaxStaleness.Duration,
		checkInterval: stalenessCheckInterval(cfg),
		cancel:        nil,
		done:          nil,
	})
}

// runPoller starts polling and the staleness monitor of pending and installs
// it as the current poller. It also restarts a poller stopped by stopPoller,
// keeping its cached digest and last success time.
func (v *Verifier) runPoller(ctx context.Context, pending *policyPoller) {
	pending.poller.Start(ctx)

	monitorCtx, cancel := context.WithCancel(ctx)

	started := &policyPoller{
		poller:        pending.poller,
		fetcher:       pending.fetcher,
		ociRef:        pending.ociRef,
		maxStaleness:  pending.maxStaleness,
		checkInterval: pending.checkInterval,
		cancel:        cancel,
		done:          make(chan struct{}),
	}

	go v.monitorStaleness(monitorCtx, started, started.checkInterval)

	v.poller.Store(started)
}

// stopPoller detaches the current poller, stops it and returns it (nil when
// no poller was running) so it can be resumed with runPoller. The poller
// callback (onPolicyUpdate) acquires v.mu, so callers must not hold v.mu.
func (v *Verifier) stopPoller() *policyPoller {
	stopped := v.poller.Swap(nil)
	if stopped == nil {
		return nil
	}

	stopped.poller.Stop()
	stopped.cancel()
	<-stopped.done

	return stopped
}

// ociRollbackSeed returns the newest OCI policy artifact creation time
// accepted so far for ociRef, so a replacement policy fetcher keeps rejecting
// older artifacts. A different reference starts without a guard.
func (v *Verifier) ociRollbackSeed(ociRef string) time.Time {
	return pollerRollbackSeed(v.poller.Load(), ociRef)
}

func pollerRollbackSeed(current *policyPoller, ociRef string) time.Time {
	if current == nil || current.ociRef != ociRef {
		return time.Time{}
	}

	return current.fetcher.NewestCreated()
}

func stalenessCheckInterval(cfg *config.Config) time.Duration {
	return min(cfg.Policy.PollInterval.Duration, maxStalenessCheckInterval)
}

// monitorStaleness keeps the OCI policy staleness gauge current and logs an
// error once policy.oci_max_staleness is exceeded.
func (v *Verifier) monitorStaleness(
	ctx context.Context, current *policyPoller, interval time.Duration,
) {
	defer close(current.done)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	exceeded := false

	for {
		staleFor := time.Since(current.poller.LastSuccess())
		v.snap().metrics.PolicyOCIStalenessSeconds.Set(staleFor.Seconds())

		isStale := current.maxStaleness > 0 && staleFor > current.maxStaleness
		if isStale && !exceeded {
			slog.ErrorContext(ctx,
				"OCI policies exceeded the maximum staleness, reporting not ready",
				"oci_ref", current.ociRef,
				"stale_for", staleFor.Round(time.Second).String(),
				"oci_max_staleness", current.maxStaleness.String(),
			)
		}

		exceeded = isStale

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// policiesStale reports whether the applied OCI policies exceeded
// policy.oci_max_staleness.
func (v *Verifier) policiesStale() (stale bool, reason string) {
	current := v.poller.Load()
	if current == nil || current.maxStaleness <= 0 {
		return false, ""
	}

	staleFor := time.Since(current.poller.LastSuccess())
	if staleFor <= current.maxStaleness {
		return false, ""
	}

	return true, fmt.Sprintf(
		"OCI policies not refreshed for %s (policy.oci_max_staleness %s)",
		staleFor.Round(time.Second), current.maxStaleness,
	)
}

func (v *Verifier) onPolicyUpdate(ctx context.Context, policies map[string]*policy.Policy) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	state := v.state.Load()

	if len(policies) == 0 {
		return ErrNoPolicies
	}

	newHashes, err := hashPolicies(policies)
	if err != nil {
		return fmt.Errorf("hashing updated OCI policies: %w", err)
	}

	trust := computeTrustFingerprint(state.config, policies)

	if policyHashesEqual(state.policyHashes, newHashes) && trust == state.trust {
		return nil
	}

	err = validateUpdatedPolicies(state.config, policies)
	if err != nil {
		return err
	}

	next, err := v.buildSnapshot(ctx, state, &snapshotInput{
		config:       state.config,
		policies:     policies,
		policyHashes: newHashes,
		trust:        trust,
		fetcher:      state.fetcher,
		fetcherBasis: state.fetcherBasis,
		metrics:      state.metrics,
	})
	if err != nil {
		return fmt.Errorf("building snapshot for updated OCI policies: %w", err)
	}

	v.state.Store(next)
	retireSnapshot(state, next)

	state.metrics.PolicyReloadsTotal.Inc()

	if state.config.Enabled() {
		WarnEnforceDefaults(ctx, state.config, policies)
		WarnWarnModeDefaults(ctx, state.config, policies)
	}

	slog.InfoContext(ctx,
		"OCI policy update applied",
		"policies_count", len(policies),
	)

	return nil
}

func validateUpdatedPolicies(cfg *config.Config, policies map[string]*policy.Policy) error {
	if cfg.Enabled() {
		err := validatePoliciesModes(cfg.Verification, policies)
		if err != nil {
			return fmt.Errorf("validating updated OCI policies: %w", err)
		}
	}

	err := validatePoliciesRuntime(policies)
	if err != nil {
		return fmt.Errorf("runtime validation of updated OCI policies: %w", err)
	}

	err = validatePoliciesAgainstConfig(cfg, policies)
	if err != nil {
		return fmt.Errorf("validating updated OCI policies against config: %w", err)
	}

	return nil
}

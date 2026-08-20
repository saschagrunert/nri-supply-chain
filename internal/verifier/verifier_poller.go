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

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
)

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
	pollerInstance.Start(ctx)

	v.poller = pollerInstance
}

// stopPoller reads and nil-outs v.poller under v.mu, then stops the
// poller outside the lock. Acquiring and releasing the lock internally
// avoids a data race with Reload (which writes v.poller under v.mu)
// and avoids deadlock (the poller callback acquires v.mu, so Stop must
// not hold it).
func (v *Verifier) stopPoller() {
	v.mu.Lock()
	p := v.poller
	v.poller = nil
	v.mu.Unlock()

	if p != nil {
		p.Stop()
	}
}

func (v *Verifier) onPolicyUpdate(ctx context.Context, policies map[string]*policy.Policy) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	state := v.state.Load()

	newHashes, err := hashPolicies(policies)
	if err != nil {
		return fmt.Errorf("hashing updated OCI policies: %w", err)
	}

	if policyHashesEqual(v.policyHashes, newHashes) {
		return nil
	}

	if state.config.Enabled() {
		err = validatePoliciesModes(state.config.Verification, policies)
		if err != nil {
			return fmt.Errorf("validating updated OCI policies: %w", err)
		}
	}

	err = validatePoliciesRuntime(policies)
	if err != nil {
		return fmt.Errorf("runtime validation of updated OCI policies: %w", err)
	}

	v.applyPolicyUpdate(ctx, state, policies, newHashes)

	return nil
}

func (v *Verifier) applyPolicyUpdate(
	ctx context.Context,
	state *snapshot,
	policies map[string]*policy.Policy,
	newHashes map[string]string,
) {
	state.cache.Stop()

	resetVerificationCaches()

	snap := newSnapshot(state.config, policies, newHashes, state.metrics, state.fetcher)
	snap.circuitBreakers = state.circuitBreakers
	snap.fetchSem = state.fetchSem
	snap.auditLogger = state.auditLogger

	v.state.Store(snap)
	v.policyHashes = newHashes

	state.metrics.PolicyReloadsTotal.Inc()

	if state.config.Enabled() {
		WarnEnforceDefaults(ctx, state.config, policies)
		WarnWarnModeDefaults(ctx, state.config, policies)
	}

	slog.Info(
		"OCI policy update applied",
		"policies_count", len(policies),
	)
}

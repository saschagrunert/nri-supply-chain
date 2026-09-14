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

package plugin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
)

const (
	// runtimeConfigApplyWait bounds how long Configure waits for the
	// configuration passed by the runtime to be applied before returning,
	// so a fast apply avoids a window of unreadiness while a slow one never
	// runs into the runtime's request deadline.
	runtimeConfigApplyWait = 500 * time.Millisecond

	// defaultRuntimeConfigRetryInitial and defaultRuntimeConfigRetryMaximum
	// bound the backoff between retries of a configuration passed by the
	// runtime that failed to apply (for example during a registry outage).
	defaultRuntimeConfigRetryInitial = time.Second
	defaultRuntimeConfigRetryMaximum = time.Minute

	// runtimeConfigRetryFactor multiplies the retry backoff after each
	// failed apply.
	runtimeConfigRetryFactor = 2
)

// pendingRuntimeConfig is a configuration passed by the runtime that has not
// been applied yet.
type pendingRuntimeConfig struct {
	cfg *config.Config
	// raw is the configuration as passed by the runtime, used to recognize
	// an unchanged configuration on reconnect.
	raw string
	// enforcement describes which namespaces may enforce verification once
	// the configuration is applied.
	enforcement runtimeEnforcement
	// superseded is closed when a newer configuration replaces this one, to
	// stop retries.
	superseded chan struct{}
}

// runtimeEnforcement describes which namespaces a configuration enforces,
// determined without network access so Configure can decide it within the
// runtime's request deadline.
type runtimeEnforcement struct {
	// all is set when every namespace may enforce: global enforce mode, OCI
	// policies that cannot be inspected before they are fetched, or local
	// policies that could not be loaded.
	all bool
	// global is the global verification mode.
	global config.VerificationMode
	// policies are the local policies, keyed by namespace ("" for the
	// default policy), when the global mode is warn.
	policies map[string]*policy.Policy
}

// enforces reports whether the namespace enforces verification.
func (e *runtimeEnforcement) enforces(namespace string) bool {
	if e.all {
		return true
	}

	pol, found := e.policies[namespace]
	if !found {
		pol = e.policies[""]
	}

	return pol != nil && pol.EffectiveMode(e.global) == config.ModeEnforce
}

// newRuntimeEnforcement determines which namespaces cfg enforces. Local
// policies are loaded from disk; OCI policies are only known after they are
// fetched, so a warn configuration with OCI policies is treated as enforcing
// every namespace, failing closed.
func newRuntimeEnforcement(ctx context.Context, cfg *config.Config) runtimeEnforcement {
	enforcement := runtimeEnforcement{all: false, global: cfg.Verification, policies: nil}

	switch cfg.Verification {
	case config.ModeDisabled:
		return enforcement
	case config.ModeEnforce:
		enforcement.all = true

		return enforcement
	case config.ModeWarn:
	}

	if cfg.Policy.Source == config.PolicySourceOCI {
		enforcement.all = true

		return enforcement
	}

	policies, err := policy.LoadAll(cfg.PolicyDir)
	if err != nil {
		slog.WarnContext(ctx,
			"Loading the policies of the configuration passed by the runtime failed; "+
				"treating every namespace as enforcing until the configuration is applied",
			"policy_dir", cfg.PolicyDir,
			"error", err,
		)

		enforcement.all = true

		return enforcement
	}

	enforcement.policies = policies

	return enforcement
}

// SetConfigApplier sets how a configuration passed by the runtime is applied.
// Without an applier, only the verifier is reloaded.
func (p *Plugin) SetConfigApplier(applier ConfigApplier) {
	p.runtimeConfig.applier.Store(&applier)
}

// applyRuntimeConfig applies a configuration passed by the runtime in the
// background: reloading the verifier can take longer than the runtime's
// request deadline (creating the attestation fetcher, fetching OCI policies),
// and a plugin that misses it is closed. The plugin reports not ready until
// the configuration is applied, and denies admissions in namespaces the
// configuration enforces while it is pending. A failed apply is retried with
// backoff until it succeeds or a newer configuration arrives. A configuration
// identical to the last applied one (a reconnect) is not applied again.
// Configure waits briefly so a fast apply does not leave a window of
// unreadiness.
func (p *Plugin) applyRuntimeConfig(ctx context.Context, raw string, cfg *config.Config) {
	state := &p.runtimeConfig

	if current := state.pending.Load(); current != nil && current.raw == raw {
		slog.InfoContext(ctx, "The configuration passed by the runtime is already being applied")

		return
	}

	last := state.lastApplied.Load()
	if state.pending.Load() == nil && last != nil && *last == raw {
		slog.InfoContext(ctx, "The configuration passed by the runtime is unchanged, keeping it")

		return
	}

	pending := &pendingRuntimeConfig{
		cfg:         cfg,
		raw:         raw,
		enforcement: newRuntimeEnforcement(ctx, cfg),
		superseded:  make(chan struct{}),
	}

	if previous := state.pending.Swap(pending); previous != nil {
		close(previous.superseded)
	}

	state.failure.Store(nil)

	firstAttempt := make(chan struct{})

	go p.applyRuntimeConfigWithRetry(context.WithoutCancel(ctx), pending, firstAttempt)

	wait := runtimeConfigApplyWait
	if deadline, ok := ctx.Deadline(); ok {
		wait = min(wait, time.Until(deadline)/2) //nolint:mnd // half of the remaining request time
	}

	timer := time.NewTimer(wait)
	defer timer.Stop()

	select {
	case <-firstAttempt:
	case <-timer.C:
		slog.InfoContext(ctx, "Applying the configuration passed by the runtime in the background")
	}
}

// applyRuntimeConfigWithRetry applies pending until it succeeds, a newer
// configuration supersedes it, or the apply is canceled. firstAttempt is
// closed after the first attempt.
func (p *Plugin) applyRuntimeConfigWithRetry(
	ctx context.Context, pending *pendingRuntimeConfig, firstAttempt chan struct{},
) {
	state := &p.runtimeConfig
	backoff := state.retryBackoffInitial()

	for attempt := 1; ; attempt++ {
		applied, err := p.attemptRuntimeConfig(ctx, pending)

		if attempt == 1 {
			close(firstAttempt)
		}

		if applied || err == nil || errors.Is(err, context.Canceled) {
			return
		}

		slog.ErrorContext(ctx, "Applying the configuration passed by the runtime failed",
			"error", err,
			"attempt", attempt,
			"retry_in", backoff,
		)

		timer := time.NewTimer(backoff)

		select {
		case <-timer.C:
		case <-pending.superseded:
			timer.Stop()

			return
		}

		backoff = min(backoff*runtimeConfigRetryFactor, state.retryBackoffMaximum())
	}
}

// attemptRuntimeConfig applies pending once. applied is true when pending was
// applied; err is nil without applied when pending was superseded.
func (p *Plugin) attemptRuntimeConfig(
	ctx context.Context, pending *pendingRuntimeConfig,
) (applied bool, err error) {
	state := &p.runtimeConfig

	state.mu.Lock()
	defer state.mu.Unlock()

	// A newer configuration arrived meanwhile; its own apply handles it.
	if state.pending.Load() != pending {
		return false, nil
	}

	err = p.applyConfig(ctx, pending.cfg)
	if err != nil {
		reason := err.Error()
		state.failure.Store(&reason)
		p.setRuntimeConfigApplyFailed(true)

		return false, err
	}

	if state.pending.CompareAndSwap(pending, nil) {
		state.failure.Store(nil)
		state.lastApplied.Store(&pending.raw)
		p.setRuntimeConfigApplyFailed(false)
	}

	slog.InfoContext(ctx, "Applied the configuration passed by the runtime",
		"mode", pending.cfg.Verification,
	)

	return true, nil
}

func (p *Plugin) setRuntimeConfigApplyFailed(failed bool) {
	if p.metrics == nil {
		return
	}

	if failed {
		p.metrics.RuntimeConfigApplyFailed.Set(1)
	} else {
		p.metrics.RuntimeConfigApplyFailed.Set(0)
	}
}

func (p *Plugin) applyConfig(ctx context.Context, cfg *config.Config) error {
	if applier := p.runtimeConfig.applier.Load(); applier != nil && *applier != nil {
		return (*applier)(ctx, cfg)
	}

	err := p.verifier.Reload(ctx, cfg)
	if err != nil {
		return fmt.Errorf("applying NRI config: %w", err)
	}

	return nil
}

// pendingEnforcingRuntimeConfig reports whether a configuration passed by the
// runtime that enforces verification in the namespace has not been applied
// yet. Until then the verifier still runs the previous (by default disabled)
// configuration.
func (p *Plugin) pendingEnforcingRuntimeConfig(namespace string) bool {
	pending := p.runtimeConfig.pending.Load()

	return pending != nil && pending.enforcement.enforces(namespace)
}

func (s *runtimeConfigState) retryBackoffInitial() time.Duration {
	if initial := time.Duration(s.retryInitial.Load()); initial > 0 {
		return initial
	}

	return defaultRuntimeConfigRetryInitial
}

func (s *runtimeConfigState) retryBackoffMaximum() time.Duration {
	if maximum := time.Duration(s.retryMaximum.Load()); maximum > 0 {
		return maximum
	}

	return defaultRuntimeConfigRetryMaximum
}

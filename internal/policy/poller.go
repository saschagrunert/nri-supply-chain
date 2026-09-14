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

package policy

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// staleIntervals is the number of consecutive poll intervals without a
// successful registry check after which failures are logged at error level.
const staleIntervals = 10

// ReloadFunc is called when the poller detects a policy update. Returning an
// error signals that the update was rejected (e.g. validation failure), which
// causes the poller to retry on the next tick instead of caching the digest.
type ReloadFunc func(policies map[string]*Policy) error

// Poller periodically checks an OCI registry for policy updates by comparing
// the remote manifest digest with a locally cached digest. When the digest
// changes, it fetches the new policies and invokes the reload callback.
type Poller struct {
	fetcher      *OCIFetcher
	ociRef       string
	interval     time.Duration
	onReload     ReloadFunc
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	cachedDigest string
	lastSuccess  time.Time
	mu           sync.Mutex
}

// NewPoller creates a policy poller that checks for updates at the given
// interval. The onReload callback is invoked with the new policy map
// whenever the remote digest changes.
func NewPoller(
	fetcher *OCIFetcher,
	ociRef string,
	interval time.Duration,
	onReload ReloadFunc,
) *Poller {
	return &Poller{
		fetcher:      fetcher,
		ociRef:       ociRef,
		interval:     interval,
		onReload:     onReload,
		cancel:       nil,
		wg:           sync.WaitGroup{},
		cachedDigest: "",
		lastSuccess:  time.Now(),
		mu:           sync.Mutex{},
	}
}

// LastSuccess returns the last time the applied policies were known to be
// current (or the poller creation time before that): a registry check that
// found the applied digest unchanged, or a successfully applied update. While
// the registry is unreachable, or a changed artifact keeps being rejected, the
// previously applied policies stay in effect, so this indicates how stale they
// may be.
func (p *Poller) LastSuccess() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.lastSuccess
}

// SetCachedDigest stores the initial digest so the first poll only re-fetches
// when the remote artifact has actually changed.
func (p *Poller) SetCachedDigest(digest string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.cachedDigest = digest
}

// Start begins the polling loop. It runs in a background goroutine and
// returns immediately. Call Stop to cancel.
func (p *Poller) Start(ctx context.Context) {
	pollCtx, cancel := context.WithCancel(ctx)

	p.mu.Lock()
	prev := p.cancel
	p.cancel = cancel
	p.mu.Unlock()

	if prev != nil {
		prev()
		p.wg.Wait()
	}

	p.wg.Add(1)

	go p.run(pollCtx)
}

// Stop cancels the polling loop and waits for the background goroutine
// to finish.
func (p *Poller) Stop() {
	p.mu.Lock()
	cancel := p.cancel
	p.mu.Unlock()

	if cancel != nil {
		cancel()
	}

	p.wg.Wait()
}

func (p *Poller) run(ctx context.Context) {
	defer p.wg.Done()

	p.mu.Lock()
	pending := p.cachedDigest == ""
	p.mu.Unlock()

	if pending {
		p.poll(ctx)
	}

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.poll(ctx)
		}
	}
}

func (p *Poller) poll(ctx context.Context) {
	digest, err := p.fetcher.CheckDigest(ctx, p.ociRef)
	if err != nil {
		p.logFailure(ctx, "OCI policy digest check failed", err)

		return
	}

	p.mu.Lock()
	changed := digest != p.cachedDigest

	// A changed digest only counts as current once it was applied.
	if !changed {
		p.lastSuccess = time.Now()
	}
	p.mu.Unlock()

	if !changed {
		slog.DebugContext(ctx, "OCI policy digest unchanged, skipping reload",
			"oci_ref", p.ociRef,
			"digest", digest,
		)

		return
	}

	p.fetchAndApply(ctx)
}

func (p *Poller) fetchAndApply(ctx context.Context) {
	result, err := p.fetcher.FetchFromOCI(ctx, p.ociRef)
	if err != nil {
		p.logFailure(ctx, "OCI policy fetch failed", err)

		return
	}

	p.mu.Lock()
	alreadyApplied := result.Digest == p.cachedDigest

	if alreadyApplied {
		p.lastSuccess = time.Now()
	}
	p.mu.Unlock()

	if alreadyApplied {
		slog.DebugContext(ctx, "OCI policy digest unchanged after fetch, skipping reload",
			"oci_ref", p.ociRef,
			"digest", result.Digest,
		)

		return
	}

	slog.InfoContext(ctx, "OCI policy update detected, reloading policies",
		"oci_ref", p.ociRef,
		"digest", result.Digest,
	)

	if p.onReload != nil {
		reloadErr := p.onReload(result.Policies)
		if reloadErr != nil {
			p.logFailure(ctx, "OCI policy reload rejected, will retry next poll",
				reloadErr, "digest", result.Digest,
			)

			return
		}
	}

	// Only an applied artifact raises the rollback guard, so a rejected
	// update never blocks re-tagging the previous good artifact.
	p.fetcher.SeedNewestCreated(result.Created)

	p.mu.Lock()
	p.cachedDigest = result.Digest
	p.lastSuccess = time.Now()
	p.mu.Unlock()
}

// logFailure logs a failed poll together with how long the applied policies
// have not been refreshed. After staleIntervals poll intervals the failure is
// logged at error level so stale policies do not go unnoticed.
func (p *Poller) logFailure(ctx context.Context, msg string, err error, attrs ...any) {
	staleFor := time.Since(p.LastSuccess())

	level := slog.LevelWarn
	if staleFor > staleIntervals*p.interval {
		level = slog.LevelError
	}

	args := append([]any{
		"oci_ref", p.ociRef,
		"stale_for", staleFor.Round(time.Second).String(),
	}, attrs...)

	slog.Log(ctx, level, msg, append(args, "error", err)...)
}

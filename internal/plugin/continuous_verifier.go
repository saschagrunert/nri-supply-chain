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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/containerd/nri/pkg/api"
	"google.golang.org/protobuf/proto"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/feed"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	batchYieldDuration = 100 * time.Millisecond
	triggerTimer       = "timer"
	triggerFeed        = "feed"
	triggerManual      = "trigger"
)

// containerForReverify holds a snapshot of container data needed for
// re-verification, avoiding holding the registry lock during verification.
type containerForReverify struct {
	id             string
	imageRef       string
	digest         string
	indexDigest    string
	namespace      string
	serviceAccount string
	state          VerificationState
}

// RunContinuousVerifier starts the background re-verification loop. It blocks
// until ctx is cancelled. Start in the errgroup alongside nriStub.Run.
func (p *Plugin) RunContinuousVerifier(ctx context.Context, interval time.Duration) {
	if !p.remediation.started.CompareAndSwap(false, true) {
		slog.WarnContext(ctx, "Continuous verifier already running, ignoring duplicate call")

		return
	}

	defer p.remediation.started.Store(false)

	slog.InfoContext(ctx, "Continuous verifier waiting for prewarm", "interval", interval)

	select {
	case <-ctx.Done():
		return
	case <-p.prewarm.doneCh:
	}

	slog.InfoContext(ctx, "Continuous verifier started", "interval", interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.InfoContext(ctx, "Continuous verifier stopped")

			return
		case <-ticker.C:
			p.runVerificationCycle(ctx, triggerTimer, nil, nil)
		case <-p.remediation.reverifyTrigger:
			p.runVerificationCycle(ctx, triggerManual, nil, nil)
		case feedPURLs := <-p.remediation.feedTrigger:
			filterIDs := p.matchFeedPURLs(feedPURLs)
			if len(filterIDs) > 0 {
				p.runVerificationCycle(ctx, triggerFeed, filterIDs, feedPURLs)
			}
		}
	}
}

// StartContinuousVerifier starts the continuous verifier in the background
// unless it is already running, for example when a configuration passed by
// the runtime enables remediation.
func (p *Plugin) StartContinuousVerifier(ctx context.Context, interval time.Duration) {
	if p.remediation.started.Load() {
		return
	}

	go p.RunContinuousVerifier(ctx, interval)
}

//nolint:cyclop,funlen // batching, filtering, and yield logic require branching
func (p *Plugin) runVerificationCycle(
	ctx context.Context, trigger string,
	filterIDs map[string]struct{}, feedPURLs []string,
) {
	mode := config.RemediationModeDisabled
	if modePtr := p.remediation.mode.Load(); modePtr != nil {
		mode = *modePtr
	}

	snapshot := p.containers.SnapshotIDs()

	var targets []containerForReverify

	resolved := make(map[string]digestResolution)

	//nolint:gocritic // value copy intentional: snapshot holds copies
	for containerID, csnap := range snapshot {
		if filterIDs != nil {
			if _, keep := filterIDs[containerID]; !keep {
				continue
			}
		}

		target := containerForReverify{
			id:             containerID,
			imageRef:       csnap.imageRef,
			digest:         csnap.digest,
			indexDigest:    csnap.indexDigest,
			namespace:      csnap.namespace,
			serviceAccount: csnap.serviceAccount,
			state:          csnap.state,
		}

		if csnap.unresolvedDigest != "" &&
			!p.resolveTargetDigest(ctx, &target, csnap.unresolvedDigest, resolved) {
			continue
		}

		if target.digest == "" {
			// Without a digest the verifier cannot bind attestations to the
			// running image; containers without a known image digest are
			// left alone instead of being reported as degraded.
			slog.DebugContext(ctx, "Skipping re-verification of container without digest",
				"container", containerID,
				"image", csnap.imageRef,
			)

			continue
		}

		targets = append(targets, target)
	}

	if len(targets) == 0 {
		p.metrics.ContinuousVerifierLastRun.SetToCurrentTime()

		return
	}

	batchSize := p.batchSize()

	var updates []*pendingUpdate

	for batchStart := 0; batchStart < len(targets); batchStart += batchSize {
		if ctx.Err() != nil {
			return
		}

		end := min(batchStart+batchSize, len(targets))
		batch := targets[batchStart:end]

		for j := range batch {
			update := p.reverifyContainer(ctx, &batch[j], trigger, mode, feedPURLs)
			if update != nil {
				updates = append(updates, update)
			}
		}

		if batchStart+batchSize < len(targets) {
			yieldTimer := time.NewTimer(batchYieldDuration)

			select {
			case <-ctx.Done():
				yieldTimer.Stop()

				return
			case <-yieldTimer.C:
			}
		}
	}

	if len(updates) > 0 {
		p.applyUpdates(ctx, updates)
	}

	p.updateTrackedContainerGauge()
	p.metrics.ContinuousVerifierLastRun.SetToCurrentTime()

	slog.InfoContext(ctx, "Continuous verification cycle completed",
		"trigger", trigger,
		"containers", len(targets),
		"updates", len(updates),
	)
}

func (p *Plugin) reverifyContainer(
	ctx context.Context, target *containerForReverify,
	trigger string, mode config.RemediationMode, feedPURLs []string,
) *pendingUpdate {
	if trigger != triggerTimer {
		p.verifier.InvalidateCache(target.digest, target.namespace)
	}

	start := time.Now()

	result, err := p.verifier.Verify(ctx, &types.VerifyRequest{
		ImageRef:       target.imageRef,
		Digest:         target.digest,
		IndexDigest:    target.indexDigest,
		Namespace:      target.namespace,
		ServiceAccount: target.serviceAccount,
	})

	duration := time.Since(start).Seconds()
	p.metrics.ReverificationDuration.WithLabelValues(target.namespace).Observe(duration)

	// In enforce mode a failed verification comes with its result; only an
	// error without a decision is a re-verification error.
	if err != nil && (result == nil || !errors.Is(err, types.ErrVerificationFailed)) {
		p.handleReverifyError(ctx, target, err)

		return nil
	}

	// A verification that could not complete (for example a registry outage)
	// says nothing about the image: it neither degrades the container nor
	// recovers or rolls it back, and it does not count as an error. A
	// persistent outage therefore never degrades a container, even in enforce
	// mode; it is logged and counted so it stays visible.
	if resultIncomplete(result) {
		p.metrics.ReverificationTotal.WithLabelValues(target.namespace, "incomplete").Inc()
		p.recordIncompleteReverification(ctx, target, result.Reason)

		return nil
	}

	p.containers.UpdateState(target.id, func(cState *containerState) {
		cState.consecutiveErrors = 0
		cState.consecutiveIncomplete = 0
	})

	degraded := !result.Verified

	resultLabel := "pass"
	if degraded {
		resultLabel = "degraded"
	}

	p.metrics.ReverificationTotal.WithLabelValues(target.namespace, resultLabel).Inc()

	return p.applyStateTransition(ctx, target, result, degraded, trigger, mode, feedPURLs)
}

// digestResolution is the result of resolving a runtime image digest, shared
// by the containers of a verification cycle that run the same image.
type digestResolution struct {
	digest      string
	indexDigest string
	err         error
}

// resolveTargetDigest resolves the runtime digest of a container whose digest
// was not resolved at admission or recovery (verification was not needed, or
// the registry was unreachable) and records the result, so the container is
// re-verified against the image it runs. A failed resolution counts as an
// incomplete re-verification and returns false.
func (p *Plugin) resolveTargetDigest(
	ctx context.Context, target *containerForReverify, runtimeDigest string,
	resolved map[string]digestResolution,
) bool {
	key := target.imageRef + "\x00" + runtimeDigest

	res, found := resolved[key]
	if !found {
		resolveCtx, cancel := context.WithTimeout(ctx, time.Duration(p.fetchTimeout.Load()))
		res.digest, res.indexDigest, res.err = p.resolveRuntimeDigest(
			resolveCtx, target.imageRef, runtimeDigest,
		)

		cancel()

		resolved[key] = res
	}

	if res.err != nil {
		p.metrics.ReverificationTotal.WithLabelValues(target.namespace, "incomplete").Inc()
		p.recordIncompleteReverification(ctx, target, "resolving image digest: "+res.err.Error())

		return false
	}

	p.containers.UpdateState(target.id, func(cState *containerState) {
		if cState.unresolvedDigest == runtimeDigest {
			cState.digest = res.digest
			cState.indexDigest = res.indexDigest
			cState.unresolvedDigest = ""
		}
	})

	target.digest = res.digest
	target.indexDigest = res.indexDigest

	return true
}

// recordIncompleteReverification counts an incomplete re-verification and
// warns once it has been incomplete for consecutiveErrorThreshold cycles.
func (p *Plugin) recordIncompleteReverification(
	ctx context.Context, target *containerForReverify, reason string,
) {
	incomplete := 0

	p.containers.UpdateState(target.id, func(cState *containerState) {
		cState.consecutiveIncomplete++
		incomplete = cState.consecutiveIncomplete
	})

	if incomplete == consecutiveErrorThreshold {
		slog.WarnContext(ctx,
			"Re-verification keeps failing to complete; the container keeps its state",
			"container", target.id,
			"image", target.imageRef,
			"cycles", incomplete,
			"reason", reason,
		)

		return
	}

	slog.DebugContext(ctx, "Re-verification incomplete, keeping container state",
		"container", target.id,
		"image", target.imageRef,
		"reason", reason,
	)
}

func (p *Plugin) handleReverifyError(
	ctx context.Context, target *containerForReverify, err error,
) {
	slog.WarnContext(ctx, "Re-verification error",
		"container", target.id,
		"image", target.imageRef,
		"error", err,
	)

	p.metrics.ReverificationTotal.WithLabelValues(target.namespace, "error").Inc()

	p.containers.UpdateState(target.id, func(cState *containerState) {
		cState.consecutiveErrors++

		if cState.consecutiveErrors >= consecutiveErrorThreshold &&
			(cState.state == StateVerified || cState.state == StateSkipped) {
			cState.state = StateDegraded

			slog.WarnContext(ctx, "Container degraded after consecutive re-verification errors",
				"container", target.id,
				"image", target.imageRef,
				"errors", cState.consecutiveErrors,
			)
		}
	})
}

// pendingUpdate is a container update and the state transition to record
// once the runtime has applied it. Recording the transition only after a
// successful UpdateContainers call keeps the state machine in its previous
// state when the update fails, so the next cycle retries it.
type pendingUpdate struct {
	update *api.ContainerUpdate
	commit func(cState *containerState)
}

//nolint:cyclop,funlen // state machine with three transitions and mode-gated remediation
func (p *Plugin) applyStateTransition(
	ctx context.Context, target *containerForReverify, result *types.Result,
	degraded bool, trigger string, mode config.RemediationMode,
	feedPURLs []string,
) *pendingUpdate {
	triggerHash := computeTriggerHash(trigger, target.digest, feedPURLs)

	var pending *pendingUpdate

	p.containers.UpdateState(target.id, func(cState *containerState) {
		cState.lastResult = result
		cState.purls = extractPURLsFromResult(result)

		prevState := cState.state

		switch {
		case !degraded && prevState == StateSkipped:
			cState.state = StateVerified

			slog.InfoContext(ctx, "Container verification passed",
				"container", target.id,
				"image", target.imageRef,
				"namespace", target.namespace,
			)

		case !degraded && prevState == StateThrottled && p.hasTrustedOriginals(cState):
			// Stay throttled until the runtime confirms the rollback.
			pending = p.rollbackUpdate(ctx, target, cState.originalResources)

		case !degraded && prevState != StateVerified:
			cState.state = StateVerified

			slog.InfoContext(ctx, "Container verification recovered",
				"container", target.id,
				"image", target.imageRef,
				"namespace", target.namespace,
				"from_state", prevState.String(),
			)
			p.metrics.RemediationActionsTotal.WithLabelValues(
				"recover", target.namespace,
			).Inc()

		case degraded && (prevState == StateVerified || prevState == StateSkipped):
			cState.state = StateDegraded
			cState.lastTriggerHash = triggerHash

			slog.WarnContext(ctx, "Container verification degraded",
				"container", target.id,
				"image", target.imageRef,
				"namespace", target.namespace,
				"trigger", trigger,
			)
			p.metrics.RemediationActionsTotal.WithLabelValues("warn", target.namespace).Inc()

		case degraded && prevState == StateDegraded:
			if p.shouldThrottle(ctx, target, cState, mode, trigger, triggerHash) {
				pending = p.throttleUpdate(
					ctx,
					target,
					cState.originalResources,
					trigger,
					triggerHash,
				)
			}

		case degraded && prevState == StateThrottled:
			// Stays throttled until verification recovers (handled by the
			// !degraded branches above). No escalation beyond Throttled.
		}
	})

	return pending
}

// hasTrustedOriginals reports whether the container's recorded original
// resources can be restored. Resources captured from a container recovered
// after a plugin restart without the original resources annotation may
// already be throttled.
func (p *Plugin) hasTrustedOriginals(cState *containerState) bool {
	return cState.originalResources != nil && !cState.recoveredOnRestart
}

func (p *Plugin) shouldThrottle(
	ctx context.Context, target *containerForReverify, cState *containerState,
	mode config.RemediationMode, trigger, triggerHash string,
) bool {
	if mode.Severity() < config.RemediationModeThrottle.Severity() {
		return false
	}

	if !p.hasTrustedOriginals(cState) {
		// Throttling relative to resources that may already be throttled
		// would stack limits and could never be rolled back correctly.
		slog.DebugContext(ctx, "Not throttling container without recorded original resources",
			"container", target.id,
			"image", target.imageRef,
			"recovered_on_restart", cState.recoveredOnRestart,
		)

		return false
	}

	return p.cooldownElapsed(cState) &&
		(trigger == triggerTimer || cState.lastTriggerHash != triggerHash)
}

func (p *Plugin) throttleUpdate(
	ctx context.Context, target *containerForReverify,
	original *api.LinuxResources, trigger, triggerHash string,
) *pendingUpdate {
	update := p.buildThrottleUpdate(target.id, original)
	if update == nil {
		return nil
	}

	cpuPct, memPct := p.throttlePercents()

	return &pendingUpdate{
		update: update,
		commit: func(cState *containerState) {
			cState.state = StateThrottled
			cState.lastRemediation = time.Now()
			cState.lastTriggerHash = triggerHash

			slog.WarnContext(ctx, "Container throttled",
				"container", target.id,
				"image", target.imageRef,
				"namespace", target.namespace,
				"trigger", trigger,
				"cpu_quota_percent", cpuPct,
				"memory_limit_percent", memPct,
			)
			p.metrics.RemediationActionsTotal.WithLabelValues("throttle", target.namespace).
				Inc()
		},
	}
}

func (p *Plugin) rollbackUpdate(
	ctx context.Context, target *containerForReverify, original *api.LinuxResources,
) *pendingUpdate {
	return &pendingUpdate{
		update: buildRollbackUpdate(target.id, original),
		commit: func(cState *containerState) {
			cState.state = StateVerified

			slog.InfoContext(ctx, "Container verification recovered",
				"container", target.id,
				"image", target.imageRef,
				"namespace", target.namespace,
				"from_state", StateThrottled.String(),
			)
			p.metrics.RemediationActionsTotal.WithLabelValues(
				"rollback", target.namespace,
			).Inc()
		},
	}
}

func (p *Plugin) cooldownElapsed(cState *containerState) bool {
	if cState.lastRemediation.IsZero() {
		return true
	}

	cooldown := config.DefaultRemediationCooldown
	if cfg := p.remediation.cfg.Load(); cfg != nil &&
		cfg.Cooldown.Duration > 0 {
		cooldown = cfg.Cooldown.Duration
	}

	return time.Since(cState.lastRemediation) > cooldown
}

func (p *Plugin) buildThrottleUpdate(
	containerID string, original *api.LinuxResources,
) *api.ContainerUpdate {
	if original == nil {
		return nil
	}

	cpuPercent, memPercent := p.throttlePercents()
	resources := &api.LinuxResources{}

	if cpu := original.GetCpu(); cpu != nil {
		throttledCPU := &api.LinuxCPU{}

		if quota := cpu.GetQuota(); quota != nil {
			throttledQuota := max(
				quota.GetValue()*int64(cpuPercent)/percentDivisor,
				minCPUQuotaMicros,
			)

			throttledCPU.Quota = &api.OptionalInt64{Value: throttledQuota}
		}

		if shares := cpu.GetShares(); shares != nil {
			//nolint:gosec // cpuPercent is validated positive by throttlePercents()
			throttledShares := max(
				shares.GetValue()*uint64(cpuPercent)/percentDivisor,
				minCPUShares,
			)

			throttledCPU.Shares = &api.OptionalUInt64{Value: throttledShares}
		}

		resources.Cpu = throttledCPU
	}

	// A memory limit below the container's working set makes the kernel
	// OOM-kill it, so memory is only throttled when explicitly configured
	// below 100 percent.
	if mem := original.GetMemory(); mem != nil && memPercent < percentDivisor {
		throttledMem := &api.LinuxMemory{}

		if limit := mem.GetLimit(); limit != nil {
			throttledLimit := max(
				limit.GetValue()*int64(memPercent)/percentDivisor,
				minMemoryLimitBytes,
			)
			throttledMem.Limit = &api.OptionalInt64{Value: throttledLimit}
		}

		resources.Memory = throttledMem
	}

	return &api.ContainerUpdate{
		ContainerId:   containerID,
		Linux:         &api.LinuxContainerUpdate{Resources: resources},
		IgnoreFailure: false,
	}
}

// looksThrottled reports whether current holds exactly the limits a throttle
// update derived from original sets, and at least one of them differs from
// original. Limits changed for other reasons (for example an in-place resize)
// do not match and are left alone.
func (p *Plugin) looksThrottled(current, original *api.LinuxResources) bool {
	throttled := p.buildThrottleUpdate("", original).GetLinux().GetResources()
	if throttled == nil || current == nil {
		return false
	}

	limits := []limitMatch{
		compareLimit(
			optionalInt64(throttled.GetCpu().GetQuota()),
			optionalInt64(current.GetCpu().GetQuota()),
			optionalInt64(original.GetCpu().GetQuota()),
		),
		compareLimit(
			optionalUint64(throttled.GetCpu().GetShares()),
			optionalUint64(current.GetCpu().GetShares()),
			optionalUint64(original.GetCpu().GetShares()),
		),
		compareLimit(
			optionalInt64(throttled.GetMemory().GetLimit()),
			optionalInt64(current.GetMemory().GetLimit()),
			optionalInt64(original.GetMemory().GetLimit()),
		),
	}

	compared, changed := false, false

	for _, limit := range limits {
		if !limit.compared {
			continue
		}

		if !limit.matches {
			return false
		}

		compared = true
		changed = changed || limit.changed
	}

	return compared && changed
}

// limitMatch is the comparison of one throttleable limit.
type limitMatch struct {
	// compared is false when the throttle update does not set the limit.
	compared bool
	// matches is true when the current limit equals the throttled limit.
	matches bool
	// changed is true when the throttled limit differs from the original.
	changed bool
}

func compareLimit[T comparable](throttled, current, original *T) limitMatch {
	if throttled == nil {
		return limitMatch{compared: false, matches: false, changed: false}
	}

	return limitMatch{
		compared: true,
		matches:  current != nil && *current == *throttled,
		changed:  original == nil || *original != *throttled,
	}
}

func optionalInt64(value *api.OptionalInt64) *int64 {
	if value == nil {
		return nil
	}

	v := value.GetValue()

	return &v
}

func optionalUint64(value *api.OptionalUInt64) *uint64 {
	if value == nil {
		return nil
	}

	v := value.GetValue()

	return &v
}

func (p *Plugin) throttlePercents() (cpuPercent, memPercent int) {
	if cfg := p.remediation.cfg.Load(); cfg != nil {
		cpuPercent = cfg.Throttle.CPUQuotaPercent
		memPercent = cfg.Throttle.MemoryLimitPercent
	}

	if cpuPercent <= 0 {
		cpuPercent = defaultThrottleCPUPercent
	}

	if memPercent <= 0 {
		memPercent = defaultThrottleMemPercent
	}

	cpuPercent = min(cpuPercent, percentDivisor)
	memPercent = min(memPercent, percentDivisor)

	return cpuPercent, memPercent
}

func buildRollbackUpdate(
	containerID string, original *api.LinuxResources,
) *api.ContainerUpdate {
	restored := deepCopyLinuxResources(original)

	return &api.ContainerUpdate{
		ContainerId:   containerID,
		Linux:         &api.LinuxContainerUpdate{Resources: restored},
		IgnoreFailure: false,
	}
}

func deepCopyLinuxResources(src *api.LinuxResources) *api.LinuxResources {
	if src == nil {
		return nil
	}

	cloned, ok := proto.Clone(src).(*api.LinuxResources)
	if !ok {
		return nil
	}

	return cloned
}

// applyUpdates sends the pending updates to the runtime and records the
// state transition of every update the runtime applied. Failed updates keep
// their previous state and are retried by the next cycle.
func (p *Plugin) applyUpdates(ctx context.Context, pending []*pendingUpdate) {
	stub := p.getStubUpdater()
	if stub == nil {
		slog.WarnContext(ctx, "Cannot apply remediation updates: NRI stub not available")
		p.metrics.RemediationErrorsTotal.WithLabelValues("update").Inc()

		return
	}

	updates := make([]*api.ContainerUpdate, 0, len(pending))
	for _, pu := range pending {
		updates = append(updates, pu.update)
	}

	failed, err := stub.UpdateContainers(updates)
	if err != nil {
		slog.ErrorContext(ctx, "UpdateContainers failed", "error", err)
		p.metrics.RemediationErrorsTotal.WithLabelValues("update").Inc()

		return
	}

	failedIDs := make(map[string]struct{}, len(failed))

	for _, failedUpdate := range failed {
		slog.WarnContext(ctx, "Container update failed",
			"container", failedUpdate.GetContainerId(),
		)
		p.metrics.RemediationErrorsTotal.WithLabelValues("partial").Inc()

		failedIDs[failedUpdate.GetContainerId()] = struct{}{}
	}

	for _, pu := range pending {
		if _, didFail := failedIDs[pu.update.GetContainerId()]; didFail {
			continue
		}

		p.containers.UpdateState(pu.update.GetContainerId(), pu.commit)
	}
}

func (p *Plugin) updateTrackedContainerGauge() {
	counts := p.containers.StateCounts()

	p.metrics.TrackedContainers.WithLabelValues("verified").Set(
		float64(counts[StateVerified]),
	)
	p.metrics.TrackedContainers.WithLabelValues("skipped").Set(
		float64(counts[StateSkipped]),
	)
	p.metrics.TrackedContainers.WithLabelValues("degraded").Set(
		float64(counts[StateDegraded]),
	)
	p.metrics.TrackedContainers.WithLabelValues("throttled").Set(
		float64(counts[StateThrottled]),
	)
	p.metrics.ReverificationIncompleteContainers.Set(
		float64(p.containers.IncompleteCount(consecutiveErrorThreshold)),
	)
}

func (p *Plugin) batchSize() int {
	if cfg := p.remediation.cfg.Load(); cfg != nil && cfg.BatchSize > 0 {
		return cfg.BatchSize
	}

	return config.DefaultRemediationBatchSize
}

func computeTriggerHash(trigger, digest string, feedPURLs []string) string {
	input := trigger + "\x00" + digest

	if len(feedPURLs) > 0 {
		if slices.IsSorted(feedPURLs) {
			input += "\x00" + strings.Join(feedPURLs, "\x00")
		} else {
			sorted := slices.Clone(feedPURLs)
			slices.Sort(sorted)
			input += "\x00" + strings.Join(sorted, "\x00")
		}
	}

	h := sha256.Sum256([]byte(input))

	return hex.EncodeToString(h[:8])
}

// matchFeedPURLs returns the containers whose SBOM purls match the feed
// specs. Matching compares package identity (type, namespace, name) and
// honors feed versions and SEMVER ranges; see feed.Matcher.
func (p *Plugin) matchFeedPURLs(feedPURLs []string) map[string]struct{} {
	matcher := feed.NewMatcher(feedPURLs)

	snapshot := p.containers.SnapshotIDs()

	matched := make(map[string]struct{})

	//nolint:gocritic // value copy intentional: snapshot holds copies
	for containerID, csnap := range snapshot {
		if matcher.MatchesAny(csnap.purls) {
			matched[containerID] = struct{}{}
		}
	}

	return matched
}

const (
	defaultThrottleCPUPercent = 10
	defaultThrottleMemPercent = 100
	percentDivisor            = 100
	minCPUQuotaMicros         = 1000
	minCPUShares              = 2
	minMemoryLimitBytes       = 4 << 20 // 4 MiB
	consecutiveErrorThreshold = 3
)

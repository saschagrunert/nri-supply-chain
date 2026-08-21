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
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/containerd/nri/pkg/api"
	"google.golang.org/protobuf/proto"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
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
	slog.Info("Continuous verifier waiting for prewarm", "interval", interval)

	select {
	case <-ctx.Done():
		return
	case <-p.prewarmDoneCh:
	}

	slog.Info("Continuous verifier started", "interval", interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("Continuous verifier stopped")

			return
		case <-ticker.C:
			p.runVerificationCycle(ctx, triggerTimer, nil, nil)
		case <-p.reverifyTrigger:
			p.runVerificationCycle(ctx, triggerManual, nil, nil)
		case feedPURLs := <-p.feedTrigger:
			filterIDs := p.matchFeedPURLs(feedPURLs)
			if len(filterIDs) > 0 {
				p.runVerificationCycle(ctx, triggerFeed, filterIDs, feedPURLs)
			}
		}
	}
}

//nolint:cyclop,funlen // batching, filtering, and yield logic require branching
func (p *Plugin) runVerificationCycle(
	ctx context.Context, trigger string,
	filterIDs map[string]struct{}, feedPURLs []string,
) {
	mode := config.RemediationModeDisabled
	if modePtr := p.remediationMode.Load(); modePtr != nil {
		mode = *modePtr
	}

	snapshot := p.containers.SnapshotIDs()

	var targets []containerForReverify

	//nolint:gocritic // value copy intentional: snapshot holds copies
	for containerID, csnap := range snapshot {
		if filterIDs != nil {
			if _, keep := filterIDs[containerID]; !keep {
				continue
			}
		}

		targets = append(targets, containerForReverify{
			id:             containerID,
			imageRef:       csnap.imageRef,
			digest:         csnap.digest,
			indexDigest:    csnap.indexDigest,
			namespace:      csnap.namespace,
			serviceAccount: csnap.serviceAccount,
			state:          csnap.state,
		})
	}

	if len(targets) == 0 {
		p.metrics.ContinuousVerifierLastRun.SetToCurrentTime()

		return
	}

	batchSize := p.batchSize()

	var updates []*api.ContainerUpdate

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
		p.applyUpdates(updates)
	}

	p.updateTrackedContainerGauge()
	p.metrics.ContinuousVerifierLastRun.SetToCurrentTime()

	slog.Info("Continuous verification cycle completed",
		"trigger", trigger,
		"containers", len(targets),
		"updates", len(updates),
	)
}

func (p *Plugin) reverifyContainer(
	ctx context.Context, target *containerForReverify,
	trigger string, mode config.RemediationMode, feedPURLs []string,
) *api.ContainerUpdate {
	if trigger != triggerTimer {
		p.verifier.InvalidateCache(target.digest, target.namespace)
	}

	start := time.Now()

	result, err := p.verifier.Verify(
		ctx, target.imageRef, target.digest, target.indexDigest,
		target.namespace, target.serviceAccount,
	)

	duration := time.Since(start).Seconds()
	p.metrics.ReverificationDuration.WithLabelValues(target.namespace).Observe(duration)

	if err != nil {
		slog.Warn("Re-verification error",
			"container", target.id,
			"image", target.imageRef,
			"error", err,
		)

		p.metrics.ReverificationTotal.WithLabelValues(target.namespace, "error").Inc()

		return nil
	}

	degraded := !result.Allowed
	for i := range result.CheckResults {
		if !result.CheckResults[i].Passed {
			degraded = true

			break
		}
	}

	resultLabel := "pass"
	if degraded {
		resultLabel = "degraded"
	}

	p.metrics.ReverificationTotal.WithLabelValues(target.namespace, resultLabel).Inc()

	return p.applyStateTransition(target, result, degraded, trigger, mode, feedPURLs)
}

//nolint:cyclop,funlen // state machine with three transitions and mode-gated remediation
func (p *Plugin) applyStateTransition(
	target *containerForReverify, result *types.Result,
	degraded bool, trigger string, mode config.RemediationMode,
	feedPURLs []string,
) *api.ContainerUpdate {
	triggerHash := computeTriggerHash(trigger, target.digest, feedPURLs)

	var update *api.ContainerUpdate

	p.containers.UpdateState(target.id, func(cState *containerState) {
		cState.lastResult = result
		cState.purls = extractPURLsFromResult(result)

		wasRecoveredOnRestart := cState.recoveredOnRestart

		if cState.recoveredOnRestart && !degraded {
			cState.recoveredOnRestart = false
		}

		prevState := cState.state

		switch {
		case !degraded && prevState != StateVerified:
			cState.state = StateVerified

			slog.Info("Container verification recovered",
				"container", target.id,
				"image", target.imageRef,
				"namespace", target.namespace,
				"from_state", prevState.String(),
			)

			if prevState == StateThrottled &&
				cState.originalResources != nil &&
				!wasRecoveredOnRestart {
				update = buildRollbackUpdate(target.id, cState.originalResources)
				p.metrics.RemediationActionsTotal.WithLabelValues(
					"rollback", target.namespace,
				).Inc()
			} else {
				p.metrics.RemediationActionsTotal.WithLabelValues(
					"recover", target.namespace,
				).Inc()
			}

		case degraded && prevState == StateVerified:
			cState.state = StateDegraded
			cState.lastTriggerHash = triggerHash

			slog.Warn("Container verification degraded",
				"container", target.id,
				"image", target.imageRef,
				"namespace", target.namespace,
				"trigger", trigger,
			)
			p.metrics.RemediationActionsTotal.WithLabelValues("warn", target.namespace).Inc()

		case degraded && prevState == StateDegraded:
			if mode.Severity() >= config.RemediationModeThrottle.Severity() &&
				cState.originalResources != nil {
				if p.cooldownElapsed(cState) &&
					(trigger == triggerTimer || cState.lastTriggerHash != triggerHash) {
					cState.state = StateThrottled
					cState.lastRemediation = time.Now()
					cState.lastTriggerHash = triggerHash

					cpuPct, memPct := p.throttlePercents()
					update = p.buildThrottleUpdate(target.id, cState.originalResources)

					slog.Warn("Container throttled",
						"container", target.id,
						"image", target.imageRef,
						"namespace", target.namespace,
						"trigger", trigger,
						"cpu_quota_percent", cpuPct,
						"memory_limit_percent", memPct,
					)
					p.metrics.RemediationActionsTotal.WithLabelValues("throttle", target.namespace).
						Inc()
				}
			}

		case degraded && prevState == StateThrottled:
			// Stays throttled until verification recovers (handled by the
			// !degraded branch above). No escalation beyond Throttled.
		}
	})

	return update
}

func (p *Plugin) cooldownElapsed(cState *containerState) bool {
	if cState.lastRemediation.IsZero() {
		return true
	}

	cooldown := config.DefaultRemediationCooldown
	if cfg := p.remediationConfig.Load(); cfg != nil &&
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

	if mem := original.GetMemory(); mem != nil {
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
		IgnoreFailure: true,
	}
}

func (p *Plugin) throttlePercents() (cpuPercent, memPercent int) {
	if cfg := p.remediationConfig.Load(); cfg != nil {
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
		IgnoreFailure: true,
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

func (p *Plugin) applyUpdates(updates []*api.ContainerUpdate) {
	stub := p.getStubUpdater()
	if stub == nil {
		slog.Warn("Cannot apply remediation updates: NRI stub not available")

		return
	}

	failed, err := stub.UpdateContainers(updates)
	if err != nil {
		slog.Error("UpdateContainers failed", "error", err)
		p.metrics.RemediationErrorsTotal.WithLabelValues("update").Inc()

		return
	}

	for _, f := range failed {
		slog.Warn("Container update failed",
			"container", f.GetContainerId(),
		)
		p.metrics.RemediationErrorsTotal.WithLabelValues("partial").Inc()
	}
}

func (p *Plugin) updateTrackedContainerGauge() {
	counts := p.containers.StateCounts()

	p.metrics.TrackedContainers.WithLabelValues("verified").Set(
		float64(counts[StateVerified]),
	)
	p.metrics.TrackedContainers.WithLabelValues("degraded").Set(
		float64(counts[StateDegraded]),
	)
	p.metrics.TrackedContainers.WithLabelValues("throttled").Set(
		float64(counts[StateThrottled]),
	)
}

func (p *Plugin) batchSize() int {
	if cfg := p.remediationConfig.Load(); cfg != nil && cfg.BatchSize > 0 {
		return cfg.BatchSize
	}

	return config.DefaultRemediationBatchSize
}

func computeTriggerHash(trigger, digest string, feedPURLs []string) string {
	input := trigger + "\x00" + digest

	if len(feedPURLs) > 0 {
		sorted := slices.Clone(feedPURLs)
		slices.Sort(sorted)
		input += "\x00" + strings.Join(sorted, "\x00")
	}

	h := sha256.Sum256([]byte(input))

	return hex.EncodeToString(h[:8])
}

func (p *Plugin) matchFeedPURLs(feedPURLs []string) map[string]struct{} {
	feedSet := make(map[string]struct{}, len(feedPURLs))
	for _, purl := range feedPURLs {
		feedSet[purl] = struct{}{}
	}

	snapshot := p.containers.SnapshotIDs()

	matched := make(map[string]struct{})

	//nolint:gocritic // value copy intentional: snapshot holds copies
	for containerID, csnap := range snapshot {
		for _, purl := range csnap.purls {
			if _, found := feedSet[purl]; found {
				matched[containerID] = struct{}{}

				break
			}
		}
	}

	return matched
}

const (
	defaultThrottleCPUPercent = 10
	defaultThrottleMemPercent = 50
	percentDivisor            = 100
	minCPUQuotaMicros         = 1000
	minCPUShares              = 2
	minMemoryLimitBytes       = 4 << 20 // 4 MiB
)

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
	"time"

	"github.com/containerd/nri/pkg/api"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

// ExportResolveImage exposes resolveImage for external tests.
func ExportResolveImage(annotations map[string]string) (imageRef, digest string) {
	return resolveImage(annotations)
}

// ExportPrewarmImage is an exported alias for prewarmImage.
type ExportPrewarmImage = prewarmImage

// NewExportPrewarmImage creates a prewarmImage for external tests.
func NewExportPrewarmImage(
	imageRef, digest, indexDigest, namespace, container string,
) ExportPrewarmImage {
	return prewarmImage{
		imageRef:      imageRef,
		digest:        digest,
		indexDigest:   indexDigest,
		runtimeDigest: "",
		namespace:     namespace,
		container:     container,
		containerIDs:  nil,
	}
}

// ExportPrewarmCache exposes prewarmCache for external tests.
func (p *Plugin) ExportPrewarmCache(ctx context.Context, images []ExportPrewarmImage) {
	p.prewarmCache(ctx, images)
}

// ExportSetDigestResolver replaces the digest resolver for testing.
func (p *Plugin) ExportSetDigestResolver(fn DigestResolveFunc) {
	p.digestResolver = fn
}

// ExportDefaultDigestResolver exposes registryAwareResolver for testing.
func ExportDefaultDigestResolver(
	ctx context.Context, imageRef string,
) (digest, indexDigest string, err error) {
	plug := &Plugin{ //nolint:exhaustruct_v5 // zero-value fields are intentional
		verifier:    nil,
		metrics:     nil,
		configPath:  "",
		containers:  newContainerRegistry(),
		prewarm:     newPrewarmState(),
		remediation: newRemediationState(),
	}

	return plug.registryAwareResolver(ctx, imageRef)
}

// ExportSetPrewarmDone sets a callback that fires when prewarmCache completes.
func (p *Plugin) ExportSetPrewarmDone(fn func()) {
	p.prewarm.done = fn
}

// ExportFilterRelevantAnnotations exposes filterRelevantAnnotations for testing.
func ExportFilterRelevantAnnotations(annotations map[string]string) map[string]string {
	return filterRelevantAnnotations(annotations)
}

// ExportBuildVerificationAdjustment exposes buildVerificationAdjustment for testing.
func ExportBuildVerificationAdjustment(
	result *types.Result, mode config.VerificationMode,
) *api.ContainerAdjustment {
	return buildVerificationAdjustment(result, mode)
}

// ExportMetrics returns the plugin metrics.
func (p *Plugin) ExportMetrics() *metrics.Metrics {
	return p.metrics
}

// ExportSetRuntimeConfigRetry sets the backoff used to retry a configuration
// passed by the runtime that failed to apply.
func (p *Plugin) ExportSetRuntimeConfigRetry(initial, maximum time.Duration) {
	p.runtimeConfig.retryInitial.Store(int64(initial))
	p.runtimeConfig.retryMaximum.Store(int64(maximum))
}

// ExportFetchTimeout returns the current fetch timeout value.
func (p *Plugin) ExportFetchTimeout() time.Duration {
	return time.Duration(p.fetchTimeout.Load())
}

// ExportDigestResolveTimeout returns the current digest resolve timeout value.
func (p *Plugin) ExportDigestResolveTimeout() time.Duration {
	return time.Duration(p.digestResolveTimeout.Load())
}

// ExportStoreContainerTime stores a creation timestamp for a container ID.
func (p *Plugin) ExportStoreContainerTime(containerID string, t time.Time) {
	state := &containerState{ //nolint:exhaustruct_v5 // test helper, zero-value fields intentional
		digest:    exportTestDigest,
		createdAt: t,
		state:     StateVerified,
	}
	p.containers.Store(containerID, state)
}

// exportTestDigest is the digest assigned by test helpers that do not take
// one; the continuous verifier skips containers without a digest.
const exportTestDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

// ExportLoadContainerTime loads the creation timestamp for a container ID.
func (p *Plugin) ExportLoadContainerTime(containerID string) (time.Time, bool) {
	cs, found := p.containers.Load(containerID)
	if !found {
		return time.Time{}, false
	}

	return cs.createdAt, true
}

// ExportComputeTriggerHash exposes computeTriggerHash for external tests.
func ExportComputeTriggerHash(trigger, digest string, feedPURLs []string) string {
	return computeTriggerHash(trigger, digest, feedPURLs)
}

// ExportBuildRollbackUpdate exposes buildRollbackUpdate for external tests.
func ExportBuildRollbackUpdate(
	containerID string, original *api.LinuxResources,
) *api.ContainerUpdate {
	return buildRollbackUpdate(containerID, original)
}

// ExportStoreContainerWithResources stores a container with original resources,
// digest, and image ref for testing throttle and rollback paths.
func (p *Plugin) ExportStoreContainerWithResources(
	containerID, imageRef, digest string, resources *api.LinuxResources,
) {
	state := &containerState{ //nolint:exhaustruct_v5 // test helper, zero-value fields intentional
		imageRef:          imageRef,
		digest:            digest,
		createdAt:         time.Now(),
		state:             StateVerified,
		originalResources: resources,
	}
	p.containers.Store(containerID, state)
}

// ExportStoreRecoveredContainer stores a container that was recovered on
// restart, with original resources and a degraded state, for testing that
// rollback is skipped for restart-recovered containers.
func (p *Plugin) ExportStoreRecoveredContainer(
	containerID, imageRef, digest string, resources *api.LinuxResources,
) {
	state := &containerState{ //nolint:exhaustruct_v5 // test helper, zero-value fields intentional
		imageRef:           imageRef,
		digest:             digest,
		createdAt:          time.Now(),
		state:              StateThrottled,
		originalResources:  resources,
		recoveredOnRestart: true,
	}
	p.containers.Store(containerID, state)
}

// ExportStoreContainerWithPURLs stores a container with specific PURLs for
// testing feed PURL matching.
func (p *Plugin) ExportStoreContainerWithPURLs(containerID string, purls []string) {
	state := &containerState{ //nolint:exhaustruct_v5 // test helper, zero-value fields intentional
		digest:    exportTestDigest,
		createdAt: time.Now(),
		state:     StateVerified,
		purls:     purls,
	}
	p.containers.Store(containerID, state)
}

// ExportMatchFeedPURLs exposes matchFeedPURLs for external tests.
func (p *Plugin) ExportMatchFeedPURLs(feedPURLs []string) map[string]struct{} {
	return p.matchFeedPURLs(feedPURLs)
}

// ExportContainerState holds exported container state fields for test assertions.
type ExportContainerState struct {
	RecoveredOnRestart bool
	ServiceAccount     string
	Digest             string
	IndexDigest        string
	PURLs              []string
	State              VerificationState
	HasOriginals       bool
}

// ExportGetContainerState returns exported container state fields for testing.
// Reads fields under the registry lock to avoid races with UpdateState.
func (p *Plugin) ExportGetContainerState(containerID string) (ExportContainerState, bool) {
	var result ExportContainerState

	found := p.containers.ReadState(containerID, func(cs containerState) {
		result = ExportContainerState{
			RecoveredOnRestart: cs.recoveredOnRestart,
			ServiceAccount:     cs.serviceAccount,
			Digest:             cs.digest,
			IndexDigest:        cs.indexDigest,
			PURLs:              cs.purls,
			State:              cs.state,
			HasOriginals:       cs.originalResources != nil,
		}
	})

	if !found {
		return ExportContainerState{}, false //nolint:exhaustruct_v5 // zero-value fields intentional
	}

	return result, true
}

// ExportFeedTrigger returns the feed trigger channel for test assertions.
func (p *Plugin) ExportFeedTrigger() <-chan []string {
	return p.remediation.feedTrigger
}

// ExportDeepCopyLinuxResources exposes deepCopyLinuxResources for testing.
func ExportDeepCopyLinuxResources(src *api.LinuxResources) *api.LinuxResources {
	return deepCopyLinuxResources(src)
}

// ExportThrottlePercents exposes throttlePercents for testing.
func (p *Plugin) ExportThrottlePercents() (cpuPercent, memPercent int) {
	return p.throttlePercents()
}

// ExportExtractPURLsFromResult exposes extractPURLsFromResult for testing.
func ExportExtractPURLsFromResult(result *types.Result) []string {
	return extractPURLsFromResult(result)
}

// ExportCaptureLinuxResources exposes captureLinuxResources for testing.
func ExportCaptureLinuxResources(ctr *api.Container) *api.LinuxResources {
	return captureLinuxResources(ctr)
}

// ExportStoreContainerInState stores a container in a specific state with a
// recent lastRemediation time, for testing cooldown enforcement.
func (p *Plugin) ExportStoreContainerInState(
	containerID, imageRef, digest string,
	state VerificationState,
	resources *api.LinuxResources,
	lastRemediation time.Time,
) {
	cs := &containerState{ //nolint:exhaustruct_v5 // test helper
		imageRef:          imageRef,
		digest:            digest,
		createdAt:         time.Now(),
		state:             state,
		originalResources: resources,
		lastRemediation:   lastRemediation,
	}
	p.containers.Store(containerID, cs)
}

// ExportStoreContainerInStateSimple stores a container in a specific
// verification state for testing state transitions.
func (p *Plugin) ExportStoreContainerInStateSimple(
	containerID, imageRef, digest string,
	state VerificationState,
) {
	cs := &containerState{ //nolint:exhaustruct_v5 // test helper
		imageRef:  imageRef,
		digest:    digest,
		createdAt: time.Now(),
		state:     state,
	}
	p.containers.Store(containerID, cs)
}

// ExportGetConsecutiveErrors returns the consecutive error count for testing.
func (p *Plugin) ExportGetConsecutiveErrors(containerID string) (int, bool) {
	var count int

	found := p.containers.ReadState(containerID, func(cs containerState) {
		count = cs.consecutiveErrors
	})

	return count, found
}

// ExportRunVerificationCycle runs a single continuous verification cycle.
func (p *Plugin) ExportRunVerificationCycle(ctx context.Context, trigger string) {
	p.runVerificationCycle(ctx, trigger, nil, nil)
}

// ExportTriggerTimer and ExportTriggerManual expose the cycle trigger names.
const (
	ExportTriggerTimer  = triggerTimer
	ExportTriggerManual = triggerManual
)

// ExportStoreContainerState stores a container with the given digest, state,
// original resources, and recovery flag for remediation tests.
func (p *Plugin) ExportStoreContainerState(
	containerID, digest string, state VerificationState,
	resources *api.LinuxResources, recoveredOnRestart bool,
) {
	p.containers.Store(containerID, &containerState{ //nolint:exhaustruct_v5 // test helper
		imageRef:           "img:latest",
		digest:             digest,
		createdAt:          time.Now(),
		state:              state,
		originalResources:  resources,
		recoveredOnRestart: recoveredOnRestart,
	})
}

// ExportBuildThrottleUpdate exposes buildThrottleUpdate for testing.
func (p *Plugin) ExportBuildThrottleUpdate(
	containerID string, original *api.LinuxResources,
) *api.ContainerUpdate {
	return p.buildThrottleUpdate(containerID, original)
}

// ExportDecodeOriginalResources exposes decodeOriginalResources for testing.
func ExportDecodeOriginalResources(value string) (*api.LinuxResources, error) {
	return decodeOriginalResources(value)
}

// ExportStoreContainerWithPURLsFor sets the SBOM purls of an already tracked
// container.
func (p *Plugin) ExportStoreContainerWithPURLsFor(containerID string, purls []string) {
	p.containers.UpdateState(containerID, func(cs *containerState) {
		cs.purls = purls
	})
}

// ExportAdmissionContext exposes admissionContext for external tests.
func (p *Plugin) ExportAdmissionContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return p.admissionContext(ctx)
}

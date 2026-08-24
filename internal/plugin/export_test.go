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
		imageRef:    imageRef,
		digest:      digest,
		indexDigest: indexDigest,
		namespace:   namespace,
		container:   container,
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
		verifier:        nil,
		metrics:         nil,
		configPath:      "",
		containers:      newContainerRegistry(),
		prewarmDoneCh:   make(chan struct{}),
		reverifyTrigger: make(chan struct{}, 1),
		feedTrigger:     make(chan []string, 1),
	}

	return plug.registryAwareResolver(ctx, imageRef)
}

// ExportSetPrewarmDone sets a callback that fires when prewarmCache completes.
func (p *Plugin) ExportSetPrewarmDone(fn func()) {
	p.prewarmDone = fn
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
		createdAt: t,
		state:     StateVerified,
	}
	p.containers.Store(containerID, state)
}

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
	PURLs              []string
	State              VerificationState
}

// ExportGetContainerState returns exported container state fields for testing.
// Reads fields under the registry lock to avoid races with UpdateState.
func (p *Plugin) ExportGetContainerState(containerID string) (ExportContainerState, bool) {
	var result ExportContainerState

	found := p.containers.ReadState(containerID, func(cs containerState) {
		result = ExportContainerState{
			RecoveredOnRestart: cs.recoveredOnRestart,
			ServiceAccount:     cs.serviceAccount,
			PURLs:              cs.purls,
			State:              cs.state,
		}
	})

	if !found {
		return ExportContainerState{}, false //nolint:exhaustruct_v5 // zero-value fields intentional
	}

	return result, true
}

// ExportFeedTrigger returns the feed trigger channel for test assertions.
func (p *Plugin) ExportFeedTrigger() <-chan []string {
	return p.feedTrigger
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

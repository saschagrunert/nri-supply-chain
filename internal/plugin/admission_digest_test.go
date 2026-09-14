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

package plugin_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/api"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/plugin"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	scTypes "github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	testRuntimeIndexDigest = "sha256:c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
	testPlatformDigest     = "sha256:d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5"
)

func newDigestTestVerifier(shouldVerify bool) *admissionVerifier {
	return &admissionVerifier{
		mode:             config.ModeEnforce,
		delay:            0,
		admissionTimeout: time.Second,
		shouldVerify:     shouldVerify,
		result:           passingResult(config.ModeEnforce),
		mu:               sync.Mutex{},
		requests:         nil,
	}
}

// resolverRecorder is a DigestResolveFunc that records requested references.
type resolverRecorder struct {
	mu          sync.Mutex
	refs        []string
	digest      string
	indexDigest string
	err         error
}

func (r *resolverRecorder) resolve(
	_ context.Context, imageRef string,
) (digest, indexDigest string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.refs = append(r.refs, imageRef)

	return r.digest, r.indexDigest, r.err
}

func (r *resolverRecorder) calls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]string(nil), r.refs...)
}

func TestBuildVerificationAdjustmentFetchFailureIncomplete(t *testing.T) {
	t.Parallel()

	result := &scTypes.Result{
		Allowed: true, Verified: false, Mode: string(config.ModeWarn), Reason: "fetch failed",
		CheckResults: []scTypes.CheckResult{
			*scTypes.WarnResult(scTypes.CheckTypeFetch, "attestation fetch failed"),
		},
	}

	annotations := plugin.ExportBuildVerificationAdjustment(result, config.ModeWarn).
		GetAnnotations()

	if got := annotations[plugin.AnnotationVerified]; got != testValFalse {
		t.Errorf("verified = %q, want %q", got, testValFalse)
	}

	if got := annotations[plugin.AnnotationIncomplete]; got != testValTrue {
		t.Errorf("incomplete = %q, want %q", got, testValTrue)
	}
}

func TestCreateContainerPrefersAnnotationDigestOverRuntimeDigest(t *testing.T) {
	t.Parallel()

	verif := newDigestTestVerifier(true)
	plug := plugin.New(verif, metrics.New(), "", time.Second, time.Second, nil)

	resolver := &resolverRecorder{
		mu: sync.Mutex{}, refs: nil, digest: testPlatformDigest, indexDigest: "", err: nil,
	}
	plug.ExportSetDigestResolver(resolver.resolve)

	ctr := admissionContainer(testDigest)
	ctr.Image = &api.Image{Name: testImage, Digest: testRuntimeIndexDigest, ConfigDigest: ""}

	_, _, err := plug.CreateContainer(t.Context(), admissionPod(), ctr)
	testutil.AssertNoError(t, err)

	if req := verif.lastRequest(t); req.Digest != testDigest || req.IndexDigest != "" {
		t.Errorf("expected the annotation digest, got %+v", req)
	}

	if calls := resolver.calls(); len(calls) != 0 {
		t.Errorf("expected no registry resolution, got %v", calls)
	}
}

func TestCreateContainerResolvesRuntimeDigest(t *testing.T) {
	t.Parallel()

	verif := newDigestTestVerifier(true)
	plug := plugin.New(verif, metrics.New(), "", time.Second, time.Second, nil)

	resolver := &resolverRecorder{
		mu: sync.Mutex{}, refs: nil,
		digest: testPlatformDigest, indexDigest: testRuntimeIndexDigest, err: nil,
	}
	plug.ExportSetDigestResolver(resolver.resolve)

	ctr := admissionContainer("")
	ctr.Image = &api.Image{Name: testImage, Digest: testRuntimeIndexDigest, ConfigDigest: ""}

	_, _, err := plug.CreateContainer(t.Context(), admissionPod(), ctr)
	testutil.AssertNoError(t, err)

	req := verif.lastRequest(t)
	if req.Digest != testPlatformDigest || req.IndexDigest != testRuntimeIndexDigest {
		t.Errorf("expected platform and index digests, got %+v", req)
	}

	calls := resolver.calls()
	if len(calls) != 1 || !strings.HasSuffix(calls[0], "/nginx@"+testRuntimeIndexDigest) {
		t.Errorf("expected resolution of the digest-pinned runtime image, got %v", calls)
	}
}

func TestCreateContainerFallsBackToRuntimeDigest(t *testing.T) {
	t.Parallel()

	verif := newDigestTestVerifier(true)
	plug := plugin.New(verif, metrics.New(), "", time.Second, time.Second, nil)

	resolver := &resolverRecorder{
		mu: sync.Mutex{}, refs: nil, digest: "", indexDigest: "", err: errRegistryUnavailable,
	}
	plug.ExportSetDigestResolver(resolver.resolve)

	ctr := admissionContainer("")
	ctr.Image = &api.Image{Name: testImage, Digest: testRuntimeIndexDigest, ConfigDigest: ""}

	_, _, err := plug.CreateContainer(t.Context(), admissionPod(), ctr)
	testutil.AssertNoError(t, err)

	if req := verif.lastRequest(t); req.Digest != testRuntimeIndexDigest || req.IndexDigest != "" {
		t.Errorf("expected the runtime digest as fallback, got %+v", req)
	}
}

// digestRequiringVerifier requires a digest for every image, like a verifier
// whose snapshot changed between ShouldVerify and Verify.
type digestRequiringVerifier struct {
	*admissionVerifier
}

func (v *digestRequiringVerifier) Verify(
	ctx context.Context, req *scTypes.VerifyRequest,
) (*scTypes.Result, error) {
	if req.Digest == "" {
		v.mu.Lock()
		v.requests = append(v.requests, *req)
		v.mu.Unlock()

		return nil, scTypes.ErrDigestRequired
	}

	return v.admissionVerifier.Verify(ctx, req)
}

func TestCreateContainerResolvesDigestWhenVerifierRequiresIt(t *testing.T) {
	t.Parallel()

	verif := &digestRequiringVerifier{admissionVerifier: newDigestTestVerifier(false)}
	plug := plugin.New(verif, metrics.New(), "", time.Second, time.Second, nil)

	resolver := &resolverRecorder{
		mu: sync.Mutex{}, refs: nil, digest: testPlatformDigest, indexDigest: "", err: nil,
	}
	plug.ExportSetDigestResolver(resolver.resolve)

	_, _, err := plug.CreateContainer(t.Context(), admissionPod(), admissionContainer(""))
	testutil.AssertNoError(t, err)

	if req := verif.lastRequest(t); req.Digest != testPlatformDigest {
		t.Errorf("expected a retry with the resolved digest, got %+v", req)
	}

	if calls := resolver.calls(); len(calls) != 1 {
		t.Errorf("expected one digest resolution, got %v", calls)
	}
}

func TestAdmissionContextProportionalSafetyMargin(t *testing.T) {
	t.Parallel()

	verif := newDigestTestVerifier(true)
	verif.admissionTimeout = 10 * time.Second

	plug := plugin.New(verif, metrics.New(), "", time.Second, time.Second, nil)

	runtimeCtx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()

	runtimeDeadline, _ := runtimeCtx.Deadline()

	admissionCtx, cancelAdmission := plug.ExportAdmissionContext(runtimeCtx)
	defer cancelAdmission()

	deadline, ok := admissionCtx.Deadline()
	if !ok {
		t.Fatal("expected an admission deadline")
	}

	// 10% of the remaining three seconds is larger than the fixed 100ms
	// minimum margin.
	margin := runtimeDeadline.Sub(deadline)
	if margin < 250*time.Millisecond || margin > 350*time.Millisecond {
		t.Errorf("expected a safety margin of about 300ms, got %s", margin)
	}
}

func TestSynchronizePrewarmUsesRuntimeImage(t *testing.T) {
	t.Parallel()

	verif := newDigestTestVerifier(true)
	plug := plugin.New(verif, metrics.New(), "", time.Second, time.Second, nil)

	done := make(chan struct{})

	plug.ExportSetPrewarmDone(func() { close(done) })

	resolver := &resolverRecorder{
		mu: sync.Mutex{}, refs: nil,
		digest: testPlatformDigest, indexDigest: testRuntimeIndexDigest, err: nil,
	}
	plug.ExportSetDigestResolver(resolver.resolve)

	pods := []*api.PodSandbox{{Id: testPodID, Namespace: testNamespace, Name: testPodName}}
	containers := []*api.Container{{
		Id:           testContainerID,
		PodSandboxId: testPodID,
		Name:         testCtrName,
		Annotations:  map[string]string{plugin.AnnotationImageName: testImage},
		Image:        &api.Image{Name: testImage, Digest: testRuntimeIndexDigest, ConfigDigest: ""},
	}}

	_, err := plug.Synchronize(t.Context(), pods, containers)
	testutil.AssertNoError(t, err)
	waitForPrewarm(t, done)

	req := verif.lastRequest(t)
	if req.Digest != testPlatformDigest || req.IndexDigest != testRuntimeIndexDigest {
		t.Errorf("expected prewarm to resolve the runtime digest like admission, got %+v", req)
	}

	calls := resolver.calls()
	if len(calls) != 1 || !strings.HasSuffix(calls[0], "/nginx@"+testRuntimeIndexDigest) {
		t.Errorf("expected prewarm to resolve the digest-pinned runtime image, got %v", calls)
	}

	state, found := plug.ExportGetContainerState(testContainerID)
	if !found || state.Digest != testPlatformDigest {
		t.Errorf("expected the recovered container to record the platform digest, got %+v", state)
	}
}

func TestSynchronizePrewarmWarmsEveryAnnotationDigest(t *testing.T) {
	t.Parallel()

	verif := newDigestTestVerifier(true)
	plug := plugin.New(verif, metrics.New(), "", time.Second, time.Second, nil)

	done := make(chan struct{})

	plug.ExportSetPrewarmDone(func() { close(done) })

	pods := []*api.PodSandbox{{Id: testPodID, Namespace: testNamespace, Name: testPodName}}
	containers := []*api.Container{
		{
			Id: "ctr-old", PodSandboxId: testPodID, Name: "old",
			Annotations: map[string]string{
				plugin.AnnotationImageName: testImage,
				plugin.AnnotationImageRef:  testDigest,
			},
		},
		{
			Id: "ctr-new", PodSandboxId: testPodID, Name: "new",
			Annotations: map[string]string{
				plugin.AnnotationImageName: testImage,
				plugin.AnnotationImageRef:  testPlatformDigest,
			},
		},
	}

	_, err := plug.Synchronize(t.Context(), pods, containers)
	testutil.AssertNoError(t, err)
	waitForPrewarm(t, done)

	verif.mu.Lock()
	defer verif.mu.Unlock()

	warmed := make(map[string]bool)
	for _, req := range verif.requests {
		warmed[req.Digest] = true
	}

	if !warmed[testDigest] || !warmed[testPlatformDigest] {
		t.Errorf("expected both running digests of the tag to be pre-warmed, got %v", warmed)
	}
}

func TestContinuousVerifierResolvesDigestOfContainerAdmittedWithoutVerification(t *testing.T) {
	t.Parallel()

	verif := newDigestTestVerifier(false)
	plug := plugin.New(verif, metrics.New(), "", time.Second, time.Second, nil)

	resolver := &resolverRecorder{
		mu: sync.Mutex{}, refs: nil,
		digest: testPlatformDigest, indexDigest: testRuntimeIndexDigest, err: nil,
	}
	plug.ExportSetDigestResolver(resolver.resolve)

	ctr := admissionContainer("")
	ctr.Image = &api.Image{Name: testImage, Digest: testRuntimeIndexDigest, ConfigDigest: ""}

	_, _, err := plug.CreateContainer(t.Context(), admissionPod(), ctr)
	testutil.AssertNoError(t, err)

	if calls := resolver.calls(); len(calls) != 0 {
		t.Errorf("expected no registry resolution at admission, got %v", calls)
	}

	// Verification is enabled for the image after the container started.
	verif.shouldVerify = true

	plug.ExportRunVerificationCycle(t.Context(), plugin.ExportTriggerTimer)

	req := verif.lastRequest(t)
	if req.Digest != testPlatformDigest || req.IndexDigest != testRuntimeIndexDigest {
		t.Errorf("expected re-verification of the resolved runtime digest, got %+v", req)
	}

	state, found := plug.ExportGetContainerState(ctr.GetId())
	if !found || state.Digest != testPlatformDigest || state.IndexDigest != testRuntimeIndexDigest {
		t.Errorf("expected the container to record the resolved digests, got %+v", state)
	}
}

func TestContinuousVerifierResolvesRuntimeDigestUnresolvedAtAdmission(t *testing.T) {
	t.Parallel()

	verif := newDigestTestVerifier(true)
	plug := plugin.New(verif, metrics.New(), "", time.Second, time.Second, nil)

	resolver := &resolverRecorder{
		mu: sync.Mutex{}, refs: nil, digest: "", indexDigest: "", err: errRegistryUnavailable,
	}
	plug.ExportSetDigestResolver(resolver.resolve)

	ctr := admissionContainer("")
	ctr.Image = &api.Image{Name: testImage, Digest: testRuntimeIndexDigest, ConfigDigest: ""}

	_, _, err := plug.CreateContainer(t.Context(), admissionPod(), ctr)
	testutil.AssertNoError(t, err)

	// The registry recovers.
	resolver.mu.Lock()
	resolver.digest, resolver.indexDigest, resolver.err = testPlatformDigest, testRuntimeIndexDigest, nil
	resolver.mu.Unlock()

	plug.ExportRunVerificationCycle(t.Context(), plugin.ExportTriggerTimer)

	req := verif.lastRequest(t)
	if req.Digest != testPlatformDigest || req.IndexDigest != testRuntimeIndexDigest {
		t.Errorf("expected re-verification of the resolved runtime digest, got %+v", req)
	}
}

func TestContinuousVerifierResolvesRuntimeDigestUnresolvedAtRecovery(t *testing.T) {
	t.Parallel()

	verif := newDigestTestVerifier(true)
	plug := plugin.New(verif, metrics.New(), "", time.Second, time.Second, nil)

	done := make(chan struct{})

	plug.ExportSetPrewarmDone(func() { close(done) })

	resolver := &resolverRecorder{
		mu: sync.Mutex{}, refs: nil, digest: "", indexDigest: "", err: errRegistryUnavailable,
	}
	plug.ExportSetDigestResolver(resolver.resolve)

	pods := []*api.PodSandbox{{Id: testPodID, Namespace: testNamespace, Name: testPodName}}
	containers := []*api.Container{{
		Id:           testContainerID,
		PodSandboxId: testPodID,
		Name:         testCtrName,
		Annotations:  map[string]string{plugin.AnnotationImageName: testImage},
		Image:        &api.Image{Name: testImage, Digest: testRuntimeIndexDigest, ConfigDigest: ""},
	}}

	_, err := plug.Synchronize(t.Context(), pods, containers)
	testutil.AssertNoError(t, err)
	waitForPrewarm(t, done)

	state, found := plug.ExportGetContainerState(testContainerID)
	if !found || state.Digest != "" {
		t.Errorf("expected the unresolved runtime digest not to be recorded, got %+v", state)
	}

	verif.mu.Lock()
	prewarmRequests := len(verif.requests)
	verif.mu.Unlock()

	// While the registry is unreachable the container is not re-verified.
	plug.ExportRunVerificationCycle(t.Context(), plugin.ExportTriggerTimer)

	verif.mu.Lock()
	outageRequests := len(verif.requests)
	verif.mu.Unlock()

	if outageRequests != prewarmRequests {
		t.Errorf("expected no re-verification during the outage, got %d requests", outageRequests)
	}

	// The registry recovers.
	resolver.mu.Lock()
	resolver.digest, resolver.indexDigest, resolver.err = testPlatformDigest, testRuntimeIndexDigest, nil
	resolver.mu.Unlock()

	plug.ExportRunVerificationCycle(t.Context(), plugin.ExportTriggerTimer)

	req := verif.lastRequest(t)
	if req.Digest != testPlatformDigest || req.IndexDigest != testRuntimeIndexDigest {
		t.Errorf("expected re-verification of the resolved runtime digest, got %+v", req)
	}

	state, found = plug.ExportGetContainerState(testContainerID)
	if !found || state.Digest != testPlatformDigest || state.IndexDigest != testRuntimeIndexDigest {
		t.Errorf("expected the container to record the resolved digests, got %+v", state)
	}
}

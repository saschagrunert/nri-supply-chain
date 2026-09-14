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
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/api"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/plugin"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	scTypes "github.com/saschagrunert/nri-supply-chain/internal/types"
)

var errSlowVerification = errors.New("verification interrupted")

// admissionVerifier is a configurable ImageVerifier for admission tests.
type admissionVerifier struct {
	mode             config.VerificationMode
	delay            time.Duration
	admissionTimeout time.Duration
	shouldVerify     bool
	result           *scTypes.Result

	mu       sync.Mutex
	requests []scTypes.VerifyRequest
}

func (v *admissionVerifier) Verify(
	ctx context.Context, req *scTypes.VerifyRequest,
) (*scTypes.Result, error) {
	v.mu.Lock()
	v.requests = append(v.requests, *req)
	v.mu.Unlock()

	select {
	case <-time.After(v.delay):
	case <-ctx.Done():
		if v.mode == config.ModeEnforce {
			return nil, fmt.Errorf("%w: %w", errSlowVerification, ctx.Err())
		}

		return &scTypes.Result{
			Allowed: true, Verified: false, Mode: string(v.mode), Reason: "interrupted",
			CheckResults: []scTypes.CheckResult{
				*scTypes.WarnResult(scTypes.CheckTypeInternal, "verification error"),
			},
		}, nil
	}

	return v.result, nil
}

func (v *admissionVerifier) ShouldVerify(
	_ context.Context, _, _ string,
) (verify bool, reason string) {
	return v.shouldVerify, "image is excluded"
}

func (v *admissionVerifier) AdmissionTimeout() time.Duration { return v.admissionTimeout }

func (v *admissionVerifier) Ready() (ready bool, reason string) { return true, "" }

func (v *admissionVerifier) Enforcing() bool { return v.mode == config.ModeEnforce }

func (v *admissionVerifier) EffectiveModeForNamespace(_ string) config.VerificationMode {
	return v.mode
}

func (v *admissionVerifier) Reload(_ context.Context, _ *config.Config) error { return nil }

func (v *admissionVerifier) InvalidateCache(_, _ string) {}

func (v *admissionVerifier) Status() scTypes.StatusResponse {
	return scTypes.StatusResponse{
		Ready:           true,
		Mode:            string(v.mode),
		Policies:        scTypes.PolicyStatus{Count: 0, Namespaces: []string{}, Source: ""},
		Cache:           scTypes.CacheStatus{Size: 0, MaxSize: 0},
		CircuitBreakers: map[string]string{},
		NRI:             scTypes.NRIStatus{Connected: false},
	}
}

func (v *admissionVerifier) lastRequest(t *testing.T) scTypes.VerifyRequest {
	t.Helper()

	v.mu.Lock()
	defer v.mu.Unlock()

	if len(v.requests) == 0 {
		t.Fatal("expected a verification request")
	}

	return v.requests[len(v.requests)-1]
}

func passingResult(mode config.VerificationMode) *scTypes.Result {
	return &scTypes.Result{
		Allowed: true, Verified: true, Mode: string(mode), Reason: "",
		CheckResults: []scTypes.CheckResult{*scTypes.PassResult(scTypes.CheckTypeSLSA, "ok")},
	}
}

func admissionPod() *api.PodSandbox {
	return &api.PodSandbox{Namespace: testNamespace, Name: testPodName}
}

func admissionContainer(digest string) *api.Container {
	annotations := map[string]string{plugin.AnnotationImageName: testImage}
	if digest != "" {
		annotations[plugin.AnnotationImageRef] = digest
	}

	return &api.Container{Id: "ctr-admission", Name: testCtrName, Annotations: annotations}
}

func TestCreateContainerAdmissionTimeoutDeniesInEnforce(t *testing.T) {
	t.Parallel()

	verif := &admissionVerifier{
		mode:             config.ModeEnforce,
		delay:            time.Minute,
		admissionTimeout: 50 * time.Millisecond,
		shouldVerify:     true,
		result:           passingResult(config.ModeEnforce),
		mu:               sync.Mutex{},
		requests:         nil,
	}

	plug := plugin.New(verif, metrics.New(), "", time.Second, time.Second, nil)

	start := time.Now()
	_, _, err := plug.CreateContainer(t.Context(), admissionPod(), admissionContainer(testDigest))
	elapsed := time.Since(start)

	if !errors.Is(err, plugin.ErrAdmissionTimeout) {
		t.Fatalf("expected ErrAdmissionTimeout, got %v", err)
	}

	if elapsed > 5*time.Second {
		t.Errorf("admission took %s, expected it to be bounded by the admission timeout", elapsed)
	}
}

func TestCreateContainerAdmissionTimeoutMarksIncompleteInWarn(t *testing.T) {
	t.Parallel()

	verif := &admissionVerifier{
		mode:             config.ModeWarn,
		delay:            time.Minute,
		admissionTimeout: 50 * time.Millisecond,
		shouldVerify:     true,
		result:           passingResult(config.ModeWarn),
		mu:               sync.Mutex{},
		requests:         nil,
	}

	plug := plugin.New(verif, metrics.New(), "", time.Second, time.Second, nil)

	adj, _, err := plug.CreateContainer(t.Context(), admissionPod(), admissionContainer(testDigest))
	testutil.AssertNoError(t, err)

	annotations := adj.GetAnnotations()

	if got := annotations[plugin.AnnotationVerified]; got != testValFalse {
		t.Errorf("verified = %q, want %q", got, testValFalse)
	}

	if got := annotations[plugin.AnnotationIncomplete]; got != testValTrue {
		t.Errorf("incomplete = %q, want %q", got, testValTrue)
	}
}

func TestCreateContainerAdmissionAnswersBeforeRuntimeDeadline(t *testing.T) {
	t.Parallel()

	verif := &admissionVerifier{
		mode:             config.ModeEnforce,
		delay:            time.Minute,
		admissionTimeout: time.Minute,
		shouldVerify:     true,
		result:           passingResult(config.ModeEnforce),
		mu:               sync.Mutex{},
		requests:         nil,
	}

	plug := plugin.New(verif, metrics.New(), "", time.Second, time.Second, nil)

	// The runtime deadline is shorter than the admission timeout, so the
	// plugin must answer ahead of it instead of timing out with the runtime.
	ctx, cancel := context.WithTimeout(t.Context(), 400*time.Millisecond)
	defer cancel()

	_, _, err := plug.CreateContainer(ctx, admissionPod(), admissionContainer(testDigest))
	if !errors.Is(err, plugin.ErrAdmissionTimeout) {
		t.Fatalf("expected ErrAdmissionTimeout, got %v", err)
	}

	if ctx.Err() != nil {
		t.Error("expected the plugin to answer before the runtime deadline")
	}
}

func TestCreateContainerSkipsDigestResolutionForSkippedImages(t *testing.T) {
	t.Parallel()

	verif := &admissionVerifier{
		mode:             config.ModeEnforce,
		delay:            0,
		admissionTimeout: time.Second,
		shouldVerify:     false,
		result:           passingResult(config.ModeEnforce),
		mu:               sync.Mutex{},
		requests:         nil,
	}

	plug := plugin.New(verif, metrics.New(), "", time.Second, time.Second, nil)

	var resolved atomic.Bool

	plug.ExportSetDigestResolver(func(_ context.Context, _ string) (string, string, error) {
		resolved.Store(true)

		return "", "", errRegistryUnavailable
	})

	_, _, err := plug.CreateContainer(t.Context(), admissionPod(), admissionContainer(""))
	testutil.AssertNoError(t, err)

	if resolved.Load() {
		t.Error("expected no digest resolution for an image that needs no verification")
	}

	if req := verif.lastRequest(t); req.Digest != "" || req.ImageRef != testImage {
		t.Errorf("unexpected verification request %+v", req)
	}
}

func TestCreateContainerUsesRuntimeImageWithoutAnnotations(t *testing.T) {
	t.Parallel()

	verif := &admissionVerifier{
		mode:             config.ModeEnforce,
		delay:            0,
		admissionTimeout: time.Second,
		shouldVerify:     true,
		result:           passingResult(config.ModeEnforce),
		mu:               sync.Mutex{},
		requests:         nil,
	}

	plug := plugin.New(verif, metrics.New(), "", time.Second, time.Second, nil)

	ctr := &api.Container{
		Id:    "ctr-runtime-image",
		Name:  testCtrName,
		Image: &api.Image{Name: "ghcr.io/org/app@" + testDigest, Digest: "", ConfigDigest: ""},
	}

	_, _, err := plug.CreateContainer(t.Context(), admissionPod(), ctr)
	testutil.AssertNoError(t, err)

	req := verif.lastRequest(t)
	if req.ImageRef != "ghcr.io/org/app@"+testDigest || req.Digest != testDigest {
		t.Errorf("unexpected verification request %+v", req)
	}
}

func TestBuildVerificationAdjustmentWarnFailureNotVerified(t *testing.T) {
	t.Parallel()

	result := &scTypes.Result{
		Allowed: true, Verified: false, Mode: string(config.ModeWarn), Reason: "denied",
		CheckResults: []scTypes.CheckResult{
			*scTypes.FailResult(scTypes.CheckTypeSLSA, "missing", nil),
		},
	}

	adj := plugin.ExportBuildVerificationAdjustment(result, config.ModeWarn)
	annotations := adj.GetAnnotations()

	if got := annotations[plugin.AnnotationVerified]; got != testValFalse {
		t.Errorf("verified = %q, want %q", got, testValFalse)
	}

	if _, ok := annotations[plugin.AnnotationIncomplete]; ok {
		t.Error("expected no incomplete annotation for a completed verification")
	}
}

func TestCreateContainerRecordsOriginalResources(t *testing.T) {
	t.Parallel()

	verif := &admissionVerifier{
		mode:             config.ModeEnforce,
		delay:            0,
		admissionTimeout: time.Second,
		shouldVerify:     true,
		result:           passingResult(config.ModeEnforce),
		mu:               sync.Mutex{},
		requests:         nil,
	}

	plug := plugin.New(verif, metrics.New(), "", time.Second, time.Second, nil)

	ctr := admissionContainer(testDigest)
	ctr.Linux = &api.LinuxContainer{
		Resources: &api.LinuxResources{
			Cpu:    &api.LinuxCPU{Quota: &api.OptionalInt64{Value: 50000}},
			Memory: &api.LinuxMemory{Limit: &api.OptionalInt64{Value: 1 << 20}},
		},
	}

	adj, _, err := plug.CreateContainer(t.Context(), admissionPod(), ctr)
	testutil.AssertNoError(t, err)

	want, ok := plugin.OriginalResourcesAnnotation(ctr.GetLinux().GetResources())
	if !ok {
		t.Fatal("expected throttleable limits to encode")
	}

	if got := adj.GetAnnotations()[plugin.AnnotationOriginalResources]; got != want {
		t.Errorf("original resources annotation = %q, want %q", got, want)
	}
}

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
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/api"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/plugin"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	scTypes "github.com/saschagrunert/nri-supply-chain/internal/types"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

var errRegistryUnavailable = errors.New("registry unavailable")

const (
	testNamespace = "default"
	testPodName   = "test-pod"
	testPodID     = "pod-1"
	testCtrName   = "test-container"
	testImage     = "nginx:latest"
	testDigest    = "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	testArchAmd64 = "amd64"
	testArchArm64 = "arm64"
	testArchS390x = "s390x"
	testOSLinux   = "linux"
	testOSZos     = "zos"

	testValTrue  = "true"
	testValFalse = "false"
	testValWarn  = "warn"
)

func TestCreateContainerDisabled(t *testing.T) {
	t.Parallel()

	plug := newTestPlugin(t, config.ModeDisabled, "")

	pod := &api.PodSandbox{
		Namespace: testNamespace,
		Name:      testPodName,
	}
	ctr := &api.Container{
		Name: testCtrName,
		Labels: map[string]string{
			"app": "test",
		},
		Annotations: map[string]string{
			plugin.AnnotationImage:    testImage,
			plugin.AnnotationImageRef: testDigest,
		},
	}

	adj, updates, err := plug.CreateContainer(context.Background(), pod, ctr)
	testutil.AssertNoError(t, err)

	if adj != nil {
		t.Error("expected nil adjustment")
	}

	if updates != nil {
		t.Error("expected nil updates")
	}
}

func TestCreateContainerMissingAnnotationsEnforce(t *testing.T) {
	t.Parallel()

	plug := newTestPlugin(t, config.ModeEnforce, "")

	pod := &api.PodSandbox{
		Namespace: testNamespace,
		Name:      testPodName,
	}
	ctr := &api.Container{
		Name:        testCtrName,
		Annotations: map[string]string{},
	}

	_, _, err := plug.CreateContainer(context.Background(), pod, ctr)
	if err == nil {
		t.Fatal("expected error for missing annotations in enforce mode")
	}
}

func TestCreateContainerMissingAnnotationsWarn(t *testing.T) {
	t.Parallel()

	plug := newTestPlugin(t, config.ModeWarn, "")

	pod := &api.PodSandbox{
		Namespace: testNamespace,
		Name:      testPodName,
	}
	ctr := &api.Container{
		Name:        testCtrName,
		Annotations: map[string]string{},
	}

	adj, updates, err := plug.CreateContainer(context.Background(), pod, ctr)
	testutil.AssertNoError(t, err)

	if adj == nil {
		t.Fatal("expected non-nil adjustment for warn mode with missing annotations")
	}

	annotations := adj.GetAnnotations()

	if v := annotations[plugin.AnnotationVerified]; v != testValFalse {
		t.Errorf("verified = %q, want %q", v, testValFalse)
	}

	if v := annotations[plugin.AnnotationMode]; v != testValWarn {
		t.Errorf("mode = %q, want %q", v, testValWarn)
	}

	if updates != nil {
		t.Error("expected nil updates")
	}
}

func TestCreateContainerMissingAnnotationsPerNamespaceEnforce(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{}`)
	testutil.WritePolicy(t, dir, "production.json", `{
		"mode": "enforce"
	}`)

	plug := newTestPlugin(t, config.ModeWarn, dir)

	pod := &api.PodSandbox{
		Namespace: "production",
		Name:      testPodName,
	}
	ctr := &api.Container{
		Name:        testCtrName,
		Annotations: map[string]string{},
	}

	_, _, err := plug.CreateContainer(context.Background(), pod, ctr)
	if err == nil {
		t.Fatal("expected error for missing annotations in per-namespace enforce mode")
	}
}

func TestCreateContainerEnforceReject(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{
		"trust": {
			"builders": [{"id": "test", "maxLevel": 3}]
		},
		"slsa": {"missingPolicy": "deny"}
	}`)

	plug := newTestPlugin(t, config.ModeEnforce, dir)

	pod := &api.PodSandbox{
		Namespace: testNamespace,
		Name:      testPodName,
	}
	ctr := &api.Container{
		Name: testCtrName,
		Annotations: map[string]string{
			plugin.AnnotationImage:    testImage,
			plugin.AnnotationImageRef: testDigest,
		},
	}

	_, _, err := plug.CreateContainer(context.Background(), pod, ctr)
	if err == nil {
		t.Fatal("expected error for enforce mode with deny policy")
	}
}

func TestCreateContainerWarnAllow(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{
		"trust": {
			"builders": [{"id": "test", "maxLevel": 3}]
		},
		"slsa": {"missingPolicy": "deny"}
	}`)

	plug := newTestPlugin(t, config.ModeWarn, dir)

	pod := &api.PodSandbox{
		Namespace: testNamespace,
		Name:      testPodName,
	}
	ctr := &api.Container{
		Name: testCtrName,
		Annotations: map[string]string{
			plugin.AnnotationImage:    testImage,
			plugin.AnnotationImageRef: testDigest,
		},
	}

	adj, updates, err := plug.CreateContainer(context.Background(), pod, ctr)
	testutil.AssertNoError(t, err)

	if adj == nil {
		t.Fatal("expected non-nil adjustment for warn mode")
	}

	annotations := adj.GetAnnotations()

	if v := annotations[plugin.AnnotationVerified]; v != testValFalse {
		t.Errorf("verified = %q, want %q", v, testValFalse)
	}

	if v := annotations[plugin.AnnotationMode]; v != testValWarn {
		t.Errorf("mode = %q, want %q", v, testValWarn)
	}

	wantChecks := "slsa:fail,vex:pass,sbom:pass,scai:pass,source:pass," +
		"buildenv:pass,vulnscan:pass,testresult:pass,runtimetrace:pass"
	if v := annotations[plugin.AnnotationChecks]; v != wantChecks {
		t.Errorf("checks = %q, want %q", v, wantChecks)
	}

	if updates != nil {
		t.Error("expected nil updates")
	}
}

func TestConfigureWithEmptyConfig(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	met := metrics.New()

	v, err := verifier.New(t.Context(), cfg, met, nil)
	testutil.AssertNoError(t, err)

	plug := plugin.New(v, met, "", 30*time.Second, 1*time.Second, nil)

	_, err = plug.Configure(context.Background(), "", "cri-o", "1.32")
	testutil.AssertNoError(t, err)
}

func TestConfigureWithNRIConfig(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{}`)

	cfg := config.DefaultConfig()
	met := metrics.New()

	v, err := verifier.New(t.Context(), cfg, met, nil)
	testutil.AssertNoError(t, err)

	plug := plugin.New(v, met, "", 30*time.Second, 1*time.Second, nil)

	tomlConfig := `verification = "warn"` + "\n" +
		`policy_dir = "` + dir + `"` + "\n"

	_, err = plug.Configure(context.Background(), tomlConfig, "cri-o", "1.32")
	testutil.AssertNoError(t, err)
}

func TestConfigureWithInvalidNRIConfig(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	met := metrics.New()

	v, err := verifier.New(t.Context(), cfg, met, nil)
	testutil.AssertNoError(t, err)

	plug := plugin.New(v, met, "", 30*time.Second, 1*time.Second, nil)

	_, err = plug.Configure(context.Background(), `[[[invalid`, "cri-o", "1.32")
	if err == nil {
		t.Fatal("expected error for invalid TOML")
	}
}

func TestConfigureWithInvalidPolicyDir(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	met := metrics.New()

	v, err := verifier.New(t.Context(), cfg, met, nil)
	testutil.AssertNoError(t, err)

	plug := plugin.New(v, met, "", 30*time.Second, 1*time.Second, nil)

	tomlConfig := "verification = \"warn\"\n" +
		"policy_dir = \"/nonexistent/policies\"\n"

	_, err = plug.Configure(context.Background(), tomlConfig, "cri-o", "1.32")
	if err == nil {
		t.Fatal("expected error for nonexistent policy dir")
	}
}

func TestConfigureSkipsWhenConfigPathSet(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	met := metrics.New()

	v, err := verifier.New(t.Context(), cfg, met, nil)
	testutil.AssertNoError(t, err)

	plug := plugin.New(v, met, "/some/config.toml", 30*time.Second, 1*time.Second, nil)

	_, err = plug.Configure(context.Background(), `verification = "enforce"`, "cri-o", "1.32")
	testutil.AssertNoError(t, err)
}

const (
	testCrioImage          = "crio-image"
	testContainerdDigest   = "sha256:c0a1ae4deadbeef0c0a1ae4deadbeef0c0a1ae4deadbeef0c0a1ae4deadbeef0"
	testContainerdImageRef = "containerd-image"
)

func TestResolveImageCRIO(t *testing.T) {
	t.Parallel()

	imageRef, digest := plugin.ExportResolveImage(map[string]string{
		plugin.AnnotationImage:    testImage,
		plugin.AnnotationImageRef: testDigest,
	})

	if imageRef != testImage {
		t.Errorf("imageRef = %q, want %q", imageRef, testImage)
	}

	if digest != testDigest {
		t.Errorf("digest = %q, want %q", digest, testDigest)
	}
}

func TestResolveImageContainerd(t *testing.T) {
	t.Parallel()

	imageRef, digest := plugin.ExportResolveImage(map[string]string{
		plugin.AnnotationContainerdImage:    testImage,
		plugin.AnnotationContainerdImageRef: testContainerdDigest,
	})

	if imageRef != testImage {
		t.Errorf("imageRef = %q, want %q", imageRef, testImage)
	}

	if digest != testContainerdDigest {
		t.Errorf("digest = %q, want %q", digest, testContainerdDigest)
	}
}

func TestResolveImageCRIOPrecedence(t *testing.T) {
	t.Parallel()

	imageRef, digest := plugin.ExportResolveImage(map[string]string{
		plugin.AnnotationImage:              testCrioImage,
		plugin.AnnotationImageRef:           testDigest,
		plugin.AnnotationContainerdImage:    testContainerdImageRef,
		plugin.AnnotationContainerdImageRef: testContainerdDigest,
	})

	if imageRef != testCrioImage {
		t.Errorf("imageRef = %q, want %q", imageRef, testCrioImage)
	}

	if digest != testDigest {
		t.Errorf("digest = %q, want %q", digest, testDigest)
	}
}

func TestResolveImageEmpty(t *testing.T) {
	t.Parallel()

	imageRef, digest := plugin.ExportResolveImage(map[string]string{})

	if imageRef != "" {
		t.Errorf("imageRef = %q, want empty", imageRef)
	}

	if digest != "" {
		t.Errorf("digest = %q, want empty", digest)
	}
}

func TestResolveImagePartialFallback(t *testing.T) {
	t.Parallel()

	imageRef, digest := plugin.ExportResolveImage(map[string]string{
		plugin.AnnotationImage:              testCrioImage,
		plugin.AnnotationContainerdImageRef: testContainerdDigest,
	})

	if imageRef != testCrioImage {
		t.Errorf("imageRef = %q, want %q", imageRef, testCrioImage)
	}

	if digest != testContainerdDigest {
		t.Errorf("digest = %q, want %q", digest, testContainerdDigest)
	}
}

func TestResolveImageContainerdPairOverPartialCRIO(t *testing.T) {
	t.Parallel()

	imageRef, digest := plugin.ExportResolveImage(map[string]string{
		plugin.AnnotationImage:              testCrioImage,
		plugin.AnnotationContainerdImage:    testContainerdImageRef,
		plugin.AnnotationContainerdImageRef: testContainerdDigest,
	})

	if imageRef != testContainerdImageRef {
		t.Errorf("imageRef = %q, want %q", imageRef, testContainerdImageRef)
	}

	if digest != testContainerdDigest {
		t.Errorf("digest = %q, want %q", digest, testContainerdDigest)
	}
}

func TestResolveImageCRIOInvalidDigestRepoDigests(t *testing.T) {
	t.Parallel()

	imageRef, digest := plugin.ExportResolveImage(map[string]string{
		plugin.AnnotationImageName:        testImage,
		plugin.AnnotationImageRepoDigests: "docker.io/library/nginx@not-a-valid-digest",
	})

	if imageRef != testImage {
		t.Errorf("imageRef = %q, want %q", imageRef, testImage)
	}

	if digest != "" {
		t.Errorf("digest = %q, want empty for invalid CRI-O repo digest", digest)
	}
}

func TestResolveImageCRIOInvalidDigestImageRef(t *testing.T) {
	t.Parallel()

	imageRef, digest := plugin.ExportResolveImage(map[string]string{
		plugin.AnnotationImageName: testImage,
		plugin.AnnotationImageRef:  "not-a-valid-digest",
	})

	if imageRef != testImage {
		t.Errorf("imageRef = %q, want %q", imageRef, testImage)
	}

	if digest != "" {
		t.Errorf("digest = %q, want empty for invalid CRI-O ImageRef annotation", digest)
	}
}

func TestResolveImageCRIOValidDigestRepoDigests(t *testing.T) {
	t.Parallel()

	const validDigest = "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abcd"

	imageRef, digest := plugin.ExportResolveImage(map[string]string{
		plugin.AnnotationImageName:        testImage,
		plugin.AnnotationImageRepoDigests: "docker.io/library/nginx@" + validDigest,
	})

	if imageRef != testImage {
		t.Errorf("imageRef = %q, want %q", imageRef, testImage)
	}

	if digest != validDigest {
		t.Errorf("digest = %q, want %q", digest, validDigest)
	}
}

func TestResolveImageContainerdInvalidDigest(t *testing.T) {
	t.Parallel()

	imageRef, digest := plugin.ExportResolveImage(map[string]string{
		plugin.AnnotationContainerdImage:    testImage,
		plugin.AnnotationContainerdImageRef: "not-a-digest",
	})

	if imageRef != testImage {
		t.Errorf("imageRef = %q, want %q", imageRef, testImage)
	}

	if digest != "" {
		t.Errorf("digest = %q, want empty for invalid digest ref", digest)
	}
}

func TestResolveImageContainerdDigestFromImageName(t *testing.T) {
	t.Parallel()

	digestRef := "localhost:5050/test/cb-test@" + testContainerdDigest

	imageRef, digest := plugin.ExportResolveImage(map[string]string{
		plugin.AnnotationContainerdImage: digestRef,
	})

	if imageRef != digestRef {
		t.Errorf("imageRef = %q, want %q", imageRef, digestRef)
	}

	if digest != testContainerdDigest {
		t.Errorf("digest = %q, want %q", digest, testContainerdDigest)
	}
}

func TestSynchronizePrewarm(t *testing.T) {
	t.Parallel()

	plug, done := newTestPluginWithPrewarmSignal(t, config.ModeDisabled, "")

	pods := []*api.PodSandbox{
		{Id: testPodID, Namespace: testNamespace, Name: testPodName},
	}

	containers := []*api.Container{
		{
			Id:           "ctr-1",
			PodSandboxId: testPodID,
			Name:         testCtrName,
			Annotations: map[string]string{
				plugin.AnnotationImage:    testImage,
				plugin.AnnotationImageRef: testDigest,
			},
		},
	}

	updates, err := plug.Synchronize(context.Background(), pods, containers)
	testutil.AssertNoError(t, err)

	if updates != nil {
		t.Error("expected nil updates")
	}

	waitForPrewarm(t, done)
}

func TestSynchronizeNoContainers(t *testing.T) {
	t.Parallel()

	plug := newTestPlugin(t, config.ModeDisabled, "")

	updates, err := plug.Synchronize(
		context.Background(), []*api.PodSandbox{}, []*api.Container{},
	)
	testutil.AssertNoError(t, err)

	if updates != nil {
		t.Error("expected nil updates")
	}
}

func TestSynchronizeDeduplicates(t *testing.T) {
	t.Parallel()

	plug, done := newTestPluginWithPrewarmSignal(t, config.ModeDisabled, "")

	pods := []*api.PodSandbox{
		{Id: testPodID, Namespace: testNamespace, Name: testPodName},
	}

	containers := []*api.Container{
		{
			Id:           "ctr-1",
			PodSandboxId: testPodID,
			Name:         "container-a",
			Annotations: map[string]string{
				plugin.AnnotationImage:    testImage,
				plugin.AnnotationImageRef: testDigest,
			},
		},
		{
			Id:           "ctr-2",
			PodSandboxId: testPodID,
			Name:         "container-b",
			Annotations: map[string]string{
				plugin.AnnotationImage:    testImage,
				plugin.AnnotationImageRef: testDigest,
			},
		},
	}

	updates, err := plug.Synchronize(context.Background(), pods, containers)
	testutil.AssertNoError(t, err)

	if updates != nil {
		t.Error("expected nil updates")
	}

	waitForPrewarm(t, done)
}

func newTestPlugin(t *testing.T, mode config.VerificationMode, policyDir string) *plugin.Plugin {
	t.Helper()

	cfg := config.DefaultConfig()
	cfg.Verification = mode

	if policyDir != "" {
		cfg.PolicyDir = policyDir
	}

	met := metrics.New()

	v, err := verifier.New(t.Context(), cfg, met, nil)
	testutil.AssertNoError(t, err)

	return plugin.New(v, met, "", 30*time.Second, 1*time.Second, nil)
}

func newTestPluginWithPrewarmSignal(
	t *testing.T, mode config.VerificationMode, policyDir string,
) (plug *plugin.Plugin, done <-chan struct{}) {
	t.Helper()

	plug = newTestPlugin(t, mode, policyDir)

	ch := make(chan struct{}, 1)

	plug.ExportSetPrewarmDone(func() { ch <- struct{}{} })

	return plug, ch
}

func waitForPrewarm(t *testing.T, done <-chan struct{}) {
	t.Helper()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for prewarm to complete")
	}
}

func TestSynchronizePrewarmVerifyError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{
		"trust": {
			"builders": [{"id": "test", "maxLevel": 3}]
		},
		"slsa": {"missingPolicy": "deny"}
	}`)

	plug, done := newTestPluginWithPrewarmSignal(t, config.ModeEnforce, dir)

	pods := []*api.PodSandbox{
		{Id: testPodID, Namespace: testNamespace, Name: testPodName},
	}

	containers := []*api.Container{
		{
			Id:           "ctr-err-1",
			PodSandboxId: testPodID,
			Name:         "error-container",
			Annotations: map[string]string{
				plugin.AnnotationImage:    testImage,
				plugin.AnnotationImageRef: testDigest,
			},
		},
	}

	updates, err := plug.Synchronize(context.Background(), pods, containers)
	testutil.AssertNoError(t, err)

	if updates != nil {
		t.Error("expected nil updates")
	}

	waitForPrewarm(t, done)
}

func TestSynchronizePrewarmCancelledContext(t *testing.T) {
	t.Parallel()

	plug, done := newTestPluginWithPrewarmSignal(t, config.ModeDisabled, "")

	pods := []*api.PodSandbox{
		{Id: testPodID, Namespace: testNamespace, Name: testPodName},
	}

	// Create enough containers to exceed semaphore capacity, so some
	// will fail to acquire the semaphore when context is cancelled.
	containers := make([]*api.Container, 10)
	for i := range containers {
		idx := strconv.Itoa(i)
		// Use a unique padded hex digest per container.
		hexPad := "000000000000000000000000000000000000000000000000000000000000000"

		containers[i] = &api.Container{
			Id:           "ctr-cancel-" + idx,
			PodSandboxId: testPodID,
			Name:         "cancel-container-" + idx,
			Annotations: map[string]string{
				plugin.AnnotationImage:    "image-" + idx + ":latest",
				plugin.AnnotationImageRef: "sha256:" + idx + hexPad[:64-len(idx)],
			},
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately so sem.Acquire fails.

	updates, err := plug.Synchronize(ctx, pods, containers)
	testutil.AssertNoError(t, err)

	if updates != nil {
		t.Error("expected nil updates")
	}

	waitForPrewarm(t, done)
}

func TestSynchronizeSkipsMissingAnnotations(t *testing.T) {
	t.Parallel()

	plug, done := newTestPluginWithPrewarmSignal(t, config.ModeDisabled, "")

	pods := []*api.PodSandbox{
		{Id: testPodID, Namespace: testNamespace, Name: testPodName},
	}

	// Containers with empty annotations should be skipped during
	// image collection, exercising the imageRef=="" continue branch.
	containers := []*api.Container{
		{
			Id:           "ctr-no-annot",
			PodSandboxId: testPodID,
			Name:         "no-annotations",
			Annotations:  map[string]string{},
		},
		{
			Id:           "ctr-has-annot",
			PodSandboxId: testPodID,
			Name:         "has-annotations",
			Annotations: map[string]string{
				plugin.AnnotationImage:    testImage,
				plugin.AnnotationImageRef: testDigest,
			},
		},
	}

	updates, err := plug.Synchronize(context.Background(), pods, containers)
	testutil.AssertNoError(t, err)

	if updates != nil {
		t.Error("expected nil updates")
	}

	waitForPrewarm(t, done)
}

func TestPrewarmCacheDirectCancel(t *testing.T) {
	t.Parallel()

	plug := newTestPlugin(t, config.ModeDisabled, "")

	images := make([]plugin.ExportPrewarmImage, 10)
	hexPad := "000000000000000000000000000000000000000000000000000000000000000"

	for i := range images {
		idx := strconv.Itoa(i)
		images[i] = plugin.NewExportPrewarmImage(
			"image-"+idx+":latest",
			"sha256:"+idx+hexPad[:64-len(idx)],
			"",
			testNamespace,
			"container-"+idx,
		)
	}

	// Cancel context immediately so sem.Acquire fails inside prewarmCache,
	// covering the "Pre-warm cache cancelled" and "Pre-warm cache wait
	// cancelled" error paths.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	plug.ExportPrewarmCache(ctx, images)
}

func TestCreateContainerResolvesDigestWhenMissing(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{
		"slsa": {"missingPolicy": "allow"},
		"vex": {"missingPolicy": "allow"}
	}`)

	plug := newTestPlugin(t, config.ModeWarn, dir)
	plug.ExportSetDigestResolver(func(_ context.Context, _ string) (string, string, error) {
		return testDigest, "", nil
	})

	pod := &api.PodSandbox{
		Namespace: testNamespace,
		Name:      testPodName,
	}
	ctr := &api.Container{
		Name: testCtrName,
		Annotations: map[string]string{
			plugin.AnnotationContainerdImage: testImage,
		},
	}

	_, _, err := plug.CreateContainer(context.Background(), pod, ctr)
	testutil.AssertNoError(t, err)
}

func TestCreateContainerResolveDigestFailureEnforce(t *testing.T) {
	t.Parallel()

	plug := newTestPlugin(t, config.ModeEnforce, "")
	plug.ExportSetDigestResolver(func(_ context.Context, _ string) (string, string, error) {
		return "", "", errRegistryUnavailable
	})

	pod := &api.PodSandbox{
		Namespace: testNamespace,
		Name:      testPodName,
	}
	ctr := &api.Container{
		Name: testCtrName,
		Annotations: map[string]string{
			plugin.AnnotationContainerdImage: testImage,
		},
	}

	_, _, err := plug.CreateContainer(context.Background(), pod, ctr)
	if err == nil {
		t.Fatal("expected error for resolve failure in enforce mode")
	}
}

func TestCreateContainerResolveDigestFailureWarn(t *testing.T) {
	t.Parallel()

	plug := newTestPlugin(t, config.ModeWarn, "")
	plug.ExportSetDigestResolver(func(_ context.Context, _ string) (string, string, error) {
		return "", "", errRegistryUnavailable
	})

	pod := &api.PodSandbox{
		Namespace: testNamespace,
		Name:      testPodName,
	}
	ctr := &api.Container{
		Name: testCtrName,
		Annotations: map[string]string{
			plugin.AnnotationContainerdImage: testImage,
		},
	}

	_, _, err := plug.CreateContainer(context.Background(), pod, ctr)
	testutil.AssertNoError(t, err)
}

func TestCreateContainerSkipsResolveWhenDigestPresent(t *testing.T) {
	t.Parallel()

	plug := newTestPlugin(t, config.ModeWarn, "")
	plug.ExportSetDigestResolver(func(_ context.Context, _ string) (string, string, error) {
		t.Fatal("digest resolver should not be called when digest is present")

		return "", "", nil
	})

	pod := &api.PodSandbox{
		Namespace: testNamespace,
		Name:      testPodName,
	}
	ctr := &api.Container{
		Name: testCtrName,
		Annotations: map[string]string{
			plugin.AnnotationImage:    testImage,
			plugin.AnnotationImageRef: testDigest,
		},
	}

	_, _, err := plug.CreateContainer(context.Background(), pod, ctr)
	testutil.AssertNoError(t, err)
}

func TestSynchronizeResolvesDigestForPrewarm(t *testing.T) {
	t.Parallel()

	plug, done := newTestPluginWithPrewarmSignal(t, config.ModeDisabled, "")
	plug.ExportSetDigestResolver(func(_ context.Context, _ string) (string, string, error) {
		return testDigest, "", nil
	})

	pods := []*api.PodSandbox{
		{Id: testPodID, Namespace: testNamespace, Name: testPodName},
	}

	containers := []*api.Container{
		{
			Id:           "ctr-resolve-1",
			PodSandboxId: testPodID,
			Name:         "resolve-container",
			Annotations: map[string]string{
				plugin.AnnotationContainerdImage: testImage,
			},
		},
	}

	updates, err := plug.Synchronize(context.Background(), pods, containers)
	testutil.AssertNoError(t, err)

	if updates != nil {
		t.Error("expected nil updates")
	}

	waitForPrewarm(t, done)
}

func TestSynchronizeResolveDigestFailureSkipsContainer(t *testing.T) {
	t.Parallel()

	plug := newTestPlugin(t, config.ModeDisabled, "")
	plug.ExportSetDigestResolver(func(_ context.Context, _ string) (string, string, error) {
		return "", "", errRegistryUnavailable
	})

	pods := []*api.PodSandbox{
		{Id: testPodID, Namespace: testNamespace, Name: testPodName},
	}

	containers := []*api.Container{
		{
			Id:           "ctr-fail-resolve",
			PodSandboxId: testPodID,
			Name:         "fail-resolve-container",
			Annotations: map[string]string{
				plugin.AnnotationContainerdImage: testImage,
			},
		},
	}

	updates, err := plug.Synchronize(context.Background(), pods, containers)
	testutil.AssertNoError(t, err)

	if updates != nil {
		t.Error("expected nil updates")
	}
}

func TestDefaultDigestResolverSingleImage(t *testing.T) {
	t.Parallel()

	regHandler := registry.New()
	server := httptest.NewServer(regHandler)

	t.Cleanup(server.Close)

	addr := strings.TrimPrefix(server.URL, "http://")
	imgRef := addr + "/test:latest"

	img, err := mutate.ConfigFile(empty.Image, nil)
	if err != nil {
		t.Fatalf("creating test image: %v", err)
	}

	err = crane.Push(img, imgRef, crane.Insecure)
	if err != nil {
		t.Fatalf("pushing test image: %v", err)
	}

	digest, indexDigest, err := plugin.ExportDefaultDigestResolver(context.Background(), imgRef)
	testutil.AssertNoError(t, err)

	if !strings.HasPrefix(digest, "sha256:") {
		t.Errorf("digest = %q, expected sha256: prefix", digest)
	}

	if indexDigest != "" {
		t.Errorf("indexDigest = %q, expected empty for single manifest", indexDigest)
	}
}

func TestDefaultDigestResolverManifestList(t *testing.T) {
	t.Parallel()

	regHandler := registry.New()
	server := httptest.NewServer(regHandler)

	t.Cleanup(server.Close)

	addr := strings.TrimPrefix(server.URL, "http://")
	imgRef := addr + "/multiarch:latest"

	amdImg, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{
		Architecture: testArchAmd64,
		OS:           testOSLinux,
	})
	if err != nil {
		t.Fatalf("creating amd64 image: %v", err)
	}

	armImg, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{
		Architecture: testArchArm64,
		OS:           testOSLinux,
	})
	if err != nil {
		t.Fatalf("creating arm64 image: %v", err)
	}

	idx := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{
			Add: amdImg,
			Descriptor: v1.Descriptor{
				Platform: &v1.Platform{
					Architecture: testArchAmd64,
					OS:           testOSLinux,
				},
			},
		},
		mutate.IndexAddendum{
			Add: armImg,
			Descriptor: v1.Descriptor{
				Platform: &v1.Platform{
					Architecture: testArchArm64,
					OS:           testOSLinux,
				},
			},
		},
	)

	ref, err := name.ParseReference(imgRef)
	if err != nil {
		t.Fatalf("parsing reference: %v", err)
	}

	err = remote.WriteIndex(ref, idx, remote.WithTransport(server.Client().Transport))
	if err != nil {
		t.Fatalf("pushing index: %v", err)
	}

	digest, indexDigest, err := plugin.ExportDefaultDigestResolver(context.Background(), imgRef)
	testutil.AssertNoError(t, err)

	if !strings.HasPrefix(digest, "sha256:") {
		t.Errorf("digest = %q, expected sha256: prefix", digest)
	}

	// Verify it resolved to a platform image, not the index.
	idxDigest, err := idx.Digest()
	if err != nil {
		t.Fatalf("getting index digest: %v", err)
	}

	if digest == idxDigest.String() {
		t.Errorf("digest should be a platform image digest, not the index digest %s", digest)
	}

	if indexDigest != idxDigest.String() {
		t.Errorf("indexDigest = %q, expected %q", indexDigest, idxDigest.String())
	}
}

func TestDefaultDigestResolverDockerManifestList(t *testing.T) {
	t.Parallel()

	regHandler := registry.New()
	server := httptest.NewServer(regHandler)

	t.Cleanup(server.Close)

	addr := strings.TrimPrefix(server.URL, "http://")
	imgRef := addr + "/docker-multiarch:latest"

	img, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{
		Architecture: testArchAmd64,
		OS:           testOSLinux,
	})
	if err != nil {
		t.Fatalf("creating image: %v", err)
	}

	idx := mutate.IndexMediaType(
		mutate.AppendManifests(empty.Index,
			mutate.IndexAddendum{
				Add: img,
				Descriptor: v1.Descriptor{
					Platform: &v1.Platform{
						Architecture: testArchAmd64,
						OS:           testOSLinux,
					},
				},
			},
		),
		types.DockerManifestList,
	)

	ref, err := name.ParseReference(imgRef)
	if err != nil {
		t.Fatalf("parsing reference: %v", err)
	}

	err = remote.WriteIndex(ref, idx, remote.WithTransport(server.Client().Transport))
	if err != nil {
		t.Fatalf("pushing index: %v", err)
	}

	digest, indexDigest, err := plugin.ExportDefaultDigestResolver(context.Background(), imgRef)
	testutil.AssertNoError(t, err)

	if !strings.HasPrefix(digest, "sha256:") {
		t.Errorf("digest = %q, expected sha256: prefix", digest)
	}

	idxDigest, err := idx.Digest()
	if err != nil {
		t.Fatalf("getting index digest: %v", err)
	}

	if indexDigest != idxDigest.String() {
		t.Errorf("indexDigest = %q, expected %q", indexDigest, idxDigest.String())
	}
}

func TestDefaultDigestResolverManifestListNoPlatformMatch(t *testing.T) {
	t.Parallel()

	regHandler := registry.New()
	server := httptest.NewServer(regHandler)

	t.Cleanup(server.Close)

	addr := strings.TrimPrefix(server.URL, "http://")
	imgRef := addr + "/no-match:latest"

	img, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{
		Architecture: testArchS390x,
		OS:           testOSLinux,
	})
	if err != nil {
		t.Fatalf("creating image: %v", err)
	}

	idx := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{
			Add: img,
			Descriptor: v1.Descriptor{
				Platform: &v1.Platform{
					Architecture: testArchS390x,
					OS:           testOSZos,
				},
			},
		},
	)

	ref, err := name.ParseReference(imgRef)
	if err != nil {
		t.Fatalf("parsing reference: %v", err)
	}

	err = remote.WriteIndex(ref, idx, remote.WithTransport(server.Client().Transport))
	if err != nil {
		t.Fatalf("pushing index: %v", err)
	}

	_, _, err = plugin.ExportDefaultDigestResolver(context.Background(), imgRef)
	if err == nil {
		t.Fatal("expected error for no matching platform")
	}

	if !strings.Contains(err.Error(), "no matching platform") {
		t.Errorf("error = %q, expected to contain 'no matching platform'", err)
	}
}

func TestDefaultDigestResolverInvalidRef(t *testing.T) {
	t.Parallel()

	_, _, err := plugin.ExportDefaultDigestResolver(context.Background(), ":::invalid")
	if err == nil {
		t.Fatal("expected error for invalid image reference")
	}

	if !strings.Contains(err.Error(), "parsing image reference") {
		t.Errorf("error = %q, expected to contain 'parsing image reference'", err)
	}
}

func TestCancelPrewarm(t *testing.T) {
	t.Parallel()

	plug, done := newTestPluginWithPrewarmSignal(t, config.ModeDisabled, "")

	pods := []*api.PodSandbox{
		{Id: testPodID, Namespace: testNamespace, Name: testPodName},
	}

	containers := []*api.Container{
		{
			Id:           "ctr-cancel-prewarm",
			PodSandboxId: testPodID,
			Name:         "cancel-prewarm-container",
			Annotations: map[string]string{
				plugin.AnnotationImage:    testImage,
				plugin.AnnotationImageRef: testDigest,
			},
		},
	}

	updates, err := plug.Synchronize(context.Background(), pods, containers)
	testutil.AssertNoError(t, err)

	if updates != nil {
		t.Error("expected nil updates")
	}

	plug.CancelPrewarm()

	waitForPrewarm(t, done)
}

func TestConcurrentCreateContainer(t *testing.T) {
	t.Parallel()

	plug := newTestPlugin(t, config.ModeDisabled, "")

	const goroutines = 20

	var wg sync.WaitGroup

	wg.Add(goroutines)

	for i := range goroutines {
		go func() {
			defer wg.Done()

			idx := strconv.Itoa(i)
			hexPad := "000000000000000000000000000000000000000000000000000000000000000"

			pod := &api.PodSandbox{
				Namespace: testNamespace,
				Name:      "pod-" + idx,
			}
			ctr := &api.Container{
				Name: "ctr-" + idx,
				Annotations: map[string]string{
					plugin.AnnotationImage:    "image-" + idx + ":latest",
					plugin.AnnotationImageRef: "sha256:" + idx + hexPad[:64-len(idx)],
				},
			}

			_, _, err := plug.CreateContainer(context.Background(), pod, ctr)
			if err != nil {
				t.Errorf("concurrent CreateContainer: %v", err)
			}
		}()
	}

	wg.Wait()
}

func TestConcurrentSynchronizeAndCancelPrewarm(t *testing.T) {
	t.Parallel()

	plug := newTestPlugin(t, config.ModeDisabled, "")

	pods := []*api.PodSandbox{
		{Id: testPodID, Namespace: testNamespace, Name: testPodName},
	}

	containers := []*api.Container{
		{
			Id:           "ctr-race-1",
			PodSandboxId: testPodID,
			Name:         "race-container",
			Annotations: map[string]string{
				plugin.AnnotationImage:    testImage,
				plugin.AnnotationImageRef: testDigest,
			},
		},
	}

	const goroutines = 10

	var wg sync.WaitGroup

	wg.Add(goroutines * 2)

	for range goroutines {
		go func() {
			defer wg.Done()

			_, err := plug.Synchronize(context.Background(), pods, containers)
			if err != nil {
				t.Errorf("concurrent Synchronize: %v", err)
			}
		}()

		go func() {
			defer wg.Done()

			plug.CancelPrewarm()
		}()
	}

	wg.Wait()
}

type capturingVerifier struct {
	serviceAccount string
	mu             sync.Mutex
}

func (v *capturingVerifier) Verify(
	_ context.Context,
	_, _, _, _, serviceAccount string,
) (*scTypes.Result, error) {
	v.mu.Lock()
	v.serviceAccount = serviceAccount
	v.mu.Unlock()

	return &scTypes.Result{Allowed: true, Reason: "", CheckResults: nil}, nil
}

func (v *capturingVerifier) Ready() (ready bool, reason string) { return true, "" }

func (v *capturingVerifier) Enforcing() bool { return false }

func (v *capturingVerifier) EffectiveModeForNamespace(_ string) config.VerificationMode {
	return config.ModeWarn
}

func (v *capturingVerifier) Reload(_ context.Context, _ *config.Config) error { return nil }

var errVerifyFailed = errors.New("verification failed")

type failingVerifier struct{}

func (v *failingVerifier) Verify(
	_ context.Context, _, _, _, _, _ string,
) (*scTypes.Result, error) {
	return nil, errVerifyFailed
}

func (v *failingVerifier) Ready() (ready bool, reason string)               { return true, "" }
func (v *failingVerifier) Enforcing() bool                                  { return true }
func (v *failingVerifier) Reload(_ context.Context, _ *config.Config) error { return nil }

func (v *failingVerifier) EffectiveModeForNamespace(_ string) config.VerificationMode {
	return config.ModeEnforce
}

func (v *failingVerifier) Status() scTypes.StatusResponse {
	return scTypes.StatusResponse{
		Ready:           false,
		Mode:            string(config.ModeEnforce),
		Policies:        scTypes.PolicyStatus{Count: 0, Namespaces: []string{}, Source: ""},
		Cache:           scTypes.CacheStatus{Size: 0, MaxSize: 0},
		CircuitBreakers: map[string]string{},
		NRI:             scTypes.NRIStatus{Connected: false},
	}
}

func (v *capturingVerifier) Status() scTypes.StatusResponse {
	return scTypes.StatusResponse{
		Ready: true,
		Mode:  "warn",
		Policies: scTypes.PolicyStatus{
			Count:      0,
			Namespaces: []string{},
			Source:     "local",
		},
		Cache: scTypes.CacheStatus{
			Size:    0,
			MaxSize: 0,
		},
		CircuitBreakers: map[string]string{},
		NRI:             scTypes.NRIStatus{Connected: false},
	}
}

func TestCreateContainerPassesServiceAccount(t *testing.T) {
	t.Parallel()

	cv := &capturingVerifier{serviceAccount: "", mu: sync.Mutex{}}
	met := metrics.New()

	plug := plugin.New(cv, met, "", 30*time.Second, 1*time.Second, nil)

	const testSA = "my-service-account"

	pod := &api.PodSandbox{
		Namespace: testNamespace,
		Name:      testPodName,
		Annotations: map[string]string{
			plugin.AnnotationServiceAccount: testSA,
		},
	}
	ctr := &api.Container{
		Name: testCtrName,
		Annotations: map[string]string{
			plugin.AnnotationImage:    testImage,
			plugin.AnnotationImageRef: testDigest,
		},
	}

	_, _, err := plug.CreateContainer(context.Background(), pod, ctr)
	testutil.AssertNoError(t, err)

	cv.mu.Lock()
	got := cv.serviceAccount
	cv.mu.Unlock()

	if got != testSA {
		t.Errorf("expected service account %q, got %q", testSA, got)
	}
}

func TestCreateContainerEmptyServiceAccount(t *testing.T) {
	t.Parallel()

	cv := &capturingVerifier{serviceAccount: "", mu: sync.Mutex{}}
	met := metrics.New()

	plug := plugin.New(cv, met, "", 30*time.Second, 1*time.Second, nil)

	pod := &api.PodSandbox{
		Namespace: testNamespace,
		Name:      testPodName,
	}
	ctr := &api.Container{
		Name: testCtrName,
		Annotations: map[string]string{
			plugin.AnnotationImage:    testImage,
			plugin.AnnotationImageRef: testDigest,
		},
	}

	_, _, err := plug.CreateContainer(context.Background(), pod, ctr)
	testutil.AssertNoError(t, err)

	cv.mu.Lock()
	got := cv.serviceAccount
	cv.mu.Unlock()

	if got != "" {
		t.Errorf("expected empty service account, got %q", got)
	}
}

func TestConcurrentSynchronizeReplacesPreviousPrewarm(t *testing.T) {
	t.Parallel()

	plug := newTestPlugin(t, config.ModeDisabled, "")

	pods := []*api.PodSandbox{
		{Id: testPodID, Namespace: testNamespace, Name: testPodName},
	}

	for i := range 5 {
		idx := strconv.Itoa(i)

		containers := []*api.Container{
			{
				Id:           "ctr-seq-" + idx,
				PodSandboxId: testPodID,
				Name:         "seq-container-" + idx,
				Annotations: map[string]string{
					plugin.AnnotationImage:    "image-" + idx + ":latest",
					plugin.AnnotationImageRef: testDigest,
				},
			},
		}

		_, err := plug.Synchronize(context.Background(), pods, containers)
		testutil.AssertNoError(t, err)
	}
}

func TestBuildVerificationAdjustmentNilResult(t *testing.T) {
	t.Parallel()

	adj := plugin.ExportBuildVerificationAdjustment(nil, config.ModeWarn)
	if adj != nil {
		t.Error("expected nil adjustment for nil result")
	}
}

func TestBuildVerificationAdjustmentDisabledMode(t *testing.T) {
	t.Parallel()

	result := &scTypes.Result{Allowed: true, Reason: "", CheckResults: nil}

	adj := plugin.ExportBuildVerificationAdjustment(result, config.ModeDisabled)
	if adj != nil {
		t.Error("expected nil adjustment for disabled mode")
	}
}

func TestBuildVerificationAdjustmentWarnAllowed(t *testing.T) {
	t.Parallel()

	result := &scTypes.Result{
		Allowed: true,
		Reason:  "",
		CheckResults: []scTypes.CheckResult{
			*scTypes.PassResult(scTypes.CheckTypeSLSA, "ok"),
			*scTypes.WarnResult(scTypes.CheckTypeSBOM, "partial"),
		},
	}

	adj := plugin.ExportBuildVerificationAdjustment(result, config.ModeWarn)
	if adj == nil {
		t.Fatal("expected non-nil adjustment")
	}

	annotations := adj.GetAnnotations()

	if v := annotations[plugin.AnnotationVerified]; v != testValTrue {
		t.Errorf("verified = %q, want %q", v, testValTrue)
	}

	if v := annotations[plugin.AnnotationMode]; v != testValWarn {
		t.Errorf("mode = %q, want %q", v, testValWarn)
	}

	if v := annotations[plugin.AnnotationChecks]; v != "slsa:pass,sbom:warn" {
		t.Errorf("checks = %q, want %q", v, "slsa:pass,sbom:warn")
	}
}

func TestBuildVerificationAdjustmentEnforceDenied(t *testing.T) {
	t.Parallel()

	result := &scTypes.Result{
		Allowed: false,
		Reason:  "",
		CheckResults: []scTypes.CheckResult{
			*scTypes.PassResult(scTypes.CheckTypeVEX, "ok"),
			*scTypes.FailResult(scTypes.CheckTypeNotation, "invalid signature", nil),
		},
	}

	adj := plugin.ExportBuildVerificationAdjustment(result, config.ModeEnforce)
	if adj == nil {
		t.Fatal("expected non-nil adjustment")
	}

	annotations := adj.GetAnnotations()

	if v := annotations[plugin.AnnotationVerified]; v != testValFalse {
		t.Errorf("verified = %q, want %q", v, testValFalse)
	}

	if v := annotations[plugin.AnnotationMode]; v != "enforce" {
		t.Errorf("mode = %q, want %q", v, "enforce")
	}

	if v := annotations[plugin.AnnotationChecks]; v != "vex:pass,notation:fail" {
		t.Errorf("checks = %q, want %q", v, "vex:pass,notation:fail")
	}
}

func TestBuildVerificationAdjustmentEnforceAllowed(t *testing.T) {
	t.Parallel()

	result := &scTypes.Result{
		Allowed: true,
		Reason:  "",
		CheckResults: []scTypes.CheckResult{
			*scTypes.PassResult(scTypes.CheckTypeSLSA, "ok"),
			*scTypes.PassResult(scTypes.CheckTypeVEX, "ok"),
		},
	}

	adj := plugin.ExportBuildVerificationAdjustment(result, config.ModeEnforce)
	if adj == nil {
		t.Fatal("expected non-nil adjustment")
	}

	annotations := adj.GetAnnotations()

	if v := annotations[plugin.AnnotationVerified]; v != testValTrue {
		t.Errorf("verified = %q, want %q", v, testValTrue)
	}

	if v := annotations[plugin.AnnotationMode]; v != "enforce" {
		t.Errorf("mode = %q, want %q", v, "enforce")
	}

	if v := annotations[plugin.AnnotationChecks]; v != "slsa:pass,vex:pass" {
		t.Errorf("checks = %q, want %q", v, "slsa:pass,vex:pass")
	}
}

func TestBuildVerificationAdjustmentNoCheckResults(t *testing.T) {
	t.Parallel()

	result := &scTypes.Result{Allowed: true, Reason: "", CheckResults: nil}

	adj := plugin.ExportBuildVerificationAdjustment(result, config.ModeWarn)
	if adj == nil {
		t.Fatal("expected non-nil adjustment")
	}

	annotations := adj.GetAnnotations()

	if v := annotations[plugin.AnnotationVerified]; v != testValTrue {
		t.Errorf("verified = %q, want %q", v, testValTrue)
	}

	if v := annotations[plugin.AnnotationMode]; v != testValWarn {
		t.Errorf("mode = %q, want %q", v, testValWarn)
	}

	if _, ok := annotations[plugin.AnnotationChecks]; ok {
		t.Error("expected no checks annotation when check results are empty")
	}
}

func TestBuildVerificationAdjustmentAllCheckTypes(t *testing.T) {
	t.Parallel()

	result := &scTypes.Result{
		Allowed: true,
		Reason:  "",
		CheckResults: []scTypes.CheckResult{
			*scTypes.PassResult(scTypes.CheckTypeSLSA, ""),
			*scTypes.PassResult(scTypes.CheckTypeVEX, ""),
			*scTypes.PassResult(scTypes.CheckTypeNotation, ""),
			*scTypes.WarnResult(scTypes.CheckTypeSBOM, ""),
		},
	}

	adj := plugin.ExportBuildVerificationAdjustment(result, config.ModeEnforce)
	if adj == nil {
		t.Fatal("expected non-nil adjustment")
	}

	want := "slsa:pass,vex:pass,notation:pass,sbom:warn"
	if v := adj.GetAnnotations()[plugin.AnnotationChecks]; v != want {
		t.Errorf("checks = %q, want %q", v, want)
	}
}

func TestCreateContainerWarnAllowReturnsAdjustment(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{
		"slsa": {"missingPolicy": "allow"},
		"vex": {"missingPolicy": "allow"}
	}`)

	plug := newTestPlugin(t, config.ModeWarn, dir)

	pod := &api.PodSandbox{
		Namespace: testNamespace,
		Name:      testPodName,
	}
	ctr := &api.Container{
		Name: testCtrName,
		Annotations: map[string]string{
			plugin.AnnotationImage:    testImage,
			plugin.AnnotationImageRef: testDigest,
		},
	}

	adj, updates, err := plug.CreateContainer(context.Background(), pod, ctr)
	testutil.AssertNoError(t, err)

	if adj == nil {
		t.Fatal("expected non-nil adjustment for warn mode")
	}

	annotations := adj.GetAnnotations()

	if _, ok := annotations[plugin.AnnotationVerified]; !ok {
		t.Error("expected verified annotation")
	}

	if v := annotations[plugin.AnnotationMode]; v != testValWarn {
		t.Errorf("mode = %q, want %q", v, testValWarn)
	}

	if updates != nil {
		t.Error("expected nil updates")
	}
}

func TestFilterRelevantAnnotations(t *testing.T) {
	t.Parallel()

	annotations := map[string]string{
		plugin.AnnotationImageName:       "docker.io/library/nginx",
		plugin.AnnotationImage:           "docker.io/library/nginx@sha256:abc",
		plugin.AnnotationContainerdImage: "docker.io/library/nginx:latest",
		"unrelated-key":                  "should be filtered out",
		"another-key":                    "also filtered",
	}

	filtered := plugin.ExportFilterRelevantAnnotations(annotations)

	if len(filtered) != 3 {
		t.Errorf("expected 3 filtered annotations, got %d", len(filtered))
	}

	if filtered[plugin.AnnotationImageName] != "docker.io/library/nginx" {
		t.Errorf("expected ImageName annotation, got %q",
			filtered[plugin.AnnotationImageName])
	}

	if _, ok := filtered["unrelated-key"]; ok {
		t.Error("expected unrelated-key to be filtered out")
	}
}

func TestFilterRelevantAnnotationsEmpty(t *testing.T) {
	t.Parallel()

	filtered := plugin.ExportFilterRelevantAnnotations(map[string]string{
		"irrelevant": "value",
	})

	if len(filtered) != 0 {
		t.Errorf("expected 0 filtered annotations, got %d", len(filtered))
	}
}

func TestRemoveContainerUnknownID(t *testing.T) {
	t.Parallel()

	cv := &capturingVerifier{serviceAccount: "", mu: sync.Mutex{}}
	met := metrics.New()
	plug := plugin.New(cv, met, "", 30*time.Second, 1*time.Second, nil)

	pod := &api.PodSandbox{
		Namespace: testNamespace,
		Name:      testPodName,
	}
	ctr := &api.Container{
		Id:   "unknown-container",
		Name: testCtrName,
	}

	err := plug.RemoveContainer(context.Background(), pod, ctr)
	testutil.AssertNoError(t, err)

	count := promtestutil.CollectAndCount(met.ContainerLifetime)
	if count != 0 {
		t.Errorf("expected 0 metric samples, got %d", count)
	}
}

func TestRemoveContainerRecordsLifetime(t *testing.T) {
	t.Parallel()

	cv := &capturingVerifier{serviceAccount: "", mu: sync.Mutex{}}
	met := metrics.New()
	plug := plugin.New(cv, met, "", 30*time.Second, 1*time.Second, nil)

	const ctrID = "test-ctr-1"

	// Store a creation time in the past.
	plug.ExportStoreContainerTime(ctrID, time.Now().Add(-5*time.Second))

	pod := &api.PodSandbox{
		Namespace: testNamespace,
		Name:      testPodName,
	}
	ctr := &api.Container{
		Id:   ctrID,
		Name: testCtrName,
	}

	err := plug.RemoveContainer(context.Background(), pod, ctr)
	testutil.AssertNoError(t, err)

	count := promtestutil.CollectAndCount(met.ContainerLifetime)
	if count == 0 {
		t.Error("expected container lifetime metric to be recorded")
	}
}

func TestCreateThenRemoveContainerRecordsPositiveLifetime(t *testing.T) {
	t.Parallel()

	cv := &capturingVerifier{serviceAccount: "", mu: sync.Mutex{}}
	met := metrics.New()
	plug := plugin.New(cv, met, "", 30*time.Second, 1*time.Second, nil)

	const ctrID = "lifecycle-ctr"

	pod := &api.PodSandbox{
		Namespace: testNamespace,
		Name:      testPodName,
	}
	ctr := &api.Container{
		Id:   ctrID,
		Name: testCtrName,
		Annotations: map[string]string{
			plugin.AnnotationImage:    testImage,
			plugin.AnnotationImageRef: testDigest,
		},
	}

	_, _, err := plug.CreateContainer(context.Background(), pod, ctr)
	testutil.AssertNoError(t, err)

	// Verify the timestamp was stored.
	if _, ok := plug.ExportLoadContainerTime(ctrID); !ok {
		t.Fatal("expected container time to be stored after CreateContainer")
	}

	err = plug.RemoveContainer(context.Background(), pod, ctr)
	testutil.AssertNoError(t, err)

	count := promtestutil.CollectAndCount(met.ContainerLifetime)
	if count == 0 {
		t.Error("expected container lifetime metric to be recorded")
	}

	// After removal the entry should be gone.
	if _, ok := plug.ExportLoadContainerTime(ctrID); ok {
		t.Error("expected container time to be deleted after RemoveContainer")
	}
}

func TestSynchronizeCleansStaleContainerTimes(t *testing.T) {
	t.Parallel()

	cv := &capturingVerifier{serviceAccount: "", mu: sync.Mutex{}}
	met := metrics.New()
	plug := plugin.New(cv, met, "", 30*time.Second, 1*time.Second, nil)

	// Simulate containers that were created while the plugin was active.
	plug.ExportStoreContainerTime("active-ctr", time.Now())
	plug.ExportStoreContainerTime("stale-ctr", time.Now())

	pods := []*api.PodSandbox{
		{Id: testPodID, Namespace: testNamespace, Name: testPodName},
	}

	// Only "active-ctr" is still running.
	containers := []*api.Container{
		{
			Id:           "active-ctr",
			PodSandboxId: testPodID,
			Name:         testCtrName,
		},
	}

	_, err := plug.Synchronize(context.Background(), pods, containers)
	testutil.AssertNoError(t, err)

	if _, ok := plug.ExportLoadContainerTime("active-ctr"); !ok {
		t.Error("expected active container time to be preserved")
	}

	if _, ok := plug.ExportLoadContainerTime("stale-ctr"); ok {
		t.Error("expected stale container time to be cleaned up")
	}
}

func TestSynchronizeDoesNotTrackPreExistingContainers(t *testing.T) {
	t.Parallel()

	cv := &capturingVerifier{serviceAccount: "", mu: sync.Mutex{}}
	met := metrics.New()
	plug := plugin.New(cv, met, "", 30*time.Second, 1*time.Second, nil)

	const ctrID = "pre-existing-ctr"

	pods := []*api.PodSandbox{
		{Id: testPodID, Namespace: testNamespace, Name: testPodName},
	}

	containers := []*api.Container{
		{
			Id:           ctrID,
			PodSandboxId: testPodID,
			Name:         testCtrName,
		},
	}

	_, err := plug.Synchronize(context.Background(), pods, containers)
	testutil.AssertNoError(t, err)

	// Pre-existing containers should not be tracked because we did not
	// observe their creation and cannot report an accurate lifetime.
	if _, ok := plug.ExportLoadContainerTime(ctrID); ok {
		t.Error("expected Synchronize to not track pre-existing containers")
	}
}

func TestMissingAnnotationsWarnModeTracksLifetime(t *testing.T) {
	t.Parallel()

	cv := &capturingVerifier{serviceAccount: "", mu: sync.Mutex{}}
	met := metrics.New()
	plug := plugin.New(cv, met, "", 30*time.Second, 1*time.Second, nil)

	const ctrID = "missing-annot-ctr"

	pod := &api.PodSandbox{
		Namespace: testNamespace,
		Name:      testPodName,
	}
	ctr := &api.Container{
		Id:          ctrID,
		Name:        testCtrName,
		Annotations: map[string]string{},
	}

	_, _, err := plug.CreateContainer(context.Background(), pod, ctr)
	testutil.AssertNoError(t, err)

	if _, ok := plug.ExportLoadContainerTime(ctrID); !ok {
		t.Fatal("expected container time to be stored on missing-annotations warn path")
	}

	err = plug.RemoveContainer(context.Background(), pod, ctr)
	testutil.AssertNoError(t, err)

	count := promtestutil.CollectAndCount(met.ContainerLifetime)
	if count == 0 {
		t.Error("expected container lifetime metric after RemoveContainer")
	}

	if _, ok := plug.ExportLoadContainerTime(ctrID); ok {
		t.Error("expected container time to be deleted after RemoveContainer")
	}
}

func TestCreateContainerVerifyErrorDoesNotTrackTime(t *testing.T) {
	t.Parallel()

	fv := &failingVerifier{}
	met := metrics.New()
	plug := plugin.New(fv, met, "", 30*time.Second, 1*time.Second, nil)

	const ctrID = "fail-verify-ctr"

	pod := &api.PodSandbox{
		Namespace: testNamespace,
		Name:      testPodName,
	}
	ctr := &api.Container{
		Id:   ctrID,
		Name: testCtrName,
		Annotations: map[string]string{
			plugin.AnnotationImage:    testImage,
			plugin.AnnotationImageRef: testDigest,
		},
	}

	_, _, err := plug.CreateContainer(context.Background(), pod, ctr)
	if err == nil {
		t.Fatal("expected CreateContainer to return an error")
	}

	if _, ok := plug.ExportLoadContainerTime(ctrID); ok {
		t.Error("expected container time to not be stored after verification failure")
	}
}

func TestMissingAnnotationsEnforceModeDoesNotTrackTime(t *testing.T) {
	t.Parallel()

	fv := &failingVerifier{}
	met := metrics.New()
	plug := plugin.New(fv, met, "", 30*time.Second, 1*time.Second, nil)

	const ctrID = "enforce-missing-annot-ctr"

	pod := &api.PodSandbox{
		Namespace: testNamespace,
		Name:      testPodName,
	}
	ctr := &api.Container{
		Id:          ctrID,
		Name:        testCtrName,
		Annotations: map[string]string{},
	}

	_, _, err := plug.CreateContainer(context.Background(), pod, ctr)
	if err == nil {
		t.Fatal("expected CreateContainer to return an error in enforce mode")
	}

	if _, ok := plug.ExportLoadContainerTime(ctrID); ok {
		t.Error("expected container time to not be stored after enforce-mode rejection")
	}
}

func TestRemoveContainerConcurrentSameID(t *testing.T) {
	t.Parallel()

	cv := &capturingVerifier{serviceAccount: "", mu: sync.Mutex{}}
	met := metrics.New()
	plug := plugin.New(cv, met, "", 30*time.Second, 1*time.Second, nil)

	const ctrID = "concurrent-ctr"

	plug.ExportStoreContainerTime(ctrID, time.Now().Add(-5*time.Second))

	pod := &api.PodSandbox{
		Namespace: testNamespace,
		Name:      testPodName,
	}
	ctr := &api.Container{
		Id:   ctrID,
		Name: testCtrName,
	}

	var wg sync.WaitGroup

	for range 10 {
		wg.Go(func() {
			err := plug.RemoveContainer(context.Background(), pod, ctr)
			if err != nil {
				t.Errorf("RemoveContainer returned error: %v", err)
			}
		})
	}

	wg.Wait()

	count := promtestutil.CollectAndCount(met.ContainerLifetime)
	if count == 0 {
		t.Error("expected at least one lifetime metric observation")
	}
}

func TestPluginStatusReadyRequiresNRIConnection(t *testing.T) {
	t.Parallel()

	cv := &capturingVerifier{serviceAccount: "", mu: sync.Mutex{}}
	met := metrics.New()
	plug := plugin.New(cv, met, "", 30*time.Second, 1*time.Second, nil)

	status := plug.Status()
	if status.Ready {
		t.Error("expected ready=false before NRI connection")
	}

	if status.NRI.Connected {
		t.Error("expected nri.connected=false before Configure")
	}

	_, err := plug.Configure(context.Background(), "", "cri-o", "1.32")
	testutil.AssertNoError(t, err)

	status = plug.Status()
	if !status.Ready {
		t.Error("expected ready=true after NRI connection")
	}

	if !status.NRI.Connected {
		t.Error("expected nri.connected=true after Configure")
	}

	plug.SetDisconnected()

	status = plug.Status()
	if status.Ready {
		t.Error("expected ready=false after NRI disconnect")
	}

	if status.NRI.Connected {
		t.Error("expected nri.connected=false after SetDisconnected")
	}
}

func TestSetFetchTimeout(t *testing.T) {
	t.Parallel()

	cv := &capturingVerifier{serviceAccount: "", mu: sync.Mutex{}}
	met := metrics.New()
	plug := plugin.New(cv, met, "", 30*time.Second, 1*time.Second, nil)

	if got := plug.ExportFetchTimeout(); got != 30*time.Second {
		t.Errorf("initial fetch timeout = %v, want %v", got, 30*time.Second)
	}

	plug.SetFetchTimeout(45 * time.Second)

	if got := plug.ExportFetchTimeout(); got != 45*time.Second {
		t.Errorf("updated fetch timeout = %v, want %v", got, 45*time.Second)
	}
}

func TestSetDigestResolveTimeout(t *testing.T) {
	t.Parallel()

	cv := &capturingVerifier{serviceAccount: "", mu: sync.Mutex{}}
	met := metrics.New()
	plug := plugin.New(cv, met, "", 30*time.Second, 1*time.Second, nil)

	if got := plug.ExportDigestResolveTimeout(); got != 1*time.Second {
		t.Errorf("initial digest resolve timeout = %v, want %v", got, 1*time.Second)
	}

	plug.SetDigestResolveTimeout(5 * time.Second)

	if got := plug.ExportDigestResolveTimeout(); got != 5*time.Second {
		t.Errorf("updated digest resolve timeout = %v, want %v", got, 5*time.Second)
	}
}

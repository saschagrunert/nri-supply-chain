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
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/api"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/plugin"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

const (
	testNamespace = "default"
	testPodName   = "test-pod"
	testPodID     = "pod-1"
	testCtrName   = "test-container"
	testImage     = "nginx:latest"
	testDigest    = "sha256:abc123"
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

	if adj != nil {
		t.Error("expected nil adjustment")
	}

	if updates != nil {
		t.Error("expected nil updates")
	}
}

func TestCreateContainerEnforceReject(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePolicy(t, dir, "default.json", `{
		"trust": {
			"builders": [{"id": "test", "maxLevel": 3}]
		},
		"provenance": {"missingPolicy": "deny"}
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
	writePolicy(t, dir, "default.json", `{
		"trust": {
			"builders": [{"id": "test", "maxLevel": 3}]
		},
		"provenance": {"missingPolicy": "deny"}
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

	_, _, err := plug.CreateContainer(context.Background(), pod, ctr)
	testutil.AssertNoError(t, err)
}

func TestConfigureWithEmptyConfig(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	met := metrics.New()

	v, err := verifier.New(cfg, met, nil)
	testutil.AssertNoError(t, err)

	plug := plugin.New(v, met, "", 30*time.Second)

	_, err = plug.Configure(context.Background(), "", "cri-o", "1.32")
	testutil.AssertNoError(t, err)
}

func TestConfigureWithNRIConfig(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePolicy(t, dir, "default.json", `{}`)

	cfg := config.DefaultConfig()
	met := metrics.New()

	v, err := verifier.New(cfg, met, nil)
	testutil.AssertNoError(t, err)

	plug := plugin.New(v, met, "", 30*time.Second)

	tomlConfig := `verification = "warn"` + "\n" +
		`policy_dir = "` + dir + `"` + "\n"

	_, err = plug.Configure(context.Background(), tomlConfig, "cri-o", "1.32")
	testutil.AssertNoError(t, err)
}

func TestConfigureWithInvalidNRIConfig(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	met := metrics.New()

	v, err := verifier.New(cfg, met, nil)
	testutil.AssertNoError(t, err)

	plug := plugin.New(v, met, "", 30*time.Second)

	_, err = plug.Configure(context.Background(), `[[[invalid`, "cri-o", "1.32")
	if err == nil {
		t.Fatal("expected error for invalid TOML")
	}
}

func TestConfigureWithInvalidPolicyDir(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	met := metrics.New()

	v, err := verifier.New(cfg, met, nil)
	testutil.AssertNoError(t, err)

	plug := plugin.New(v, met, "", 30*time.Second)

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

	v, err := verifier.New(cfg, met, nil)
	testutil.AssertNoError(t, err)

	plug := plugin.New(v, met, "/some/config.toml", 30*time.Second)

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

func TestSynchronizePrewarm(t *testing.T) {
	t.Parallel()

	plug := newTestPlugin(t, config.ModeDisabled, "")

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

	// Give the prewarm goroutine time to complete.
	time.Sleep(100 * time.Millisecond)
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

	plug := newTestPlugin(t, config.ModeDisabled, "")

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

	time.Sleep(100 * time.Millisecond)
}

func newTestPlugin(t *testing.T, mode config.VerificationMode, policyDir string) *plugin.Plugin {
	t.Helper()

	cfg := config.DefaultConfig()
	cfg.Verification = mode

	if policyDir != "" {
		cfg.PolicyDir = policyDir
	}

	met := metrics.New()

	v, err := verifier.New(cfg, met, nil)
	testutil.AssertNoError(t, err)

	return plugin.New(v, met, "", 30*time.Second)
}

func writePolicy(t *testing.T, dir, name, content string) {
	t.Helper()

	err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600)
	if err != nil {
		t.Fatalf("writing policy: %v", err)
	}
}

func TestSynchronizePrewarmVerifyError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePolicy(t, dir, "default.json", `{
		"trust": {
			"builders": [{"id": "test", "maxLevel": 3}]
		},
		"provenance": {"missingPolicy": "deny"}
	}`)

	plug := newTestPlugin(t, config.ModeEnforce, dir)

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

	// Give the prewarm goroutine time to complete.
	time.Sleep(200 * time.Millisecond)
}

func TestSynchronizePrewarmCancelledContext(t *testing.T) {
	t.Parallel()

	plug := newTestPlugin(t, config.ModeDisabled, "")

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

	// Give the prewarm goroutine time to complete (it should exit quickly).
	time.Sleep(200 * time.Millisecond)
}

func TestSynchronizeSkipsMissingAnnotations(t *testing.T) {
	t.Parallel()

	plug := newTestPlugin(t, config.ModeDisabled, "")

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

	// Give the prewarm goroutine time to complete.
	time.Sleep(100 * time.Millisecond)
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
			testNamespace,
		)
	}

	// Cancel context immediately so sem.Acquire fails inside prewarmCache,
	// covering the "Pre-warm cache cancelled" and "Pre-warm cache wait
	// cancelled" error paths.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	plug.ExportPrewarmCache(ctx, images)
}

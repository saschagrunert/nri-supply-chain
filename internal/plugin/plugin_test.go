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
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/plugin"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

var errRegistryUnavailable = errors.New("registry unavailable")

const (
	testNamespace = "default"
	testPodName   = "test-pod"
	testPodID     = "pod-1"
	testCtrName   = "test-container"
	testImage     = "nginx:latest"
	testDigest    = "sha256:abc123"
	testArchAmd64 = "amd64"
	testArchArm64 = "arm64"
	testArchS390x = "s390x"
	testOSLinux   = "linux"
	testOSZos     = "zos"
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
	writePolicy(t, dir, "default.json", `{
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

func writePolicy(t *testing.T, dir, filename, content string) {
	t.Helper()

	err := os.WriteFile(filepath.Join(dir, filename), []byte(content), 0o600)
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
		"slsa": {"missingPolicy": "deny"}
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

func TestCreateContainerResolvesDigestWhenMissing(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePolicy(t, dir, "default.json", `{
		"slsa": {"missingPolicy": "allow"},
		"vex": {"missingPolicy": "allow"}
	}`)

	plug := newTestPlugin(t, config.ModeWarn, dir)
	plug.ExportSetDigestResolver(func(_ context.Context, _ string) (string, error) {
		return testDigest, nil
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
	plug.ExportSetDigestResolver(func(_ context.Context, _ string) (string, error) {
		return "", errRegistryUnavailable
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
	plug.ExportSetDigestResolver(func(_ context.Context, _ string) (string, error) {
		return "", errRegistryUnavailable
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
	plug.ExportSetDigestResolver(func(_ context.Context, _ string) (string, error) {
		t.Fatal("digest resolver should not be called when digest is present")

		return "", nil
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

	plug := newTestPlugin(t, config.ModeDisabled, "")
	plug.ExportSetDigestResolver(func(_ context.Context, _ string) (string, error) {
		return testDigest, nil
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

	time.Sleep(100 * time.Millisecond)
}

func TestSynchronizeResolveDigestFailureSkipsContainer(t *testing.T) {
	t.Parallel()

	plug := newTestPlugin(t, config.ModeDisabled, "")
	plug.ExportSetDigestResolver(func(_ context.Context, _ string) (string, error) {
		return "", errRegistryUnavailable
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

	time.Sleep(100 * time.Millisecond)
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

	digest, err := plugin.ExportDefaultDigestResolver(context.Background(), imgRef)
	testutil.AssertNoError(t, err)

	if !strings.HasPrefix(digest, "sha256:") {
		t.Errorf("digest = %q, expected sha256: prefix", digest)
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

	digest, err := plugin.ExportDefaultDigestResolver(context.Background(), imgRef)
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

	digest, err := plugin.ExportDefaultDigestResolver(context.Background(), imgRef)
	testutil.AssertNoError(t, err)

	if !strings.HasPrefix(digest, "sha256:") {
		t.Errorf("digest = %q, expected sha256: prefix", digest)
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

	_, err = plugin.ExportDefaultDigestResolver(context.Background(), imgRef)
	if err == nil {
		t.Fatal("expected error for no matching platform")
	}

	if !strings.Contains(err.Error(), "no matching platform") {
		t.Errorf("error = %q, expected to contain 'no matching platform'", err)
	}
}

func TestDefaultDigestResolverInvalidRef(t *testing.T) {
	t.Parallel()

	_, err := plugin.ExportDefaultDigestResolver(context.Background(), ":::invalid")
	if err == nil {
		t.Fatal("expected error for invalid image reference")
	}

	if !strings.Contains(err.Error(), "parsing image reference") {
		t.Errorf("error = %q, expected to contain 'parsing image reference'", err)
	}
}

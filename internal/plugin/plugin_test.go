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
	"testing"

	"github.com/containerd/nri/pkg/api"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/plugin"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

const (
	testNamespace = "default"
	testPodName   = "test-pod"
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
	assertNoError(t, err)

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
	assertNoError(t, err)

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
	assertNoError(t, err)
}

func TestConfigureWithEmptyConfig(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	met := metrics.New()

	v, err := verifier.New(cfg, met, nil)
	assertNoError(t, err)

	plug := plugin.New(v, met, "")

	_, err = plug.Configure(context.Background(), "", "cri-o", "1.32")
	assertNoError(t, err)
}

func TestConfigureWithNRIConfig(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePolicy(t, dir, "default.json", `{}`)

	cfg := config.DefaultConfig()
	met := metrics.New()

	v, err := verifier.New(cfg, met, nil)
	assertNoError(t, err)

	plug := plugin.New(v, met, "")

	tomlConfig := `verification = "warn"` + "\n" +
		`policy_dir = "` + dir + `"` + "\n"

	_, err = plug.Configure(context.Background(), tomlConfig, "cri-o", "1.32")
	assertNoError(t, err)
}

func TestConfigureWithInvalidNRIConfig(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	met := metrics.New()

	v, err := verifier.New(cfg, met, nil)
	assertNoError(t, err)

	plug := plugin.New(v, met, "")

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
	assertNoError(t, err)

	plug := plugin.New(v, met, "")

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
	assertNoError(t, err)

	plug := plugin.New(v, met, "/some/config.toml")

	_, err = plug.Configure(context.Background(), `verification = "enforce"`, "cri-o", "1.32")
	assertNoError(t, err)
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

func newTestPlugin(t *testing.T, mode, policyDir string) *plugin.Plugin {
	t.Helper()

	cfg := config.DefaultConfig()
	cfg.Verification = mode

	if policyDir != "" {
		cfg.PolicyDir = policyDir
	}

	met := metrics.New()

	v, err := verifier.New(cfg, met, nil)
	assertNoError(t, err)

	return plugin.New(v, met, "")
}

func writePolicy(t *testing.T, dir, name, content string) {
	t.Helper()

	err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600)
	if err != nil {
		t.Fatalf("writing policy: %v", err)
	}
}

func assertNoError(t *testing.T, err error) {
	t.Helper()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

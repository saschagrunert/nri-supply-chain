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

func TestCreateContainerMissingAnnotations(t *testing.T) {
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

func TestSetStub(t *testing.T) {
	t.Parallel()

	plug := newTestPlugin(t, config.ModeDisabled, "")
	plug.SetStub(nil)
}

func TestConfigureWithEmptyConfig(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()

	v, err := verifier.New(cfg, metrics.New())
	assertNoError(t, err)

	plug := plugin.New(v, "")

	_, err = plug.Configure(context.Background(), "", "cri-o", "1.32")
	assertNoError(t, err)
}

func TestConfigureWithNRIConfig(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePolicy(t, dir, "default.json", `{}`)

	cfg := config.DefaultConfig()

	v, err := verifier.New(cfg, metrics.New())
	assertNoError(t, err)

	plug := plugin.New(v, "")

	tomlConfig := `verification = "warn"` + "\n" +
		`policy_dir = "` + dir + `"` + "\n"

	_, err = plug.Configure(context.Background(), tomlConfig, "cri-o", "1.32")
	assertNoError(t, err)
}

func TestConfigureWithInvalidNRIConfig(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()

	v, err := verifier.New(cfg, metrics.New())
	assertNoError(t, err)

	plug := plugin.New(v, "")

	_, err = plug.Configure(context.Background(), `[[[invalid`, "cri-o", "1.32")
	if err == nil {
		t.Fatal("expected error for invalid TOML")
	}
}

func TestConfigureSkipsWhenConfigPathSet(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()

	v, err := verifier.New(cfg, metrics.New())
	assertNoError(t, err)

	plug := plugin.New(v, "/some/config.toml")

	_, err = plug.Configure(context.Background(), `verification = "enforce"`, "cri-o", "1.32")
	assertNoError(t, err)
}

func newTestPlugin(t *testing.T, mode, policyDir string) *plugin.Plugin {
	t.Helper()

	cfg := config.DefaultConfig()
	cfg.Verification = mode

	if policyDir != "" {
		cfg.PolicyDir = policyDir
	}

	v, err := verifier.New(cfg, metrics.New())
	assertNoError(t, err)

	return plugin.New(v, "")
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

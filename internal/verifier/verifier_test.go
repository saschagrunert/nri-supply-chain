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

package verifier_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

func TestVerifyDisabled(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()

	v, err := verifier.New(cfg, metrics.New())
	assertNoError(t, err)

	result, err := v.Verify(context.Background(), "nginx:latest", "sha256:abc", "default")
	assertNoError(t, err)

	if !result.Allowed {
		t.Error("expected allowed when disabled")
	}
}

func TestNewError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePolicy(t, dir, "bad.json", `{invalid json}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir

	_, err := verifier.New(cfg, metrics.New())
	if err == nil {
		t.Error("expected error for invalid policy")
	}
}

func TestVerifyWarnMode(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePolicy(t, dir, "default.json", `{
		"trust": {
			"builders": [{"id": "https://example.com/builder", "maxLevel": 2}]
		},
		"provenance": {"missingPolicy": "deny"}
	}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir

	v, err := verifier.New(cfg, metrics.New())
	assertNoError(t, err)

	result, err := v.Verify(context.Background(), "nginx:latest", "sha256:abc", "default")
	assertNoError(t, err)

	if !result.Allowed {
		t.Error("expected allowed in warn mode even with deny policy")
	}
}

func TestVerifyEnforceMode(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePolicy(t, dir, "default.json", `{
		"trust": {
			"builders": [{"id": "https://example.com/builder", "maxLevel": 2}]
		},
		"provenance": {"missingPolicy": "deny"}
	}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.PolicyDir = dir

	v, err := verifier.New(cfg, metrics.New())
	assertNoError(t, err)

	_, err = v.Verify(context.Background(), "nginx:latest", "sha256:abc", "default")
	if err == nil {
		t.Fatal("expected error in enforce mode with deny policy")
	}

	if !errors.Is(err, verifier.ErrVerificationFailed) {
		t.Errorf("expected ErrVerificationFailed, got %v", err)
	}
}

func TestVerifyExcluded(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePolicy(t, dir, "default.json", `{
		"exclude": ["gcr.io/internal/*"],
		"trust": {
			"builders": [{"id": "test", "maxLevel": 3}]
		},
		"provenance": {"missingPolicy": "deny"}
	}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.PolicyDir = dir

	v, err := verifier.New(cfg, metrics.New())
	assertNoError(t, err)

	result, err := v.Verify(
		context.Background(), "gcr.io/internal/app", "sha256:abc", "default",
	)
	assertNoError(t, err)

	if !result.Allowed {
		t.Error("expected excluded image to be allowed")
	}
}

func TestVerifyNamespacePolicy(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePolicy(t, dir, "default.json", `{
		"trust": {
			"builders": [{"id": "test", "maxLevel": 3}]
		},
		"provenance": {"missingPolicy": "deny"}
	}`)
	writePolicy(t, dir, "staging.json", `{
		"provenance": {"missingPolicy": "allow"}
	}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.PolicyDir = dir

	verif, err := verifier.New(cfg, metrics.New())
	assertNoError(t, err)

	_, err = verif.Verify(
		context.Background(), "nginx:latest", "sha256:abc", "default",
	)
	if err == nil {
		t.Error("expected error for default namespace")
	}

	result, err := verif.Verify(
		context.Background(), "nginx:latest", "sha256:def", "staging",
	)
	assertNoError(t, err)

	if !result.Allowed {
		t.Error("expected allowed for staging namespace")
	}
}

func TestVerifyNoBuilders(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePolicy(t, dir, "default.json", `{}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.PolicyDir = dir

	v, err := verifier.New(cfg, metrics.New())
	assertNoError(t, err)

	result, err := v.Verify(
		context.Background(), "nginx:latest", "sha256:abc", "default",
	)
	assertNoError(t, err)

	if !result.Allowed {
		t.Error("expected allowed with no builders configured")
	}
}

func TestVerifyCache(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePolicy(t, dir, "default.json", `{}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir
	cfg.CacheTTL = config.Duration{Duration: time.Hour}

	verif, err := verifier.New(cfg, metrics.New())
	assertNoError(t, err)

	result1, err := verif.Verify(
		context.Background(), "nginx:latest", "sha256:abc", "default",
	)
	assertNoError(t, err)

	result2, err := verif.Verify(
		context.Background(), "nginx:latest", "sha256:abc", "default",
	)
	assertNoError(t, err)

	if result1.Reason != result2.Reason {
		t.Errorf(
			"expected cached result to match: %q vs %q",
			result1.Reason, result2.Reason,
		)
	}
}

func TestVerifyAllowPolicy(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePolicy(t, dir, "default.json", `{
		"trust": {
			"builders": [{"id": "test", "maxLevel": 3}]
		},
		"provenance": {"missingPolicy": "allow"}
	}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.PolicyDir = dir

	v, err := verifier.New(cfg, metrics.New())
	assertNoError(t, err)

	result, err := v.Verify(
		context.Background(), "nginx:latest", "sha256:abc", "default",
	)
	assertNoError(t, err)

	if !result.Allowed {
		t.Error("expected allowed with allow policy")
	}
}

func TestVerifyWarnPolicy(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePolicy(t, dir, "default.json", `{
		"trust": {
			"builders": [{"id": "test", "maxLevel": 3}]
		},
		"provenance": {"missingPolicy": "warn"}
	}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.PolicyDir = dir

	v, err := verifier.New(cfg, metrics.New())
	assertNoError(t, err)

	result, err := v.Verify(
		context.Background(), "nginx:latest", "sha256:abc", "default",
	)
	assertNoError(t, err)

	if !result.Allowed {
		t.Error("expected allowed with warn policy")
	}

	if result.Reason == "" {
		t.Error("expected non-empty reason for warn result")
	}
}

func TestVerifyFallbackPolicy(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.PolicyDir = dir

	v, err := verifier.New(cfg, metrics.New())
	assertNoError(t, err)

	result, err := v.Verify(
		context.Background(), "nginx:latest", "sha256:abc", "unknown-ns",
	)
	assertNoError(t, err)

	if !result.Allowed {
		t.Error("expected allowed with empty fallback policy")
	}
}

func TestVerifyMalformedExcludePattern(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePolicy(t, dir, "default.json", `{
		"exclude": ["valid-pattern*"],
		"trust": {
			"builders": [{"id": "test", "maxLevel": 3}]
		},
		"provenance": {"missingPolicy": "allow"}
	}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir

	v, err := verifier.New(cfg, metrics.New())
	assertNoError(t, err)

	result, err := v.Verify(
		context.Background(), "nginx:latest", "sha256:abc", "default",
	)
	assertNoError(t, err)

	if !result.Allowed {
		t.Error("expected allowed")
	}
}

func TestVerifyNewWithDisabledSkipsPolicyLoad(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.PolicyDir = "/nonexistent/path"

	v, err := verifier.New(cfg, metrics.New())
	assertNoError(t, err)

	result, err := v.Verify(
		context.Background(), "nginx:latest", "sha256:abc", "default",
	)
	assertNoError(t, err)

	if !result.Allowed {
		t.Error("expected allowed when disabled")
	}
}

func TestReload(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePolicy(t, dir, "default.json", `{}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir

	verif, err := verifier.New(cfg, metrics.New())
	assertNoError(t, err)

	newCfg := config.DefaultConfig()
	newCfg.Verification = config.ModeEnforce
	newCfg.PolicyDir = dir

	assertNoError(t, verif.Reload(newCfg))
}

func TestReloadError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePolicy(t, dir, "default.json", `{}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir

	verif, err := verifier.New(cfg, metrics.New())
	assertNoError(t, err)

	badDir := t.TempDir()
	writePolicy(t, badDir, "bad.json", `{invalid json}`)

	badCfg := config.DefaultConfig()
	badCfg.Verification = config.ModeEnforce
	badCfg.PolicyDir = badDir

	err = verif.Reload(badCfg)
	if err == nil {
		t.Error("expected error reloading with invalid policy")
	}
}

func TestReloadDisabled(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePolicy(t, dir, "default.json", `{}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir

	verif, err := verifier.New(cfg, metrics.New())
	assertNoError(t, err)

	disabledCfg := config.DefaultConfig()
	assertNoError(t, verif.Reload(disabledCfg))

	result, err := verif.Verify(
		context.Background(), "nginx:latest", "sha256:abc", "default",
	)
	assertNoError(t, err)

	if !result.Allowed {
		t.Error("expected allowed after reload to disabled")
	}
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

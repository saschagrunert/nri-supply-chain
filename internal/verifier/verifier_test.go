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
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

func TestNewFetcher(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()

	fetcher := verifier.NewFetcher(cfg)
	if fetcher == nil {
		t.Fatal("expected non-nil OCIFetcher from NewFetcher")
	}
}

func TestVerify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		imageRef    string
		setupDir    func(t *testing.T) string
		mode        config.VerificationMode
		wantAllowed bool
		wantErr     error
	}{
		{
			name:     "disabled mode allows",
			imageRef: "",
			setupDir: func(_ *testing.T) string {
				return ""
			},
			mode:        config.ModeDisabled,
			wantAllowed: true,
			wantErr:     nil,
		},
		{
			name:     "warn mode allows with deny policy",
			imageRef: "",
			setupDir: func(t *testing.T) string {
				t.Helper()

				dir := t.TempDir()
				writePolicy(t, dir, "default.json", `{
					"trust": {"builders": [{"id": "test", "maxLevel": 2}]},
					"provenance": {"missingPolicy": "deny"}
				}`)

				return dir
			},
			mode:        config.ModeWarn,
			wantAllowed: true,
			wantErr:     nil,
		},
		{
			name:     "enforce mode rejects with deny policy",
			imageRef: "",
			setupDir: func(t *testing.T) string {
				t.Helper()

				dir := t.TempDir()
				writePolicy(t, dir, "default.json", `{
					"trust": {"builders": [{"id": "test", "maxLevel": 2}]},
					"provenance": {"missingPolicy": "deny"}
				}`)

				return dir
			},
			mode:        config.ModeEnforce,
			wantAllowed: false,
			wantErr:     verifier.ErrVerificationFailed,
		},
		{
			name:     "excluded image allowed",
			imageRef: "gcr.io/internal/app",
			setupDir: func(t *testing.T) string {
				t.Helper()

				dir := t.TempDir()
				writePolicy(t, dir, "default.json", `{
					"exclude": ["gcr.io/internal/*"],
					"trust": {"builders": [{"id": "test", "maxLevel": 3}]},
					"provenance": {"missingPolicy": "deny"}
				}`)

				return dir
			},
			mode:        config.ModeEnforce,
			wantAllowed: true,
			wantErr:     nil,
		},
		{
			name:     "no builders configured allows",
			imageRef: "",
			setupDir: func(t *testing.T) string {
				t.Helper()

				dir := t.TempDir()
				writePolicy(t, dir, "default.json", `{}`)

				return dir
			},
			mode:        config.ModeEnforce,
			wantAllowed: true,
			wantErr:     nil,
		},
		{
			name:     "allow policy allows",
			imageRef: "",
			setupDir: func(t *testing.T) string {
				t.Helper()

				dir := t.TempDir()
				writePolicy(t, dir, "default.json", `{
					"trust": {"builders": [{"id": "test", "maxLevel": 3}]},
					"provenance": {"missingPolicy": "allow"}
				}`)

				return dir
			},
			mode:        config.ModeEnforce,
			wantAllowed: true,
			wantErr:     nil,
		},
		{
			name:     "warn policy allows with reason",
			imageRef: "",
			setupDir: func(t *testing.T) string {
				t.Helper()

				dir := t.TempDir()
				writePolicy(t, dir, "default.json", `{
					"trust": {"builders": [{"id": "test", "maxLevel": 3}]},
					"provenance": {"missingPolicy": "warn"}
				}`)

				return dir
			},
			mode:        config.ModeEnforce,
			wantAllowed: true,
			wantErr:     nil,
		},
		{
			name:     "fallback empty policy denies in enforce",
			imageRef: "",
			setupDir: func(t *testing.T) string {
				t.Helper()

				return t.TempDir()
			},
			mode:        config.ModeEnforce,
			wantAllowed: false,
			wantErr:     verifier.ErrVerificationFailed,
		},
		{
			name:     "fallback empty policy allows in warn",
			imageRef: "",
			setupDir: func(t *testing.T) string {
				t.Helper()

				return t.TempDir()
			},
			mode:        config.ModeWarn,
			wantAllowed: true,
			wantErr:     nil,
		},
		{
			name:     "VEX deny policy rejects",
			imageRef: "",
			setupDir: func(t *testing.T) string {
				t.Helper()

				dir := t.TempDir()
				writePolicy(t, dir, "default.json", `{
					"provenance": {"missingPolicy": "allow"},
					"vex": {"missingPolicy": "deny"}
				}`)

				return dir
			},
			mode:        config.ModeEnforce,
			wantAllowed: false,
			wantErr:     verifier.ErrVerificationFailed,
		},
		{
			name:     "disabled skips nonexistent policy dir",
			imageRef: "",
			setupDir: func(_ *testing.T) string {
				return "/nonexistent/path"
			},
			mode:        config.ModeDisabled,
			wantAllowed: true,
			wantErr:     nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			dir := test.setupDir(t)

			cfg := config.DefaultConfig()
			cfg.Verification = test.mode

			if dir != "" {
				cfg.PolicyDir = dir
			}

			imageRef := test.imageRef
			if imageRef == "" {
				imageRef = "nginx:latest"
			}

			verif, err := verifier.New(cfg, metrics.New(), nil)
			testutil.AssertNoError(t, err)

			result, err := verif.Verify(
				context.Background(), imageRef, "sha256:abc", "default",
			)

			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) {
					t.Errorf("expected error %v, got %v", test.wantErr, err)
				}

				return
			}

			testutil.AssertNoError(t, err)

			if result.Allowed != test.wantAllowed {
				t.Errorf("expected allowed=%v, got allowed=%v (reason: %s)",
					test.wantAllowed, result.Allowed, result.Reason)
			}
		})
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

	verif, err := verifier.New(cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)

	result1, err := verif.Verify(
		context.Background(), "nginx:latest", "sha256:abc", "default",
	)
	testutil.AssertNoError(t, err)

	result2, err := verif.Verify(
		context.Background(), "nginx:latest", "sha256:abc", "default",
	)
	testutil.AssertNoError(t, err)

	if result1.Reason != result2.Reason {
		t.Errorf("expected cached result to match: %q vs %q",
			result1.Reason, result2.Reason)
	}
}

func TestVerifyCacheWarnMode(t *testing.T) {
	t.Parallel()

	// Warn mode with deny policy: the underlying check fails (no provenance),
	// but warn mode overrides to Allowed=true. The cached result must also
	// be Allowed=true on subsequent lookups.
	dir := t.TempDir()
	writePolicy(t, dir, "default.json", `{
		"trust": {"builders": [{"id": "test", "maxLevel": 2}]},
		"provenance": {"missingPolicy": "deny"}
	}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir
	cfg.CacheTTL = config.Duration{Duration: time.Hour}

	verif, err := verifier.New(cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)

	result1, err := verif.Verify(
		context.Background(), "nginx:latest", "sha256:warn-cache", "default",
	)
	testutil.AssertNoError(t, err)

	if !result1.Allowed {
		t.Fatalf("first call: expected Allowed=true in warn mode, got false (reason: %s)",
			result1.Reason)
	}

	result2, err := verif.Verify(
		context.Background(), "nginx:latest", "sha256:warn-cache", "default",
	)
	testutil.AssertNoError(t, err)

	if !result2.Allowed {
		t.Fatalf(
			"second call (cache hit): expected Allowed=true in warn mode, got false (reason: %s)",
			result2.Reason,
		)
	}

	if result1.Reason != result2.Reason {
		t.Errorf("expected cached reason to match: %q vs %q",
			result1.Reason, result2.Reason)
	}
}

func TestVerifyCacheEnforceMode(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePolicy(t, dir, "default.json", `{
		"trust": {"builders": [{"id": "test", "maxLevel": 2}]},
		"provenance": {"missingPolicy": "deny"}
	}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.PolicyDir = dir
	cfg.CacheTTL = config.Duration{Duration: time.Hour}

	verif, err := verifier.New(cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)

	_, err = verif.Verify(
		context.Background(), "nginx:latest", "sha256:enforce-cache", "default",
	)

	if !errors.Is(err, verifier.ErrVerificationFailed) {
		t.Fatalf("first call: expected ErrVerificationFailed, got %v", err)
	}

	_, err = verif.Verify(
		context.Background(), "nginx:latest", "sha256:enforce-cache", "default",
	)

	if !errors.Is(err, verifier.ErrVerificationFailed) {
		t.Fatalf(
			"second call (cache hit): expected ErrVerificationFailed, got %v", err,
		)
	}
}

func TestVerifyNamespacePolicy(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePolicy(t, dir, "default.json", `{
		"trust": {"builders": [{"id": "test", "maxLevel": 3}]},
		"provenance": {"missingPolicy": "deny"}
	}`)
	writePolicy(t, dir, "staging.json", `{
		"provenance": {"missingPolicy": "allow"}
	}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.PolicyDir = dir

	verif, err := verifier.New(cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)

	_, err = verif.Verify(
		context.Background(), "nginx:latest", "sha256:abc", "default",
	)
	if err == nil {
		t.Error("expected error for default namespace")
	}

	result, err := verif.Verify(
		context.Background(), "nginx:latest", "sha256:def", "staging",
	)
	testutil.AssertNoError(t, err)

	if !result.Allowed {
		t.Error("expected allowed for staging namespace")
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		setup   func(t *testing.T) *config.Config
		wantErr bool
	}{
		{
			name: "invalid policy",
			setup: func(t *testing.T) *config.Config {
				t.Helper()

				dir := t.TempDir()
				writePolicy(t, dir, "bad.json", `{invalid json}`)

				cfg := config.DefaultConfig()
				cfg.Verification = config.ModeWarn
				cfg.PolicyDir = dir

				return cfg
			},
			wantErr: true,
		},
		{
			name: "disabled skips policy load",
			setup: func(_ *testing.T) *config.Config {
				cfg := config.DefaultConfig()
				cfg.PolicyDir = "/nonexistent/path"

				return cfg
			},
			wantErr: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cfg := test.setup(t)
			_, err := verifier.New(cfg, metrics.New(), nil)

			if test.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestReload(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		newCfg  func(t *testing.T) *config.Config
		wantErr bool
	}{
		{
			name: "success",
			newCfg: func(t *testing.T) *config.Config {
				t.Helper()

				dir := t.TempDir()
				writePolicy(t, dir, "default.json", `{}`)

				cfg := config.DefaultConfig()
				cfg.Verification = config.ModeEnforce
				cfg.PolicyDir = dir

				return cfg
			},
			wantErr: false,
		},
		{
			name: "invalid policy",
			newCfg: func(t *testing.T) *config.Config {
				t.Helper()

				dir := t.TempDir()
				writePolicy(t, dir, "bad.json", `{invalid json}`)

				cfg := config.DefaultConfig()
				cfg.Verification = config.ModeEnforce
				cfg.PolicyDir = dir

				return cfg
			},
			wantErr: true,
		},
		{
			name: "reload to disabled",
			newCfg: func(_ *testing.T) *config.Config {
				return config.DefaultConfig()
			},
			wantErr: false,
		},
		{
			name: "creates new fetcher",
			newCfg: func(t *testing.T) *config.Config {
				t.Helper()

				dir := t.TempDir()
				writePolicy(t, dir, "default.json", `{}`)

				cfg := config.DefaultConfig()
				cfg.Verification = config.ModeWarn
				cfg.PolicyDir = dir

				return cfg
			},
			wantErr: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			writePolicy(t, dir, "default.json", `{}`)

			cfg := config.DefaultConfig()
			cfg.Verification = config.ModeWarn
			cfg.PolicyDir = dir

			verif, err := verifier.New(cfg, metrics.New(), nil)
			testutil.AssertNoError(t, err)

			newCfg := test.newCfg(t)
			err = verif.Reload(t.Context(), newCfg)

			if test.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				return
			}

			testutil.AssertNoError(t, err)
		})
	}
}

func TestReloadPreservesCacheWhenConfigUnchanged(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePolicy(t, dir, "default.json", `{}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir
	cfg.CacheTTL = config.Duration{Duration: time.Hour}

	verif, err := verifier.New(cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)

	result1, err := verif.Verify(
		context.Background(), "nginx:latest", "sha256:preserve", "default",
	)
	testutil.AssertNoError(t, err)

	reloadCfg := config.DefaultConfig()
	reloadCfg.Verification = config.ModeWarn
	reloadCfg.PolicyDir = dir
	reloadCfg.CacheTTL = config.Duration{Duration: time.Hour}

	err = verif.Reload(t.Context(), reloadCfg)
	testutil.AssertNoError(t, err)

	result2, err := verif.Verify(
		context.Background(), "nginx:latest", "sha256:preserve", "default",
	)
	testutil.AssertNoError(t, err)

	if result1.Reason != result2.Reason {
		t.Errorf("expected cached result to survive reload: %q vs %q",
			result1.Reason, result2.Reason)
	}
}

func TestReloadClearsCacheWhenCacheFailureTTLChanges(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePolicy(t, dir, "default.json", `{}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir
	cfg.CacheTTL = config.Duration{Duration: time.Hour}
	cfg.CacheFailureTTL = config.Duration{Duration: 5 * time.Minute}

	// Verify that changing only CacheFailureTTL is detected.
	changed := config.DefaultConfig()
	changed.Verification = cfg.Verification
	changed.PolicyDir = cfg.PolicyDir
	changed.CacheTTL = cfg.CacheTTL
	changed.CacheFailureTTL = config.Duration{Duration: 10 * time.Minute}
	changed.FetchFailurePolicy = cfg.FetchFailurePolicy
	changed.FetchTimeout = cfg.FetchTimeout

	if !verifier.ExportCacheAffectingFieldsChanged(cfg, changed) {
		t.Error("expected cache invalidation when CacheFailureTTL changes")
	}

	// Confirm no invalidation when CacheFailureTTL is the same.
	same := config.DefaultConfig()
	same.Verification = cfg.Verification
	same.PolicyDir = cfg.PolicyDir
	same.CacheTTL = cfg.CacheTTL
	same.CacheFailureTTL = cfg.CacheFailureTTL
	same.FetchFailurePolicy = cfg.FetchFailurePolicy
	same.FetchTimeout = cfg.FetchTimeout

	if verifier.ExportCacheAffectingFieldsChanged(cfg, same) {
		t.Error("expected no cache invalidation when CacheFailureTTL is unchanged")
	}
}

func TestReloadClearsCacheWhenPolicyChanges(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePolicy(t, dir, "default.json", `{}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir
	cfg.CacheTTL = config.Duration{Duration: time.Hour}

	verif, err := verifier.New(cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)

	result1, err := verif.Verify(
		context.Background(), "nginx:latest", "sha256:polchange", "default",
	)
	testutil.AssertNoError(t, err)

	writePolicy(t, dir, "default.json", `{"provenance":{"missingPolicy":"deny"}}`)

	reloadCfg := config.DefaultConfig()
	reloadCfg.Verification = config.ModeWarn
	reloadCfg.PolicyDir = dir
	reloadCfg.CacheTTL = config.Duration{Duration: time.Hour}

	err = verif.Reload(t.Context(), reloadCfg)
	testutil.AssertNoError(t, err)

	result2, err := verif.Verify(
		context.Background(), "nginx:latest", "sha256:polchange", "default",
	)
	testutil.AssertNoError(t, err)

	if result1.Reason == result2.Reason {
		t.Error("expected cache to be cleared after policy change")
	}
}

const testDockerNginx = "docker.io/library/nginx:latest"

func TestBuildDigestRef(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		imageRef string
		digest   string
		expected string
	}{
		{
			name:     "empty digest returns imageRef",
			imageRef: testDockerNginx,
			digest:   "",
			expected: testDockerNginx,
		},
		{
			name:     "imageRef already has digest",
			imageRef: "docker.io/library/nginx@sha256:abc123",
			digest:   "sha256:def456",
			expected: "docker.io/library/nginx@sha256:abc123",
		},
		{
			name:     "appends digest to tag ref",
			imageRef: testDockerNginx,
			digest:   "sha256:abc123",
			expected: "index.docker.io/library/nginx@sha256:abc123",
		},
		{
			name:     "invalid imageRef returns original",
			imageRef: ":::invalid",
			digest:   "sha256:abc123",
			expected: ":::invalid",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := verifier.ExportBuildDigestRef(test.imageRef, test.digest)
			if got != test.expected {
				t.Errorf("expected %q, got %q", test.expected, got)
			}
		})
	}
}

func TestReady(t *testing.T) {
	t.Parallel()

	t.Run("disabled mode is ready", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()

		verif, err := verifier.New(cfg, metrics.New(), nil)
		testutil.AssertNoError(t, err)

		ready, reason := verif.Ready()
		if !ready {
			t.Errorf("expected ready=true for disabled mode, got reason=%q", reason)
		}
	})

	t.Run("enabled with policies is ready", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		writePolicy(t, dir, "default.json", `{}`)

		cfg := config.DefaultConfig()
		cfg.Verification = config.ModeWarn
		cfg.PolicyDir = dir

		verif, err := verifier.New(cfg, metrics.New(), nil)
		testutil.AssertNoError(t, err)

		ready, reason := verif.Ready()
		if !ready {
			t.Errorf("expected ready=true, got reason=%q", reason)
		}
	})

	t.Run("enabled with no policies is not ready", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()

		cfg := config.DefaultConfig()
		cfg.Verification = config.ModeWarn
		cfg.PolicyDir = dir

		verif, err := verifier.New(cfg, metrics.New(), nil)
		testutil.AssertNoError(t, err)

		ready, reason := verif.Ready()
		if ready {
			t.Error("expected ready=false when enabled with no policies")
		}

		if reason != "no policies loaded" {
			t.Errorf("expected reason %q, got %q", "no policies loaded", reason)
		}
	})
}

func TestResultHasFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		result   *types.Result
		expected bool
	}{
		{
			name: "allowed result has no failures",
			result: &types.Result{
				Allowed:      true,
				Reason:       "ok",
				CheckResults: nil,
			},
			expected: false,
		},
		{
			name: "disallowed result has failures",
			result: &types.Result{
				Allowed:      false,
				Reason:       "denied",
				CheckResults: nil,
			},
			expected: true,
		},
		{
			name: "allowed with failed check has failures",
			result: &types.Result{
				Allowed: true,
				Reason:  "partial",
				CheckResults: []types.CheckResult{
					{Type: "slsa", Passed: false, Status: types.StatusFail, Detail: "err"},
				},
			},
			expected: true,
		},
		{
			name: "allowed with passing checks has no failures",
			result: &types.Result{
				Allowed: true,
				Reason:  "ok",
				CheckResults: []types.CheckResult{
					{Type: "slsa", Passed: true, Status: types.StatusPass, Detail: "ok"},
				},
			},
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := verifier.ExportResultHasFailures(test.result)
			if got != test.expected {
				t.Errorf("expected %v, got %v", test.expected, got)
			}
		})
	}
}

func TestWarnEnforceDefaultsDoesNotPanicForWarnMode(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn

	policies := map[string]*policy.Policy{
		"": {},
	}

	// Should not panic; no warnings emitted for non-enforce mode.
	verifier.WarnEnforceDefaults(cfg, policies)
}

func TestWarnEnforceDefaultsEmitsForEnforceMode(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce

	policies := map[string]*policy.Policy{
		"": {},
	}

	// Should not panic; warnings are emitted but we just verify it runs.
	verifier.WarnEnforceDefaults(cfg, policies)
}

func TestEnforcing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		mode     config.VerificationMode
		expected bool
	}{
		{name: "disabled", mode: config.ModeDisabled, expected: false},
		{name: "warn", mode: config.ModeWarn, expected: false},
		{name: "enforce", mode: config.ModeEnforce, expected: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cfg := config.DefaultConfig()
			cfg.Verification = test.mode

			verif, err := verifier.New(cfg, metrics.New(), nil)
			testutil.AssertNoError(t, err)

			if got := verif.Enforcing(); got != test.expected {
				t.Errorf("expected %v, got %v", test.expected, got)
			}
		})
	}
}

func TestHandleMissingAttestationUnknownPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		pol        policy.Action
		wantPassed bool
		wantStatus string
	}{
		{
			name:       "allow policy passes",
			pol:        policy.ActionAllow,
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name:       "warn policy passes with warn status",
			pol:        policy.ActionWarn,
			wantPassed: true,
			wantStatus: types.StatusWarn,
		},
		{
			name:       "deny policy fails",
			pol:        policy.ActionDeny,
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name:       "unknown policy defaults to deny",
			pol:        "invalid-value",
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name:       "empty policy defaults to deny",
			pol:        "",
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name:       "random string defaults to deny",
			pol:        "something-unexpected",
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			result := verifier.ExportHandleMissingAttestation(
				test.pol, "test_check", "test detail",
			)

			if result.Passed != test.wantPassed {
				t.Errorf("expected Passed=%v, got %v", test.wantPassed, result.Passed)
			}

			if result.Status != test.wantStatus {
				t.Errorf("expected Status=%q, got %q", test.wantStatus, result.Status)
			}

			if result.Type != "test_check" {
				t.Errorf("expected Type=%q, got %q", "test_check", result.Type)
			}
		})
	}
}

func writePolicy(t *testing.T, dir, name, content string) {
	t.Helper()

	err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600)
	if err != nil {
		t.Fatalf("writing policy: %v", err)
	}
}

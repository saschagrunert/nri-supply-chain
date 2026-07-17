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

package config_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/policy"
)

func TestDefaultConfig(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()

	assertEqual(t, config.ModeDisabled, cfg.Verification)
	assertEqual(t, 30*time.Second, cfg.FetchTimeout.Duration)
	assertEqual(t, policy.ActionWarn, cfg.FetchFailurePolicy)
	assertEqual(t, 24*time.Hour, cfg.CacheTTL.Duration)
	assertEqual(t, "/etc/nri-supply-chain/policies", cfg.PolicyDir)
	assertEqual(t, "127.0.0.1:9090", cfg.MetricsAddr)
}

func TestConfigEnabled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		mode     string
		expected bool
	}{
		{name: config.ModeDisabled, mode: config.ModeDisabled, expected: false},
		{name: config.ModeWarn, mode: config.ModeWarn, expected: true},
		{name: config.ModeEnforce, mode: config.ModeEnforce, expected: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cfg := config.DefaultConfig()
			cfg.Verification = test.mode

			assertEqual(t, test.expected, cfg.Enabled())
		})
	}
}

func TestConfigValidateDefaults(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		modify      func(*config.Config)
		wantErr     bool
		expectedErr error
	}{
		{
			name:        "default is valid",
			modify:      func(_ *config.Config) {},
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name:        "invalid verification mode",
			modify:      func(c *config.Config) { c.Verification = "invalid" },
			wantErr:     true,
			expectedErr: config.ErrInvalidVerificationMode,
		},
		{
			name: "warn mode valid",
			modify: func(c *config.Config) {
				c.Verification = config.ModeWarn
				c.PolicyDir = "/tmp/policies"
			},
			wantErr:     false,
			expectedErr: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cfg := config.DefaultConfig()
			test.modify(cfg)

			err := cfg.Validate()
			if test.wantErr && err == nil {
				t.Error("expected error, got nil")
			}

			if !test.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if test.expectedErr != nil && !errors.Is(err, test.expectedErr) {
				t.Errorf("expected error %v, got %v", test.expectedErr, err)
			}
		})
	}
}

func TestConfigValidateEnabledPolicies(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		modify      func(*config.Config)
		wantErr     bool
		expectedErr error
	}{
		{
			name: "invalid fetch failure policy",
			modify: func(c *config.Config) {
				c.Verification = config.ModeWarn
				c.FetchFailurePolicy = "invalid"
			},
			wantErr:     true,
			expectedErr: policy.ErrInvalidAction,
		},
		{
			name: "zero fetch timeout",
			modify: func(c *config.Config) {
				c.Verification = config.ModeWarn
				c.FetchTimeout = config.Duration{Duration: 0}
			},
			wantErr:     true,
			expectedErr: config.ErrFetchTimeoutNotPositive,
		},
		{
			name: "negative cache TTL",
			modify: func(c *config.Config) {
				c.Verification = config.ModeWarn
				c.CacheTTL = config.Duration{Duration: -1 * time.Second}
			},
			wantErr:     true,
			expectedErr: config.ErrCacheTTLNegative,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cfg := config.DefaultConfig()
			test.modify(cfg)

			err := cfg.Validate()
			if test.wantErr && err == nil {
				t.Error("expected error, got nil")
			}

			if !test.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if test.expectedErr != nil && !errors.Is(err, test.expectedErr) {
				t.Errorf("expected error %v, got %v", test.expectedErr, err)
			}
		})
	}
}

func TestConfigValidateEnabledPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		modify      func(*config.Config)
		wantErr     bool
		expectedErr error
	}{
		{
			name: "empty policy dir when enabled",
			modify: func(c *config.Config) {
				c.Verification = config.ModeWarn
				c.PolicyDir = ""
			},
			wantErr:     true,
			expectedErr: config.ErrPolicyDirEmpty,
		},
		{
			name: "relative policy dir",
			modify: func(c *config.Config) {
				c.Verification = config.ModeWarn
				c.PolicyDir = "relative/path"
			},
			wantErr:     true,
			expectedErr: config.ErrPolicyDirNotAbsolute,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cfg := config.DefaultConfig()
			test.modify(cfg)

			err := cfg.Validate()
			if test.wantErr && err == nil {
				t.Error("expected error, got nil")
			}

			if !test.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if test.expectedErr != nil && !errors.Is(err, test.expectedErr) {
				t.Errorf("expected error %v, got %v", test.expectedErr, err)
			}
		})
	}
}

func TestConfigValidateRuntime(t *testing.T) {
	t.Parallel()

	t.Run("disabled skips runtime checks", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		assertNoError(t, cfg.ValidateRuntime())
	})

	t.Run("existing directory passes", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()

		cfg := config.DefaultConfig()
		cfg.Verification = config.ModeWarn
		cfg.PolicyDir = dir

		assertNoError(t, cfg.ValidateRuntime())
	})

	t.Run("missing directory fails", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Verification = config.ModeWarn
		cfg.PolicyDir = "/nonexistent/path"

		assertError(t, cfg.ValidateRuntime())
	})

	t.Run("file instead of directory fails", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		filePath := filepath.Join(dir, "not-a-dir")
		assertNoError(t, os.WriteFile(filePath, []byte(""), 0o600))

		cfg := config.DefaultConfig()
		cfg.Verification = config.ModeWarn
		cfg.PolicyDir = filePath

		err := cfg.ValidateRuntime()
		assertError(t, err)

		if !errors.Is(err, config.ErrPolicyDirNotDirectory) {
			t.Errorf("expected error %v, got %v", config.ErrPolicyDirNotDirectory, err)
		}
	})
}

func TestLoadFromFile(t *testing.T) {
	t.Parallel()

	t.Run("valid config", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "config.toml")

		policyDir := filepath.Join(dir, "policies")
		assertNoError(t, os.MkdirAll(policyDir, 0o750))

		content := `verification = "warn"
fetch_timeout = "10s"
fetch_failure_policy = "deny"
cache_ttl = "1h"
policy_dir = "` + policyDir + `"
metrics_addr = ":8080"
`
		assertNoError(t, os.WriteFile(cfgPath, []byte(content), 0o600))

		cfg, err := config.LoadFromFile(cfgPath)
		assertNoError(t, err)

		assertEqual(t, config.ModeWarn, cfg.Verification)
		assertEqual(t, 10*time.Second, cfg.FetchTimeout.Duration)
		assertEqual(t, policy.ActionDeny, cfg.FetchFailurePolicy)
		assertEqual(t, time.Hour, cfg.CacheTTL.Duration)
		assertEqual(t, policyDir, cfg.PolicyDir)
		assertEqual(t, ":8080", cfg.MetricsAddr)
	})

	t.Run("missing file", func(t *testing.T) {
		t.Parallel()

		_, err := config.LoadFromFile("/nonexistent/config.toml")
		assertError(t, err)
	})
}

func TestLoadFromString(t *testing.T) {
	t.Parallel()

	cfg, err := config.LoadFromString(`verification = "enforce"
fetch_timeout = "5s"
policy_dir = "/tmp/policies"
`)
	assertNoError(t, err)
	assertEqual(t, config.ModeEnforce, cfg.Verification)
	assertEqual(t, 5*time.Second, cfg.FetchTimeout.Duration)
}

func TestDurationMarshalText(t *testing.T) {
	t.Parallel()

	dur := config.Duration{Duration: 5 * time.Second}

	text, err := dur.MarshalText()
	assertNoError(t, err)
	assertEqual(t, "5s", string(text))
}

func TestDurationUnmarshalTextError(t *testing.T) {
	t.Parallel()

	var dur config.Duration

	err := dur.UnmarshalText([]byte("not-a-duration"))
	assertError(t, err)
}

func TestLoadFromStringErrors(t *testing.T) {
	t.Parallel()

	t.Run("invalid TOML", func(t *testing.T) {
		t.Parallel()

		_, err := config.LoadFromString(`[[[invalid`)
		assertError(t, err)
	})

	t.Run("validation failure", func(t *testing.T) {
		t.Parallel()

		_, err := config.LoadFromString(`verification = "invalid"`)
		assertError(t, err)

		if !errors.Is(err, config.ErrInvalidVerificationMode) {
			t.Errorf("expected error %v, got %v", config.ErrInvalidVerificationMode, err)
		}
	})
}

func TestLoadFromFileValidationError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")

	content := `verification = "warn"
policy_dir = "relative/path"
`
	assertNoError(t, os.WriteFile(cfgPath, []byte(content), 0o600))

	_, err := config.LoadFromFile(cfgPath)
	assertError(t, err)

	if !errors.Is(err, config.ErrPolicyDirNotAbsolute) {
		t.Errorf("expected error %v, got %v", config.ErrPolicyDirNotAbsolute, err)
	}
}

func assertEqual[T comparable](t *testing.T, expected, actual T) {
	t.Helper()

	if expected != actual {
		t.Errorf("expected %v, got %v", expected, actual)
	}
}

func assertNoError(t *testing.T, err error) {
	t.Helper()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func assertError(t *testing.T, err error) {
	t.Helper()

	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

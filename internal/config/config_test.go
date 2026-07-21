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
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
)

func TestDefaultConfig(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()

	testutil.AssertEqual(t, config.ModeDisabled, cfg.Verification)
	testutil.AssertEqual(t, 30*time.Second, cfg.FetchTimeout.Duration)
	testutil.AssertEqual(t, policy.ActionWarn, cfg.FetchFailurePolicy)
	testutil.AssertEqual(t, 24*time.Hour, cfg.CacheTTL.Duration)
	testutil.AssertEqual(t, 5*time.Minute, cfg.CacheFailureTTL.Duration)
	testutil.AssertEqual(t, "/etc/nri-supply-chain/policies", cfg.PolicyDir)
	testutil.AssertEqual(t, "127.0.0.1:9090", cfg.MetricsAddr)
}

func TestConfigEnabled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		mode     config.VerificationMode
		expected bool
	}{
		{name: string(config.ModeDisabled), mode: config.ModeDisabled, expected: false},
		{name: string(config.ModeWarn), mode: config.ModeWarn, expected: true},
		{name: string(config.ModeEnforce), mode: config.ModeEnforce, expected: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cfg := config.DefaultConfig()
			cfg.Verification = test.mode

			testutil.AssertEqual(t, test.expected, cfg.Enabled())
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
			modify:      func(c *config.Config) { c.Verification = config.VerificationMode("invalid") },
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
				c.FetchFailurePolicy = policy.Action("invalid")
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
		testutil.AssertNoError(t, cfg.ValidateRuntime())
	})

	t.Run("existing directory passes", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()

		cfg := config.DefaultConfig()
		cfg.Verification = config.ModeWarn
		cfg.PolicyDir = dir

		testutil.AssertNoError(t, cfg.ValidateRuntime())
	})

	t.Run("missing directory fails", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Verification = config.ModeWarn
		cfg.PolicyDir = "/nonexistent/path"

		testutil.AssertError(t, cfg.ValidateRuntime())
	})

	t.Run("file instead of directory fails", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		filePath := filepath.Join(dir, "not-a-dir")
		testutil.AssertNoError(t, os.WriteFile(filePath, []byte(""), 0o600))

		cfg := config.DefaultConfig()
		cfg.Verification = config.ModeWarn
		cfg.PolicyDir = filePath

		err := cfg.ValidateRuntime()
		testutil.AssertError(t, err)

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
		testutil.AssertNoError(t, os.MkdirAll(policyDir, 0o750))

		content := `verification = "warn"
fetch_timeout = "10s"
fetch_failure_policy = "deny"
cache_ttl = "1h"
policy_dir = "` + policyDir + `"
metrics_addr = ":8080"
`
		testutil.AssertNoError(t, os.WriteFile(cfgPath, []byte(content), 0o600))

		cfg, err := config.LoadFromFile(cfgPath)
		testutil.AssertNoError(t, err)

		testutil.AssertEqual(t, config.ModeWarn, cfg.Verification)
		testutil.AssertEqual(t, 10*time.Second, cfg.FetchTimeout.Duration)
		testutil.AssertEqual(t, policy.ActionDeny, cfg.FetchFailurePolicy)
		testutil.AssertEqual(t, time.Hour, cfg.CacheTTL.Duration)
		testutil.AssertEqual(t, policyDir, cfg.PolicyDir)
		testutil.AssertEqual(t, ":8080", cfg.MetricsAddr)
	})

	t.Run("missing file", func(t *testing.T) {
		t.Parallel()

		_, err := config.LoadFromFile("/nonexistent/config.toml")
		testutil.AssertError(t, err)
	})
}

func TestLoadFromString(t *testing.T) {
	t.Parallel()

	cfg, err := config.LoadFromString(`verification = "enforce"
fetch_timeout = "5s"
policy_dir = "/tmp/policies"
`)
	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, config.ModeEnforce, cfg.Verification)
	testutil.AssertEqual(t, 5*time.Second, cfg.FetchTimeout.Duration)
}

func TestDurationMarshalText(t *testing.T) {
	t.Parallel()

	dur := config.Duration{Duration: 5 * time.Second}

	text, err := dur.MarshalText()
	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, "5s", string(text))
}

func TestDurationUnmarshalTextError(t *testing.T) {
	t.Parallel()

	var dur config.Duration

	err := dur.UnmarshalText([]byte("not-a-duration"))
	testutil.AssertError(t, err)
}

func TestLoadFromStringErrors(t *testing.T) {
	t.Parallel()

	t.Run("invalid TOML", func(t *testing.T) {
		t.Parallel()

		_, err := config.LoadFromString(`[[[invalid`)
		testutil.AssertError(t, err)
	})

	t.Run("validation failure", func(t *testing.T) {
		t.Parallel()

		_, err := config.LoadFromString(`verification = "invalid"`)
		testutil.AssertError(t, err)

		if !errors.Is(err, config.ErrInvalidVerificationMode) {
			t.Errorf("expected error %v, got %v", config.ErrInvalidVerificationMode, err)
		}
	})
}

func TestConfigValidateMetricsAddr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{name: "default is valid", addr: "127.0.0.1:9090", wantErr: false},
		{name: "port only", addr: ":8080", wantErr: false},
		{name: "ipv6 localhost", addr: "[::1]:9090", wantErr: false},
		{name: "empty is valid", addr: "", wantErr: false},
		{name: "missing port", addr: "127.0.0.1", wantErr: true},
		{name: "bare hostname", addr: "localhost", wantErr: true},
		{name: "garbage", addr: "not-an-address", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cfg := config.DefaultConfig()
			cfg.MetricsAddr = test.addr

			err := cfg.Validate()
			if test.wantErr && err == nil {
				t.Error("expected error, got nil")
			}

			if !test.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if test.wantErr && err != nil {
				if !errors.Is(err, config.ErrInvalidMetricsAddr) {
					t.Errorf("expected ErrInvalidMetricsAddr, got %v", err)
				}
			}
		})
	}
}

func TestConfigValidateCircuitBreakerThreshold(t *testing.T) {
	t.Parallel()

	t.Run("negative", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Verification = config.ModeWarn
		cfg.CircuitBreakerThreshold = -1

		err := cfg.Validate()
		if !errors.Is(err, config.ErrCircuitBreakerThreshold) {
			t.Errorf("expected ErrCircuitBreakerThreshold, got %v", err)
		}
	})

	t.Run("zero", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Verification = config.ModeWarn
		cfg.CircuitBreakerThreshold = 0

		err := cfg.Validate()
		if !errors.Is(err, config.ErrCircuitBreakerThreshold) {
			t.Errorf("expected ErrCircuitBreakerThreshold, got %v", err)
		}
	})
}

func TestConfigValidateCircuitBreakerCooldown(t *testing.T) {
	t.Parallel()

	t.Run("zero", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Verification = config.ModeWarn
		cfg.CircuitBreakerCooldown = config.Duration{Duration: 0}

		err := cfg.Validate()
		if !errors.Is(err, config.ErrCircuitBreakerCooldown) {
			t.Errorf("expected ErrCircuitBreakerCooldown, got %v", err)
		}
	})

	t.Run("negative", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Verification = config.ModeWarn
		cfg.CircuitBreakerCooldown = config.Duration{
			Duration: -1 * time.Second,
		}

		err := cfg.Validate()
		if !errors.Is(err, config.ErrCircuitBreakerCooldown) {
			t.Errorf("expected ErrCircuitBreakerCooldown, got %v", err)
		}
	})
}

func TestConfigValidateCacheFailureTTL(t *testing.T) {
	t.Parallel()

	t.Run("negative cache failure TTL rejected", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Verification = config.ModeWarn
		cfg.CacheFailureTTL = config.Duration{Duration: -1 * time.Second}

		err := cfg.Validate()
		if !errors.Is(err, config.ErrCacheFailureTTLNegative) {
			t.Errorf("expected ErrCacheFailureTTLNegative, got %v", err)
		}
	})

	t.Run("zero cache failure TTL is valid (disables short caching)", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Verification = config.ModeWarn
		cfg.CacheFailureTTL = config.Duration{Duration: 0}

		testutil.AssertNoError(t, cfg.Validate())
	})

	t.Run("positive cache failure TTL is valid", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Verification = config.ModeWarn
		cfg.CacheFailureTTL = config.Duration{Duration: 5 * time.Minute}

		testutil.AssertNoError(t, cfg.Validate())
	})
}

func TestConfigValidateFetchRateLimit(t *testing.T) {
	t.Parallel()

	t.Run("negative rate limit rejected", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Verification = config.ModeWarn
		cfg.FetchRateLimit = -1.0

		err := cfg.Validate()
		if !errors.Is(err, config.ErrFetchRateLimitNegative) {
			t.Errorf("expected ErrFetchRateLimitNegative, got %v", err)
		}
	})

	t.Run("zero rate limit is valid (unlimited)", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Verification = config.ModeWarn

		testutil.AssertNoError(t, cfg.Validate())
	})

	t.Run("positive rate limit is valid", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Verification = config.ModeWarn
		cfg.FetchRateLimit = 50.0

		testutil.AssertNoError(t, cfg.Validate())
	})
}

func TestConfigValidateLogLevel(t *testing.T) {
	t.Parallel()

	t.Run("valid levels", func(t *testing.T) {
		t.Parallel()

		for _, level := range []string{"debug", "info", "warn", "error"} {
			t.Run(level, func(t *testing.T) {
				t.Parallel()

				cfg := config.DefaultConfig()
				cfg.LogLevel = level

				testutil.AssertNoError(t, cfg.Validate())
			})
		}
	})

	t.Run("empty is valid", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		testutil.AssertNoError(t, cfg.Validate())
	})

	t.Run("invalid level", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.LogLevel = "invalid"

		err := cfg.Validate()
		if !errors.Is(err, config.ErrInvalidLogLevel) {
			t.Errorf("expected ErrInvalidLogLevel, got %v", err)
		}
	})
}

func TestLoadFromStringLogLevel(t *testing.T) {
	t.Parallel()

	cfg, err := config.LoadFromString(`log_level = "debug"`)
	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, "debug", cfg.LogLevel)
}

func TestLoadFromFileUnknownKeys(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")

	content := `verification = "disabled"
unknown_key = "value"
`
	testutil.AssertNoError(t, os.WriteFile(cfgPath, []byte(content), 0o600))

	_, err := config.LoadFromFile(cfgPath)
	testutil.AssertError(t, err)

	if !errors.Is(err, config.ErrUnknownConfigKeys) {
		t.Errorf("expected error %v, got %v", config.ErrUnknownConfigKeys, err)
	}
}

func TestLoadFromStringUnknownKeys(t *testing.T) {
	t.Parallel()

	_, err := config.LoadFromString(`unknown_field = "test"`)
	testutil.AssertError(t, err)

	if !errors.Is(err, config.ErrUnknownConfigKeys) {
		t.Errorf("expected error %v, got %v", config.ErrUnknownConfigKeys, err)
	}
}

func TestLoadFromFileValidationError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")

	content := `verification = "warn"
policy_dir = "relative/path"
`
	testutil.AssertNoError(t, os.WriteFile(cfgPath, []byte(content), 0o600))

	_, err := config.LoadFromFile(cfgPath)
	testutil.AssertError(t, err)

	if !errors.Is(err, config.ErrPolicyDirNotAbsolute) {
		t.Errorf("expected error %v, got %v", config.ErrPolicyDirNotAbsolute, err)
	}
}

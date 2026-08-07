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
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	testTUFMirrorURL                         = "https://tuf.example.com"
	testTUFRootPath                          = "/etc/sigstore/root.json"
	testXExampleURL                          = "https://x.example.com"
	testModeUnknown  config.VerificationMode = "unknown"
)

const (
	testPrefixDockerIO = "docker.io"
	testPrefixGHCR     = "ghcr.io"
)

const (
	testRegistryGHCR   = "ghcr.io"
	testMirrorInternal = "mirror.internal"
	testOCIRef         = "ghcr.io/myorg/policies:v1"
	testIssuerGoogle   = "https://accounts.google.com"
	testKeyPath        = "/etc/keys/policy.pub"
	testSANPattern     = "*@example.com"
)

func TestDefaultConfig(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()

	testutil.AssertEqual(t, config.LatestConfigVersion, cfg.ConfigVersion)
	testutil.AssertEqual(t, config.ModeDisabled, cfg.Verification)
	testutil.AssertEqual(t, 30*time.Second, cfg.FetchTimeout.Duration)
	testutil.AssertEqual(t, 1*time.Second, cfg.DigestResolveTimeout.Duration)
	testutil.AssertEqual(t, types.ActionWarn, cfg.FetchFailurePolicy)
	testutil.AssertEqual(t, 24*time.Hour, cfg.CacheTTL.Duration)
	testutil.AssertEqual(t, 5*time.Minute, cfg.CacheFailureTTL.Duration)
	testutil.AssertEqual(t, "/etc/nri-supply-chain/policies", cfg.PolicyDir)
	testutil.AssertEqual(t, "127.0.0.1:9090", cfg.MetricsAddr)
	testutil.AssertEqual(t, int64(10<<20), cfg.MaxAttestationSize)
	testutil.AssertEqual(t, 10_000, cfg.CacheMaxEntries)
}

func TestConfigVersionOmittedDefaultsToOne(t *testing.T) {
	t.Parallel()

	cfg, err := config.LoadFromString(``)
	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, config.LatestConfigVersion, cfg.ConfigVersion)
}

func TestConfigVersionExplicitZero(t *testing.T) {
	t.Parallel()

	cfg, err := config.LoadFromString("config_version = 0")
	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, 1, cfg.ConfigVersion)
}

func TestConfigVersionExplicitOne(t *testing.T) {
	t.Parallel()

	cfg, err := config.LoadFromString(`config_version = 1`)
	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, 1, cfg.ConfigVersion)
}

func TestConfigVersionTooNew(t *testing.T) {
	t.Parallel()

	_, err := config.LoadFromString(`config_version = 999`)
	testutil.AssertErrorIs(t, err, config.ErrConfigVersionTooNew)
}

func TestConfigVersionNegative(t *testing.T) {
	t.Parallel()

	_, err := config.LoadFromString(`config_version = -1`)
	testutil.AssertErrorIs(t, err, config.ErrInvalidConfigVersion)
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
				c.FetchFailurePolicy = types.Action("invalid")
			},
			wantErr:     true,
			expectedErr: types.ErrInvalidAction,
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

func TestConfigValidateDigestResolveTimeout(t *testing.T) {
	t.Parallel()

	t.Run("zero rejected", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.DigestResolveTimeout = config.Duration{Duration: 0}

		err := cfg.Validate()
		if !errors.Is(err, config.ErrDigestResolveTimeoutNotPositive) {
			t.Errorf("expected ErrDigestResolveTimeoutNotPositive, got %v", err)
		}
	})

	t.Run("negative rejected", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.DigestResolveTimeout = config.Duration{Duration: -1 * time.Second}

		err := cfg.Validate()
		if !errors.Is(err, config.ErrDigestResolveTimeoutNotPositive) {
			t.Errorf("expected ErrDigestResolveTimeoutNotPositive, got %v", err)
		}
	})

	t.Run("exceeds max rejected", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.DigestResolveTimeout = config.Duration{Duration: 6 * time.Second}

		err := cfg.Validate()
		if !errors.Is(err, config.ErrDigestResolveTimeoutTooHigh) {
			t.Errorf("expected ErrDigestResolveTimeoutTooHigh, got %v", err)
		}
	})

	t.Run("at max is valid", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.DigestResolveTimeout = config.Duration{Duration: 5 * time.Second}

		testutil.AssertNoError(t, cfg.Validate())
	})

	t.Run("positive within range is valid", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.DigestResolveTimeout = config.Duration{Duration: 3 * time.Second}

		testutil.AssertNoError(t, cfg.Validate())
	})
}

func TestLoadFromStringDigestResolveTimeout(t *testing.T) {
	t.Parallel()

	cfg, err := config.LoadFromString(`digest_resolve_timeout = "3s"`)
	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, 3*time.Second, cfg.DigestResolveTimeout.Duration)
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

	t.Run("symlink policy_dir rejected", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		realDir := filepath.Join(dir, "real")
		testutil.AssertNoError(t, os.Mkdir(realDir, 0o750))

		linkDir := filepath.Join(dir, "link")
		testutil.AssertNoError(t, os.Symlink(realDir, linkDir))

		cfg := config.DefaultConfig()
		cfg.Verification = config.ModeWarn
		cfg.PolicyDir = linkDir

		err := cfg.ValidateRuntime()
		if !errors.Is(err, config.ErrSymlinkNotAllowed) {
			t.Errorf("expected ErrSymlinkNotAllowed, got %v", err)
		}
	})

	t.Run("symlink tuf_root rejected", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		realFile := filepath.Join(dir, "root.json")
		testutil.AssertNoError(t, os.WriteFile(realFile, []byte(`{}`), 0o600))

		linkFile := filepath.Join(dir, "root-link.json")
		testutil.AssertNoError(t, os.Symlink(realFile, linkFile))

		cfg := config.DefaultConfig()
		cfg.Verification = config.ModeWarn
		cfg.PolicyDir = dir
		cfg.Sigstore.TUFMirror = testTUFMirrorURL
		cfg.Sigstore.TUFRoot = linkFile

		err := cfg.ValidateRuntime()
		if !errors.Is(err, config.ErrSymlinkNotAllowed) {
			t.Errorf("expected ErrSymlinkNotAllowed, got %v", err)
		}
	})

	t.Run("symlink ca_cert rejected", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		realCert := filepath.Join(dir, "ca.crt")
		testutil.AssertNoError(t, os.WriteFile(realCert, []byte("cert"), 0o600))

		linkCert := filepath.Join(dir, "ca-link.crt")
		testutil.AssertNoError(t, os.Symlink(realCert, linkCert))

		cfg := config.DefaultConfig()
		cfg.Verification = config.ModeWarn
		cfg.PolicyDir = dir
		cfg.Registries = []config.Registry{
			{
				Prefix: "ghcr.io", Mirror: "", CACert: linkCert, Insecure: false,
			},
		}

		err := cfg.ValidateRuntime()
		if !errors.Is(err, config.ErrSymlinkNotAllowed) {
			t.Errorf("expected ErrSymlinkNotAllowed, got %v", err)
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
		testutil.AssertEqual(t, types.ActionDeny, cfg.FetchFailurePolicy)
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
	testutil.AssertEqual(t, types.ActionDeny, cfg.FetchFailurePolicy)
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

func TestConfigValidateMetricsAddrNonLoopbackWarning(t *testing.T) {
	t.Parallel()

	nonLoopbackAddrs := []string{
		"0.0.0.0:9090",
		"10.0.0.1:9090",
		"[::]:9090",
		"metrics.example.com:9090",
	}

	for _, addr := range nonLoopbackAddrs {
		t.Run(addr, func(t *testing.T) {
			t.Parallel()

			cfg := config.DefaultConfig()
			cfg.MetricsAddr = addr

			err := cfg.Validate()
			if err != nil {
				t.Errorf("expected no error for %q, got %v", addr, err)
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

func TestConfigNormalizeClampsFailureTTL(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.CacheTTL = config.Duration{Duration: 1 * time.Hour}
	cfg.CacheFailureTTL = config.Duration{Duration: 2 * time.Hour}

	testutil.AssertNoError(t, cfg.Validate())

	cfg.Normalize()

	if cfg.CacheFailureTTL.Duration != cfg.CacheTTL.Duration {
		t.Errorf(
			"expected CacheFailureTTL clamped to %v, got %v",
			cfg.CacheTTL.Duration, cfg.CacheFailureTTL.Duration,
		)
	}
}

func TestConfigNormalizeNoOpWhenWithinRange(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.CacheTTL = config.Duration{Duration: 1 * time.Hour}
	cfg.CacheFailureTTL = config.Duration{Duration: 5 * time.Minute}

	original := cfg.CacheFailureTTL.Duration

	cfg.Normalize()

	if cfg.CacheFailureTTL.Duration != original {
		t.Errorf(
			"expected CacheFailureTTL unchanged at %v, got %v",
			original, cfg.CacheFailureTTL.Duration,
		)
	}
}

func TestConfigValidateIdempotent(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.CacheTTL = config.Duration{Duration: 1 * time.Hour}
	cfg.CacheFailureTTL = config.Duration{Duration: 2 * time.Hour}

	testutil.AssertNoError(t, cfg.Validate())

	if cfg.CacheFailureTTL.Duration != 2*time.Hour {
		t.Error("Validate() should not mutate CacheFailureTTL")
	}

	testutil.AssertNoError(t, cfg.Validate())

	if cfg.CacheFailureTTL.Duration != 2*time.Hour {
		t.Error("second Validate() call should not mutate CacheFailureTTL")
	}
}

func TestConfigNormalizeZeroCacheTTLResetsFailureTTL(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.CacheTTL = config.Duration{Duration: 0}
	cfg.CacheFailureTTL = config.Duration{Duration: 5 * time.Minute}

	cfg.Normalize()

	if cfg.CacheFailureTTL.Duration != 0 {
		t.Errorf("expected CacheFailureTTL reset to 0, got %v", cfg.CacheFailureTTL.Duration)
	}
}

func TestConfigNormalizeZeroCacheTTLSkipsWhenFailureTTLAlsoZero(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.CacheTTL = config.Duration{Duration: 0}
	cfg.CacheFailureTTL = config.Duration{Duration: 0}

	cfg.Normalize()

	testutil.AssertEqual(t, time.Duration(0), cfg.CacheFailureTTL.Duration)
}

func TestNormalizeDockerIOPrefix(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Registries = []config.Registry{
		{
			Prefix:   testPrefixDockerIO,
			Mirror:   "mirror.internal.example.com",
			CACert:   "",
			Insecure: false,
		},
	}

	cfg.Normalize()

	if cfg.Registries[0].Prefix != "index.docker.io" {
		t.Errorf(
			"expected prefix normalized to %q, got %q",
			"index.docker.io", cfg.Registries[0].Prefix,
		)
	}
}

func TestApplyModeDefaults(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		mode           config.VerificationMode
		policy         types.Action
		explicit       bool
		expectedPolicy types.Action
	}{
		{
			name:           "enforce implicit warn becomes deny",
			mode:           config.ModeEnforce,
			policy:         types.ActionWarn,
			explicit:       false,
			expectedPolicy: types.ActionDeny,
		},
		{
			name:           "enforce explicit warn preserved",
			mode:           config.ModeEnforce,
			policy:         types.ActionWarn,
			explicit:       true,
			expectedPolicy: types.ActionWarn,
		},
		{
			name:           "enforce implicit deny unchanged",
			mode:           config.ModeEnforce,
			policy:         types.ActionDeny,
			explicit:       false,
			expectedPolicy: types.ActionDeny,
		},
		{
			name:           "enforce explicit deny unchanged",
			mode:           config.ModeEnforce,
			policy:         types.ActionDeny,
			explicit:       true,
			expectedPolicy: types.ActionDeny,
		},
		{
			name:           "enforce implicit allow unchanged",
			mode:           config.ModeEnforce,
			policy:         types.ActionAllow,
			explicit:       false,
			expectedPolicy: types.ActionAllow,
		},
		{
			name:           "enforce explicit allow unchanged",
			mode:           config.ModeEnforce,
			policy:         types.ActionAllow,
			explicit:       true,
			expectedPolicy: types.ActionAllow,
		},
		{
			name:           "warn mode unchanged",
			mode:           config.ModeWarn,
			policy:         types.ActionWarn,
			explicit:       false,
			expectedPolicy: types.ActionWarn,
		},
		{
			name:           "disabled mode unchanged",
			mode:           config.ModeDisabled,
			policy:         types.ActionWarn,
			explicit:       false,
			expectedPolicy: types.ActionWarn,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cfg := config.DefaultConfig()
			cfg.Verification = test.mode
			cfg.FetchFailurePolicy = test.policy

			cfg.ApplyModeDefaults(test.explicit)

			testutil.AssertEqual(t, test.expectedPolicy, cfg.FetchFailurePolicy)
		})
	}
}

func TestApplyModeDefaultsViaLoadFromString(t *testing.T) {
	t.Parallel()

	t.Run("enforce without explicit policy gets deny", func(t *testing.T) {
		t.Parallel()

		cfg, err := config.LoadFromString(`verification = "enforce"
policy_dir = "/tmp/policies"
`)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, types.ActionDeny, cfg.FetchFailurePolicy)
	})

	t.Run("enforce with explicit warn keeps warn", func(t *testing.T) {
		t.Parallel()

		cfg, err := config.LoadFromString(`verification = "enforce"
fetch_failure_policy = "warn"
policy_dir = "/tmp/policies"
`)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, types.ActionWarn, cfg.FetchFailurePolicy)
	})

	t.Run("enforce with explicit deny keeps deny", func(t *testing.T) {
		t.Parallel()

		cfg, err := config.LoadFromString(`verification = "enforce"
fetch_failure_policy = "deny"
policy_dir = "/tmp/policies"
`)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, types.ActionDeny, cfg.FetchFailurePolicy)
	})

	t.Run("warn mode keeps default", func(t *testing.T) {
		t.Parallel()

		cfg, err := config.LoadFromString(`verification = "warn"
policy_dir = "/tmp/policies"
`)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, types.ActionWarn, cfg.FetchFailurePolicy)
	})

	t.Run("warn to enforce reload changes policy", func(t *testing.T) {
		t.Parallel()

		warnCfg, err := config.LoadFromString(`verification = "warn"
policy_dir = "/tmp/policies"
`)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, types.ActionWarn, warnCfg.FetchFailurePolicy)

		enforceCfg, err := config.LoadFromString(`verification = "enforce"
policy_dir = "/tmp/policies"
`)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, types.ActionDeny, enforceCfg.FetchFailurePolicy)
	})
}

func TestConfigValidateVerificationTimeout(t *testing.T) {
	t.Parallel()

	t.Run("default is valid", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		testutil.AssertNoError(t, cfg.Validate())
		testutil.AssertEqual(t, 5*time.Minute, cfg.VerificationTimeout.Duration)
	})

	t.Run("zero rejected", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.VerificationTimeout = config.Duration{Duration: 0}

		err := cfg.Validate()
		if !errors.Is(err, config.ErrVerificationTimeoutNotPositive) {
			t.Errorf("expected ErrVerificationTimeoutNotPositive, got %v", err)
		}
	})

	t.Run("negative rejected", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.VerificationTimeout = config.Duration{Duration: -1 * time.Second}

		err := cfg.Validate()
		if !errors.Is(err, config.ErrVerificationTimeoutNotPositive) {
			t.Errorf("expected ErrVerificationTimeoutNotPositive, got %v", err)
		}
	})

	t.Run("exceeds maximum rejected", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.VerificationTimeout = config.Duration{Duration: 31 * time.Minute}

		err := cfg.Validate()
		if !errors.Is(err, config.ErrVerificationTimeoutTooHigh) {
			t.Errorf("expected ErrVerificationTimeoutTooHigh, got %v", err)
		}
	})

	t.Run("at maximum is valid", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.VerificationTimeout = config.Duration{Duration: 30 * time.Minute}

		testutil.AssertNoError(t, cfg.Validate())
	})

	t.Run("custom value is valid", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.VerificationTimeout = config.Duration{Duration: 10 * time.Minute}

		testutil.AssertNoError(t, cfg.Validate())
	})
}

func TestLoadFromStringVerificationTimeout(t *testing.T) {
	t.Parallel()

	cfg, err := config.LoadFromString(`verification_timeout = "10m"`)
	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, 10*time.Minute, cfg.VerificationTimeout.Duration)
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

	t.Run("rate limit exceeding max rejected", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Verification = config.ModeWarn
		cfg.FetchRateLimit = 10001.0

		err := cfg.Validate()
		if !errors.Is(err, config.ErrFetchRateLimitTooHigh) {
			t.Errorf("expected ErrFetchRateLimitTooHigh, got %v", err)
		}
	})

	t.Run("rate limit at max is valid", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Verification = config.ModeWarn
		cfg.FetchRateLimit = 10000.0

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

func TestLoadFromFileRejectsOversizedConfig(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")

	oversized := make([]byte, 10<<20+1)
	for i := range oversized {
		oversized[i] = '#'
	}

	testutil.AssertNoError(t, os.WriteFile(cfgPath, oversized, 0o600))

	_, err := config.LoadFromFile(cfgPath)
	if !errors.Is(err, config.ErrConfigFileTooLarge) {
		t.Errorf("expected ErrConfigFileTooLarge, got %v", err)
	}
}

func TestConfigValidateCollectsMultipleErrors(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Verification = config.VerificationMode("invalid")
	cfg.LogLevel = "bogus"
	cfg.CircuitBreakerThreshold = -1
	cfg.CircuitBreakerCooldown = config.Duration{Duration: -1}

	err := cfg.Validate()
	testutil.AssertError(t, err)

	if !errors.Is(err, config.ErrInvalidVerificationMode) {
		t.Errorf("expected ErrInvalidVerificationMode, got %v", err)
	}

	if !errors.Is(err, config.ErrInvalidLogLevel) {
		t.Errorf("expected ErrInvalidLogLevel, got %v", err)
	}

	if !errors.Is(err, config.ErrCircuitBreakerThreshold) {
		t.Errorf("expected ErrCircuitBreakerThreshold, got %v", err)
	}

	if !errors.Is(err, config.ErrCircuitBreakerCooldown) {
		t.Errorf("expected ErrCircuitBreakerCooldown, got %v", err)
	}
}

func TestConfigValidateRegistries(t *testing.T) {
	t.Parallel()

	t.Run("valid registry", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Registries = []config.Registry{
			{
				Prefix: testRegistryGHCR, Mirror: testMirrorInternal,
				CACert: "", Insecure: false,
			},
		}

		testutil.AssertNoError(t, cfg.Validate())
	})

	t.Run("empty prefix rejected", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Registries = []config.Registry{
			{
				Prefix: "", Mirror: testMirrorInternal,
				CACert: "", Insecure: false,
			},
		}

		err := cfg.Validate()
		if !errors.Is(err, config.ErrRegistryPrefixEmpty) {
			t.Errorf("expected ErrRegistryPrefixEmpty, got %v", err)
		}
	})

	t.Run("relative ca_cert rejected", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Registries = []config.Registry{
			{
				Prefix: testRegistryGHCR, Mirror: "",
				CACert: "relative/path.pem", Insecure: false,
			},
		}

		err := cfg.Validate()
		if !errors.Is(err, config.ErrRegistryCACertNotAbsolute) {
			t.Errorf("expected ErrRegistryCACertNotAbsolute, got %v", err)
		}
	})

	t.Run("absolute ca_cert accepted", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Registries = []config.Registry{
			{
				Prefix: testRegistryGHCR, Mirror: "",
				CACert: "/etc/ssl/ca.pem", Insecure: false,
			},
		}

		testutil.AssertNoError(t, cfg.Validate())
	})

	t.Run("insecure emits warning but is valid", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Registries = []config.Registry{
			{
				Prefix: "dev-registry.local", Mirror: "",
				CACert: "", Insecure: true,
			},
		}

		testutil.AssertNoError(t, cfg.Validate())
	})

	t.Run("multiple errors collected", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Registries = []config.Registry{
			{
				Prefix: "", Mirror: "mirror",
				CACert: "", Insecure: false,
			},
			{
				Prefix: testRegistryGHCR, Mirror: "",
				CACert: "relative.pem", Insecure: false,
			},
		}

		err := cfg.Validate()
		testutil.AssertError(t, err)

		if !errors.Is(err, config.ErrRegistryPrefixEmpty) {
			t.Errorf("expected ErrRegistryPrefixEmpty, got %v", err)
		}

		if !errors.Is(err, config.ErrRegistryCACertNotAbsolute) {
			t.Errorf("expected ErrRegistryCACertNotAbsolute, got %v", err)
		}
	})

	t.Run("duplicate prefix rejected", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Registries = []config.Registry{
			{
				Prefix: testRegistryGHCR, Mirror: testMirrorInternal,
				CACert: "", Insecure: false,
			},
			{
				Prefix: testRegistryGHCR, Mirror: "other-mirror.example.com",
				CACert: "", Insecure: false,
			},
		}

		err := cfg.Validate()
		if !errors.Is(err, config.ErrDuplicateRegistryPrefix) {
			t.Errorf("expected ErrDuplicateRegistryPrefix, got %v", err)
		}
	})

	t.Run("docker.io and index.docker.io treated as duplicate", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Registries = []config.Registry{
			{
				Prefix:   testPrefixDockerIO,
				Mirror:   "mirror-a.example.com",
				CACert:   "",
				Insecure: false,
			},
			{
				Prefix:   "index.docker.io",
				Mirror:   "mirror-b.example.com",
				CACert:   "",
				Insecure: false,
			},
		}

		err := cfg.Validate()
		if !errors.Is(err, config.ErrDuplicateRegistryPrefix) {
			t.Errorf("expected ErrDuplicateRegistryPrefix, got %v", err)
		}
	})
}

func TestConfigValidateRuntimeRegistryCACert(t *testing.T) {
	t.Parallel()

	t.Run("existing ca_cert passes", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		certPath := filepath.Join(dir, "ca.pem")
		testutil.AssertNoError(t, os.WriteFile(certPath, []byte("cert"), 0o600))

		cfg := config.DefaultConfig()
		cfg.Registries = []config.Registry{
			{
				Prefix: testRegistryGHCR, Mirror: "",
				CACert: certPath, Insecure: false,
			},
		}

		testutil.AssertNoError(t, cfg.ValidateRuntime())
	})

	t.Run("missing ca_cert fails", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Registries = []config.Registry{
			{
				Prefix: testRegistryGHCR, Mirror: "",
				CACert: "/nonexistent/ca.pem", Insecure: false,
			},
		}

		err := cfg.ValidateRuntime()
		if !errors.Is(err, config.ErrRegistryCACertNotFound) {
			t.Errorf("expected ErrRegistryCACertNotFound, got %v", err)
		}
	})

	t.Run("no ca_cert skips check", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Registries = []config.Registry{
			{
				Prefix: testRegistryGHCR, Mirror: testMirrorInternal,
				CACert: "", Insecure: false,
			},
		}

		testutil.AssertNoError(t, cfg.ValidateRuntime())
	})
}

func TestLoadFromStringRegistries(t *testing.T) {
	t.Parallel()

	cfg, err := config.LoadFromString(`
[[registries]]
prefix = "ghcr.io"
mirror = "mirror.internal.example.com"

[[registries]]
prefix = "registry.internal.example.com"
ca_cert = "/etc/ssl/certs/internal-ca.pem"
insecure = false
`)
	testutil.AssertNoError(t, err)

	if len(cfg.Registries) != 2 {
		t.Fatalf("expected 2 registries, got %d", len(cfg.Registries))
	}

	testutil.AssertEqual(t, testRegistryGHCR, cfg.Registries[0].Prefix)
	testutil.AssertEqual(t, "mirror.internal.example.com", cfg.Registries[0].Mirror)
	testutil.AssertEqual(t, "", cfg.Registries[0].CACert)
	testutil.AssertEqual(t, false, cfg.Registries[0].Insecure)

	testutil.AssertEqual(t, "registry.internal.example.com", cfg.Registries[1].Prefix)
	testutil.AssertEqual(t, "", cfg.Registries[1].Mirror)
	testutil.AssertEqual(t, "/etc/ssl/certs/internal-ca.pem", cfg.Registries[1].CACert)
	testutil.AssertEqual(t, false, cfg.Registries[1].Insecure)
}

func TestConfigValidateCacheCollectsMultipleErrors(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.CacheTTL = config.Duration{Duration: -1}
	cfg.CacheFailureTTL = config.Duration{Duration: -1}

	err := cfg.Validate()
	testutil.AssertError(t, err)

	if !errors.Is(err, config.ErrCacheTTLNegative) {
		t.Errorf("expected ErrCacheTTLNegative, got %v", err)
	}

	if !errors.Is(err, config.ErrCacheFailureTTLNegative) {
		t.Errorf("expected ErrCacheFailureTTLNegative, got %v", err)
	}
}

func TestDefaultConfigSigstore(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	testutil.AssertEqual(t, "", cfg.Sigstore.TUFMirror)
	testutil.AssertEqual(t, "", cfg.Sigstore.TUFRoot)
}

func TestConfigValidateTUFMirror(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mirror  string
		wantErr bool
	}{
		{name: "empty is valid", mirror: "", wantErr: false},
		{name: "valid https URL", mirror: testTUFMirrorURL, wantErr: false},
		{name: "http URL rejected", mirror: "http://tuf.local:8080", wantErr: true},
		{name: "valid URL with path", mirror: "https://tuf.example.com/repo", wantErr: false},
		{name: "missing scheme", mirror: "tuf.example.com", wantErr: true},
		{name: "invalid scheme", mirror: "ftp://tuf.example.com", wantErr: true},
		{name: "missing host", mirror: "https://", wantErr: true},
		{name: "bare path", mirror: "/some/path", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cfg := config.DefaultConfig()
			cfg.Sigstore.TUFMirror = test.mirror

			err := cfg.Validate()
			if test.wantErr && err == nil {
				t.Error("expected error, got nil")
			}

			if !test.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if test.wantErr && err != nil && !errors.Is(err, config.ErrInvalidTUFMirror) {
				t.Errorf("expected ErrInvalidTUFMirror, got %v", err)
			}
		})
	}
}

func TestLoadFromStringSigstore(t *testing.T) {
	t.Parallel()

	t.Run("valid tuf_mirror", func(t *testing.T) {
		t.Parallel()

		cfg, err := config.LoadFromString(`
[sigstore]
tuf_mirror = "https://tuf.example.com"
`)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, testTUFMirrorURL, cfg.Sigstore.TUFMirror)
	})

	t.Run("empty sigstore section", func(t *testing.T) {
		t.Parallel()

		cfg, err := config.LoadFromString(`
[sigstore]
`)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, "", cfg.Sigstore.TUFMirror)
	})

	t.Run("unknown key in sigstore section", func(t *testing.T) {
		t.Parallel()

		_, err := config.LoadFromString(`
[sigstore]
tuf_mirror = "https://tuf.example.com"
unknown_field = "value"
`)
		testutil.AssertError(t, err)

		if !errors.Is(err, config.ErrUnknownConfigKeys) {
			t.Errorf("expected ErrUnknownConfigKeys, got %v", err)
		}
	})

	t.Run("invalid tuf_mirror URL", func(t *testing.T) {
		t.Parallel()

		_, err := config.LoadFromString(`
[sigstore]
tuf_mirror = "not-a-url"
`)
		testutil.AssertError(t, err)

		if !errors.Is(err, config.ErrInvalidTUFMirror) {
			t.Errorf("expected ErrInvalidTUFMirror, got %v", err)
		}
	})

	t.Run("valid tuf_root absolute path", func(t *testing.T) {
		t.Parallel()

		cfg, err := config.LoadFromString(`
[sigstore]
tuf_mirror = "https://tuf.example.com"
tuf_root = "/etc/sigstore/root.json"
`)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, testTUFRootPath, cfg.Sigstore.TUFRoot)
	})

	t.Run("tuf_root without tuf_mirror rejected", func(t *testing.T) {
		t.Parallel()

		_, err := config.LoadFromString(`
[sigstore]
tuf_root = "/etc/sigstore/root.json"
`)
		testutil.AssertError(t, err)

		if !errors.Is(err, config.ErrTUFRootRequiresMirror) {
			t.Errorf("expected ErrTUFRootRequiresMirror, got %v", err)
		}
	})

	t.Run("tuf_root relative path rejected", func(t *testing.T) {
		t.Parallel()

		_, err := config.LoadFromString(`
[sigstore]
tuf_root = "relative/root.json"
`)
		testutil.AssertError(t, err)

		if !errors.Is(err, config.ErrTUFRootNotAbsolute) {
			t.Errorf("expected ErrTUFRootNotAbsolute, got %v", err)
		}
	})

	t.Run("both tuf_mirror and tuf_root valid", func(t *testing.T) {
		t.Parallel()

		cfg, err := config.LoadFromString(`
[sigstore]
tuf_mirror = "https://tuf.example.com"
tuf_root = "/etc/sigstore/root.json"
`)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, testTUFMirrorURL, cfg.Sigstore.TUFMirror)
		testutil.AssertEqual(t, testTUFRootPath, cfg.Sigstore.TUFRoot)
	})
}

func TestConfigValidateTUFRoot(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		root        string
		mirror      string
		wantErr     bool
		expectedErr error
	}{
		{
			name: "empty root is valid", root: "",
			mirror: "", wantErr: false, expectedErr: nil,
		},
		{
			name: "absolute path is valid", root: testTUFRootPath,
			mirror: testTUFMirrorURL, wantErr: false, expectedErr: nil,
		},
		{
			name: "relative path rejected", root: "relative/root.json",
			mirror: testTUFMirrorURL, wantErr: true, expectedErr: config.ErrTUFRootNotAbsolute,
		},
		{
			name: "bare filename rejected", root: "root.json",
			mirror: testTUFMirrorURL, wantErr: true, expectedErr: config.ErrTUFRootNotAbsolute,
		},
		{
			name: "root without mirror rejected", root: testTUFRootPath,
			mirror: "", wantErr: true, expectedErr: config.ErrTUFRootRequiresMirror,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cfg := config.DefaultConfig()
			cfg.Sigstore.TUFRoot = test.root
			cfg.Sigstore.TUFMirror = test.mirror

			err := cfg.Validate()
			if test.wantErr && err == nil {
				t.Error("expected error, got nil")
			}

			if !test.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if test.expectedErr != nil && err != nil && !errors.Is(err, test.expectedErr) {
				t.Errorf("expected %v, got %v", test.expectedErr, err)
			}
		})
	}
}

func TestConfigValidateRuntimeTUFRoot(t *testing.T) {
	t.Parallel()

	t.Run("existing file passes", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		rootPath := filepath.Join(dir, "root.json")
		testutil.AssertNoError(t, os.WriteFile(rootPath, []byte(`{}`), 0o600))

		policyDir := filepath.Join(dir, "policies")
		testutil.AssertNoError(t, os.MkdirAll(policyDir, 0o750))

		cfg := config.DefaultConfig()
		cfg.Verification = config.ModeWarn
		cfg.PolicyDir = policyDir
		cfg.Sigstore.TUFRoot = rootPath

		testutil.AssertNoError(t, cfg.ValidateRuntime())
	})

	t.Run("missing file fails", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()

		cfg := config.DefaultConfig()
		cfg.Verification = config.ModeWarn
		cfg.PolicyDir = dir
		cfg.Sigstore.TUFRoot = filepath.Join(dir, "nonexistent-root.json")

		err := cfg.ValidateRuntime()
		testutil.AssertError(t, err)

		if !errors.Is(err, config.ErrTUFRootNotFound) {
			t.Errorf("expected ErrTUFRootNotFound, got %v", err)
		}
	})

	t.Run("empty file fails", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		rootPath := filepath.Join(dir, "root.json")
		testutil.AssertNoError(t, os.WriteFile(rootPath, []byte{}, 0o600))

		policyDir := filepath.Join(dir, "policies")
		testutil.AssertNoError(t, os.MkdirAll(policyDir, 0o750))

		cfg := config.DefaultConfig()
		cfg.Verification = config.ModeWarn
		cfg.PolicyDir = policyDir
		cfg.Sigstore.TUFRoot = rootPath

		err := cfg.ValidateRuntime()
		testutil.AssertError(t, err)

		if !errors.Is(err, config.ErrTUFRootEmpty) {
			t.Errorf("expected ErrTUFRootEmpty, got %v", err)
		}
	})

	t.Run("directory fails", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()

		policyDir := filepath.Join(dir, "policies")
		testutil.AssertNoError(t, os.MkdirAll(policyDir, 0o750))

		rootDir := filepath.Join(dir, "rootdir")
		testutil.AssertNoError(t, os.MkdirAll(rootDir, 0o750))

		cfg := config.DefaultConfig()
		cfg.Verification = config.ModeWarn
		cfg.PolicyDir = policyDir
		cfg.Sigstore.TUFRoot = rootDir

		err := cfg.ValidateRuntime()
		testutil.AssertError(t, err)

		if !errors.Is(err, config.ErrTUFRootNotRegularFile) {
			t.Errorf("expected ErrTUFRootNotRegularFile, got %v", err)
		}
	})

	t.Run("disabled mode skips tuf_root check", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Sigstore.TUFRoot = "/nonexistent/root.json"

		testutil.AssertNoError(t, cfg.ValidateRuntime())
	})
}

func TestVerificationModeStrictness(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		mode     config.VerificationMode
		expected config.Strictness
	}{
		{name: "mode disabled", mode: config.ModeDisabled, expected: config.StrictnessDisabled},
		{name: "mode warn", mode: config.ModeWarn, expected: config.StrictnessWarn},
		{name: "mode enforce", mode: config.ModeEnforce, expected: config.StrictnessEnforce},
		{name: "mode unknown", mode: testModeUnknown, expected: -1},
		{name: "mode empty", mode: "", expected: -1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := test.mode.Strictness()
			if got != test.expected {
				t.Errorf("expected strictness %d, got %d", test.expected, got)
			}
		})
	}
}

func TestVerificationModeIsValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		mode     config.VerificationMode
		expected bool
	}{
		{name: "disabled is valid", mode: config.ModeDisabled, expected: true},
		{name: "warn is valid", mode: config.ModeWarn, expected: true},
		{name: "enforce is valid", mode: config.ModeEnforce, expected: true},
		{name: "unknown is invalid", mode: testModeUnknown, expected: false},
		{name: "empty is invalid", mode: "", expected: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := test.mode.IsValid()
			if got != test.expected {
				t.Errorf("expected IsValid=%v, got %v", test.expected, got)
			}
		})
	}
}

func TestStrictnessOrdering(t *testing.T) {
	t.Parallel()

	disabled := config.ModeDisabled.Strictness()
	warn := config.ModeWarn.Strictness()
	enforce := config.ModeEnforce.Strictness()

	if disabled >= warn {
		t.Errorf("expected disabled (%d) < warn (%d)", disabled, warn)
	}

	if warn >= enforce {
		t.Errorf("expected warn (%d) < enforce (%d)", warn, enforce)
	}
}

func TestWarnInsecureRegistriesDoesNotPanic(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.Registries = []config.Registry{
		{
			Prefix:   "insecure.example.com",
			Mirror:   "mirror.example.com",
			CACert:   "",
			Insecure: true,
		},
	}

	cfg.WarnInsecureRegistries()
}

func TestNormalizePrefixViaValidation(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = t.TempDir()
	cfg.Registries = []config.Registry{
		{
			Prefix:   testPrefixDockerIO,
			Mirror:   "mirror1.example.com",
			CACert:   "",
			Insecure: false,
		},
		{
			Prefix:   testPrefixDockerIO,
			Mirror:   "mirror2.example.com",
			CACert:   "",
			Insecure: false,
		},
	}

	err := cfg.Validate()
	if !errors.Is(err, config.ErrDuplicateRegistryPrefix) {
		t.Errorf(
			"expected duplicate prefix error for docker.io entries, got %v",
			err,
		)
	}
}

func TestNormalizePrefixCaseInsensitive(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = t.TempDir()
	cfg.Registries = []config.Registry{
		{
			Prefix: "GHCR.IO", Mirror: "MIRROR.INTERNAL", CACert: "",
			Insecure: false,
		},
	}

	err := cfg.Validate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cfg.Normalize()

	if cfg.Registries[0].Prefix != testPrefixGHCR {
		t.Errorf("Prefix = %q, want %q (lowercased)", cfg.Registries[0].Prefix, testPrefixGHCR)
	}

	if cfg.Registries[0].Mirror != testMirrorInternal {
		t.Errorf("Mirror = %q, want %q (lowercased)", cfg.Registries[0].Mirror, testMirrorInternal)
	}
}

func TestNormalizeDuplicateCaseInsensitive(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = t.TempDir()
	cfg.Registries = []config.Registry{
		{
			Prefix: testPrefixGHCR, Mirror: "mirror1.internal", CACert: "",
			Insecure: false,
		},
		{
			Prefix: "GHCR.IO", Mirror: "mirror2.internal", CACert: "",
			Insecure: false,
		},
	}

	err := cfg.Validate()
	if !errors.Is(err, config.ErrDuplicateRegistryPrefix) {
		t.Errorf("expected duplicate prefix error for case-variant entries, got %v", err)
	}
}

func TestValidateRegistryPrefixInvalid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		prefix string
	}{
		{"scheme in prefix", "https://registry.example.com"},
		{"slash in prefix", "registry.example.com/path"},
		{"space in prefix", "registry example.com"},
		{"consecutive dots", "a..b"},
		{"leading dot", ".example.com"},
		{"trailing dot", "example.com."},
		{"dots only", "..."},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := config.DefaultConfig()
			cfg.Verification = config.ModeWarn
			cfg.PolicyDir = t.TempDir()
			cfg.Registries = []config.Registry{
				{
					Prefix: tc.prefix, Mirror: "mirror.internal", CACert: "",
					Insecure: false,
				},
			}

			err := cfg.Validate()
			if !errors.Is(err, config.ErrRegistryPrefixInvalid) {
				t.Errorf("expected ErrRegistryPrefixInvalid for %q, got %v",
					tc.prefix, err)
			}
		})
	}
}

func TestValidateRegistryMirrorInvalid(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = t.TempDir()
	cfg.Registries = []config.Registry{
		{
			Prefix: testPrefixGHCR, Mirror: "https://mirror.internal", CACert: "",
			Insecure: false,
		},
	}

	err := cfg.Validate()
	if !errors.Is(err, config.ErrRegistryMirrorInvalid) {
		t.Errorf("expected ErrRegistryMirrorInvalid, got %v", err)
	}
}

func TestValidateRegistryMirrorSameAsPrefix(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = t.TempDir()
	cfg.Registries = []config.Registry{
		{
			Prefix: testPrefixGHCR, Mirror: "ghcr.io", CACert: "", Insecure: false,
		},
	}

	err := cfg.Validate()
	if !errors.Is(err, config.ErrRegistryMirrorSameAsPrefix) {
		t.Errorf("expected ErrRegistryMirrorSameAsPrefix, got %v", err)
	}
}

func TestValidateInsecureRegistryInEnforceMode(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.PolicyDir = t.TempDir()
	cfg.Registries = []config.Registry{
		{
			Prefix: testPrefixGHCR, Mirror: "", CACert: "", Insecure: true,
		},
	}

	err := cfg.Validate()
	if !errors.Is(err, config.ErrInsecureRegistryInEnforceMode) {
		t.Errorf("expected ErrInsecureRegistryInEnforceMode, got %v", err)
	}
}

func TestValidateInsecureRegistryAllowedInWarnMode(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = t.TempDir()
	cfg.Registries = []config.Registry{
		{
			Prefix: testPrefixGHCR, Mirror: "", CACert: "", Insecure: true,
		},
	}

	testutil.AssertNoError(t, cfg.Validate())
}

func TestRegistriesChanged(t *testing.T) {
	t.Parallel()

	reg := config.Registry{
		Prefix: testPrefixGHCR, Mirror: "mirror.internal", CACert: "", Insecure: false,
	}

	tests := []struct {
		name string
		prev []config.Registry
		next []config.Registry
		want bool
	}{
		{name: "both nil", prev: nil, next: nil, want: false},
		{name: "both empty", prev: []config.Registry{}, next: []config.Registry{}, want: false},
		{name: "nil vs empty", prev: nil, next: []config.Registry{}, want: false},
		{name: "added", prev: nil, next: []config.Registry{reg}, want: true},
		{name: "removed", prev: []config.Registry{reg}, next: nil, want: true},
		{name: "equal", prev: []config.Registry{reg}, next: []config.Registry{reg}, want: false},
		{name: "mirror changed", prev: []config.Registry{reg}, next: []config.Registry{
			{
				Prefix: testPrefixGHCR, Mirror: "other.internal", CACert: "",
				Insecure: false,
			},
		}, want: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := config.RegistriesChanged(test.prev, test.next); got != test.want {
				t.Errorf("RegistriesChanged() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestConfigValidatePolicyConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		modify      func(*config.Config)
		wantErr     bool
		expectedErr error
	}{
		{
			name:        "default local source is valid",
			modify:      func(_ *config.Config) {},
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name: "explicit local source is valid",
			modify: func(c *config.Config) {
				c.Policy.Source = config.PolicySourceLocal
			},
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name: "oci source with valid ref",
			modify: func(c *config.Config) {
				c.Policy.Source = config.PolicySourceOCI
				c.Policy.OCIRef = testOCIRef
			},
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name: "oci source with digest pinning",
			modify: func(c *config.Config) {
				c.Policy.Source = config.PolicySourceOCI
				c.Policy.OCIRef = "ghcr.io/myorg/policies@sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
			},
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name: "invalid policy source",
			modify: func(c *config.Config) {
				c.Policy.Source = "ftp"
			},
			wantErr:     true,
			expectedErr: config.ErrInvalidPolicySource,
		},
		{
			name: "oci source requires oci_ref",
			modify: func(c *config.Config) {
				c.Policy.Source = config.PolicySourceOCI
			},
			wantErr:     true,
			expectedErr: config.ErrPolicyOCIRefRequired,
		},
		{
			name: "oci source with invalid ref",
			modify: func(c *config.Config) {
				c.Policy.Source = config.PolicySourceOCI
				c.Policy.OCIRef = "NOT A VALID REF!!!"
			},
			wantErr:     true,
			expectedErr: config.ErrPolicyOCIRefInvalid,
		},
		{
			name: "poll interval below minimum",
			modify: func(c *config.Config) {
				c.Policy.Source = config.PolicySourceOCI
				c.Policy.OCIRef = testOCIRef
				c.Policy.PollInterval = config.Duration{Duration: 10 * time.Second}
			},
			wantErr:     true,
			expectedErr: config.ErrPollIntervalTooShort,
		},
		{
			name: "poll interval at minimum is valid",
			modify: func(c *config.Config) {
				c.Policy.Source = config.PolicySourceOCI
				c.Policy.OCIRef = testOCIRef
				c.Policy.PollInterval = config.Duration{Duration: 30 * time.Second}
			},
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name: "oci source skips policy_dir validation",
			modify: func(c *config.Config) {
				c.Verification = config.ModeWarn
				c.Policy.Source = config.PolicySourceOCI
				c.Policy.OCIRef = testOCIRef
				c.PolicyDir = "" // would normally fail for local source
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

func TestConfigValidatePolicySignatureFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		modify      func(*config.Config)
		wantErr     bool
		expectedErr error
	}{
		{
			name: "issuers is valid",
			modify: func(c *config.Config) {
				c.Policy.Source = config.PolicySourceOCI
				c.Policy.OCIRef = testOCIRef
				c.Policy.Issuers = []string{testIssuerGoogle}
			},
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name: "keys is valid",
			modify: func(c *config.Config) {
				c.Policy.Source = config.PolicySourceOCI
				c.Policy.OCIRef = testOCIRef
				c.Policy.Keys = []string{testKeyPath}
			},
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name: "san_patterns without issuers rejected",
			modify: func(c *config.Config) {
				c.Policy.Source = config.PolicySourceOCI
				c.Policy.OCIRef = testOCIRef
				c.Policy.SANPatterns = []string{testSANPattern}
			},
			wantErr:     true,
			expectedErr: config.ErrPolicySANPatternsWithoutIssuers,
		},
		{
			name: "san_patterns with keys only rejected",
			modify: func(c *config.Config) {
				c.Policy.Source = config.PolicySourceOCI
				c.Policy.OCIRef = testOCIRef
				c.Policy.Keys = []string{testKeyPath}
				c.Policy.SANPatterns = []string{testSANPattern}
			},
			wantErr:     true,
			expectedErr: config.ErrPolicySANPatternsWithoutIssuers,
		},
		{
			name: "keys with relative path rejected",
			modify: func(c *config.Config) {
				c.Policy.Source = config.PolicySourceOCI
				c.Policy.OCIRef = testOCIRef
				c.Policy.Keys = []string{"relative/path.pub"}
			},
			wantErr:     true,
			expectedErr: config.ErrPolicySignatureKeyNotAbsolute,
		},
		{
			name: "duplicate key path rejected",
			modify: func(c *config.Config) {
				c.Policy.Source = config.PolicySourceOCI
				c.Policy.OCIRef = testOCIRef
				c.Policy.Keys = []string{testKeyPath, testKeyPath}
			},
			wantErr:     true,
			expectedErr: config.ErrPolicySignatureKeyDuplicate,
		},
		{
			name: "issuers with source=local warns but no error",
			modify: func(c *config.Config) {
				c.Policy.Source = config.PolicySourceLocal
				c.Policy.Issuers = []string{testIssuerGoogle}
			},
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name: "san_patterns with issuers is valid",
			modify: func(c *config.Config) {
				c.Policy.Source = config.PolicySourceOCI
				c.Policy.OCIRef = testOCIRef
				c.Policy.Issuers = []string{testIssuerGoogle}
				c.Policy.SANPatterns = []string{testSANPattern}
			},
			wantErr:     false,
			expectedErr: nil,
		},
		{
			name: "issuers and keys together rejected",
			modify: func(c *config.Config) {
				c.Policy.Source = config.PolicySourceOCI
				c.Policy.OCIRef = testOCIRef
				c.Policy.Issuers = []string{testIssuerGoogle}
				c.Policy.Keys = []string{testKeyPath}
			},
			wantErr:     true,
			expectedErr: config.ErrPolicyIssuersAndKeysMutuallyExclusive,
		},
		{
			name: "empty issuer string rejected",
			modify: func(c *config.Config) {
				c.Policy.Source = config.PolicySourceOCI
				c.Policy.OCIRef = testOCIRef
				c.Policy.Issuers = []string{""}
			},
			wantErr:     true,
			expectedErr: config.ErrPolicyIssuerEmpty,
		},
		{
			name: "empty san_pattern string rejected",
			modify: func(c *config.Config) {
				c.Policy.Source = config.PolicySourceOCI
				c.Policy.OCIRef = testOCIRef
				c.Policy.Issuers = []string{testIssuerGoogle}
				c.Policy.SANPatterns = []string{""}
			},
			wantErr:     true,
			expectedErr: config.ErrPolicySANPatternEmpty,
		},
		{
			name: "empty key path rejected",
			modify: func(c *config.Config) {
				c.Policy.Source = config.PolicySourceOCI
				c.Policy.OCIRef = testOCIRef
				c.Policy.Keys = []string{""}
			},
			wantErr:     true,
			expectedErr: config.ErrPolicyKeyEmpty,
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

func TestConfigLoadFromStringPolicySection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		toml     string
		wantErr  bool
		checkCfg func(*testing.T, *config.Config)
	}{
		{
			name: "policy section with oci source",
			toml: `
[policy]
source = "oci"
oci_ref = "ghcr.io/myorg/policies:v1"
poll_interval = "10m"
`,
			wantErr: false,
			checkCfg: func(t *testing.T, cfg *config.Config) {
				t.Helper()

				testutil.AssertEqual(t, config.PolicySourceOCI, cfg.Policy.Source)
				testutil.AssertEqual(t, testOCIRef, cfg.Policy.OCIRef)
				testutil.AssertEqual(t, 10*time.Minute, cfg.Policy.PollInterval.Duration)
			},
		},
		{
			name:    "empty config uses defaults",
			toml:    "",
			wantErr: false,
			checkCfg: func(t *testing.T, cfg *config.Config) {
				t.Helper()

				testutil.AssertEqual(t, config.PolicySourceLocal, cfg.Policy.Source)
				testutil.AssertEqual(t, "", cfg.Policy.OCIRef)
				testutil.AssertEqual(t, 5*time.Minute, cfg.Policy.PollInterval.Duration)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cfg, err := config.LoadFromString(test.toml)
			if test.wantErr {
				testutil.AssertError(t, err)

				return
			}

			testutil.AssertNoError(t, err)

			if test.checkCfg != nil {
				test.checkCfg(t, cfg)
			}
		})
	}
}

func TestLoadFromStringSigstoreRoots(t *testing.T) {
	t.Parallel()

	t.Run("multiple roots parsed", func(t *testing.T) {
		t.Parallel()

		cfg, err := config.LoadFromString(`
[[sigstore.roots]]
name = "github"
tuf_mirror = "https://tuf-repo.github.com"
tuf_root = "/etc/sigstore/github-root.json"

[[sigstore.roots]]
name = "internal"
tuf_mirror = "https://tuf.internal.example.com"
`)
		testutil.AssertNoError(t, err)

		if len(cfg.Sigstore.Roots) != 2 {
			t.Fatalf("expected 2 roots, got %d", len(cfg.Sigstore.Roots))
		}

		testutil.AssertEqual(t, "github", cfg.Sigstore.Roots[0].Name)
		testutil.AssertEqual(t, "https://tuf-repo.github.com", cfg.Sigstore.Roots[0].TUFMirror)
		testutil.AssertEqual(t, "/etc/sigstore/github-root.json", cfg.Sigstore.Roots[0].TUFRoot)

		testutil.AssertEqual(t, "internal", cfg.Sigstore.Roots[1].Name)
		testutil.AssertEqual(t, "https://tuf.internal.example.com", cfg.Sigstore.Roots[1].TUFMirror)
		testutil.AssertEqual(t, "", cfg.Sigstore.Roots[1].TUFRoot)
	})

	t.Run("backward compat scalar tuf_mirror still works", func(t *testing.T) {
		t.Parallel()

		cfg, err := config.LoadFromString(`
[sigstore]
tuf_mirror = "https://tuf.example.com"
tuf_root = "/etc/sigstore/root.json"
`)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, testTUFMirrorURL, cfg.Sigstore.TUFMirror)
		testutil.AssertEqual(t, testTUFRootPath, cfg.Sigstore.TUFRoot)

		if len(cfg.Sigstore.Roots) != 0 {
			t.Errorf("expected empty roots, got %d", len(cfg.Sigstore.Roots))
		}
	})

	t.Run("mutual exclusion scalar and roots", func(t *testing.T) {
		t.Parallel()

		_, err := config.LoadFromString(`
[sigstore]
tuf_mirror = "https://tuf.example.com"

[[sigstore.roots]]
name = "extra"
tuf_mirror = "https://extra.example.com"
`)
		testutil.AssertError(t, err)

		if !errors.Is(err, config.ErrSigstoreRootsMutualExclusion) {
			t.Errorf("expected ErrSigstoreRootsMutualExclusion, got %v", err)
		}
	})

	t.Run("duplicate names rejected", func(t *testing.T) {
		t.Parallel()

		_, err := config.LoadFromString(`
[[sigstore.roots]]
name = "github"
tuf_mirror = "https://tuf-repo.github.com"

[[sigstore.roots]]
name = "github"
tuf_mirror = "https://other.example.com"
`)
		testutil.AssertError(t, err)

		if !errors.Is(err, config.ErrSigstoreRootNameDuplicate) {
			t.Errorf("expected ErrSigstoreRootNameDuplicate, got %v", err)
		}
	})

	t.Run("missing name rejected", func(t *testing.T) {
		t.Parallel()

		_, err := config.LoadFromString(`
[[sigstore.roots]]
tuf_mirror = "https://tuf-repo.github.com"
`)
		testutil.AssertError(t, err)

		if !errors.Is(err, config.ErrSigstoreRootNameRequired) {
			t.Errorf("expected ErrSigstoreRootNameRequired, got %v", err)
		}
	})

	t.Run("tuf_root without tuf_mirror in roots rejected", func(t *testing.T) {
		t.Parallel()

		_, err := config.LoadFromString(`
[[sigstore.roots]]
name = "broken"
tuf_root = "/etc/sigstore/root.json"
`)
		testutil.AssertError(t, err)

		if !errors.Is(err, config.ErrTUFRootRequiresMirror) {
			t.Errorf("expected ErrTUFRootRequiresMirror, got %v", err)
		}
	})

	t.Run("invalid tuf_mirror URL in roots rejected", func(t *testing.T) {
		t.Parallel()

		_, err := config.LoadFromString(`
[[sigstore.roots]]
name = "broken"
tuf_mirror = "http://insecure.example.com"
`)
		testutil.AssertError(t, err)

		if !errors.Is(err, config.ErrInvalidTUFMirror) {
			t.Errorf("expected ErrInvalidTUFMirror, got %v", err)
		}
	})

	t.Run("relative tuf_root in roots rejected", func(t *testing.T) {
		t.Parallel()

		_, err := config.LoadFromString(`
[[sigstore.roots]]
name = "broken"
tuf_mirror = "https://tuf.example.com"
tuf_root = "relative/root.json"
`)
		testutil.AssertError(t, err)

		if !errors.Is(err, config.ErrTUFRootNotAbsolute) {
			t.Errorf("expected ErrTUFRootNotAbsolute, got %v", err)
		}
	})

	t.Run("include_public_root false", func(t *testing.T) {
		t.Parallel()

		cfg, err := config.LoadFromString(`
[sigstore]
include_public_root = false

[[sigstore.roots]]
name = "private"
tuf_mirror = "https://tuf.internal.example.com"
`)
		testutil.AssertNoError(t, err)

		if cfg.Sigstore.ShouldIncludePublicRoot() {
			t.Error("expected ShouldIncludePublicRoot() == false")
		}
	})

	t.Run("include_public_root default is true", func(t *testing.T) {
		t.Parallel()

		cfg, err := config.LoadFromString(`
[[sigstore.roots]]
name = "private"
tuf_mirror = "https://tuf.internal.example.com"
`)
		testutil.AssertNoError(t, err)

		if !cfg.Sigstore.ShouldIncludePublicRoot() {
			t.Error("expected ShouldIncludePublicRoot() == true by default")
		}
	})
}

func TestEffectiveRoots(t *testing.T) {
	t.Parallel()

	t.Run("empty config returns nil", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		roots := cfg.Sigstore.EffectiveRoots()

		if roots != nil {
			t.Errorf("expected nil, got %v", roots)
		}
	})

	t.Run("scalar mirror synthesizes single entry", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Sigstore.TUFMirror = testTUFMirrorURL
		cfg.Sigstore.TUFRoot = testTUFRootPath

		roots := cfg.Sigstore.EffectiveRoots()

		if len(roots) != 1 {
			t.Fatalf("expected 1 root, got %d", len(roots))
		}

		testutil.AssertEqual(t, "default", roots[0].Name)
		testutil.AssertEqual(t, testTUFMirrorURL, roots[0].TUFMirror)
		testutil.AssertEqual(t, testTUFRootPath, roots[0].TUFRoot)
	})

	t.Run("roots array returned directly", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Sigstore.Roots = []config.SigstoreRootSource{
			{Name: "a", TUFMirror: "https://a.example.com", TUFRoot: ""},
			{Name: "b", TUFMirror: "https://b.example.com", TUFRoot: ""},
		}

		roots := cfg.Sigstore.EffectiveRoots()

		if len(roots) != 2 {
			t.Fatalf("expected 2 roots, got %d", len(roots))
		}

		testutil.AssertEqual(t, "a", roots[0].Name)
		testutil.AssertEqual(t, "b", roots[1].Name)
	})
}

func TestSigstoreConfigChanged(t *testing.T) {
	t.Parallel()

	t.Run("identical configs", func(t *testing.T) {
		t.Parallel()

		a := &config.SigstoreConfig{
			TUFMirror: testTUFMirrorURL, TUFRoot: "",
			Roots: nil, IncludePublicRoot: nil,
		}
		b := &config.SigstoreConfig{
			TUFMirror: testTUFMirrorURL, TUFRoot: "",
			Roots: nil, IncludePublicRoot: nil,
		}

		if config.SigstoreConfigChanged(a, b) {
			t.Error("expected no change")
		}
	})

	t.Run("mirror changed", func(t *testing.T) {
		t.Parallel()

		a := &config.SigstoreConfig{
			TUFMirror: "https://a.example.com", TUFRoot: "",
			Roots: nil, IncludePublicRoot: nil,
		}
		b := &config.SigstoreConfig{
			TUFMirror: "https://b.example.com", TUFRoot: "",
			Roots: nil, IncludePublicRoot: nil,
		}

		if !config.SigstoreConfigChanged(a, b) {
			t.Error("expected change")
		}
	})

	t.Run("roots list changed", func(t *testing.T) {
		t.Parallel()

		a := &config.SigstoreConfig{
			TUFMirror: "",
			TUFRoot:   "",
			Roots: []config.SigstoreRootSource{
				{Name: "x", TUFMirror: testXExampleURL, TUFRoot: ""},
			},
			IncludePublicRoot: nil,
		}
		b := &config.SigstoreConfig{
			TUFMirror: "",
			TUFRoot:   "",
			Roots: []config.SigstoreRootSource{
				{Name: "y", TUFMirror: "https://y.example.com", TUFRoot: ""},
			},
			IncludePublicRoot: nil,
		}

		if !config.SigstoreConfigChanged(a, b) {
			t.Error("expected change")
		}
	})

	t.Run("include_public_root changed", func(t *testing.T) {
		t.Parallel()

		falseVal := false
		a := &config.SigstoreConfig{
			TUFMirror: "",
			TUFRoot:   "",
			Roots: []config.SigstoreRootSource{
				{Name: "x", TUFMirror: testXExampleURL, TUFRoot: ""},
			},
			IncludePublicRoot: &falseVal,
		}
		b := &config.SigstoreConfig{
			TUFMirror: "",
			TUFRoot:   "",
			Roots: []config.SigstoreRootSource{
				{Name: "x", TUFMirror: testXExampleURL, TUFRoot: ""},
			},
			IncludePublicRoot: nil,
		}

		if !config.SigstoreConfigChanged(a, b) {
			t.Error("expected change when include_public_root differs")
		}
	})

	t.Run("scalar to roots migration is detected", func(t *testing.T) {
		t.Parallel()

		prev := &config.SigstoreConfig{
			TUFMirror:         testTUFMirrorURL,
			TUFRoot:           "",
			Roots:             nil,
			IncludePublicRoot: nil,
		}
		next := &config.SigstoreConfig{
			TUFMirror: "",
			TUFRoot:   "",
			Roots: []config.SigstoreRootSource{
				{Name: "default", TUFMirror: testTUFMirrorURL, TUFRoot: ""},
			},
			IncludePublicRoot: nil,
		}

		if !config.SigstoreConfigChanged(prev, next) {
			t.Error("expected change when migrating from scalar to roots array")
		}
	})
}

func TestValidateRuntimeSigstoreRootsTUFRoot(t *testing.T) {
	t.Parallel()

	t.Run("valid roots tuf_root file", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		rootPath := filepath.Join(dir, "root.json")
		testutil.AssertNoError(t, os.WriteFile(rootPath, []byte(`{}`), 0o600))

		policyDir := filepath.Join(dir, "policies")
		testutil.AssertNoError(t, os.MkdirAll(policyDir, 0o750))

		cfg := config.DefaultConfig()
		cfg.Verification = config.ModeWarn
		cfg.PolicyDir = policyDir
		cfg.Sigstore.Roots = []config.SigstoreRootSource{
			{
				Name:      "test",
				TUFMirror: testTUFMirrorURL,
				TUFRoot:   rootPath,
			},
		}

		testutil.AssertNoError(t, cfg.ValidateRuntime())
	})

	t.Run("missing roots tuf_root file fails", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()

		cfg := config.DefaultConfig()
		cfg.Verification = config.ModeWarn
		cfg.PolicyDir = dir
		cfg.Sigstore.Roots = []config.SigstoreRootSource{
			{
				Name:      "test",
				TUFMirror: testTUFMirrorURL,
				TUFRoot:   filepath.Join(dir, "nonexistent.json"),
			},
		}

		err := cfg.ValidateRuntime()
		if !errors.Is(err, config.ErrTUFRootNotFound) {
			t.Errorf("expected ErrTUFRootNotFound, got %v", err)
		}
	})
}

func TestConfigLoadFromStringPolicySignature(t *testing.T) {
	t.Parallel()

	t.Run("issuers from TOML", func(t *testing.T) {
		t.Parallel()

		cfg, err := config.LoadFromString(`
[policy]
source = "oci"
oci_ref = "ghcr.io/myorg/policies:v1"
issuers = ["https://accounts.google.com"]
san_patterns = ["*@example.com"]
`)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, true, cfg.Policy.SignatureVerificationRequired())

		if len(cfg.Policy.Issuers) != 1 || cfg.Policy.Issuers[0] != testIssuerGoogle {
			t.Errorf("unexpected issuers: %v", cfg.Policy.Issuers)
		}

		if len(cfg.Policy.SANPatterns) != 1 || cfg.Policy.SANPatterns[0] != testSANPattern {
			t.Errorf("unexpected san_patterns: %v", cfg.Policy.SANPatterns)
		}
	})

	t.Run("keys from TOML", func(t *testing.T) {
		t.Parallel()

		cfg, err := config.LoadFromString(`
[policy]
source = "oci"
oci_ref = "ghcr.io/myorg/policies:v1"
keys = ["/etc/keys/policy.pub"]
`)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, true, cfg.Policy.SignatureVerificationRequired())

		if len(cfg.Policy.Keys) != 1 || cfg.Policy.Keys[0] != testKeyPath {
			t.Errorf("unexpected keys: %v", cfg.Policy.Keys)
		}
	})
}

func TestConfigValidatePolicyKeysRuntime(t *testing.T) {
	t.Parallel()

	t.Run("no keys configured (issuers only) returns nil", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()

		cfg := config.DefaultConfig()
		cfg.Verification = config.ModeWarn
		cfg.PolicyDir = dir
		cfg.Policy.Issuers = []string{testIssuerGoogle}

		testutil.AssertNoError(t, cfg.ValidateRuntime())
	})

	t.Run("valid key file returns nil", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		keyPath := filepath.Join(dir, "policy.pub")
		testutil.AssertNoError(t, os.WriteFile(keyPath, []byte("pubkey"), 0o600))

		cfg := config.DefaultConfig()
		cfg.Verification = config.ModeWarn
		cfg.PolicyDir = dir
		cfg.Policy.Keys = []string{keyPath}

		testutil.AssertNoError(t, cfg.ValidateRuntime())
	})

	t.Run("key file does not exist returns stat error", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		missingKey := filepath.Join(dir, "nonexistent.pub")

		cfg := config.DefaultConfig()
		cfg.Verification = config.ModeWarn
		cfg.PolicyDir = dir
		cfg.Policy.Keys = []string{missingKey}

		err := cfg.ValidateRuntime()
		testutil.AssertError(t, err)
		testutil.AssertContains(t, err.Error(), "nonexistent.pub")
	})

	t.Run("key file is a symlink returns ErrSymlinkNotAllowed", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		realKey := filepath.Join(dir, "real.pub")
		testutil.AssertNoError(t, os.WriteFile(realKey, []byte("pubkey"), 0o600))

		linkKey := filepath.Join(dir, "link.pub")
		testutil.AssertNoError(t, os.Symlink(realKey, linkKey))

		cfg := config.DefaultConfig()
		cfg.Verification = config.ModeWarn
		cfg.PolicyDir = dir
		cfg.Policy.Keys = []string{linkKey}

		err := cfg.ValidateRuntime()
		testutil.AssertErrorIs(t, err, config.ErrSymlinkNotAllowed)
	})

	t.Run("key file is a directory returns ErrPolicyKeyNotRegularFile", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		keyDir := filepath.Join(dir, "not-a-file")
		testutil.AssertNoError(t, os.Mkdir(keyDir, 0o750))

		cfg := config.DefaultConfig()
		cfg.Verification = config.ModeWarn
		cfg.PolicyDir = dir
		cfg.Policy.Keys = []string{keyDir}

		err := cfg.ValidateRuntime()
		testutil.AssertErrorIs(t, err, config.ErrPolicyKeyNotRegularFile)
	})

	t.Run("multiple keys with mixed errors", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()

		// Valid key.
		goodKey := filepath.Join(dir, "good.pub")
		testutil.AssertNoError(t, os.WriteFile(goodKey, []byte("pubkey"), 0o600))

		// Missing key.
		missingKey := filepath.Join(dir, "missing.pub")

		// Directory key.
		dirKey := filepath.Join(dir, "dir-key")
		testutil.AssertNoError(t, os.Mkdir(dirKey, 0o750))

		cfg := config.DefaultConfig()
		cfg.Verification = config.ModeWarn
		cfg.PolicyDir = dir
		cfg.Policy.Keys = []string{goodKey, missingKey, dirKey}

		err := cfg.ValidateRuntime()
		testutil.AssertError(t, err)
		testutil.AssertContains(t, err.Error(), "missing.pub")

		testutil.AssertErrorIs(t, err, config.ErrPolicyKeyNotRegularFile)
	})
}

func TestConfigValidateMaxAttestationSize(t *testing.T) {
	t.Parallel()

	t.Run("too small", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.MaxAttestationSize = (1 << 20) - 1

		err := cfg.Validate()
		testutil.AssertErrorIs(t, err, config.ErrMaxAttestationSizeTooSmall)
	})

	t.Run("too large", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.MaxAttestationSize = (100 << 20) + 1

		err := cfg.Validate()
		testutil.AssertErrorIs(t, err, config.ErrMaxAttestationSizeTooLarge)
	})

	t.Run("at minimum boundary", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.MaxAttestationSize = 1 << 20

		err := cfg.Validate()
		testutil.AssertNoError(t, err)
	})

	t.Run("at maximum boundary", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.MaxAttestationSize = 100 << 20

		err := cfg.Validate()
		testutil.AssertNoError(t, err)
	})
}

func TestConfigValidateCacheMaxEntries(t *testing.T) {
	t.Parallel()

	t.Run("too small", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.CacheMaxEntries = 99

		err := cfg.Validate()
		testutil.AssertErrorIs(t, err, config.ErrCacheMaxEntriesTooSmall)
	})

	t.Run("too large", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.CacheMaxEntries = 1_000_001

		err := cfg.Validate()
		testutil.AssertErrorIs(t, err, config.ErrCacheMaxEntriesTooLarge)
	})

	t.Run("at minimum boundary", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.CacheMaxEntries = 100

		err := cfg.Validate()
		testutil.AssertNoError(t, err)
	})

	t.Run("at maximum boundary", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.CacheMaxEntries = 1_000_000

		err := cfg.Validate()
		testutil.AssertNoError(t, err)
	})
}

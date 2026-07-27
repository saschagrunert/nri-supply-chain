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

package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/plugin"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	sctypes "github.com/saschagrunert/nri-supply-chain/internal/types"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

//nolint:paralleltest // modifies package-level logLevelVar
func TestNewLogger(t *testing.T) {
	tests := []struct {
		name  string
		level string
		want  slog.Level
	}{
		{name: logLevelDebug, level: logLevelDebug, want: slog.LevelDebug},
		{name: logLevelInfo, level: logLevelInfo, want: slog.LevelInfo},
		{name: logLevelWarn, level: logLevelWarn, want: slog.LevelWarn},
		{name: logLevelError, level: logLevelError, want: slog.LevelError},
		{name: "unrecognized defaults to info", level: "bogus", want: slog.LevelInfo},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			updateLogLevel(test.level)

			logger := newLogger()
			handler := logger.Handler()

			if !handler.Enabled(context.Background(), test.want) {
				t.Errorf("expected level %v to be enabled", test.want)
			}

			if test.want > slog.LevelDebug {
				belowLevel := test.want - 4
				if handler.Enabled(context.Background(), belowLevel) {
					t.Errorf("expected level %v to be disabled", belowLevel)
				}
			}
		})
	}
}

func TestSetupConfig(t *testing.T) {
	t.Parallel()

	t.Run("metricsAddr override", func(t *testing.T) {
		t.Parallel()

		opts := &options{
			configPath:      "",
			metricsAddr:     ":9999",
			pluginName:      "",
			pluginIdx:       "",
			logLevel:        "",
			verifyImage:     "",
			verifyNamespace: "",
			showVersion:     false,
			validate:        false,
			jsonSchema:      "",
		}

		cfg, err := setupConfig(opts)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cfg.MetricsAddr != ":9999" {
			t.Errorf("expected :9999, got %s", cfg.MetricsAddr)
		}
	})

	t.Run("validation error", func(t *testing.T) {
		t.Parallel()

		configPath := filepath.Join(t.TempDir(), "config.toml")

		err := os.WriteFile(
			configPath,
			[]byte("verification = \"warn\"\npolicy_dir = \"/nonexistent\"\n"),
			0o600,
		)
		if err != nil {
			t.Fatalf("writing config: %v", err)
		}

		opts := &options{
			configPath:      configPath,
			metricsAddr:     "",
			pluginName:      "",
			pluginIdx:       "",
			logLevel:        "",
			verifyImage:     "",
			verifyNamespace: "",
			showVersion:     false,
			validate:        false,
			jsonSchema:      "",
		}

		_, err = setupConfig(opts)
		if err == nil {
			t.Fatal("expected error for nonexistent policy dir")
		}
	})
}

func writeTestConfig(t *testing.T, path, policyDir, mode string) {
	t.Helper()

	data := "verification = \"" + mode + "\"\npolicy_dir = \"" + policyDir + "\"\n"

	err := os.WriteFile(path, []byte(data), 0o600)
	if err != nil {
		t.Fatalf("writing config: %v", err)
	}
}

func newDisabledPlugin(t *testing.T) *plugin.Plugin {
	t.Helper()

	cfg := config.DefaultConfig()
	met := metrics.New()

	v, err := verifier.New(cfg, met, nil)
	if err != nil {
		t.Fatalf("creating verifier: %v", err)
	}

	return plugin.New(v, met, "", 30*time.Second)
}

func TestLoadConfig(t *testing.T) {
	t.Parallel()

	t.Run("default config", func(t *testing.T) {
		t.Parallel()

		cfg, err := loadConfig("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cfg == nil {
			t.Fatal("expected config, got nil")
		}
	})

	t.Run("from file", func(t *testing.T) {
		t.Parallel()

		configPath := filepath.Join(t.TempDir(), "config.toml")

		err := os.WriteFile(
			configPath,
			[]byte("verification = \"warn\"\n"),
			0o600,
		)
		if err != nil {
			t.Fatalf("writing config: %v", err)
		}

		cfg, err := loadConfig(configPath)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cfg.Verification != config.ModeWarn {
			t.Errorf("expected warn, got %s", cfg.Verification)
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		t.Parallel()

		_, err := loadConfig("/nonexistent/config.toml")
		if err == nil {
			t.Fatal("expected error for nonexistent file")
		}
	})
}

func TestRunValidationDisabled(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()

	if code := runValidation(cfg); code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
}

func TestRunValidationValid(t *testing.T) {
	t.Parallel()

	policyDir := filepath.Join(t.TempDir(), "policies")

	err := os.MkdirAll(policyDir, 0o750)
	if err != nil {
		t.Fatalf("creating policy dir: %v", err)
	}

	writeValidationPolicy(t, policyDir, "default.json",
		`{"slsa": {"missingPolicy": "warn"}}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = policyDir

	if code := runValidation(cfg); code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
}

func TestRunValidationInvalidPolicy(t *testing.T) {
	t.Parallel()

	policyDir := filepath.Join(t.TempDir(), "policies")

	err := os.MkdirAll(policyDir, 0o750)
	if err != nil {
		t.Fatalf("creating policy dir: %v", err)
	}

	writeValidationPolicy(t, policyDir, "bad.json", `{invalid json}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = policyDir

	if code := runValidation(cfg); code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestRunValidationRuntimeFailure(t *testing.T) {
	t.Parallel()

	policyDir := filepath.Join(t.TempDir(), "policies")

	err := os.MkdirAll(policyDir, 0o750)
	if err != nil {
		t.Fatalf("creating policy dir: %v", err)
	}

	writeValidationPolicy(t, policyDir, "default.json",
		`{"trust":{"verifiers":[{"id":"test","key":"/nonexistent/key.pub"}]}}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.PolicyDir = policyDir

	if code := runValidation(cfg); code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestRunValidationEnforceValid(t *testing.T) {
	t.Parallel()

	policyDir := filepath.Join(t.TempDir(), "policies")

	err := os.MkdirAll(policyDir, 0o750)
	if err != nil {
		t.Fatalf("creating policy dir: %v", err)
	}

	writeValidationPolicy(t, policyDir, "default.json",
		`{"slsa": {"missingPolicy": "allow"}}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.PolicyDir = policyDir

	if code := runValidation(cfg); code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
}

func TestWarnValidationEnforceDefaults(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *config.Config
		policies map[string]*policy.Policy
	}{
		{
			name: "fetch failure policy warn",
			cfg: func() *config.Config {
				c := config.DefaultConfig()
				c.Verification = config.ModeEnforce
				c.FetchFailurePolicy = sctypes.ActionWarn

				return c
			}(),
			policies: map[string]*policy.Policy{},
		},
		{
			name: "fetch failure policy allow",
			cfg: func() *config.Config {
				c := config.DefaultConfig()
				c.Verification = config.ModeEnforce
				c.FetchFailurePolicy = sctypes.ActionAllow

				return c
			}(),
			policies: map[string]*policy.Policy{},
		},
		{
			name: "fetch failure policy deny",
			cfg: func() *config.Config {
				c := config.DefaultConfig()
				c.Verification = config.ModeEnforce
				c.FetchFailurePolicy = sctypes.ActionDeny

				return c
			}(),
			policies: map[string]*policy.Policy{},
		},
		{
			name: "slsa missing policy allow with default namespace",
			cfg: func() *config.Config {
				c := config.DefaultConfig()
				c.Verification = config.ModeEnforce
				c.FetchFailurePolicy = sctypes.ActionDeny

				return c
			}(),
			policies: map[string]*policy.Policy{
				"": {
					SLSA: &policy.SLSAPolicy{
						MissingPolicy: sctypes.ActionAllow,
					},
				},
			},
		},
		{
			name: "slsa missing policy deny",
			cfg: func() *config.Config {
				c := config.DefaultConfig()
				c.Verification = config.ModeEnforce
				c.FetchFailurePolicy = sctypes.ActionDeny

				return c
			}(),
			policies: map[string]*policy.Policy{
				"prod": {
					SLSA: &policy.SLSAPolicy{
						MissingPolicy: sctypes.ActionDeny,
					},
				},
			},
		},
		{
			name: "VEX missing policy allow with default namespace",
			cfg: func() *config.Config {
				c := config.DefaultConfig()
				c.Verification = config.ModeEnforce
				c.FetchFailurePolicy = sctypes.ActionDeny

				return c
			}(),
			policies: map[string]*policy.Policy{
				"": {
					SLSA: &policy.SLSAPolicy{
						MissingPolicy: sctypes.ActionDeny,
					},
				},
			},
		},
		{
			name: "VEX missing policy deny",
			cfg: func() *config.Config {
				c := config.DefaultConfig()
				c.Verification = config.ModeEnforce
				c.FetchFailurePolicy = sctypes.ActionDeny

				return c
			}(),
			policies: map[string]*policy.Policy{
				"secure": {
					SLSA: &policy.SLSAPolicy{
						MissingPolicy: sctypes.ActionDeny,
					},
					VEX: &policy.VEXPolicy{
						MissingPolicy: sctypes.ActionDeny,
					},
				},
			},
		},
		{
			name: "named namespace with all defaults",
			cfg: func() *config.Config {
				c := config.DefaultConfig()
				c.Verification = config.ModeEnforce

				return c
			}(),
			policies: map[string]*policy.Policy{
				"stg": {},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Should not panic for any combination.
			verifier.WarnEnforceDefaults(test.cfg, test.policies)
		})
	}
}

func writeValidationPolicy(t *testing.T, dir, filename, content string) {
	t.Helper()

	err := os.WriteFile(
		filepath.Join(dir, filename), []byte(content), 0o600,
	)
	if err != nil {
		t.Fatalf("writing policy: %v", err)
	}
}

//nolint:paralleltest // modifies package-level logLevelVar
func TestInitLogging(t *testing.T) {
	initLogging(logLevelDebug)

	if logLevelVar.Level() != slog.LevelDebug {
		t.Errorf("expected debug level, got %v", logLevelVar.Level())
	}

	initLogging("bogus")
}

const (
	defaultPluginName = "supply-chain"
	defaultPluginIdx  = "10"
)

func defaultOpts() options {
	return options{
		configPath:      "",
		metricsAddr:     "",
		pluginName:      defaultPluginName,
		pluginIdx:       defaultPluginIdx,
		logLevel:        logLevelInfo,
		verifyImage:     "",
		verifyNamespace: defaultNamespace,
		showVersion:     false,
		validate:        false,
		jsonSchema:      "",
	}
}

func TestParseFlagsFrom(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
		want options
	}{
		{
			name: "defaults with empty args",
			args: []string{},
			want: defaultOpts(),
		},
		{
			name: "config flag",
			args: []string{"--config", "/etc/nri/config.toml"},
			want: func() options {
				o := defaultOpts()
				o.configPath = "/etc/nri/config.toml"

				return o
			}(),
		},
		{
			name: "metrics-addr flag",
			args: []string{"--metrics-addr", ":9090"},
			want: func() options {
				o := defaultOpts()
				o.metricsAddr = ":9090"

				return o
			}(),
		},
		{
			name: "plugin-name flag",
			args: []string{"--plugin-name", "custom"},
			want: func() options {
				o := defaultOpts()
				o.pluginName = "custom"

				return o
			}(),
		},
		{
			name: "plugin-idx flag",
			args: []string{"--plugin-idx", "42"},
			want: func() options {
				o := defaultOpts()
				o.pluginIdx = "42"

				return o
			}(),
		},
		{
			name: "log-level flag",
			args: []string{"--log-level", logLevelDebug},
			want: func() options {
				o := defaultOpts()
				o.logLevel = logLevelDebug

				return o
			}(),
		},
		{
			name: "version flag",
			args: []string{"--version"},
			want: func() options {
				o := defaultOpts()
				o.showVersion = true

				return o
			}(),
		},
		{
			name: "validate flag",
			args: []string{"--validate"},
			want: func() options {
				o := defaultOpts()
				o.validate = true

				return o
			}(),
		},
		{
			name: "verify-image flag",
			args: []string{"--verify-image", "quay.io/test:latest"},
			want: func() options {
				o := defaultOpts()
				o.verifyImage = "quay.io/test:latest"

				return o
			}(),
		},
		{
			name: "verify-namespace flag",
			args: []string{"--verify-namespace", "production"},
			want: func() options {
				o := defaultOpts()
				o.verifyNamespace = "production"

				return o
			}(),
		},
		{
			name: "json-schema flag",
			args: []string{"--json-schema", schemaPolicy},
			want: func() options {
				o := defaultOpts()
				o.jsonSchema = schemaPolicy

				return o
			}(),
		},
		{
			name: "multiple flags combined",
			args: []string{
				"--config", "/tmp/cfg.toml",
				"--metrics-addr", ":8080",
				"--plugin-name", "sc",
				"--plugin-idx", "5",
				"--log-level", logLevelError,
				"--verify-image", "registry.io/img:v1",
				"--verify-namespace", "staging",
			},
			want: options{
				configPath:      "/tmp/cfg.toml",
				metricsAddr:     ":8080",
				pluginName:      "sc",
				pluginIdx:       "5",
				logLevel:        logLevelError,
				verifyImage:     "registry.io/img:v1",
				verifyNamespace: "staging",
				showVersion:     false,
				validate:        false,
				jsonSchema:      "",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := parseFlagsFrom(test.args)
			if got != test.want {
				t.Errorf("parseFlagsFrom(%v)\n got: %+v\nwant: %+v",
					test.args, got, test.want)
			}
		})
	}
}

func TestOCIFetcherWithRateLimit(t *testing.T) {
	t.Parallel()

	fetcher := attestation.NewOCIFetcher()
	fetcher.SetRateLimit(10.0)

	if fetcher == nil {
		t.Fatal("expected non-nil fetcher")
	}
}

//nolint:paralleltest // modifies package-level logLevelVar
func TestUpdateLogLevel(t *testing.T) {
	tests := []struct {
		name  string
		level string
		want  slog.Level
	}{
		{name: logLevelDebug, level: logLevelDebug, want: slog.LevelDebug},
		{name: logLevelInfo, level: logLevelInfo, want: slog.LevelInfo},
		{name: logLevelWarn, level: logLevelWarn, want: slog.LevelWarn},
		{name: logLevelError, level: logLevelError, want: slog.LevelError},
		{name: "unrecognized defaults to info", level: "bogus", want: slog.LevelInfo},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			updateLogLevel(test.level)

			if logLevelVar.Level() != test.want {
				t.Errorf("expected level %v, got %v", test.want, logLevelVar.Level())
			}
		})
	}
}

//nolint:paralleltest // modifies package-level logLevelVar
func TestLogLevelDynamic(t *testing.T) {
	updateLogLevel(logLevelInfo)

	logger := newLogger()
	handler := logger.Handler()

	// Info should be enabled at info level.
	if !handler.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("expected info to be enabled at info level")
	}

	// Debug should be disabled at info level.
	if handler.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("expected debug to be disabled at info level")
	}

	// Change to debug level dynamically.
	updateLogLevel(logLevelDebug)

	// The same handler should now reflect the new level.
	if !handler.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("expected debug to be enabled after dynamic level change")
	}
}

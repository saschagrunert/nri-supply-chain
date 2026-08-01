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
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
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
		{name: "unrecognized defaults to info", level: testBogusLevel, want: slog.LevelInfo},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			updateLogLevel(test.level)

			logger := newLogger(false)
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

//nolint:paralleltest // modifies package-level logLevelVar
func TestNewLoggerCLIMode(t *testing.T) {
	updateLogLevel(logLevelInfo)

	pluginLogger := newLogger(false)
	cliLogger := newLogger(true)

	if _, ok := pluginLogger.Handler().(*slog.JSONHandler); !ok {
		t.Error("expected JSONHandler for plugin mode")
	}

	if _, ok := cliLogger.Handler().(*cliHandler); !ok {
		t.Error("expected cliHandler for CLI mode")
	}
}

func TestSetupConfig(t *testing.T) {
	t.Parallel()

	t.Run("default config path", func(t *testing.T) {
		t.Parallel()

		cfg, err := setupConfig(defaultConfigPath)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if cfg == nil {
			t.Fatal("expected config, got nil")
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

		_, err = setupConfig(configPath)
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

	t.Run("default config path missing", func(t *testing.T) {
		t.Parallel()

		cfg, err := loadConfig(defaultConfigPath)
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

	if code := runValidation(cfg); code != exitSuccess {
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

	if code := runValidation(cfg); code != exitSuccess {
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

	if code := runValidation(cfg); code != exitError {
		t.Errorf("expected exit code %d, got %d", exitError, code)
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
		`{"trust":{"verifiers":[{"id":"test","keys":["/nonexistent/key.pub"]}]}}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.PolicyDir = policyDir

	if code := runValidation(cfg); code != exitError {
		t.Errorf("expected exit code %d, got %d", exitError, code)
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

	if code := runValidation(cfg); code != exitSuccess {
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
					Sections: policy.Sections{
						SLSA: &policy.SLSAPolicy{
							MissingPolicy: sctypes.ActionAllow,
						},
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
				testNamespaceProd: {
					Sections: policy.Sections{
						SLSA: &policy.SLSAPolicy{
							MissingPolicy: sctypes.ActionDeny,
						},
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
					Sections: policy.Sections{
						SLSA: &policy.SLSAPolicy{
							MissingPolicy: sctypes.ActionDeny,
						},
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
					Sections: policy.Sections{
						SLSA: &policy.SLSAPolicy{
							MissingPolicy: sctypes.ActionDeny,
						},
						VEX: &policy.VEXPolicy{
							MissingPolicy: sctypes.ActionDeny,
						},
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

func TestRunValidationMultipleErrors(t *testing.T) {
	t.Parallel()

	policyDir := filepath.Join(t.TempDir(), "policies")

	err := os.MkdirAll(policyDir, 0o750)
	if err != nil {
		t.Fatalf("creating policy dir: %v", err)
	}

	writeValidationPolicy(t, policyDir, "a.json",
		`{"trust":{"verifiers":[{"id":"v1","keys":["/nonexistent/a.pub"]}]}}`)
	writeValidationPolicy(t, policyDir, "b.json",
		`{"trust":{"verifiers":[{"id":"v2","keys":["/nonexistent/b.pub"]}]}}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = policyDir

	if code := runValidation(cfg); code != exitError {
		t.Errorf("expected exit code %d, got %d", exitError, code)
	}
}

func TestRunValidationMultiplePolicyLoadErrors(t *testing.T) {
	t.Parallel()

	policyDir := filepath.Join(t.TempDir(), "policies")

	err := os.MkdirAll(policyDir, 0o750)
	if err != nil {
		t.Fatalf("creating policy dir: %v", err)
	}

	writeValidationPolicy(t, policyDir, "a.json", `{invalid}`)
	writeValidationPolicy(t, policyDir, "b.json", `{also invalid}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = policyDir

	if code := runValidation(cfg); code != exitError {
		t.Errorf("expected exit code %d, got %d", exitError, code)
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
	initLogging(logLevelDebug, false)

	if logLevelVar.Level() != slog.LevelDebug {
		t.Errorf("expected debug level, got %v", logLevelVar.Level())
	}

	initLogging(testBogusLevel, true)
}

const (
	testNamespaceProduction = "production"
	testNamespaceProd       = "prod"
	testBogusLevel          = "bogus"
	testFlagConfig          = "--config"
)

func TestVersionSubcommand(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	cmd := newRootCmd()
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{cmdVersion})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := "nri-supply-chain " + version + "\n"
	if buf.String() != want {
		t.Errorf("expected %q, got %q", want, buf.String())
	}
}

func TestVersionFlag(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	cmd := newRootCmd()
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--version"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(buf.String(), version) {
		t.Errorf("expected version in output, got: %s", buf.String())
	}
}

func TestHelpFlag(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	cmd := newRootCmd()
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--help"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := buf.String()

	if !strings.Contains(got, "Usage") {
		t.Errorf("expected Usage in help output, got: %s", got)
	}

	if !strings.Contains(got, cmdVerify) {
		t.Errorf("expected verify subcommand in help, got: %s", got)
	}
}

func TestVerifyRequiresArg(t *testing.T) {
	t.Parallel()

	cmd := newRootCmd()
	cmd.SetArgs([]string{cmdVerify})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when verify called without image arg")
	}
}

func TestUnknownSubcommand(t *testing.T) {
	t.Parallel()

	cmd := newRootCmd()
	cmd.SetArgs([]string{"nonexistent"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for unknown subcommand")
	}
}

func TestJSONSchemaSubcommand(t *testing.T) {
	t.Parallel()

	cmd := newRootCmd()
	cmd.SetArgs([]string{cmdJSONSchema, "policy"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestJSONSchemaInvalidType(t *testing.T) {
	t.Parallel()

	cmd := newRootCmd()
	cmd.SetArgs([]string{cmdJSONSchema, testBogusLevel})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid schema type")
	}
}

func TestJSONSchemaRequiresArg(t *testing.T) {
	t.Parallel()

	cmd := newRootCmd()
	cmd.SetArgs([]string{cmdJSONSchema})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when json-schema called without type arg")
	}
}

func TestPersistentFlags(t *testing.T) {
	t.Parallel()

	cmd := newRootCmd()
	cmd.SetArgs([]string{testFlagConfig, "/some/path", cmdVersion})

	var buf bytes.Buffer

	cmd.SetOut(&buf)

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	configFlag := cmd.PersistentFlags().Lookup("config")
	if configFlag.Value.String() != "/some/path" {
		t.Errorf("expected config=/some/path, got %s", configFlag.Value.String())
	}
}

func TestShortFlags(t *testing.T) {
	t.Parallel()

	cmd := newRootCmd()
	cmd.SetArgs([]string{"-c", "/cfg.toml", "-l", "debug", cmdVersion})

	var buf bytes.Buffer

	cmd.SetOut(&buf)

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	configFlag := cmd.PersistentFlags().Lookup("config")
	if configFlag.Value.String() != "/cfg.toml" {
		t.Errorf("expected config=/cfg.toml, got %s", configFlag.Value.String())
	}

	logLevelFlag := cmd.PersistentFlags().Lookup("log-level")
	if logLevelFlag.Value.String() != "debug" {
		t.Errorf("expected log-level=debug, got %s", logLevelFlag.Value.String())
	}
}

func TestValidateSubcommandDisabled(t *testing.T) {
	t.Parallel()

	cmd := newRootCmd()
	cmd.SetArgs([]string{cmdValidate})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateSubcommandWithConfig(t *testing.T) {
	t.Parallel()

	policyDir := filepath.Join(t.TempDir(), "policies")

	err := os.MkdirAll(policyDir, 0o750)
	if err != nil {
		t.Fatalf("creating policy dir: %v", err)
	}

	writeValidationPolicy(t, policyDir, "default.json",
		`{"slsa": {"missingPolicy": "allow"}}`)

	configPath := filepath.Join(t.TempDir(), "config.toml")
	writeTestConfig(t, configPath, policyDir, "warn")

	cmd := newRootCmd()
	cmd.SetArgs([]string{testFlagConfig, configPath, cmdValidate})

	err = cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateSubcommandSetupFailure(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "config.toml")
	writeTestConfig(t, configPath, "/nonexistent/policies", "warn")

	cmd := newRootCmd()
	cmd.SetArgs([]string{testFlagConfig, configPath, cmdValidate})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for setup failure")
	}
}

func TestVerifySubcommandSetupFailure(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "config.toml")
	writeTestConfig(t, configPath, "/nonexistent/policies", "warn")

	cmd := newRootCmd()
	cmd.SetArgs([]string{testFlagConfig, configPath, cmdVerify, "example.com/img:v1"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for setup failure")
	}
}

func TestVerifySubcommandDisabledConfig(t *testing.T) {
	t.Parallel()

	cmd := newRootCmd()
	cmd.SetArgs([]string{cmdVerify, "example.com/img:v1"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for disabled verification")
	}
}

func TestRootCommandSetupFailure(t *testing.T) {
	t.Parallel()

	cmd := newRootCmd()
	cmd.SetArgs([]string{testFlagConfig, "/nonexistent/config.toml"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for nonexistent config")
	}
}

func TestVerifySubcommandTooManyArgs(t *testing.T) {
	t.Parallel()

	cmd := newRootCmd()
	cmd.SetArgs([]string{cmdVerify, "img:v1", "extra"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for too many args")
	}
}

func TestJSONSchemaTooManyArgs(t *testing.T) {
	t.Parallel()

	cmd := newRootCmd()
	cmd.SetArgs([]string{cmdJSONSchema, "policy", "extra"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for too many args")
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
		{name: "unrecognized defaults to info", level: testBogusLevel, want: slog.LevelInfo},
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

	logger := newLogger(false)
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

func TestEffectiveLogLevel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		flagLevel   string
		configLevel string
		want        string
	}{
		{
			name:        "flag overrides config",
			flagLevel:   logLevelDebug,
			configLevel: logLevelError,
			want:        logLevelDebug,
		},
		{
			name:        "config used when flag empty",
			flagLevel:   "",
			configLevel: logLevelWarn,
			want:        logLevelWarn,
		},
		{name: "default when both empty", flagLevel: "", configLevel: "", want: logLevelInfo},
		{
			name:        "flag used when config empty",
			flagLevel:   logLevelError,
			configLevel: "",
			want:        logLevelError,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := effectiveLogLevel(test.flagLevel, test.configLevel)
			if got != test.want {
				t.Errorf("effectiveLogLevel(%q, %q) = %q, want %q",
					test.flagLevel, test.configLevel, got, test.want)
			}
		})
	}
}

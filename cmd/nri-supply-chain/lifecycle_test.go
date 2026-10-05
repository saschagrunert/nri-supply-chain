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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
)

const (
	testBundleCreate = "create"
	testBundleImage  = "registry.example/img:v1"
)

var errLifecycleTest = errors.New("boom")

func TestExitCodeFor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want int
	}{
		{name: "nil", err: nil, want: exitSuccess},
		{name: "denied", err: exitWith(exitDenied), want: exitDenied},
		{name: "error code", err: exitWith(exitError), want: exitError},
		{name: "wrapped code", err: fmt.Errorf("wrap: %w", exitWith(exitDenied)), want: exitDenied},
		{name: "legacy non-zero", err: errExitNonZero, want: exitError},
		{name: "cobra error", err: errLifecycleTest, want: exitError},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := exitCodeFor(tc.err); got != tc.want {
				t.Errorf("expected exit code %d, got %d", tc.want, got)
			}
		})
	}
}

func TestExitWith(t *testing.T) {
	t.Parallel()

	testutil.AssertNoError(t, exitWith(exitSuccess))
	testutil.AssertErrorIs(t, exitWith(exitDenied), errExitNonZero)
}

func TestRootVersionFlagHasNoShorthand(t *testing.T) {
	t.Parallel()

	cmd := newRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"-v"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected -v to be rejected at the root command")
	}

	if flag := cmd.Flags().Lookup("version"); flag == nil || flag.Shorthand != "" {
		t.Errorf("expected --version without shorthand, got %+v", flag)
	}
}

func TestRootNRISocketFlag(t *testing.T) {
	t.Parallel()

	cmd := newRootCmd()

	if cmd.Flags().Lookup("nri-socket") == nil {
		t.Fatal("expected --nri-socket flag")
	}
}

func TestRunValidationDisabledValidatesPolicies(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		policy string
		want   int
	}{
		{name: "valid policy", policy: `{"slsa": {"missingPolicy": "deny"}}`, want: exitSuccess},
		{name: "invalid json", policy: `{invalid json}`, want: exitError},
		{name: "stricter mode", policy: `{"mode": "enforce"}`, want: exitError},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			policyDir := filepath.Join(t.TempDir(), "policies")
			testutil.AssertNoError(t, os.MkdirAll(policyDir, 0o750))
			writeValidationPolicy(t, policyDir, "default.json", tc.policy)

			cfg := config.DefaultConfig()
			cfg.Verification = config.ModeDisabled
			cfg.PolicyDir = policyDir

			if code := runValidation(cfg); code != tc.want {
				t.Errorf("expected exit code %d, got %d", tc.want, code)
			}
		})
	}
}

func TestRequireConfigFile(t *testing.T) {
	t.Parallel()

	testutil.AssertNoError(t, requireConfigFile(defaultConfigPath, true))
	testutil.AssertNoError(t, requireConfigFile(filepath.Join(t.TempDir(), "custom.toml"), false))

	_, statErr := os.Stat(defaultConfigPath)
	if os.IsNotExist(statErr) {
		testutil.AssertErrorIs(t, requireConfigFile(defaultConfigPath, false), errConfigNotFound)
	}
}

func TestBundleCreateOutputFileFlag(t *testing.T) {
	t.Parallel()

	cmd := newRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{cmdBundle, testBundleCreate, "--image", testBundleImage})

	err := cmd.Execute()
	testutil.AssertErrorIs(t, err, errMissingOutputFile)

	create, _, findErr := newRootCmd().Find([]string{cmdBundle, testBundleCreate})
	testutil.AssertNoError(t, findErr)

	legacy := create.Flags().Lookup("output")
	if legacy == nil || legacy.Deprecated == "" || legacy.Shorthand != "o" {
		t.Errorf("expected deprecated --output/-o alias, got %+v", legacy)
	}

	testutil.AssertNoError(t, create.ParseFlags([]string{"-o", "bundle.tar.gz"}))

	if got := create.Flags().Lookup(flagOutputFile).Value.String(); got != "bundle.tar.gz" {
		t.Errorf("expected -o to set --%s, got %q", flagOutputFile, got)
	}
}

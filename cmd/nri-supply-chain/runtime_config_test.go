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
	"os"
	"path/filepath"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
)

func TestServeConfigPath(t *testing.T) {
	t.Parallel()

	existing := filepath.Join(t.TempDir(), "config.toml")
	testutil.AssertNoError(t, os.WriteFile(existing, []byte(`verification = "warn"`), 0o600))

	type testCase struct {
		name     string
		path     string
		explicit bool
		want     string
	}

	tests := []testCase{
		{name: "explicit empty uses runtime config", path: "", explicit: true, want: ""},
		{name: "explicit file", path: existing, explicit: true, want: existing},
		{
			name: "explicit missing file is kept", path: "/nonexistent.toml",
			explicit: true, want: "/nonexistent.toml",
		},
		{name: "non-default file", path: existing, explicit: false, want: existing},
	}

	_, statErr := os.Stat(defaultConfigPath)
	if os.IsNotExist(statErr) {
		tests = append(tests, testCase{
			name: "missing default uses runtime config", path: defaultConfigPath,
			explicit: false, want: "",
		})
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := serveConfigPath(tc.path, tc.explicit); got != tc.want {
				t.Errorf("serveConfigPath(%q, %v) = %q, want %q",
					tc.path, tc.explicit, got, tc.want)
			}
		})
	}
}

func TestSetupServeConfigWithoutFile(t *testing.T) {
	t.Parallel()

	cfg, err := setupServeConfig("")
	testutil.AssertNoError(t, err)

	if cfg.Verification != config.DefaultConfig().Verification {
		t.Errorf("expected built-in defaults, got verification %q", cfg.Verification)
	}

	// The other subcommands keep rejecting an empty config path.
	_, err = setupConfig("")
	testutil.AssertError(t, err)
}

func TestSetupServeConfigMissingFile(t *testing.T) {
	t.Parallel()

	_, err := setupServeConfig(filepath.Join(t.TempDir(), "missing.toml"))
	testutil.AssertError(t, err)

	// An explicit --config naming the missing default file must fail instead
	// of serving the built-in defaults, which disable verification.
	_, statErr := os.Stat(defaultConfigPath)
	if os.IsNotExist(statErr) {
		_, err = setupServeConfig(defaultConfigPath)
		testutil.AssertError(t, err)
	}
}

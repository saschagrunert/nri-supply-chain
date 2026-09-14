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
	"os"
	"path/filepath"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
)

// projectConfigMapFile writes name into a kubelet style ConfigMap volume
// layout (name -> ..data/name, ..data -> ..<timestamp>) and returns the path
// of the projected key.
func projectConfigMapFile(t *testing.T, name, content string) string {
	t.Helper()

	mount := t.TempDir()
	dataDir := filepath.Join(mount, "..2026_09_14_00_00_00.000000000")

	testutil.AssertNoError(t, os.Mkdir(dataDir, 0o750))
	testutil.AssertNoError(t, os.WriteFile(filepath.Join(dataDir, name), []byte(content), 0o600))
	testutil.AssertNoError(t, os.Symlink(filepath.Base(dataDir), filepath.Join(mount, "..data")))
	testutil.AssertNoError(t, os.Symlink("..data/"+name, filepath.Join(mount, name)))

	return filepath.Join(mount, name)
}

func TestValidateRuntimeAcceptsConfigMapProjectedFiles(t *testing.T) {
	t.Parallel()

	t.Run("tuf_root", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Verification = config.ModeWarn
		cfg.PolicyDir = t.TempDir()
		cfg.Sigstore.TUFMirror = testTUFMirrorURL
		cfg.Sigstore.TUFRoot = projectConfigMapFile(
			t,
			"root.json",
			`{}`,
		)

		testutil.AssertNoError(t, cfg.ValidateRuntime())
	})

	t.Run("ca_cert", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Verification = config.ModeWarn
		cfg.PolicyDir = t.TempDir()
		cfg.Registries = []config.Registry{
			{
				Prefix:   testPrefixGHCR,
				Mirror:   "",
				CACert:   projectConfigMapFile(t, "ca.crt", "cert"),
				Insecure: false,
			},
		}

		testutil.AssertNoError(t, cfg.ValidateRuntime())
	})

	t.Run("policy keys", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Verification = config.ModeWarn
		cfg.PolicyDir = t.TempDir()
		cfg.Policy.Keys = []string{projectConfigMapFile(t, "policy.pub", "pubkey")}

		testutil.AssertNoError(t, cfg.ValidateRuntime())
	})
}

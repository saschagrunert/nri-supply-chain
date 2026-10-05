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

	t.Run("guac ca_cert and auth token", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Verification = config.ModeWarn
		cfg.PolicyDir = t.TempDir()
		applyValidGUAC(cfg)
		cfg.Guac.CACertPath = projectConfigMapFile(t, "ca.crt", "cert")
		cfg.Guac.AuthTokenPath = projectConfigMapFile(t, "token", "secret")

		testutil.AssertNoError(t, cfg.ValidateRuntime())
	})

	t.Run("bundle_signature_key", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Verification = config.ModeWarn
		cfg.PolicyDir = t.TempDir()
		cfg.Offline.Mode = config.OfflineModeOffline
		cfg.Offline.AttestationStore = t.TempDir()
		cfg.Offline.BundleSignatureKey = projectConfigMapFile(t, "bundle.pub", "pubkey")

		testutil.AssertNoError(t, cfg.ValidateRuntime())
	})
}

// escapingSymlink returns a symbolic link to a regular file outside the
// directory containing the link, which the plugin refuses to read.
func escapingSymlink(t *testing.T) string {
	t.Helper()

	target := filepath.Join(t.TempDir(), "secret")
	testutil.AssertNoError(t, os.WriteFile(target, []byte("data"), 0o600))

	link := filepath.Join(t.TempDir(), "link")
	testutil.AssertNoError(t, os.Symlink(target, link))

	return link
}

func TestValidateRuntimeRejectsEscapingSymlinks(t *testing.T) {
	t.Parallel()

	for name, apply := range map[string]func(cfg *config.Config, path string){
		"guac ca_cert": func(cfg *config.Config, path string) {
			applyValidGUAC(cfg)
			cfg.Guac.CACertPath = path
		},
		"guac auth_token_path": func(cfg *config.Config, path string) {
			applyValidGUAC(cfg)
			cfg.Guac.AuthTokenPath = path
		},
		"registry ca_cert": func(cfg *config.Config, path string) {
			cfg.Registries = []config.Registry{
				{Prefix: testPrefixGHCR, Mirror: "", CACert: path, Insecure: false},
			}
		},
		"bundle_signature_key without require_bundle_signature": func(
			cfg *config.Config, path string,
		) {
			cfg.Offline.Mode = config.OfflineModeOffline
			cfg.Offline.AttestationStore = filepath.Dir(path)
			cfg.Offline.BundleSignatureKey = path
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg := config.DefaultConfig()
			cfg.Verification = config.ModeWarn
			cfg.PolicyDir = t.TempDir()
			apply(cfg, escapingSymlink(t))

			testutil.AssertErrorIs(t, cfg.ValidateRuntime(), config.ErrSymlinkNotAllowed)
		})
	}
}

func TestValidateRuntimeFileErrors(t *testing.T) {
	t.Parallel()

	t.Run("registry ca_cert is a directory", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Registries = []config.Registry{
			{Prefix: testPrefixGHCR, Mirror: "", CACert: t.TempDir(), Insecure: false},
		}

		testutil.AssertErrorIs(
			t, cfg.ValidateRuntime(), config.ErrRegistryCACertNotRegularFile,
		)
	})

	t.Run("policy key not found", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.PolicyDir = t.TempDir()
		cfg.Policy.Keys = []string{filepath.Join(t.TempDir(), "missing.pub")}

		testutil.AssertErrorIs(t, cfg.ValidateRuntime(), config.ErrPolicyKeyNotFound)
	})

	t.Run("bundle_signature_key not found without require_bundle_signature", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Offline.Mode = config.OfflineModeOffline
		cfg.Offline.AttestationStore = t.TempDir()
		cfg.Offline.BundleSignatureKey = filepath.Join(t.TempDir(), "missing.pub")

		testutil.AssertErrorIs(
			t, cfg.ValidateRuntime(), config.ErrBundleSignatureKeyNotFound,
		)
	})
}

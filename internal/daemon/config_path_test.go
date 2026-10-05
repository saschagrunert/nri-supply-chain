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

package daemon_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/daemon"
)

func TestShouldUseConfigFile(t *testing.T) {
	t.Parallel()

	t.Run("empty path", func(t *testing.T) {
		t.Parallel()

		if daemon.ShouldUseConfigFile("") {
			t.Error("expected false for empty path")
		}
	})

	t.Run("non-default path", func(t *testing.T) {
		t.Parallel()

		if !daemon.ShouldUseConfigFile("/custom/config.toml") {
			t.Error("expected true for non-default path")
		}
	})

	t.Run("default path missing", func(t *testing.T) {
		t.Parallel()

		if daemon.ShouldUseConfigFile(daemon.DefaultConfigPath) {
			t.Error("expected false when default config file does not exist")
		}
	})

	t.Run("default path exists", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		configPath := filepath.Join(dir, "config.toml")

		err := os.WriteFile(configPath, []byte(""), 0o600)
		if err != nil {
			t.Fatalf("writing config: %v", err)
		}

		if !daemon.ShouldUseConfigFile(configPath) {
			t.Error("expected true when config file exists")
		}
	})
}

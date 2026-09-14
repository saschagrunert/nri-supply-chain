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

package policy_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
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

	keyPath := projectConfigMapFile(t, "verifier.pub", "public-key-data")
	certPath := projectConfigMapFile(t, "ca.pem", "certificate-data")

	pol := verifierPolicy(nil, keyVerifier(testVerifierID, keyPath))
	pol.Notation = &policy.NotationPolicy{
		TrustStores: []policy.NotationTrustStore{{
			Name: "store", Type: "ca", Certificates: []string{certPath},
		}},
	}

	testutil.AssertNoError(t, pol.ValidateRuntime())
}

func TestValidateRuntimeRejectsEscapingKeySymlink(t *testing.T) {
	t.Parallel()

	outside := filepath.Join(t.TempDir(), "verifier.pub")
	testutil.AssertNoError(t, os.WriteFile(outside, []byte("public-key-data"), 0o600))

	keyPath := filepath.Join(t.TempDir(), "verifier.pub")
	testutil.AssertNoError(t, os.Symlink(outside, keyPath))

	pol := verifierPolicy(nil, keyVerifier(testVerifierID, keyPath))

	testutil.AssertErrorIs(t, pol.ValidateRuntime(), policy.ErrNotRegularFile)
}

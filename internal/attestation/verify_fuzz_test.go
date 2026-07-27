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

package attestation_test

import (
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
)

func FuzzArtifactPolicy(f *testing.F) {
	f.Add("sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
	f.Add("sha512:abcdef")
	f.Add("")
	f.Add("no-colon")
	f.Add("sha256:")

	f.Fuzz(func(_ *testing.T, digest string) {
		attestation.ExportArtifactPolicy(digest)
	})
}

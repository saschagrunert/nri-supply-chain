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
)

func FuzzLoad(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"trust":{"issuers":["https://example.com"]}}`))
	f.Add([]byte(`not json`))

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		p := filepath.Join(dir, "policy.json")

		os.WriteFile(p, data, 0o600)

		pol, err := policy.Load(p)
		if err != nil {
			return
		}

		pol.Validate()
	})
}

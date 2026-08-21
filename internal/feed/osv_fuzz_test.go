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

package feed_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/feed"
)

func FuzzParseFile(f *testing.F) {
	f.Add([]byte(`{"id":"GHSA-1234","affected":[` +
		`{"package":{"purl":"pkg:oci/nginx@sha256:abc"}}]}`))
	f.Add([]byte(`[{"id":"CVE-2024-0001","affected":[` +
		`{"package":{"purl":"pkg:golang/example.com/mod@v1.0.0"}}]}]`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{"id":"OSV-2024-1","affected":[]}`))
	f.Add([]byte(`[{"id":"A","affected":[` +
		`{"package":{"purl":"pkg:npm/foo@1.0"}},` +
		`{"package":{"purl":"pkg:npm/bar@2.0"}}]},` +
		`{"id":"B","affected":[` +
		`{"package":{"purl":"pkg:npm/foo@1.0"}}]}]`))

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, "vuln.json")

		err := os.WriteFile(path, data, 0o600)
		if err != nil {
			t.Fatal(err)
		}

		feed.ParseFile(path)
	})
}

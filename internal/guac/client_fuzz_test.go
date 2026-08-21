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

package guac_test

import (
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/guac"
)

func FuzzParseVulnerabilityResponse(f *testing.F) {
	f.Add([]byte(`{"vulnerabilities":[]}`), "sha256:abc")
	f.Add([]byte(`{"vulnerabilities":[{"metadata":{},"package":"sha256:abc",`+
		`"vulnerability":{"vulnerabilityIDs":["CVE-2024-1234"]}}]}`), "sha256:abc")
	f.Add([]byte(`{}`), "")
	f.Add([]byte(`null`), "")
	f.Add([]byte(``), "")

	f.Fuzz(func(_ *testing.T, data []byte, digest string) {
		_, _, _ = guac.ExportParseVulnResponse(data, digest)
	})
}

func FuzzParseDependencyResponse(f *testing.F) {
	f.Add([]byte(`{"purls":[]}`), 0)
	f.Add(
		[]byte(`{"purls":["pkg:npm/express@4.18.2","pkg:golang/stdlib@1.21.0"]}`),
		10,
	)
	f.Add([]byte(`{}`), 0)
	f.Add([]byte(`null`), 0)
	f.Add([]byte(``), 0)

	f.Fuzz(func(_ *testing.T, data []byte, maxDeps int) {
		_, _ = guac.ExportParseDepsResponse(data, maxDeps)
	})
}

func FuzzParseScorecardResponse(f *testing.F) {
	f.Add([]byte(`{"data":{"scorecards":[]}}`))
	f.Add([]byte(`{"data":{"scorecards":[{"source":{"type":"git",` +
		`"namespace":"github.com","name":"org/repo"},"scorecard":` +
		`{"aggregateScore":7.5,"checks":[{"check":"Code-Review","score":8}]}}]}}`))
	f.Add([]byte(`{"errors":[{"message":"not found"}]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(``))

	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = guac.ExportParseScorecardResponse(data)
	})
}

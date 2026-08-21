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

func BenchmarkParseVulnResponse(b *testing.B) {
	data := []byte(`{"vulnerabilities":[` +
		`{"metadata":{},"package":"sha256:abc","vulnerability":{"vulnerabilityIDs":["CVE-2024-1234"]}},` +
		`{"metadata":{},"package":"sha256:def","vulnerability":{"vulnerabilityIDs":["CVE-2024-5678","CVE-2024-9999"]}}` +
		`]}`)

	for range b.N {
		_, _, _ = guac.ExportParseVulnResponse(data, "sha256:abc")
	}
}

func BenchmarkParseDepsResponse(b *testing.B) {
	data := []byte(`{"purls":[` +
		`"pkg:npm/express@4.18.2",` +
		`"pkg:npm/lodash@4.17.21",` +
		`"pkg:golang/stdlib@1.21.0",` +
		`"pkg:pypi/requests@2.31.0",` +
		`"pkg:maven/org.apache.commons/commons-lang3@3.14.0"` +
		`]}`)

	for range b.N {
		_, _ = guac.ExportParseDepsResponse(data, 10)
	}
}

func BenchmarkParseScorecardResponse(b *testing.B) {
	data := []byte(`{"data":{"scorecards":[{"source":{"type":"git",` +
		`"namespace":"github.com","name":"org/repo"},"scorecard":` +
		`{"aggregateScore":7.5,"checks":[` +
		`{"check":"Code-Review","score":8},` +
		`{"check":"Maintained","score":10},` +
		`{"check":"Vulnerabilities","score":9}` +
		`]}}]}}`)

	for range b.N {
		_, _ = guac.ExportParseScorecardResponse(data)
	}
}

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

package vulnscan_test

import (
	"context"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/vulnscan"
)

func FuzzVerify(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"_type":"bad"}`))
	f.Add([]byte(`{
		"_type":"https://in-toto.io/Statement/v1",
		"subject":[{"name":"test","digest":{"sha256":"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"}}],
		"predicateType":"https://in-toto.io/attestation/vulns/v0.1",
		"predicate":{"scanner":{"uri":"pkg:generic/trivy","version":"0.50.0"},
		"metadata":{"scannedOn":"2025-01-15T10:00:00Z"},
		"result":{"vulnerabilities":[]}}
	}`))

	// Seed: subject digest mismatch, exercising the subject binding check.
	f.Add([]byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[{"name":"test","digest":{"sha256":` +
		`"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}}],` +
		`"predicateType":"https://in-toto.io/attestation/vulns/v0.1",` +
		`"predicate":{"scanner":{"uri":"pkg:generic/trivy","version":"0.50.0"},` +
		`"result":{"vulnerabilities":[]}}` +
		`}`))

	// Seed: vulnerabilities with scores, exercising threshold checks.
	f.Add([]byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[{"name":"test","digest":{"sha256":` +
		`"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"}}],` +
		`"predicateType":"https://in-toto.io/attestation/vulns/v0.1",` +
		`"predicate":{"scanner":{"uri":"pkg:generic/grype","version":"0.80.0"},` +
		`"metadata":{"scannedOn":"2025-01-15T10:00:00Z"},` +
		`"result":{"vulnerabilities":[` +
		`{"id":"CVE-2024-0001","severity":"critical","score":9.8},` +
		`{"id":"CVE-2024-0002","severity":"high","score":7.5}]}}` +
		`}`))

	// Seed: empty subjects list, exercising that path.
	f.Add([]byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[],` +
		`"predicateType":"https://in-toto.io/attestation/vulns/v0.1",` +
		`"predicate":{"scanner":{"uri":"pkg:generic/trivy","version":"0.50.0"},` +
		`"result":{"vulnerabilities":[]}}` +
		`}`))

	// Seed: multiple subjects with one matching, exercising multi-subject iteration.
	f.Add([]byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[` +
		`{"name":"other","digest":{"sha256":"0000000000000000000000000000000000000000000000000000000000000000"}},` +
		`{"name":"test","digest":{"sha256":"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"}}],` +
		`"predicateType":"https://in-toto.io/attestation/vulns/v0.1",` +
		`"predicate":{"scanner":{"uri":"pkg:generic/trivy","version":"0.50.0"},` +
		`"result":{"vulnerabilities":[]}}` +
		`}`))

	f.Fuzz(func(_ *testing.T, data []byte) {
		vulnscan.Verify(context.Background(), data, &policy.Policy{}, testDigest)
	})
}

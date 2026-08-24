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

package vex_test

import (
	"context"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/vex"
)

func FuzzVerify(f *testing.F) {
	f.Add([]byte(`{"subject":[],"predicate":{"statements":[]}}`))
	f.Add([]byte(`{}`))

	const testDigest = "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4" +
		"e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

	// CycloneDX BOM seed wrapped in an in-toto statement so the fuzzer
	// exercises the CycloneDX dispatch path.
	f.Add([]byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[{"name":"test","digest":{"sha256":` +
		`"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"}}],` +
		`"predicateType":"https://cyclonedx.org/bom",` +
		`"predicate":{"bomFormat":"CycloneDX","specVersion":"1.5",` +
		`"vulnerabilities":[{"id":"CVE-2024-0001",` +
		`"analysis":{"state":"not_affected"},` +
		`"affects":[{"ref":"` + testDigest + `"}]}]}` +
		`}`))

	// Seed: OpenVEX with "affected" status, exercising the affected/fail path.
	f.Add([]byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[{"name":"test","digest":{"sha256":` +
		`"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"}}],` +
		`"predicateType":"https://openvex.dev/ns",` +
		`"predicate":{"@context":"https://openvex.dev/ns/v0.2.0",` +
		`"@id":"https://openvex.dev/docs/example/vex-affected",` +
		`"statements":[{"vulnerability":{"name":"CVE-2024-9999"},` +
		`"products":[{"@id":"` + testDigest + `"}],` +
		`"status":"affected"}]}` +
		`}`))

	// Seed: OpenVEX with "under_investigation" status, exercising the
	// under_investigation path (defaults to allow with empty policy).
	f.Add([]byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[{"name":"test","digest":{"sha256":` +
		`"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"}}],` +
		`"predicateType":"https://openvex.dev/ns",` +
		`"predicate":{"@context":"https://openvex.dev/ns/v0.2.0",` +
		`"@id":"https://openvex.dev/docs/example/vex-ui",` +
		`"statements":[{"vulnerability":{"name":"CVE-2024-5555"},` +
		`"products":[{"@id":"` + testDigest + `"}],` +
		`"status":"under_investigation"}]}` +
		`}`))

	// Seed: CycloneDX BOM with "exploitable" state, exercising the
	// affected/fail path via CycloneDX format.
	f.Add([]byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[{"name":"test","digest":{"sha256":` +
		`"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"}}],` +
		`"predicateType":"https://cyclonedx.org/bom",` +
		`"predicate":{"bomFormat":"CycloneDX","specVersion":"1.5",` +
		`"vulnerabilities":[{"id":"CVE-2024-0002",` +
		`"analysis":{"state":"exploitable"},` +
		`"affects":[{"ref":"` + testDigest + `"}]}]}` +
		`}`))

	// Seed: CycloneDX BOM with "in_triage" state, exercising the
	// under_investigation path via CycloneDX format.
	f.Add([]byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[{"name":"test","digest":{"sha256":` +
		`"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"}}],` +
		`"predicateType":"https://cyclonedx.org/bom",` +
		`"predicate":{"bomFormat":"CycloneDX","specVersion":"1.5",` +
		`"vulnerabilities":[{"id":"CVE-2024-0003",` +
		`"analysis":{"state":"in_triage"},` +
		`"affects":[{"ref":"` + testDigest + `"}]}]}` +
		`}`))

	// Seed: OpenVEX with multiple statements mixing affected and not_affected,
	// exercising the multi-statement classification path.
	f.Add([]byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[{"name":"test","digest":{"sha256":` +
		`"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"}}],` +
		`"predicateType":"https://openvex.dev/ns",` +
		`"predicate":{"@context":"https://openvex.dev/ns/v0.2.0",` +
		`"@id":"https://openvex.dev/docs/example/vex-mixed",` +
		`"statements":[` +
		`{"vulnerability":{"name":"CVE-2024-1111"},"products":[{"@id":"` + testDigest + `"}],"status":"not_affected"},` +
		`{"vulnerability":{"name":"CVE-2024-2222"},"products":[{"@id":"` + testDigest + `"}],"status":"affected"}` +
		`]}` +
		`}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		result, err := vex.Verify(
			context.Background(), data, &policy.Policy{},
			"docker.io/library/nginx:latest", testDigest,
			nil,
		)
		if err == nil && result == nil {
			t.Error("Verify returned nil result and nil error")
		}

		if result != nil && result.Type == "" {
			t.Error("Verify returned result with empty Type")
		}
	})
}

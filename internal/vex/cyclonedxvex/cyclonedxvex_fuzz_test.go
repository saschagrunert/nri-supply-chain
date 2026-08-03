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

package cyclonedxvex_test

import (
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/vex/cyclonedxvex"
)

func FuzzVerify(f *testing.F) {
	f.Add([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","vulnerabilities":[]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"bomFormat":"CycloneDX"}`))

	const testDigest = "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4" +
		"e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

	// Seed: BOM with exploitable vulnerability affecting the image digest,
	// exercising the affected/fail classification path.
	f.Add([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.5",` +
		`"components":[{"type":"container","name":"nginx","bom-ref":"comp-nginx",` +
		`"hashes":[{"alg":"SHA-256",` +
		`"content":"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"}]}],` +
		`"vulnerabilities":[{"id":"CVE-2024-0001",` +
		`"analysis":{"state":"exploitable"},` +
		`"affects":[{"ref":"comp-nginx"}]}]}`))

	// Seed: BOM with in_triage vulnerability, exercising the under_investigation path.
	f.Add([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.5",` +
		`"vulnerabilities":[{"id":"CVE-2024-0002",` +
		`"analysis":{"state":"in_triage"},` +
		`"affects":[{"ref":"` + testDigest + `"}]}]}`))

	// Seed: BOM with not_affected vulnerability via component hash match,
	// exercising the component index lookup and hash matching path.
	f.Add([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.5",` +
		`"components":[{"type":"container","name":"app","bom-ref":"comp-app",` +
		`"hashes":[{"alg":"SHA-256",` +
		`"content":"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"}]}],` +
		`"vulnerabilities":[{"id":"CVE-2024-0003",` +
		`"analysis":{"state":"not_affected"},` +
		`"affects":[{"ref":"comp-app"}]}]}`))

	// Seed: BOM with multiple vulnerabilities in different states,
	// exercising the multi-vulnerability classification loop.
	f.Add([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.5",` +
		`"vulnerabilities":[` +
		`{"id":"CVE-2024-0010","analysis":{"state":"not_affected"},` +
		`"affects":[{"ref":"` + testDigest + `"}]},` +
		`{"id":"CVE-2024-0011","analysis":{"state":"exploitable"},` +
		`"affects":[{"ref":"` + testDigest + `"}]},` +
		`{"id":"CVE-2024-0012","analysis":{"state":"in_triage"},` +
		`"affects":[{"ref":"` + testDigest + `"}]}` +
		`]}`))

	f.Fuzz(func(_ *testing.T, data []byte) {
		cyclonedxvex.Verify(data, testDigest, "")
	})
}

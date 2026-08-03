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

package sbom_test

import (
	"context"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/sbom"
)

func FuzzVerify(f *testing.F) {
	f.Add([]byte(`{"subject":[],"predicate":{"packages":[]}}`))
	f.Add([]byte(`{}`))

	const testFuzzDigest = "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4" +
		"e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

	const testFuzzDigestHash = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4" +
		"e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

	// Seed: SPDX document wrapped in in-toto with a package containing a
	// license and PURL, exercising the SPDX parsing and license extraction paths.
	f.Add([]byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[{"name":"test-image","digest":{"sha256":"` + testFuzzDigestHash + `"}}],` +
		`"predicateType":"https://spdx.dev/Document",` +
		`"predicate":{"spdxVersion":"SPDX-2.3","packages":[` +
		`{"name":"mylib","licenseConcluded":"MIT","licenseDeclared":"MIT",` +
		`"externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl",` +
		`"referenceLocator":"pkg:npm/mylib@1.0.0"}]}]}` +
		`}`))

	// Seed: SPDX document with a GPL license, exercising the license
	// extraction path for compound SPDX expressions.
	f.Add([]byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[{"name":"test-image","digest":{"sha256":"` + testFuzzDigestHash + `"}}],` +
		`"predicateType":"https://spdx.dev/Document",` +
		`"predicate":{"spdxVersion":"SPDX-2.3","packages":[` +
		`{"name":"gpl-lib","licenseConcluded":"GPL-3.0-only AND MIT","licenseDeclared":"NOASSERTION",` +
		`"externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl",` +
		`"referenceLocator":"pkg:npm/gpl-lib@2.0.0"}]}]}` +
		`}`))

	// Seed: CycloneDX document wrapped in in-toto with components containing
	// licenses and PURLs, exercising the CycloneDX parsing path.
	f.Add([]byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[{"name":"test-image","digest":{"sha256":"` + testFuzzDigestHash + `"}}],` +
		`"predicateType":"https://spdx.dev/Document",` +
		`"predicate":{"bomFormat":"CycloneDX","components":[` +
		`{"name":"mylib","purl":"pkg:npm/mylib@1.0.0",` +
		`"licenses":[{"license":{"id":"MIT"}}]}]}` +
		`}`))

	// Seed: SPDX document with multiple packages and various license types,
	// exercising multi-package iteration and NOASSERTION filtering.
	f.Add([]byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[{"name":"test-image","digest":{"sha256":"` + testFuzzDigestHash + `"}}],` +
		`"predicateType":"https://spdx.dev/Document",` +
		`"predicate":{"spdxVersion":"SPDX-2.3","packages":[` +
		`{"name":"lib-a","licenseConcluded":"Apache-2.0","licenseDeclared":"NOASSERTION",` +
		`"externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl",` +
		`"referenceLocator":"pkg:npm/lib-a@1.0.0"}]},` +
		`{"name":"lib-b","licenseConcluded":"NOASSERTION","licenseDeclared":"BSD-3-Clause",` +
		`"externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl",` +
		`"referenceLocator":"pkg:npm/lib-b@2.0.0"}]},` +
		`{"name":"lib-c","licenseConcluded":"GPL-2.0-only WITH Classpath-exception-2.0",` +
		`"licenseDeclared":"NOASSERTION","externalRefs":[]}]}` +
		`}`))

	// Seed: CycloneDX document with a denied component PURL, exercising
	// the component extraction path.
	f.Add([]byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[{"name":"test-image","digest":{"sha256":"` + testFuzzDigestHash + `"}}],` +
		`"predicateType":"https://spdx.dev/Document",` +
		`"predicate":{"bomFormat":"CycloneDX","components":[` +
		`{"name":"evil-lib","purl":"pkg:npm/evil-lib@0.1.0",` +
		`"licenses":[{"license":{"name":"Proprietary"}}]},` +
		`{"name":"good-lib","purl":"pkg:npm/good-lib@3.0.0",` +
		`"licenses":[{"license":{"id":"Apache-2.0"}}]}]}` +
		`}`))

	f.Fuzz(func(_ *testing.T, data []byte) {
		sbom.Verify(context.Background(), data, &policy.Policy{}, testFuzzDigest)
	})
}

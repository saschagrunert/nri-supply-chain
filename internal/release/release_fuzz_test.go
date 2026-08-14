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

package release_test

import (
	"context"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/release"
)

func FuzzVerify(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"_type":"bad"}`))
	f.Add([]byte(`{
		"_type":"https://in-toto.io/Statement/v1",
		"subject":[{"name":"test","digest":{"sha256":"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"}}],
		"predicateType":"https://in-toto.io/attestation/release/v0.1",
		"predicate":{"purl":"pkg:oci/myapp@sha256:abc123",
		"releaseType":"production","packageId":"myapp-v1.0.0"}
	}`))

	// Seed: subject digest mismatch, exercising the subject binding check.
	f.Add([]byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[{"name":"test","digest":{"sha256":` +
		`"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}}],` +
		`"predicateType":"https://in-toto.io/attestation/release/v0.1",` +
		`"predicate":{"purl":"pkg:oci/myapp@sha256:abc123",` +
		`"releaseType":"production","packageId":"myapp-v1.0.0"}` +
		`}`))

	// Seed: empty subjects list, exercising that path.
	f.Add([]byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[],` +
		`"predicateType":"https://in-toto.io/attestation/release/v0.1",` +
		`"predicate":{"purl":"pkg:oci/other@sha256:def456",` +
		`"releaseType":"staging","packageId":"other-v2.0.0"}` +
		`}`))

	// Seed: release without packageId, exercising the requirePackageId policy path.
	f.Add([]byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[{"name":"test","digest":{"sha256":` +
		`"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"}}],` +
		`"predicateType":"https://in-toto.io/attestation/release/v0.1",` +
		`"predicate":{"purl":"pkg:oci/myapp@sha256:abc123",` +
		`"releaseType":"production"}` +
		`}`))

	// Seed: multiple subjects with one matching, exercising multi-subject iteration.
	f.Add([]byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[` +
		`{"name":"other","digest":{"sha256":"0000000000000000000000000000000000000000000000000000000000000000"}},` +
		`{"name":"test","digest":{"sha256":"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"}}],` +
		`"predicateType":"https://in-toto.io/attestation/release/v0.1",` +
		`"predicate":{"purl":"pkg:oci/myapp@sha256:abc123",` +
		`"releaseType":"production","packageId":"myapp-v1.0.0"}` +
		`}`))

	f.Fuzz(func(_ *testing.T, data []byte) {
		release.Verify(context.Background(), data, &policy.Policy{}, testDigest)
	})
}

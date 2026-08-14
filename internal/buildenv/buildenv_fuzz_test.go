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

package buildenv_test

import (
	"context"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/buildenv"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
)

func FuzzVerify(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"_type":"bad"}`))
	f.Add([]byte(`{
		"_type":"https://in-toto.io/Statement/v1",
		"subject":[{"name":"test","digest":{"sha256":"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"}}],
		"predicateType":"https://in-toto.io/attestation/build-env/v1",
		"predicate":{"properties":[{"name":"HERMETIC","value":"true"},
		{"name":"REPRODUCIBLE","value":"true"}]}
	}`))

	// Seed: subject digest mismatch, exercising the subject binding check.
	f.Add([]byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[{"name":"test","digest":{"sha256":` +
		`"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}}],` +
		`"predicateType":"https://in-toto.io/attestation/build-env/v1",` +
		`"predicate":{"properties":[{"name":"HERMETIC","value":"true"}]}` +
		`}`))

	// Seed: empty subjects list, exercising that path.
	f.Add([]byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[],` +
		`"predicateType":"https://in-toto.io/attestation/build-env/v1",` +
		`"predicate":{"properties":[{"name":"HERMETIC","value":"true"}]}` +
		`}`))

	// Seed: empty properties list, exercising the zero-property path.
	f.Add([]byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[{"name":"test","digest":{"sha256":` +
		`"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"}}],` +
		`"predicateType":"https://in-toto.io/attestation/build-env/v1",` +
		`"predicate":{"properties":[]}` +
		`}`))

	// Seed: properties with forbidden name, exercising the forbidden property check.
	f.Add([]byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[{"name":"test","digest":{"sha256":` +
		`"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"}}],` +
		`"predicateType":"https://in-toto.io/attestation/build-env/v1",` +
		`"predicate":{"properties":[` +
		`{"name":"HERMETIC","value":"true"},` +
		`{"name":"ALLOW_NETWORK","value":"true"},` +
		`{"name":"REPRODUCIBLE","value":"false"}]}` +
		`}`))

	f.Fuzz(func(_ *testing.T, data []byte) {
		buildenv.Verify(context.Background(), data, &policy.Policy{}, testDigest)
	})
}

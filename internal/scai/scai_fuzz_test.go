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

package scai_test

import (
	"context"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/scai"
)

func FuzzVerify(f *testing.F) {
	f.Add([]byte(`{"subject":[],"predicate":{"attributes":[]}}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"_type":"bad"}`))

	// Seed: valid SCAI report wrapped in an in-toto statement with matching
	// subject digest, exercising the happy-path verification.
	f.Add([]byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[{"name":"test-image","digest":{"sha256":` +
		`"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"}}],` +
		`"predicateType":"https://in-toto.io/attestation/scai/v0.3",` +
		`"predicate":{"attributes":[` +
		`{"attribute":"PASSED_CODE_REVIEW","evidence":{"url":"https://review.example.com/1"}},` +
		`{"attribute":"PASSED_TESTS","evidence":{"url":"https://ci.example.com/2"}}` +
		`]}` +
		`}`))

	// Seed: valid SCAI report with attribute that has null evidence,
	// exercising the evidence-missing path.
	f.Add([]byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[{"name":"test-image","digest":{"sha256":` +
		`"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"}}],` +
		`"predicateType":"https://in-toto.io/attestation/scai/v0.3",` +
		`"predicate":{"attributes":[` +
		`{"attribute":"PASSED_TESTS","evidence":null}` +
		`]}` +
		`}`))

	// Seed: valid SCAI report with empty object evidence, exercising the
	// empty-evidence detection path.
	f.Add([]byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[{"name":"test-image","digest":{"sha256":` +
		`"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"}}],` +
		`"predicateType":"https://in-toto.io/attestation/scai/v0.3",` +
		`"predicate":{"attributes":[` +
		`{"attribute":"FUZZ_TESTED","evidence":{}}` +
		`]}` +
		`}`))

	// Seed: valid SCAI report with empty array evidence, exercising the
	// empty-array evidence detection path.
	f.Add([]byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[{"name":"test-image","digest":{"sha256":` +
		`"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"}}],` +
		`"predicateType":"https://in-toto.io/attestation/scai/v0.3",` +
		`"predicate":{"attributes":[` +
		`{"attribute":"FUZZ_TESTED","evidence":[]}` +
		`]}` +
		`}`))

	// Seed: subject digest mismatch, exercising the subject binding check.
	f.Add([]byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[{"name":"test-image","digest":{"sha256":` +
		`"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}}],` +
		`"predicateType":"https://in-toto.io/attestation/scai/v0.3",` +
		`"predicate":{"attributes":[{"attribute":"PASSED_TESTS"}]}` +
		`}`))

	// Seed: empty attributes list, exercising the zero-attribute path.
	f.Add([]byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[{"name":"test-image","digest":{"sha256":` +
		`"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"}}],` +
		`"predicateType":"https://in-toto.io/attestation/scai/v0.3",` +
		`"predicate":{"attributes":[]}` +
		`}`))

	f.Fuzz(func(_ *testing.T, data []byte) {
		scai.Verify(context.Background(), data, &policy.Policy{}, testDigest)
	})
}

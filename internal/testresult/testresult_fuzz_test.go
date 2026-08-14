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

package testresult_test

import (
	"context"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/testresult"
)

func FuzzVerify(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"_type":"bad"}`))
	f.Add([]byte(`{
		"_type":"https://in-toto.io/Statement/v1",
		"subject":[{"name":"test","digest":{"sha256":"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"}}],
		"predicateType":"https://in-toto.io/attestation/test-result/v0.1",
		"predicate":{"suites":[{"name":"unit","passed":true,"tests":10,"failures":0}],
		"metadata":{"ranOn":"2025-01-15T10:00:00Z","framework":"go-test"}}
	}`))

	// Seed: subject digest mismatch, exercising the subject binding check.
	f.Add([]byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[{"name":"test","digest":{"sha256":` +
		`"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}}],` +
		`"predicateType":"https://in-toto.io/attestation/test-result/v0.1",` +
		`"predicate":{"result":"pass","suites":[{"name":"unit","passed":10,"failed":0}]}` +
		`}`))

	// Seed: empty subjects list, exercising that path.
	f.Add([]byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[],` +
		`"predicateType":"https://in-toto.io/attestation/test-result/v0.1",` +
		`"predicate":{"result":"pass","suites":[{"name":"unit","passed":10,"failed":0}]}` +
		`}`))

	// Seed: failing test result, exercising the overall-result-failed path.
	f.Add([]byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[{"name":"test","digest":{"sha256":` +
		`"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"}}],` +
		`"predicateType":"https://in-toto.io/attestation/test-result/v0.1",` +
		`"predicate":{"result":"fail","suites":[` +
		`{"name":"unit","passed":8,"failed":2},` +
		`{"name":"integration","passed":5,"failed":1}],` +
		`"metadata":{"finishedOn":"2025-01-15T10:30:00Z","framework":"go-test"}}` +
		`}`))

	// Seed: multiple suites with mixed results, exercising multi-suite iteration
	// and failed suite collection.
	f.Add([]byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[{"name":"test","digest":{"sha256":` +
		`"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"}}],` +
		`"predicateType":"https://in-toto.io/attestation/test-result/v0.1",` +
		`"predicate":{"result":"pass","suites":[` +
		`{"name":"unit","passed":50,"failed":0},` +
		`{"name":"integration","passed":20,"failed":0},` +
		`{"name":"e2e","passed":10,"failed":0}],` +
		`"metadata":{"finishedOn":"2025-01-15T11:00:00Z","framework":"go-test"}}` +
		`}`))

	f.Fuzz(func(_ *testing.T, data []byte) {
		testresult.Verify(context.Background(), data, &policy.Policy{}, testDigest)
	})
}

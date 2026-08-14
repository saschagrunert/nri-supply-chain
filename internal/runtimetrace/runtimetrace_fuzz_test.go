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

package runtimetrace_test

import (
	"context"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/runtimetrace"
)

func FuzzVerify(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"_type":"bad"}`))
	f.Add([]byte(`{
		"_type":"https://in-toto.io/Statement/v1",
		"subject":[{"name":"test","digest":{"sha256":"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"}}],
		"predicateType":"https://in-toto.io/attestation/runtime-trace/v0.1",
		"predicate":{"monitor":{"type":"falco","version":"0.38.0"},
		"metadata":{"collectedOn":"2025-01-15T10:00:00Z","duration":"300s"},
		"fileAccesses":[{"path":"/usr/bin/curl","operation":"exec"}]}
	}`))

	// Seed: subject digest mismatch, exercising the subject binding check.
	f.Add([]byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[{"name":"test","digest":{"sha256":` +
		`"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}}],` +
		`"predicateType":"https://in-toto.io/attestation/runtime-trace/v0.1",` +
		`"predicate":{"monitor":{"type":"falco","version":"0.38.0"},` +
		`"metadata":{"collectedOn":"2025-01-15T10:00:00Z","duration":"300s"},` +
		`"fileAccesses":[]}` +
		`}`))

	// Seed: empty subjects list, exercising that path.
	f.Add([]byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[],` +
		`"predicateType":"https://in-toto.io/attestation/runtime-trace/v0.1",` +
		`"predicate":{"monitor":{"type":"tetragon","version":"1.0.0"},` +
		`"metadata":{"collectedOn":"2025-01-15T10:00:00Z","duration":"60s"},` +
		`"fileAccesses":[]}` +
		`}`))

	// Seed: trace with process and network events, exercising all log type paths.
	f.Add([]byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[{"name":"test","digest":{"sha256":` +
		`"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"}}],` +
		`"predicateType":"https://in-toto.io/attestation/runtime-trace/v0.1",` +
		`"predicate":{"monitor":{"type":"falco","version":"0.38.0"},` +
		`"metadata":{"collectedOn":"2025-01-15T10:00:00Z","duration":"300s"},` +
		`"monitorLog":{"process":[{"name":"curl","pid":1234}],` +
		`"network":[{"destination":"10.0.0.1","port":443}],` +
		`"fileAccess":[{"name":"/etc/shadow","operation":"read"}]}}` +
		`}`))

	// Seed: multiple subjects with one matching, exercising multi-subject iteration.
	f.Add([]byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[` +
		`{"name":"other","digest":{"sha256":"0000000000000000000000000000000000000000000000000000000000000000"}},` +
		`{"name":"test","digest":{"sha256":"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"}}],` +
		`"predicateType":"https://in-toto.io/attestation/runtime-trace/v0.1",` +
		`"predicate":{"monitor":{"type":"falco","version":"0.38.0"},` +
		`"metadata":{"collectedOn":"2025-01-15T10:00:00Z","duration":"300s"},` +
		`"fileAccesses":[]}` +
		`}`))

	f.Fuzz(func(_ *testing.T, data []byte) {
		runtimetrace.Verify(context.Background(), data, &policy.Policy{}, testDigest)
	})
}

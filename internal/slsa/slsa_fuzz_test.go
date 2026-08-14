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

package slsa_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/slsa"
)

func FuzzVerify(f *testing.F) {
	seed := slsa.Statement{
		Type: "https://in-toto.io/Statement/v1",
		Subject: []slsa.Subject{
			{
				Name:   testSubjectName,
				Digest: map[string]string{testDigestAlgo: testDigestHash},
			},
		},
		PredicateType: attestation.PredicateSLSAProvenanceV1,
		Predicate: slsa.ProvenancePredicate{
			BuildDefinition: slsa.BuildDefinition{
				BuildType:          "https://actions.github.io/buildtypes/workflow/v1",
				ExternalParameters: map[string]any{"source": "https://github.com/example/repo"},
				InternalParameters: map[string]any{},
			},
			RunDetails: slsa.RunDetails{
				Builder:  slsa.Builder{ID: "https://github.com/actions/runner"},
				Metadata: slsa.Metadata{InvocationID: "run-1", StartedOn: nil},
			},
		},
	}

	seedBytes, err := json.Marshal(seed)
	if err != nil {
		f.Fatal(err)
	}

	f.Add(seedBytes)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"_type":"bad"}`))

	// Seed: valid statement with a subject digest that does NOT match testDigest,
	// exercising the subject digest mismatch path.
	f.Add([]byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[{"name":"nginx","digest":{"sha256":"` +
		`ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}}],` +
		`"predicateType":"https://slsa.dev/provenance/v1",` +
		`"predicate":{"buildDefinition":{"buildType":"https://actions.github.io/buildtypes/workflow/v1",` +
		`"externalParameters":{"source":"https://github.com/example/repo"},` +
		`"internalParameters":{}},"runDetails":{"builder":{"id":"https://github.com/actions/runner"},` +
		`"metadata":{"invocationId":"run-1"}}}` +
		`}`))

	// Seed: valid statement with empty subjects list, exercising that path.
	f.Add([]byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[],` +
		`"predicateType":"https://slsa.dev/provenance/v1",` +
		`"predicate":{"buildDefinition":{"buildType":"https://example.com/build/v1",` +
		`"externalParameters":{},"internalParameters":{}},"runDetails":{"builder":{"id":""},` +
		`"metadata":{"invocationId":""}}}` +
		`}`))

	// Seed: valid statement with multiple subjects, one matching and one not,
	// exercising the multi-subject iteration path.
	f.Add([]byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[` +
		`{"name":"other","digest":{"sha256":"0000000000000000000000000000000000000000000000000000000000000000"}},` +
		`{"name":"nginx","digest":{"sha256":"` +
		testDigestHash + `"}}],` +
		`"predicateType":"https://slsa.dev/provenance/v1",` +
		`"predicate":{"buildDefinition":{"buildType":"https://actions.github.io/buildtypes/workflow/v1",` +
		`"externalParameters":{"source":"https://github.com/example/repo","workflow":".github/workflows/ci.yml"},` +
		`"internalParameters":{}},"runDetails":{"builder":{"id":"https://github.com/actions/runner"},` +
		`"metadata":{"invocationId":"run-42"}}}` +
		`}`))

	// Seed: valid statement with extra/unknown external parameters to exercise
	// the parameter extraction paths.
	f.Add([]byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[{"name":"nginx","digest":{"sha256":"` +
		testDigestHash + `"}}],` +
		`"predicateType":"https://slsa.dev/provenance/v1",` +
		`"predicate":{"buildDefinition":{"buildType":"https://custom.example.com/build/v2",` +
		`"externalParameters":{"source":"https://github.com/other-org/other-repo",` +
		`"custom-key":"custom-value","extra":"data"},` +
		`"internalParameters":{"internal":"param"}},"runDetails":{"builder":{"id":"https://custom-builder.example.com"},` +
		`"metadata":{"invocationId":"run-999"}}}` +
		`}`))

	// Seed: valid statement with startedOn timestamp in metadata to exercise
	// the freshness verification path.
	f.Add([]byte(`{` +
		`"_type":"https://in-toto.io/Statement/v1",` +
		`"subject":[{"name":"nginx","digest":{"sha256":"` +
		testDigestHash + `"}}],` +
		`"predicateType":"https://slsa.dev/provenance/v1",` +
		`"predicate":{"buildDefinition":{"buildType":"https://actions.github.io/buildtypes/workflow/v1",` +
		`"externalParameters":{"source":"https://github.com/example/repo"},` +
		`"internalParameters":{}},"runDetails":{"builder":{"id":"https://github.com/actions/runner"},` +
		`"metadata":{"invocationId":"run-1","startedOn":"2025-01-15T10:30:00Z"}}}` +
		`}`))

	f.Fuzz(func(_ *testing.T, data []byte) {
		slsa.Verify(context.Background(), data, &policy.Policy{}, testDigest)
	})
}

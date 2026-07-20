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
				ExternalParameters: map[string]any{"source": "github.com/example/repo"},
				InternalParameters: map[string]any{},
			},
			RunDetails: slsa.RunDetails{
				Builder:  slsa.Builder{ID: "https://github.com/actions/runner"},
				Metadata: slsa.Metadata{InvocationID: "run-1"},
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

	f.Fuzz(func(_ *testing.T, data []byte) {
		slsa.Verify(data, &policy.Policy{}, testDigest)
	})
}

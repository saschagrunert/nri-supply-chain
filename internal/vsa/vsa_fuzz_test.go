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

package vsa_test

import (
	"encoding/json"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/vsa"
)

func FuzzVerify(f *testing.F) {
	seed := vsa.Statement{
		Type:          "https://in-toto.io/Statement/v1",
		PredicateType: "https://slsa.dev/verification_summary/v1",
		Predicate: vsa.Predicate{
			Verifier:           vsa.Verifier{ID: testVerifierID},
			TimeVerified:       "2024-01-15T10:00:00Z",
			ResourceURI:        testImageRef,
			Policy:             vsa.Policy{URI: testPolicyURI},
			VerificationResult: "PASSED",
			VerifiedLevels:     []string{"SLSA_BUILD_LEVEL_3"},
			SLSAVersion:        "1.0",
		},
	}

	seedBytes, err := json.Marshal(seed)
	if err != nil {
		f.Fatal(err)
	}

	f.Add(seedBytes)
	f.Add([]byte(`{}`))

	pol := &policy.Policy{
		Trust: &policy.TrustPolicy{
			Verifiers: []policy.TrustedVerifier{
				{ID: testVerifierID, Key: "/tmp/nonexistent.pub"},
			},
		},
	}

	f.Fuzz(func(_ *testing.T, data []byte) {
		vsa.Verify(data, pol, testImageRef)
	})
}

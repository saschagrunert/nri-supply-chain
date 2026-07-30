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

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/slsa"
)

func BenchmarkVerify(b *testing.B) {
	stmt := validStatement()

	data, err := json.Marshal(stmt)
	if err != nil {
		b.Fatalf("marshalling statement: %v", err)
	}

	pol := &policy.Policy{
		Sections: policy.Sections{
			Trust: &policy.TrustPolicy{
				Builders: []policy.TrustedBuilder{
					{ID: testBuilderID, MaxLevel: 2},
				},
			},
		},
	}

	b.ResetTimer()

	for range b.N {
		_, _ = slsa.Verify(data, pol, testDigest)
	}
}

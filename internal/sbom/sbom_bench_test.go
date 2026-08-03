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
	"encoding/json"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/sbom"
)

func benchMarshal(b *testing.B, val any) []byte {
	b.Helper()

	data, err := json.Marshal(val)
	if err != nil {
		b.Fatalf("marshalling: %v", err)
	}

	return data
}

func benchWrapInToto(b *testing.B, doc any, digest string) []byte {
	b.Helper()

	predBytes := benchMarshal(b, doc)

	wrapper := inTotoWrapper{
		Type: testInTotoType,
		Subject: []inTotoSubj{
			{
				Name:   testSubjectName,
				Digest: map[string]string{testDigestAlgo: digest[len(testDigestAlgo)+1:]},
			},
		},
		PredicateType: testPredicateType,
		Predicate:     predBytes,
	}

	return benchMarshal(b, wrapper)
}

func BenchmarkVerify(b *testing.B) {
	doc := validSPDXDoc()
	att := benchWrapInToto(b, doc, testDigest)

	pol := &policy.Policy{}

	b.ResetTimer()

	for range b.N {
		_, _ = sbom.Verify(context.Background(), att, pol, testDigest)
	}
}

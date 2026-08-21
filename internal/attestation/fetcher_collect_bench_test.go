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

package attestation_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
)

func BenchmarkExtractPredicateType(b *testing.B) {
	payload, err := json.Marshal(map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": testPredicateSLSA,
		"subject":       []any{},
		"predicate":     map[string]any{},
	})
	if err != nil {
		b.Fatalf("marshalling payload: %v", err)
	}

	b.ResetTimer()

	for range b.N {
		attestation.ExportExtractPredicateType(payload)
	}
}

func BenchmarkExtractPredicateTypeEmpty(b *testing.B) {
	b.ResetTimer()

	for range b.N {
		attestation.ExportExtractPredicateType([]byte(`{}`))
	}
}

func BenchmarkIsNotationCandidate(b *testing.B) {
	b.ResetTimer()

	for range b.N {
		attestation.ExportIsNotationCandidate(attestation.ExportNotationSignatureMediaType)
	}
}

func BenchmarkExceededTotalAttestationSize(b *testing.B) {
	ctx := context.Background()

	b.ResetTimer()

	for range b.N {
		attestation.ExportExceededTotalAttestationSize(ctx, 1024)
	}
}

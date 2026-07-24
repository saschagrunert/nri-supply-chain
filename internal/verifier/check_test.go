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

//nolint:testpackage // testing unexported functions
package verifier

import (
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
)

func TestBinAttestationsUnknownType(t *testing.T) {
	t.Parallel()

	attestations := []attestation.VerifiedAttestation{
		{
			PredicateType: "https://example.com/unknown",
			Payload:       []byte("u1"),
			Digest:        benchDigest,
		},
		{
			PredicateType: attestation.PredicateSLSAProvenanceV1,
			Payload:       []byte("slsa1"),
			Digest:        benchDigest,
		},
		{
			PredicateType: "https://example.com/other",
			Payload:       []byte("u2"),
			Digest:        benchDigest,
		},
	}

	bins := binAttestations(attestations)

	if len(bins.slsa) != 1 {
		t.Errorf("expected 1 SLSA attestation, got %d", len(bins.slsa))
	}

	if len(bins.vex) != 0 {
		t.Errorf("expected 0 VEX attestations, got %d", len(bins.vex))
	}

	if len(bins.vsa) != 0 {
		t.Errorf("expected 0 VSA attestations, got %d", len(bins.vsa))
	}
}

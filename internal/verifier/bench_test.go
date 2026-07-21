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

//nolint:testpackage // benchmarking unexported functions
package verifier

import (
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
)

const benchDigest = "sha256:abc"

func BenchmarkBinAttestations(b *testing.B) {
	attestations := []attestation.VerifiedAttestation{
		{
			PredicateType: attestation.PredicateSLSAProvenanceV1,
			Payload:       []byte("slsa1"),
			Digest:        benchDigest,
		},
		{PredicateType: attestation.PredicateOpenVEX, Payload: []byte("vex1"), Digest: benchDigest},
		{
			PredicateType: attestation.PredicateSLSAProvenanceV1,
			Payload:       []byte("slsa2"),
			Digest:        benchDigest,
		},
		{PredicateType: attestation.PredicateVSA, Payload: []byte("vsa1"), Digest: benchDigest},
		{PredicateType: attestation.PredicateOpenVEX, Payload: []byte("vex2"), Digest: benchDigest},
	}

	b.ResetTimer()

	for range b.N {
		binAttestations(attestations)
	}
}

func BenchmarkBinAttestationsLarge(b *testing.B) {
	const size = 100

	attestations := make([]attestation.VerifiedAttestation, 0, size)

	predicates := []string{
		attestation.PredicateSLSAProvenanceV1,
		attestation.PredicateOpenVEX,
		attestation.PredicateVSA,
	}

	for idx := range size {
		attestations = append(attestations, attestation.VerifiedAttestation{
			PredicateType: predicates[idx%len(predicates)],
			Payload:       []byte("payload"),
			Digest:        benchDigest,
		})
	}

	b.ResetTimer()

	for range b.N {
		binAttestations(attestations)
	}
}

func BenchmarkRegistryHost(b *testing.B) {
	for range b.N {
		registryHost("docker.io/library/nginx:latest")
	}
}

func BenchmarkRegistryHostWithPort(b *testing.B) {
	for range b.N {
		registryHost("myregistry.example.com:5000/myimage:v1")
	}
}

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

package notation_test

import (
	"context"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/notation"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
)

func FuzzVerify(f *testing.F) {
	f.Add([]byte("envelope-data"), "application/cose")
	f.Add([]byte{}, "application/jose+json")
	f.Add([]byte("random"), "")

	f.Fuzz(func(_ *testing.T, envelope []byte, mediaType string) {
		pol := &policy.Policy{
			Notation: &policy.NotationPolicy{
				TrustStores: []policy.NotationTrustStore{
					{
						Name:         "fuzz-store",
						Type:         "ca",
						Certificates: []string{"/nonexistent/cert.pem"},
					},
				},
				TrustPolicy: []policy.NotationTrustPolicyRule{
					{
						Name:              "fuzz-rule",
						RegistryScopes:    []string{"*"},
						TrustStores:       []string{"ca:fuzz-store"},
						TrustedIdentities: []string{"*"},
					},
				},
			},
		}

		sig := &attestation.VerifiedAttestation{
			PredicateType:     attestation.NotationSignatureMediaType,
			Payload:           envelope,
			Digest:            "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
			SignatureType:     attestation.SignatureTypeNotation,
			NotationMediaType: mediaType,
		}

		notation.Verify(
			context.Background(),
			sig,
			"example.com/img:latest",
			"sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
			pol,
		)
	})
}

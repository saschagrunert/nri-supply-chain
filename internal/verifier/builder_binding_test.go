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

package verifier_test

import (
	"errors"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

func TestBindBuilderSignerMixedBoundAndUnbound(t *testing.T) {
	t.Parallel()

	const (
		builderKey = "/etc/keys/builder.pub"
		otherKey   = "/etc/keys/other-signer.pub"
	)

	bound := policy.TrustedBuilder{
		ID: testBuilderRunner, MaxLevel: 0, Keys: []string{builderKey}, Identities: nil,
	}
	unbound := policy.TrustedBuilder{
		ID: testBuilderRunner, MaxLevel: 0, Keys: nil, Identities: nil,
	}

	tests := []struct {
		name    string
		keyPath string
		matched []policy.TrustedBuilder
		wantErr bool
	}{
		{
			"unbound first rejects other signer",
			otherKey,
			[]policy.TrustedBuilder{unbound, bound},
			true,
		},
		{
			"bound first rejects other signer",
			otherKey,
			[]policy.TrustedBuilder{bound, unbound},
			true,
		},
		{
			"bound key accepted with unbound entry",
			builderKey,
			[]policy.TrustedBuilder{unbound, bound},
			false,
		},
		{"only unbound accepts any signer", otherKey, []policy.TrustedBuilder{unbound}, false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			att := &attestation.VerifiedAttestation{
				Signer: attestation.SignerIdentity{
					KeyPath: test.keyPath, KeyPaths: nil, Issuer: "", SAN: "",
				},
			}

			err := verifier.ExportBindBuilderSigner(att, test.matched)
			if (err != nil) != test.wantErr {
				t.Fatalf("expected error=%v, got %v", test.wantErr, err)
			}

			if err != nil && !errors.Is(err, verifier.ErrBuilderSignerMismatch) {
				t.Errorf("expected ErrBuilderSignerMismatch, got %v", err)
			}
		})
	}
}

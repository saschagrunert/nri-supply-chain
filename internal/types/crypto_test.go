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

package types_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

func TestHashAlgorithmForKey(t *testing.T) {
	t.Parallel()

	p256 := genECDSA(t, elliptic.P256())
	p384 := genECDSA(t, elliptic.P384())
	p521 := genECDSA(t, elliptic.P521())
	edKey := genEd25519(t)
	rsaKey := genRSA(t)

	tests := []struct {
		name string
		key  crypto.PublicKey
		want crypto.Hash
	}{
		{"ECDSA P-256 uses SHA-256", p256, crypto.SHA256},
		{"ECDSA P-384 uses SHA-384", p384, crypto.SHA384},
		{"ECDSA P-521 uses SHA-512", p521, crypto.SHA512},
		{"Ed25519 uses SHA-512", edKey, crypto.SHA512},
		{"RSA defaults to SHA-256", rsaKey, crypto.SHA256},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := types.HashAlgorithmForKey(test.key)
			if got != test.want {
				t.Errorf("HashAlgorithmForKey() = %v, want %v", got, test.want)
			}
		})
	}
}

func genECDSA(t *testing.T, curve elliptic.Curve) *ecdsa.PublicKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	return &key.PublicKey
}

func genEd25519(t *testing.T) ed25519.PublicKey {
	t.Helper()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	return pub
}

func genRSA(t *testing.T) *rsa.PublicKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	return &key.PublicKey
}

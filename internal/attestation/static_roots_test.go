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
	"errors"
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
)

func TestVerifyBundleWithStaticRootsScopesEachRoot(t *testing.T) {
	t.Parallel()

	virtual := testutil.NewVirtualSigstore(t)
	trustedRoot := testutil.VirtualTrustedRoot(t, virtual)
	keylessBundle := testutil.KeylessBundle(
		t, virtual, signerIdentity, signerIssuer, signerStatement(t),
	)
	keylessOpts := &attestation.FetchOptions{
		TrustedIssuers: []string{signerIssuer},
		SANPatterns:    []string{signerIdentity},
		Digest:         signerTestDigest,
	}

	tests := []struct {
		name       string
		root       attestation.StaticRoot
		outOfScope bool
	}{
		{
			name: "root scoped to another issuer",
			root: attestation.StaticRoot{
				Name: "public-sigstore", Root: trustedRoot,
				Issuers: []string{signerOtherIssuer}, KeylessDisabled: false,
			},
			outOfScope: true,
		},
		{
			name: "root with keyless disabled",
			root: attestation.StaticRoot{
				Name: "bundle", Root: trustedRoot, Issuers: nil, KeylessDisabled: true,
			},
			outOfScope: true,
		},
		{
			name: "root scoped to the certificate issuer",
			root: attestation.StaticRoot{
				Name: "private", Root: trustedRoot,
				Issuers: []string{signerIssuer}, KeylessDisabled: false,
			},
			outOfScope: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// The virtual CA issues no SCTs, so verification fails even when
			// the root is in scope; the scope check happens first and is what
			// this test asserts.
			_, err := attestation.VerifyBundleWithStaticRoots(
				t.Context(), keylessBundle, keylessOpts, []attestation.StaticRoot{test.root},
			)
			testutil.AssertError(t, err)

			outOfScope := errors.Is(err, attestation.ExportErrNoTrustedIssuers())
			if outOfScope != test.outOfScope {
				t.Fatalf("out of scope = %v, want %v: %v", outOfScope, test.outOfScope, err)
			}
		})
	}
}

func TestVerifyBundleWithStaticRootsKeylessDisabledKeepsTransparencyLog(t *testing.T) {
	t.Parallel()

	virtual := testutil.NewVirtualSigstore(t)
	signer := testutil.NewKeySigner(t)

	verified, err := attestation.VerifyBundleWithStaticRoots(
		t.Context(),
		signer.SignBundleWithTlog(t, virtual, signerStatement(t), time.Now().Add(-time.Minute)),
		&attestation.FetchOptions{
			TrustedKeys:            []attestation.TrustedKeyRef{{Path: signer.PublicKeyPath}},
			RequireTransparencyLog: true,
			Digest:                 signerTestDigest,
		},
		[]attestation.StaticRoot{{
			Name: "bundle", Root: testutil.VirtualTrustedRoot(t, virtual),
			Issuers: nil, KeylessDisabled: true,
		}},
	)
	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, signer.PublicKeyPath, verified.Signer.KeyPath)
}

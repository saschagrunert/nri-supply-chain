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

func TestVerifyBundleRootAvailability(t *testing.T) {
	t.Parallel()

	trustedVirtual := testutil.NewVirtualSigstore(t)
	otherRoot := testutil.VirtualTrustedRoot(t, testutil.NewVirtualSigstore(t))
	trustedRoot := testutil.VirtualTrustedRoot(t, trustedVirtual)
	signer := testutil.NewKeySigner(t)

	keylessBundle := testutil.KeylessBundle(
		t, trustedVirtual, signerIdentity, signerIssuer, signerStatement(t),
	)
	keylessOpts := &attestation.FetchOptions{
		TrustedIssuers: []string{signerIssuer},
		SANPatterns:    []string{signerIdentity},
		Digest:         signerTestDigest,
	}
	tlogBundle := signer.SignBundleWithTlog(
		t, trustedVirtual, signerStatement(t), time.Now().Add(-time.Minute),
	)
	tlogOpts := &attestation.FetchOptions{
		TrustedKeys:            []attestation.TrustedKeyRef{{Path: signer.PublicKeyPath}},
		RequireTransparencyLog: true,
		Digest:                 signerTestDigest,
	}
	unavailable := attestation.TestRootSource{Root: nil, Err: errRootUnavailable, Issuers: nil}

	tests := []struct {
		name            string
		bundle          []byte
		opts            *attestation.FetchOptions
		sources         []attestation.TestRootSource
		wantOK          bool
		wantUnavailable bool
	}{
		{
			name:   "keyless loaded root rejects while another is unavailable",
			bundle: keylessBundle,
			opts:   keylessOpts,
			sources: []attestation.TestRootSource{
				unavailable, {Root: otherRoot, Err: nil, Issuers: nil},
			},
			wantOK:          false,
			wantUnavailable: true,
		},
		{
			name:   "keyless loaded root rejects while an out of scope root is unavailable",
			bundle: keylessBundle,
			opts:   keylessOpts,
			sources: []attestation.TestRootSource{
				{Root: nil, Err: errRootUnavailable, Issuers: []string{signerOtherIssuer}},
				{Root: otherRoot, Err: nil, Issuers: nil},
			},
			wantOK:          false,
			wantUnavailable: false,
		},
		{
			name:   "keyless loaded root accepts while another is unavailable",
			bundle: keylessBundle,
			opts:   keylessOpts,
			sources: []attestation.TestRootSource{
				unavailable, {Root: trustedRoot, Err: nil, Issuers: nil},
			},
			wantOK:          true,
			wantUnavailable: false,
		},
		{
			name:   "keyless every in-scope root unavailable",
			bundle: keylessBundle,
			opts:   keylessOpts,
			sources: []attestation.TestRootSource{
				unavailable,
				{Root: otherRoot, Err: nil, Issuers: []string{signerOtherIssuer}},
			},
			wantOK:          false,
			wantUnavailable: true,
		},
		{
			name:   "transparency log loaded root rejects while another is unavailable",
			bundle: tlogBundle,
			opts:   tlogOpts,
			sources: []attestation.TestRootSource{
				unavailable, {Root: otherRoot, Err: nil, Issuers: nil},
			},
			wantOK:          false,
			wantUnavailable: true,
		},
		{
			name:            "transparency log every root unavailable",
			bundle:          tlogBundle,
			opts:            tlogOpts,
			sources:         []attestation.TestRootSource{unavailable, unavailable},
			wantOK:          false,
			wantUnavailable: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := attestation.ExportVerifyBundleWithRootSources(
				t.Context(), test.bundle, test.opts, test.sources,
			)
			if test.wantOK {
				testutil.AssertNoError(t, err)

				return
			}

			testutil.AssertError(t, err)

			if got := errors.Is(
				err,
				attestation.ErrTrustMaterialUnavailable,
			); got != test.wantUnavailable {
				t.Fatalf("unavailable = %v, want %v: %v", got, test.wantUnavailable, err)
			}
		})
	}
}

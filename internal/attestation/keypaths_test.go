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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	ociV1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
)

var errRootUnavailable = errors.New("trusted root unavailable")

// copyKeyFile writes the signer's public key to a second path.
func copyKeyFile(t *testing.T, signer *testutil.KeySigner) string {
	t.Helper()

	dst := filepath.Join(t.TempDir(), "copy.pub")
	testutil.AssertNoError(t, os.WriteFile(dst, signer.PublicKeyPEM, 0o600))

	return dst
}

func TestVerifyBundleSameKeyAtSeveralPaths(t *testing.T) {
	t.Parallel()

	signer := testutil.NewKeySigner(t)
	bundleJSON := signer.SignBundle(t, signerStatement(t))
	expiredPath := signer.PublicKeyPath
	openPath := copyKeyFile(t, signer)
	pastBound := time.Now().Add(-time.Hour)
	expired := attestation.TrustedKeyRef{Path: expiredPath, NotAfter: pastBound}
	open := attestation.TrustedKeyRef{Path: openPath}

	tests := []struct {
		name      string
		keys      []attestation.TrustedKeyRef
		wantPaths []string
		wantErr   bool
	}{
		{
			name:      "expired entry first",
			keys:      []attestation.TrustedKeyRef{expired, open},
			wantPaths: []string{openPath},
			wantErr:   false,
		},
		{
			name:      "expired entry last",
			keys:      []attestation.TrustedKeyRef{open, expired},
			wantPaths: []string{openPath},
			wantErr:   false,
		},
		{
			name: "both entries valid keep configuration order",
			keys: []attestation.TrustedKeyRef{
				{Path: openPath}, {Path: expiredPath},
			},
			wantPaths: []string{openPath, expiredPath},
			wantErr:   false,
		},
		{
			name: "same path listed twice with one valid window",
			keys: []attestation.TrustedKeyRef{
				{Path: openPath, NotAfter: pastBound}, {Path: openPath},
			},
			wantPaths: []string{openPath},
			wantErr:   false,
		},
		{
			name: "every entry expired",
			keys: []attestation.TrustedKeyRef{
				expired, {Path: openPath, NotAfter: pastBound},
			},
			wantPaths: nil,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			verified, err := attestation.ExportVerifyBundle(
				t.Context(), bundleJSON, &attestation.FetchOptions{
					TrustedKeys: tt.keys,
					Digest:      signerTestDigest,
				}, nil,
			)

			if tt.wantErr {
				testutil.AssertError(t, err)

				return
			}

			testutil.AssertNoError(t, err)
			testutil.AssertEqual(
				t, strings.Join(tt.wantPaths, ","), strings.Join(verified.Signer.KeyPaths, ","),
			)
			testutil.AssertEqual(t, tt.wantPaths[0], verified.Signer.KeyPath)
		})
	}
}

func TestVerifyBundleKeyWindowAttributionAtIntegratedTime(t *testing.T) {
	t.Parallel()

	virtual := testutil.NewVirtualSigstore(t)
	trustedRoot := testutil.VirtualTrustedRoot(t, virtual)
	signer := testutil.NewKeySigner(t)
	integrated := time.Now().Add(-30 * time.Minute)
	bundleJSON := signer.SignBundleWithTlog(t, virtual, signerStatement(t), integrated)
	rotatedPath := copyKeyFile(t, signer)

	// The first entry expired before the entry was logged. The second one is
	// valid at the integrated time but has expired since, so attribution must
	// use the integrated time rather than the current time.
	verified, err := attestation.ExportVerifyBundle(
		t.Context(), bundleJSON, &attestation.FetchOptions{
			TrustedKeys: []attestation.TrustedKeyRef{
				{Path: signer.PublicKeyPath, NotAfter: integrated.Add(-10 * time.Minute)},
				{
					Path:      rotatedPath,
					NotBefore: integrated.Add(-time.Minute),
					NotAfter:  time.Now().Add(-time.Minute),
				},
			},
			RequireTransparencyLog: true,
			Digest:                 signerTestDigest,
		}, trustedRoot,
	)
	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, rotatedPath, strings.Join(verified.Signer.KeyPaths, ","))
}

func TestSignerIdentityMatchesAny(t *testing.T) {
	t.Parallel()

	signer := attestation.SignerIdentity{
		KeyPath: "/a.pub", KeyPaths: []string{"/a.pub", "/b.pub"}, Issuer: "", SAN: "",
	}

	testutil.AssertEqual(t, true, signer.MatchesAny(func(keyPath, _, _ string) bool {
		return keyPath == "/b.pub"
	}))
	testutil.AssertEqual(t, false, signer.MatchesAny(func(keyPath, _, _ string) bool {
		return keyPath == "/c.pub"
	}))

	keyless := attestation.SignerIdentity{
		KeyPath: "", KeyPaths: nil, Issuer: signerIssuer, SAN: signerIdentity,
	}

	testutil.AssertEqual(t, true, keyless.MatchesAny(func(keyPath, issuer, san string) bool {
		return keyPath == "" && issuer == signerIssuer && san == signerIdentity
	}))
}

func TestVerifyBundleTrustMaterialUnavailable(t *testing.T) {
	t.Parallel()

	virtual := testutil.NewVirtualSigstore(t)
	signer := testutil.NewKeySigner(t)

	t.Run("trusted root fetch failure", func(t *testing.T) {
		t.Parallel()

		bundleJSON := testutil.KeylessBundle(
			t, virtual, signerIdentity, signerIssuer, signerStatement(t),
		)

		_, err := attestation.ExportVerifyBundleWithFailingRoot(
			t.Context(), bundleJSON, &attestation.FetchOptions{
				TrustedIssuers: []string{signerIssuer},
				SANPatterns:    []string{signerIdentity},
				Digest:         signerTestDigest,
			}, errRootUnavailable,
		)
		testutil.AssertErrorIs(t, err, attestation.ErrTrustMaterialUnavailable)

		if errors.Is(err, attestation.ErrVerificationFailed) {
			t.Fatalf("unavailable trust material must not be a verification failure: %v", err)
		}
	})

	t.Run("transparency log root fetch failure", func(t *testing.T) {
		t.Parallel()

		bundleJSON := signer.SignBundleWithTlog(
			t, virtual, signerStatement(t), time.Now().Add(-time.Minute),
		)

		_, err := attestation.ExportVerifyBundleWithFailingRoot(
			t.Context(), bundleJSON, &attestation.FetchOptions{
				TrustedKeys:            []attestation.TrustedKeyRef{{Path: signer.PublicKeyPath}},
				RequireTransparencyLog: true,
				Digest:                 signerTestDigest,
			}, errRootUnavailable,
		)
		testutil.AssertErrorIs(t, err, attestation.ErrTrustMaterialUnavailable)
	})

	t.Run("key file missing", func(t *testing.T) {
		t.Parallel()

		_, err := attestation.ExportVerifyBundle(
			t.Context(), signer.SignBundle(t, signerStatement(t)), &attestation.FetchOptions{
				TrustedKeys: []attestation.TrustedKeyRef{
					{Path: filepath.Join(t.TempDir(), "missing.pub")},
				},
				Digest: signerTestDigest,
			}, nil,
		)
		testutil.AssertErrorIs(t, err, attestation.ErrTrustMaterialUnavailable)
	})
}

func TestFetchTrustMaterialUnavailableIsFetchFailure(t *testing.T) {
	t.Parallel()

	signer := testutil.NewKeySigner(t)
	desc := bundleReferrer(1)

	fetcher := attestation.NewTestOCIFetcherSigned(
		func(context.Context, []byte, *attestation.FetchOptions) (*attestation.VerifiedBundle, error) {
			return nil, fmt.Errorf(
				"%w: %w", attestation.ErrTrustMaterialUnavailable, errRootUnavailable,
			)
		},
		func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
			return fakeImageWithPayload(signer.SignBundle(t, signerStatement(t))), nil
		},
		func(_ name.Digest, _ ...remote.Option) (ociV1.ImageIndex, error) {
			return &fakeImageIndex{manifests: []ociV1.Descriptor{desc}, err: nil}, nil
		},
	)

	_, err := fetcher.Fetch(t.Context(), signerImageRef, &attestation.FetchOptions{
		Digest: signerTestDigest,
	})
	testutil.AssertErrorIs(t, err, attestation.ErrTrustMaterialUnavailable)

	if errors.Is(err, attestation.ErrVerificationFailed) {
		t.Fatalf("unavailable trust material must not be a verification failure: %v", err)
	}
}

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
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	ociV1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
)

const (
	signerTestDigest   = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	signerOtherDigest  = "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	signerIssuer       = "https://token.actions.githubusercontent.com"
	signerOtherIssuer  = "https://accounts.google.com"
	signerIdentity     = "ci@example.com"
	signerImageRef     = "registry.example.com/app@" + signerTestDigest
	signerLegacyTagRef = "registry.example.com/app"
)

func signerStatement(t *testing.T) []byte {
	t.Helper()

	return testutil.Statement(
		t, signerTestDigest, attestation.PredicateSLSAProvenanceV1,
		map[string]string{"buildType": "test"},
	)
}

func TestVerifyBundleKeyBasedSigner(t *testing.T) {
	t.Parallel()

	signer := testutil.NewKeySigner(t)
	bundleJSON := signer.SignBundle(t, signerStatement(t))

	verified, err := attestation.ExportVerifyBundle(
		t.Context(), bundleJSON, &attestation.FetchOptions{
			TrustedKeys: []attestation.TrustedKeyRef{{Path: signer.PublicKeyPath}},
			Digest:      signerTestDigest,
		}, nil,
	)
	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, signer.PublicKeyPath, verified.Signer.KeyPath)
	testutil.AssertEqual(t, "", verified.Signer.Issuer)
	testutil.AssertEqual(t, attestation.PredicateSLSAProvenanceV1, verified.PredicateType)
}

func TestVerifyBundleKeyValidityWindow(t *testing.T) {
	t.Parallel()

	signer := testutil.NewKeySigner(t)
	bundleJSON := signer.SignBundle(t, signerStatement(t))
	now := time.Now()

	tests := []struct {
		name      string
		notBefore time.Time
		notAfter  time.Time
		wantErr   bool
	}{
		{name: "no bounds", notBefore: time.Time{}, notAfter: time.Time{}, wantErr: false},
		{
			name:      "within window",
			notBefore: now.Add(-time.Hour),
			notAfter:  now.Add(time.Hour),
			wantErr:   false,
		},
		{
			name:      "expired key rejected",
			notBefore: time.Time{},
			notAfter:  now.Add(-48 * time.Hour),
			wantErr:   true,
		},
		{
			name:      "not yet valid key rejected",
			notBefore: now.Add(time.Hour),
			notAfter:  time.Time{},
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := attestation.ExportVerifyBundle(
				t.Context(), bundleJSON, &attestation.FetchOptions{
					TrustedKeys: []attestation.TrustedKeyRef{{
						Path: signer.PublicKeyPath, NotBefore: tt.notBefore, NotAfter: tt.notAfter,
					}},
					Digest: signerTestDigest,
				}, nil,
			)

			if tt.wantErr {
				testutil.AssertError(t, err)

				return
			}

			testutil.AssertNoError(t, err)
		})
	}
}

func TestVerifyBundleKeyWithTransparencyLog(t *testing.T) {
	t.Parallel()

	virtual := testutil.NewVirtualSigstore(t)
	trustedRoot := testutil.VirtualTrustedRoot(t, virtual)
	signer := testutil.NewKeySigner(t)
	integrated := time.Now().Add(-time.Minute)
	bundleJSON := signer.SignBundleWithTlog(t, virtual, signerStatement(t), integrated)

	t.Run("accepted with trusted root", func(t *testing.T) {
		t.Parallel()

		verified, err := attestation.ExportVerifyBundle(
			t.Context(), bundleJSON, &attestation.FetchOptions{
				TrustedKeys:            []attestation.TrustedKeyRef{{Path: signer.PublicKeyPath}},
				RequireTransparencyLog: true,
				Digest:                 signerTestDigest,
			}, trustedRoot,
		)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, signer.PublicKeyPath, verified.Signer.KeyPath)
	})

	t.Run("key valid at integrated time but expired now", func(t *testing.T) {
		t.Parallel()

		_, err := attestation.ExportVerifyBundle(
			t.Context(), bundleJSON, &attestation.FetchOptions{
				TrustedKeys: []attestation.TrustedKeyRef{{
					Path:     signer.PublicKeyPath,
					NotAfter: time.Now().Add(-time.Second),
				}},
				RequireTransparencyLog: true,
				Digest:                 signerTestDigest,
			}, trustedRoot,
		)
		testutil.AssertNoError(t, err)
	})

	t.Run("key expired at integrated time", func(t *testing.T) {
		t.Parallel()

		_, err := attestation.ExportVerifyBundle(
			t.Context(), bundleJSON, &attestation.FetchOptions{
				TrustedKeys: []attestation.TrustedKeyRef{{
					Path:     signer.PublicKeyPath,
					NotAfter: integrated.Add(-time.Hour),
				}},
				RequireTransparencyLog: true,
				Digest:                 signerTestDigest,
			}, trustedRoot,
		)
		testutil.AssertError(t, err)
	})

	t.Run("rejected without trusted root", func(t *testing.T) {
		t.Parallel()

		_, err := attestation.ExportVerifyBundle(
			t.Context(), bundleJSON, &attestation.FetchOptions{
				TrustedKeys:            []attestation.TrustedKeyRef{{Path: signer.PublicKeyPath}},
				RequireTransparencyLog: true,
				Digest:                 signerTestDigest,
			}, nil,
		)
		testutil.AssertErrorIs(t, err, attestation.ExportErrNoTrustedRoot())
	})

	t.Run("bundle without tlog entry rejected when required", func(t *testing.T) {
		t.Parallel()

		_, err := attestation.ExportVerifyBundle(
			t.Context(), signer.SignBundle(t, signerStatement(t)), &attestation.FetchOptions{
				TrustedKeys:            []attestation.TrustedKeyRef{{Path: signer.PublicKeyPath}},
				RequireTransparencyLog: true,
				Digest:                 signerTestDigest,
			}, trustedRoot,
		)
		testutil.AssertError(t, err)
	})
}

func TestVerifyBundleKeysAndIssuers(t *testing.T) {
	t.Parallel()

	virtual := testutil.NewVirtualSigstore(t)
	trustedRoot := testutil.VirtualTrustedRoot(t, virtual)
	signer := testutil.NewKeySigner(t)
	opts := &attestation.FetchOptions{
		TrustedKeys:    []attestation.TrustedKeyRef{{Path: signer.PublicKeyPath}},
		TrustedIssuers: []string{signerIssuer},
		SANPatterns:    []string{signerIdentity},
		Digest:         signerTestDigest,
	}

	t.Run("key signed bundle", func(t *testing.T) {
		t.Parallel()

		verified, err := attestation.ExportVerifyBundleWithRoots(
			t.Context(), signer.SignBundle(t, signerStatement(t)), opts,
			[]*root.TrustedRoot{trustedRoot}, nil, true,
		)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, signer.PublicKeyPath, verified.Signer.KeyPath)
	})

	t.Run("keyless bundle", func(t *testing.T) {
		t.Parallel()

		bundleJSON := testutil.KeylessBundle(
			t,
			virtual,
			signerIdentity,
			signerIssuer,
			signerStatement(t),
		)

		verified, err := attestation.ExportVerifyBundleWithRoots(
			t.Context(), bundleJSON, opts, []*root.TrustedRoot{trustedRoot}, nil, true,
		)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, "", verified.Signer.KeyPath)
		testutil.AssertEqual(t, signerIssuer, verified.Signer.Issuer)
		testutil.AssertEqual(t, signerIdentity, verified.Signer.SAN)
	})

	t.Run("keyless bundle requires SCTs by default", func(t *testing.T) {
		t.Parallel()

		bundleJSON := testutil.KeylessBundle(
			t,
			virtual,
			signerIdentity,
			signerIssuer,
			signerStatement(t),
		)

		_, err := attestation.ExportVerifyBundle(t.Context(), bundleJSON, opts, trustedRoot)
		testutil.AssertError(t, err)
	})

	t.Run("keyless bundle with untrusted SAN", func(t *testing.T) {
		t.Parallel()

		bundleJSON := testutil.KeylessBundle(
			t,
			virtual,
			"attacker@example.com",
			signerIssuer,
			signerStatement(t),
		)

		_, err := attestation.ExportVerifyBundleWithRoots(
			t.Context(), bundleJSON, opts, []*root.TrustedRoot{trustedRoot}, nil, true,
		)
		testutil.AssertError(t, err)
	})

	t.Run("wrong image digest", func(t *testing.T) {
		t.Parallel()

		wrongOpts := *opts
		wrongOpts.Digest = signerOtherDigest

		_, err := attestation.ExportVerifyBundleWithRoots(
			t.Context(), signer.SignBundle(t, signerStatement(t)), &wrongOpts,
			[]*root.TrustedRoot{trustedRoot}, nil, true,
		)
		testutil.AssertError(t, err)
	})
}

func TestVerifyBundleKeylessWithoutRoot(t *testing.T) {
	t.Parallel()

	virtual := testutil.NewVirtualSigstore(t)
	bundleJSON := testutil.KeylessBundle(
		t,
		virtual,
		signerIdentity,
		signerIssuer,
		signerStatement(t),
	)

	_, err := attestation.ExportVerifyBundle(t.Context(), bundleJSON, &attestation.FetchOptions{
		TrustedIssuers: []string{signerIssuer},
		Digest:         signerTestDigest,
	}, nil)
	testutil.AssertErrorIs(t, err, attestation.ExportErrNoTrustedRoot())
}

func TestVerifyBundleMultiRootIssuerScoping(t *testing.T) {
	t.Parallel()

	publicSigstore := testutil.NewVirtualSigstore(t)
	privateSigstore := testutil.NewVirtualSigstore(t)
	roots := []*root.TrustedRoot{
		testutil.VirtualTrustedRoot(t, publicSigstore),
		testutil.VirtualTrustedRoot(t, privateSigstore),
	}
	// The private root may only vouch for the private issuer.
	issuers := [][]string{nil, {signerOtherIssuer}}
	opts := &attestation.FetchOptions{
		TrustedIssuers: []string{signerIssuer, signerOtherIssuer},
		Digest:         signerTestDigest,
	}

	t.Run("private root cannot mint public issuer identity", func(t *testing.T) {
		t.Parallel()

		bundleJSON := testutil.KeylessBundle(
			t,
			privateSigstore,
			signerIdentity,
			signerIssuer,
			signerStatement(t),
		)

		// Without scoping the private root would vouch for the public issuer.
		unscoped, err := attestation.ExportVerifyBundleWithRoots(
			t.Context(), bundleJSON, opts, roots, nil, true,
		)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, signerIssuer, unscoped.Signer.Issuer)

		_, err = attestation.ExportVerifyBundleWithRoots(
			t.Context(),
			bundleJSON,
			opts,
			roots,
			issuers,
			true,
		)
		testutil.AssertError(t, err)

		// The private root rejects the identity because of its issuer scope,
		// not because of a broken certificate chain.
		if _, ok := errors.AsType[*verify.ErrNoMatchingCertificateIdentity](err); !ok {
			t.Fatalf("expected a certificate identity mismatch from the scoped root, got: %v", err)
		}
	})

	t.Run("scoped root without overlapping policy issuers", func(t *testing.T) {
		t.Parallel()

		bundleJSON := testutil.KeylessBundle(
			t, privateSigstore, signerIdentity, signerIssuer, signerStatement(t),
		)

		_, err := attestation.ExportVerifyBundleWithRoots(
			t.Context(),
			bundleJSON,
			&attestation.FetchOptions{
				TrustedIssuers: []string{signerIssuer},
				Digest:         signerTestDigest,
			},
			roots[1:],
			issuers[1:],
			true,
		)
		testutil.AssertErrorIs(t, err, attestation.ExportErrNoTrustedIssuers())
	})

	t.Run("private root vouches for its own issuer", func(t *testing.T) {
		t.Parallel()

		bundleJSON := testutil.KeylessBundle(
			t, privateSigstore, signerIdentity, signerOtherIssuer, signerStatement(t),
		)

		verified, err := attestation.ExportVerifyBundleWithRoots(
			t.Context(),
			bundleJSON,
			opts,
			roots,
			issuers,
			true,
		)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, signerOtherIssuer, verified.Signer.Issuer)
	})

	t.Run("unrestricted root accepts policy issuers", func(t *testing.T) {
		t.Parallel()

		bundleJSON := testutil.KeylessBundle(
			t,
			publicSigstore,
			signerIdentity,
			signerIssuer,
			signerStatement(t),
		)

		_, err := attestation.ExportVerifyBundleWithRoots(
			t.Context(),
			bundleJSON,
			opts,
			roots,
			issuers,
			true,
		)
		testutil.AssertNoError(t, err)
	})
}

func TestScopeIssuers(t *testing.T) {
	t.Parallel()

	policy := []string{"a", "b", "c"}

	testutil.AssertEqual(t, 3, len(attestation.ExportScopeIssuers(policy, nil)))
	testutil.AssertEqual(
		t,
		"b",
		strings.Join(attestation.ExportScopeIssuers(policy, []string{"b", "z"}), ","),
	)
	testutil.AssertEqual(t, 0, len(attestation.ExportScopeIssuers(policy, []string{"z"})))
}

func TestVerifyBundleMissingPredicateType(t *testing.T) {
	t.Parallel()

	signer := testutil.NewKeySigner(t)
	statement := []byte(
		`{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"x","digest":{"sha256":"` +
			strings.TrimPrefix(signerTestDigest, "sha256:") + `"}}]}`,
	)

	_, err := attestation.ExportVerifyBundle(
		t.Context(), signer.SignBundle(t, statement), &attestation.FetchOptions{
			TrustedKeys: []attestation.TrustedKeyRef{{Path: signer.PublicKeyPath}},
			Digest:      signerTestDigest,
		}, nil,
	)
	testutil.AssertErrorIs(t, err, attestation.ExportErrMissingPredicateType())
}

func TestBuildKeyMaterialKeepsEveryPath(t *testing.T) {
	t.Parallel()

	signer := testutil.NewKeySigner(t)

	paths, err := attestation.ExportBuildKeyMaterialPaths([]attestation.TrustedKeyRef{
		{Path: signer.PublicKeyPath},
		{Path: signer.PublicKeyPath + "-missing"},
	})
	testutil.AssertErrorIs(t, err, attestation.ErrTrustMaterialUnavailable)
	testutil.AssertEqual(t, 0, len(paths))

	paths, err = attestation.ExportBuildKeyMaterialPaths([]attestation.TrustedKeyRef{
		{Path: signer.PublicKeyPath},
		{Path: signer.PublicKeyPath},
	})
	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, 2, len(paths[signer.Hint]))
	testutil.AssertEqual(t, signer.PublicKeyPath, paths[signer.Hint][0])
}

// signedFetcher builds a fetcher that verifies real bundles with the given
// trusted key and serves the provided referrers and images.
func signedFetcher(
	images map[string]ociV1.Image, manifests []ociV1.Descriptor,
) *attestation.OCIFetcher {
	return attestation.NewTestOCIFetcherSigned(
		func(ctx context.Context, data []byte, opts *attestation.FetchOptions) (*attestation.VerifiedBundle, error) {
			return attestation.ExportVerifyBundle(ctx, data, opts, nil)
		},
		func(ref name.Reference, _ ...remote.Option) (ociV1.Image, error) {
			key := ref.Identifier()
			if img, ok := images[key]; ok {
				return img, nil
			}

			return nil, &transport.Error{StatusCode: http.StatusNotFound}
		},
		func(_ name.Digest, _ ...remote.Option) (ociV1.ImageIndex, error) {
			return &fakeImageIndex{manifests: manifests, err: nil}, nil
		},
	)
}

func referrerDigest(idx int) ociV1.Hash {
	hexPart := strings.Repeat("0", 64-len(strconv.Itoa(idx))) + strconv.Itoa(idx)

	return ociV1.Hash{Algorithm: "sha256", Hex: hexPart}
}

func TestFetchSignedReferrersPopulateSigner(t *testing.T) {
	t.Parallel()

	signer := testutil.NewKeySigner(t)
	bundleJSON := signer.SignBundle(t, signerStatement(t))
	desc := ociV1.Descriptor{
		ArtifactType: attestation.ExportBundleMediaType,
		Digest:       referrerDigest(1),
	}

	fetcher := signedFetcher(
		map[string]ociV1.Image{desc.Digest.String(): fakeImageWithPayload(bundleJSON)},
		[]ociV1.Descriptor{desc},
	)

	atts, err := fetcher.Fetch(t.Context(), signerImageRef, &attestation.FetchOptions{
		TrustedKeys: []attestation.TrustedKeyRef{{Path: signer.PublicKeyPath}},
		Digest:      signerTestDigest,
	})
	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, 1, len(atts))
	testutil.AssertEqual(t, signer.PublicKeyPath, atts[0].Signer.KeyPath)
	testutil.AssertEqual(t, string(bundleJSON), string(atts[0].Bundle))
	testutil.AssertEqual(t, attestation.PredicateSLSAProvenanceV1, atts[0].PredicateType)
}

func TestFetchUntrustedReferrerIsVerificationFailure(t *testing.T) {
	t.Parallel()

	trusted := testutil.NewKeySigner(t)
	attacker := testutil.NewKeySigner(t)
	desc := ociV1.Descriptor{
		ArtifactType: attestation.ExportBundleMediaType,
		Digest:       referrerDigest(1),
	}

	fetcher := signedFetcher(
		map[string]ociV1.Image{
			desc.Digest.String(): fakeImageWithPayload(attacker.SignBundle(t, signerStatement(t))),
		},
		[]ociV1.Descriptor{desc},
	)

	_, err := fetcher.Fetch(t.Context(), signerImageRef, &attestation.FetchOptions{
		TrustedKeys: []attestation.TrustedKeyRef{{Path: trusted.PublicKeyPath}},
		Digest:      signerTestDigest,
	})
	testutil.AssertErrorIs(t, err, attestation.ErrVerificationFailed)
}

func TestFetchTransportErrorIsNotVerificationFailure(t *testing.T) {
	t.Parallel()

	desc := ociV1.Descriptor{
		ArtifactType: attestation.ExportBundleMediaType,
		Digest:       referrerDigest(1),
	}

	fetcher := attestation.NewTestOCIFetcherSigned(
		func(context.Context, []byte, *attestation.FetchOptions) (*attestation.VerifiedBundle, error) {
			return nil, errSignatureMismatch
		},
		func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
			return nil, &transport.Error{StatusCode: http.StatusBadGateway}
		},
		func(_ name.Digest, _ ...remote.Option) (ociV1.ImageIndex, error) {
			return &fakeImageIndex{manifests: []ociV1.Descriptor{desc}, err: nil}, nil
		},
	)

	_, err := fetcher.Fetch(
		t.Context(),
		signerImageRef,
		&attestation.FetchOptions{Digest: signerTestDigest},
	)
	testutil.AssertError(t, err)

	if errors.Is(err, attestation.ErrVerificationFailed) {
		t.Fatalf("transport error must not wrap ErrVerificationFailed: %v", err)
	}
}

func TestFetchBaselineSBOMMustBeSigned(t *testing.T) {
	t.Parallel()

	signer := testutil.NewKeySigner(t)
	sbomDoc := map[string]any{"spdxVersion": "SPDX-2.3", "packages": []any{}}
	signed := signer.SignBundle(t, testutil.Statement(
		t, signerTestDigest, attestation.PredicateBaselineSBOM, sbomDoc,
	))
	unsigned := testutil.MustMarshal(t, sbomDoc)

	attDesc := ociV1.Descriptor{
		ArtifactType: attestation.ExportBundleMediaType,
		Digest:       referrerDigest(1),
	}
	signedDesc := ociV1.Descriptor{
		ArtifactType: attestation.BaselineSBOMArtifactType,
		Digest:       referrerDigest(2),
	}
	unsignedDesc := ociV1.Descriptor{
		ArtifactType: attestation.BaselineSBOMArtifactType,
		Digest:       referrerDigest(3),
	}

	fetcher := signedFetcher(
		map[string]ociV1.Image{
			attDesc.Digest.String(): fakeImageWithPayload(
				signer.SignBundle(t, signerStatement(t)),
			),
			signedDesc.Digest.String():   fakeImageWithPayload(signed),
			unsignedDesc.Digest.String(): fakeImageWithPayload(unsigned),
		},
		[]ociV1.Descriptor{attDesc, signedDesc, unsignedDesc},
	)

	atts, err := fetcher.Fetch(t.Context(), signerImageRef, &attestation.FetchOptions{
		TrustedKeys: []attestation.TrustedKeyRef{{Path: signer.PublicKeyPath}},
		Digest:      signerTestDigest,
	})
	testutil.AssertNoError(t, err)

	var baselines []attestation.VerifiedAttestation

	for idx := range atts {
		if atts[idx].PredicateType == attestation.PredicateBaselineSBOM {
			baselines = append(baselines, atts[idx])
		}
	}

	testutil.AssertEqual(t, 1, len(baselines))
	// The baseline payload is the SBOM document, not the in-toto statement.
	testutil.AssertContains(t, string(baselines[0].Payload), "SPDX-2.3")

	if strings.Contains(string(baselines[0].Payload), "predicateType") {
		t.Errorf("baseline payload still wrapped in statement: %s", baselines[0].Payload)
	}
}

func TestBaselineSBOMDocumentSubjectBinding(t *testing.T) {
	t.Parallel()

	statement := testutil.Statement(
		t,
		signerTestDigest,
		attestation.PredicateBaselineSBOM,
		map[string]string{"a": "b"},
	)

	_, err := attestation.BaselineSBOMDocument(statement, signerOtherDigest)
	testutil.AssertError(t, err)

	doc, err := attestation.BaselineSBOMDocument(statement, signerTestDigest)
	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, `{"a":"b"}`, string(doc))
}

func TestSelectReferrersBudgetPrefersExactMediaType(t *testing.T) {
	t.Parallel()

	manifests := make([]ociV1.Descriptor, 0, attestation.ExportMaxReferrers()+30)

	// Junk referrers with a generic artifact type come first.
	for idx := range attestation.ExportMaxReferrers() + 10 {
		manifests = append(
			manifests,
			ociV1.Descriptor{ArtifactType: "", Digest: referrerDigest(1000 + idx)},
		)
	}

	manifests = append(
		manifests,
		ociV1.Descriptor{
			ArtifactType: attestation.ExportBundleMediaType,
			Digest:       referrerDigest(1),
		},
		ociV1.Descriptor{
			ArtifactType: attestation.ExportBundleMediaType, Digest: referrerDigest(2),
			Annotations: map[string]string{
				attestation.ExportAnnotationPredicateType: attestation.PredicateCosignSignature,
			},
		},
		ociV1.Descriptor{
			ArtifactType: attestation.ExportBundleMediaType, Digest: referrerDigest(3),
			Size: attestation.ExportMaxReferrerManifestSize + 1,
		},
	)

	for idx := range attestation.ExportMaxNotationReferrers + 5 {
		manifests = append(manifests, ociV1.Descriptor{
			ArtifactType: attestation.NotationSignatureMediaType,
			Digest:       referrerDigest(2000 + idx),
		})
	}

	bundles, notation, _ := attestation.ExportSelectReferrers(t.Context(), manifests)

	testutil.AssertEqual(t, attestation.ExportMaxReferrers(), len(bundles))
	testutil.AssertEqual(t, referrerDigest(1).String(), bundles[0])
	testutil.AssertEqual(t, attestation.ExportMaxNotationReferrers, len(notation))

	for _, digest := range bundles {
		if digest == referrerDigest(2).String() || digest == referrerDigest(3).String() {
			t.Errorf("cosign signature or oversized referrer selected: %s", digest)
		}
	}

	// Referrers left out by the budget make the attestation set incomplete,
	// so Fetch must deny instead of evaluating the selected subset.
	signer := testutil.NewKeySigner(t)
	images := map[string]ociV1.Image{
		referrerDigest(1).String(): fakeImageWithPayload(signer.SignBundle(t, signerStatement(t))),
	}

	atts, err := signedFetcher(images, manifests).Fetch(
		t.Context(), signerImageRef, &attestation.FetchOptions{
			TrustedKeys: []attestation.TrustedKeyRef{{Path: signer.PublicKeyPath}},
			Digest:      signerTestDigest,
		},
	)
	testutil.AssertErrorIs(t, err, attestation.ErrVerificationFailed)
	testutil.AssertEqual(t, 0, len(atts))
}

func legacyCosignImage(t *testing.T, bundleJSON []byte) ociV1.Image {
	t.Helper()

	layerData, annotations := testutil.LegacyCosignLayer(t, bundleJSON)

	img, err := mutate.Append(empty.Image, mutate.Addendum{
		Layer: static.NewLayer(
			layerData,
			types.MediaType("application/vnd.dsse.envelope.v1+json"),
		),
		History:     ociV1.History{},
		Annotations: annotations,
		URLs:        nil,
		MediaType:   "",
	})
	if err != nil {
		t.Fatalf("building legacy cosign image: %v", err)
	}

	return img
}

func TestCosignTagLegacyKeySignedLayer(t *testing.T) {
	t.Parallel()

	signer := testutil.NewKeySigner(t)
	other := testutil.NewKeySigner(t)
	ref, err := name.NewDigest(signerLegacyTagRef + "@" + signerTestDigest)
	testutil.AssertNoError(t, err)

	img := legacyCosignImage(t, signer.SignBundle(t, signerStatement(t)))
	fetcher := signedFetcher(map[string]ociV1.Image{
		strings.Replace(signerTestDigest, ":", "-", 1) + ".att": img,
	}, nil)

	atts, err := fetcher.CosignTagFallback(
		t.Context(),
		ref,
		signerTestDigest,
		nil,
		&attestation.FetchOptions{
			TrustedKeys: []attestation.TrustedKeyRef{
				{Path: other.PublicKeyPath},
				{Path: signer.PublicKeyPath},
			},
			Digest: signerTestDigest,
		},
	)
	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, 1, len(atts))
	testutil.AssertEqual(t, signer.PublicKeyPath, atts[0].Signer.KeyPath)

	_, err = fetcher.CosignTagFallback(
		t.Context(),
		ref,
		signerTestDigest,
		nil,
		&attestation.FetchOptions{
			TrustedKeys: []attestation.TrustedKeyRef{{Path: other.PublicKeyPath}},
			Digest:      signerTestDigest,
		},
	)
	testutil.AssertErrorIs(t, err, attestation.ErrVerificationFailed)
}

func TestCosignTagLegacyKeylessLayer(t *testing.T) {
	t.Parallel()

	virtual := testutil.NewVirtualSigstore(t)
	trustedRoot := testutil.VirtualTrustedRoot(t, virtual)
	bundleJSON := testutil.KeylessBundle(
		t,
		virtual,
		signerIdentity,
		signerIssuer,
		signerStatement(t),
	)
	layerData, annotations := testutil.LegacyCosignLayer(t, bundleJSON)

	converted, err := attestation.ExportLegacyLayerToBundles(layerData, annotations, nil)
	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, 1, len(converted))

	verified, err := attestation.ExportVerifyBundleWithRoots(
		t.Context(), converted[0], &attestation.FetchOptions{
			TrustedIssuers: []string{signerIssuer},
			SANPatterns:    []string{signerIdentity},
			Digest:         signerTestDigest,
		}, []*root.TrustedRoot{trustedRoot}, nil, true,
	)
	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, signerIdentity, verified.Signer.SAN)
}

func TestCosignTagRegistryErrorsPropagate(t *testing.T) {
	t.Parallel()

	ref, err := name.NewDigest(signerLegacyTagRef + "@" + signerTestDigest)
	testutil.AssertNoError(t, err)

	for _, status := range []int{http.StatusUnauthorized, http.StatusInternalServerError} {
		fetcher := attestation.NewTestOCIFetcherSigned(
			func(context.Context, []byte, *attestation.FetchOptions) (*attestation.VerifiedBundle, error) {
				return nil, errSignatureMismatch
			},
			func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
				return nil, &transport.Error{StatusCode: status}
			},
			nil,
		)

		_, fetchErr := fetcher.CosignTagFallback(
			t.Context(),
			ref,
			signerTestDigest,
			nil,
			&attestation.FetchOptions{Digest: signerTestDigest},
		)
		testutil.AssertError(t, fetchErr)
	}
}

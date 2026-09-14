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

package bundle //nolint:testpackage // tests use internal store helpers

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
)

const roundTripDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func offlineVerifier(
	ctx context.Context, bundleBytes []byte, opts *attestation.FetchOptions,
) (*attestation.VerifiedBundle, error) {
	verified, err := attestation.VerifyBundle(ctx, bundleBytes, opts, nil)
	if err != nil {
		return nil, fmt.Errorf("offline verification: %w", err)
	}

	return verified, nil
}

// createAndImport packages the given attestations into a bundle, imports it,
// and returns an offline fetcher backed by the imported store.
func createAndImport(
	t *testing.T, atts []attestation.VerifiedAttestation, opts ...FetcherOption,
) *Fetcher {
	t.Helper()

	dir := t.TempDir()
	outputPath := filepath.Join(dir, "bundle.tar.gz")
	storePath := filepath.Join(dir, "store")

	//nolint:exhaustruct_v5 // test data
	err := Create(context.Background(), &CreateOptions{
		Images:       []string{roundTripDigest},
		OutputPath:   outputPath,
		Fetcher:      &createTestFetcher{attestations: atts, err: nil},
		FetchOptions: &attestation.FetchOptions{},
	})
	testutil.AssertNoError(t, err)
	testutil.AssertNoError(t, Import(outputPath, storePath, ""))

	store, err := OpenStore(storePath)
	testutil.AssertNoError(t, err)

	return NewFetcher(store, offlineVerifier, opts...)
}

func TestBundleCreateImportFetchRoundTrip(t *testing.T) {
	t.Parallel()

	signer := testutil.NewKeySigner(t)
	statement := testutil.Statement(
		t,
		roundTripDigest,
		attestation.PredicateSLSAProvenanceV1,
		map[string]string{},
	)
	signedBundle := signer.SignBundle(t, statement)

	fetcher := createAndImport(t, []attestation.VerifiedAttestation{
		{
			PredicateType: attestation.PredicateSLSAProvenanceV1,
			Payload:       statement,
			Digest:        roundTripDigest,
			SignatureType: attestation.SignatureTypeSigstore,
			Signer: attestation.SignerIdentity{
				KeyPath:  signer.PublicKeyPath,
				KeyPaths: []string{signer.PublicKeyPath},
				Issuer:   "",
				SAN:      "",
			},
			Bundle: signedBundle,
		},
		{
			// Notation signatures carry no Sigstore bundle and are skipped.
			PredicateType: attestation.NotationSignatureMediaType,
			Payload:       []byte("envelope"),
			Digest:        roundTripDigest,
			SignatureType: attestation.SignatureTypeNotation,
			Signer: attestation.SignerIdentity{
				KeyPath:  "",
				KeyPaths: nil,
				Issuer:   "",
				SAN:      "",
			},
			Bundle: nil,
		},
	})

	testutil.AssertEqual(t, 1, len(fetcher.store.Manifest().Images[roundTripDigest].Attestations))

	atts, err := fetcher.Fetch(
		context.Background(),
		"registry.example.com/app",
		&attestation.FetchOptions{
			TrustedKeys: []attestation.TrustedKeyRef{{Path: signer.PublicKeyPath}},
			Digest:      roundTripDigest,
		},
	)
	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, 1, len(atts))
	testutil.AssertEqual(t, attestation.PredicateSLSAProvenanceV1, atts[0].PredicateType)
	testutil.AssertEqual(t, signer.PublicKeyPath, atts[0].Signer.KeyPath)
	testutil.AssertEqual(t, string(statement), string(atts[0].Payload))

	// A different trusted key must not verify the bundled attestation.
	other := testutil.NewKeySigner(t)

	_, err = fetcher.Fetch(
		context.Background(),
		"registry.example.com/app",
		&attestation.FetchOptions{
			TrustedKeys: []attestation.TrustedKeyRef{{Path: other.PublicKeyPath}},
			Digest:      roundTripDigest,
		},
	)
	testutil.AssertErrorIs(t, err, attestation.ErrVerificationFailed)
}

func TestBundleForgedAttestationRejected(t *testing.T) {
	t.Parallel()

	signer := testutil.NewKeySigner(t)
	statement := testutil.Statement(
		t,
		roundTripDigest,
		attestation.PredicateSLSAProvenanceV1,
		map[string]string{},
	)

	// Bundles created by older releases stored the unsigned statement.
	fetcher := createAndImport(t, []attestation.VerifiedAttestation{{
		PredicateType: attestation.PredicateSLSAProvenanceV1,
		Payload:       statement,
		Digest:        roundTripDigest,
		SignatureType: attestation.SignatureTypeSigstore,
		Signer:        attestation.SignerIdentity{KeyPath: "", KeyPaths: nil, Issuer: "", SAN: ""},
		Bundle:        statement,
	}})

	_, err := fetcher.Fetch(
		context.Background(),
		"registry.example.com/app",
		&attestation.FetchOptions{
			TrustedKeys: []attestation.TrustedKeyRef{{Path: signer.PublicKeyPath}},
			Digest:      roundTripDigest,
		},
	)
	testutil.AssertErrorIs(t, err, attestation.ErrVerificationFailed)
}

func TestBundleKeylessWithoutTrustedRootRejected(t *testing.T) {
	t.Parallel()

	virtual := testutil.NewVirtualSigstore(t)
	statement := testutil.Statement(
		t,
		roundTripDigest,
		attestation.PredicateSLSAProvenanceV1,
		map[string]string{},
	)
	keyless := testutil.KeylessBundle(
		t,
		virtual,
		"ci@example.com",
		"https://issuer.example.com",
		statement,
	)

	fetcher := createAndImport(t, []attestation.VerifiedAttestation{{
		PredicateType: attestation.PredicateSLSAProvenanceV1,
		Payload:       statement,
		Digest:        roundTripDigest,
		SignatureType: attestation.SignatureTypeSigstore,
		Signer:        attestation.SignerIdentity{KeyPath: "", KeyPaths: nil, Issuer: "", SAN: ""},
		Bundle:        keyless,
	}})

	_, err := fetcher.Fetch(
		context.Background(),
		"registry.example.com/app",
		&attestation.FetchOptions{
			TrustedIssuers: []string{"https://issuer.example.com"},
			Digest:         roundTripDigest,
		},
	)
	testutil.AssertErrorIs(t, err, attestation.ErrVerificationFailed)
}

func TestBundleBaselineSBOMUnwrapped(t *testing.T) {
	t.Parallel()

	signer := testutil.NewKeySigner(t)
	statement := testutil.Statement(
		t,
		roundTripDigest,
		attestation.PredicateBaselineSBOM,
		map[string]string{"spdxVersion": "SPDX-2.3"},
	)

	fetcher := createAndImport(t, []attestation.VerifiedAttestation{
		{
			PredicateType: attestation.PredicateBaselineSBOM,
			Payload:       statement,
			Digest:        roundTripDigest,
			SignatureType: attestation.SignatureTypeSigstore,
			Signer: attestation.SignerIdentity{
				KeyPath:  signer.PublicKeyPath,
				KeyPaths: []string{signer.PublicKeyPath},
				Issuer:   "",
				SAN:      "",
			},
			Bundle: signer.SignBundle(t, statement),
		},
	})

	atts, err := fetcher.Fetch(
		context.Background(),
		"registry.example.com/app",
		&attestation.FetchOptions{
			TrustedKeys: []attestation.TrustedKeyRef{{Path: signer.PublicKeyPath}},
			Digest:      roundTripDigest,
		},
	)
	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, 1, len(atts))
	testutil.AssertEqual(t, `{"spdxVersion":"SPDX-2.3"}`, string(atts[0].Payload))
}

func TestStoreBlobDigestMismatchOnRead(t *testing.T) {
	t.Parallel()

	payload := []byte(`{"predicateType":"test"}`)
	digest := blobDigest(payload)

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Images: map[string]*ImageEntry{
			testImageDigest: { //nolint:exhaustruct_v5 // test data
				Attestations: []AttestationEntry{{
					PredicateType: testPredicateType,
					BlobDigest:    digest,
					Size:          int64(len(payload)),
					SignatureType: testSigType,
				}},
			},
		},
	}

	dir := createTestStore(t, manifest, map[string][]byte{digest: payload})

	store, err := OpenStore(dir)
	testutil.AssertNoError(t, err)

	// Swap the blob content after import while keeping its size.
	tampered := []byte(strings.Replace(string(payload), "test", "evil", 1))
	blobPath := filepath.Join(dir, "blobs", "sha256", strings.TrimPrefix(digest, "sha256:"))

	err = os.WriteFile(blobPath, tampered, 0o600)
	testutil.AssertNoError(t, err)

	_, err = store.AttestationsFor(testImageDigest)
	if !errors.Is(err, ErrBlobDigestMismatch) {
		t.Fatalf("AttestationsFor() error = %v, want %v", err, ErrBlobDigestMismatch)
	}
}

func TestBundleEmbedsNamedTrustedRoots(t *testing.T) {
	t.Parallel()

	const githubIssuer = "https://token.actions.githubusercontent.com"

	virtual := testutil.NewVirtualSigstore(t)
	dir := t.TempDir()
	outputPath := filepath.Join(dir, "bundle.tar.gz")
	storePath := filepath.Join(dir, "store")

	//nolint:exhaustruct_v5 // test data
	err := Create(context.Background(), &CreateOptions{
		Images:       []string{roundTripDigest},
		OutputPath:   outputPath,
		Fetcher:      &createTestFetcher{attestations: nil, err: nil},
		FetchOptions: &attestation.FetchOptions{},
		TrustedRoots: []TrustedRootSource{
			{
				Name:    "public-sigstore",
				Issuers: []string{githubIssuer},
				Root:    testutil.VirtualTrustedRoot(t, virtual),
			},
			{
				Name:    "private",
				Issuers: nil,
				Root:    testutil.VirtualTrustedRoot(t, testutil.NewVirtualSigstore(t)),
			},
		},
	})
	testutil.AssertNoError(t, err)
	testutil.AssertNoError(t, Import(outputPath, storePath, ""))

	store, err := OpenStore(storePath)
	testutil.AssertNoError(t, err)
	testutil.AssertNoError(t, VerifyBlobIntegrity(store))
	testutil.AssertEqual(t, true, store.Manifest().HasTrustedRoot())

	roots, err := store.TrustedRoots()
	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, 2, len(roots))
	testutil.AssertEqual(t, "public-sigstore", roots[0].Name)
	testutil.AssertEqual(t, githubIssuer, strings.Join(roots[0].Issuers, ","))
	testutil.AssertEqual(t, "private", roots[1].Name)

	if roots[0].Root == nil || roots[1].Root == nil {
		t.Fatal("expected parsed trusted roots")
	}
}

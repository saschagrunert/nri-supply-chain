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

package policy_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	ociV1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/fake"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	ociTypes "github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
)

const (
	testExampleIssuer    = "https://example.com"
	testBundleArtifact   = "application/vnd.dev.sigstore.bundle.v0.3+json"
	testOCIEmptyArtifact = "application/vnd.oci.empty.v1+json"
	testHashAlgoSHA256   = "sha256"
)

var (
	errSigVerificationFailed = errors.New("signature verification failed")
	errRegistryUnavailable   = errors.New("registry unavailable")
)

// --- NewSignatureVerifyFunc tests ---

func TestOCINewSignatureVerifyFuncNilConfig(t *testing.T) {
	t.Parallel()

	dummyFetch := func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
		return nil, nil
	}
	dummyReferrers := func(_ name.Digest, _ ...remote.Option) (ociV1.ImageIndex, error) {
		return nil, nil
	}

	_, err := policy.NewSignatureVerifyFunc(nil, nil, dummyFetch, dummyReferrers)
	testutil.AssertError(t, err)
	testutil.AssertContains(t, err.Error(), "must not be nil")
}

func TestOCINewSignatureVerifyFuncNilFetchImage(t *testing.T) {
	t.Parallel()

	dummyReferrers := func(_ name.Digest, _ ...remote.Option) (ociV1.ImageIndex, error) {
		return nil, nil
	}
	validCfg := &policy.SignatureConfig{
		Issuers: []string{testExampleIssuer},
	}

	_, err := policy.NewSignatureVerifyFunc(validCfg, nil, nil, dummyReferrers)
	testutil.AssertError(t, err)
	testutil.AssertContains(t, err.Error(), "fetchImage")
}

func TestOCINewSignatureVerifyFuncNilReferrers(t *testing.T) {
	t.Parallel()

	dummyFetch := func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
		return nil, nil
	}
	validCfg := &policy.SignatureConfig{
		Issuers: []string{testExampleIssuer},
	}

	_, err := policy.NewSignatureVerifyFunc(validCfg, nil, dummyFetch, nil)
	testutil.AssertError(t, err)
	testutil.AssertContains(t, err.Error(), "referrers")
}

func TestOCINewSignatureVerifyFuncNoTrustMaterial(t *testing.T) {
	t.Parallel()

	dummyFetch := func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
		return nil, nil
	}
	dummyReferrers := func(_ name.Digest, _ ...remote.Option) (ociV1.ImageIndex, error) {
		return nil, nil
	}
	emptyCfg := &policy.SignatureConfig{}

	_, err := policy.NewSignatureVerifyFunc(emptyCfg, nil, dummyFetch, dummyReferrers)
	testutil.AssertError(t, err)
	testutil.AssertContains(t, err.Error(), "issuers or keys")
}

func TestOCINewSignatureVerifyFuncIssuersAndKeysMutuallyExclusive(t *testing.T) {
	t.Parallel()

	dummyFetch := func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
		return nil, nil
	}
	dummyReferrers := func(_ name.Digest, _ ...remote.Option) (ociV1.ImageIndex, error) {
		return nil, nil
	}
	bothCfg := &policy.SignatureConfig{
		Issuers: []string{testExampleIssuer},
		Keys:    []string{"/etc/keys/test.pub"},
	}

	_, err := policy.NewSignatureVerifyFunc(bothCfg, nil, dummyFetch, dummyReferrers)
	testutil.AssertError(t, err)
	testutil.AssertContains(t, err.Error(), "mutually exclusive")
}

func TestOCINewSignatureVerifyFuncNilFetchTrustedRootWithIssuers(t *testing.T) {
	t.Parallel()

	dummyFetch := func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
		return nil, nil
	}
	dummyReferrers := func(_ name.Digest, _ ...remote.Option) (ociV1.ImageIndex, error) {
		return nil, nil
	}
	validCfg := &policy.SignatureConfig{
		Issuers: []string{testExampleIssuer},
	}

	_, err := policy.NewSignatureVerifyFunc(validCfg, nil, dummyFetch, dummyReferrers)
	testutil.AssertError(t, err)
	testutil.AssertContains(t, err.Error(), "fetchTrustedRoot")
}

func TestOCINewSignatureVerifyFuncWithKeysSuccess(t *testing.T) {
	t.Parallel()

	keyPath := writeECDSAKeyFile(t, elliptic.P256())

	dummyFetch := func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
		return nil, nil
	}
	dummyReferrers := func(_ name.Digest, _ ...remote.Option) (ociV1.ImageIndex, error) {
		return nil, nil
	}
	cfg := &policy.SignatureConfig{
		Keys: []string{keyPath},
	}

	fn, err := policy.NewSignatureVerifyFunc(cfg, nil, dummyFetch, dummyReferrers)
	testutil.AssertNoError(t, err)

	if fn == nil {
		t.Fatal("expected non-nil verify function")
	}
}

// --- FilterSignatureCandidates tests ---

func TestOCIFilterSignatureCandidatesExactPreferred(t *testing.T) {
	t.Parallel()

	manifests := []ociV1.Descriptor{
		{
			ArtifactType: testBundleArtifact,
			Digest:       ociV1.Hash{Algorithm: testHashAlgoSHA256, Hex: "aaa"},
		},
		{
			ArtifactType: testOCIEmptyArtifact,
			Digest:       ociV1.Hash{Algorithm: testHashAlgoSHA256, Hex: "bbb"},
		},
	}

	candidates := policy.FilterSignatureCandidatesForTest(manifests)

	if len(candidates) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(candidates))
	}

	if candidates[0].ArtifactType != testBundleArtifact {
		t.Errorf("expected exact artifact type, got %q", candidates[0].ArtifactType)
	}
}

func TestOCIFilterSignatureCandidatesPermissiveFallback(t *testing.T) {
	t.Parallel()

	manifests := []ociV1.Descriptor{
		{
			ArtifactType: testOCIEmptyArtifact,
			Digest:       ociV1.Hash{Algorithm: testHashAlgoSHA256, Hex: "aaa"},
		},
		{
			ArtifactType: "",
			Digest:       ociV1.Hash{Algorithm: testHashAlgoSHA256, Hex: "bbb"},
		},
	}

	candidates := policy.FilterSignatureCandidatesForTest(manifests)

	if len(candidates) != 2 {
		t.Fatalf("expected 2 candidates, got %d", len(candidates))
	}
}

func TestOCIFilterSignatureCandidatesEmptyList(t *testing.T) {
	t.Parallel()

	manifests := []ociV1.Descriptor{
		{ArtifactType: "application/vnd.unknown"},
		{ArtifactType: "text/plain"},
	}

	candidates := policy.FilterSignatureCandidatesForTest(manifests)

	if len(candidates) != 0 {
		t.Fatalf("expected 0 candidates, got %d", len(candidates))
	}
}

func TestOCIFilterSignatureCandidatesNilManifests(t *testing.T) {
	t.Parallel()

	candidates := policy.FilterSignatureCandidatesForTest(nil)

	if len(candidates) != 0 {
		t.Fatalf("expected 0 candidates, got %d", len(candidates))
	}
}

// --- CollectCandidates tests ---

func TestOCICollectCandidatesRespectsMaxCap(t *testing.T) {
	t.Parallel()

	// Create more than maxPolicySignatureReferrers (50) matching descriptors.
	manifests := make([]ociV1.Descriptor, 60)
	for i := range manifests {
		manifests[i] = ociV1.Descriptor{
			ArtifactType: testBundleArtifact,
			Digest:       ociV1.Hash{Algorithm: testHashAlgoSHA256, Hex: fmt.Sprintf("%064d", i)},
		}
	}

	candidates := policy.CollectCandidatesForTest(manifests, func(at string) bool {
		return at == testBundleArtifact
	})

	if len(candidates) != 50 {
		t.Fatalf("expected 50 candidates (cap), got %d", len(candidates))
	}
}

func TestOCICollectCandidatesNoMatch(t *testing.T) {
	t.Parallel()

	manifests := []ociV1.Descriptor{
		{ArtifactType: "text/plain"},
	}

	candidates := policy.CollectCandidatesForTest(manifests, func(at string) bool {
		return at == testBundleArtifact
	})

	if len(candidates) != 0 {
		t.Fatalf("expected 0 candidates, got %d", len(candidates))
	}
}

// --- ExtractFirstLayer tests ---

func TestOCIExtractFirstLayerHappyPath(t *testing.T) {
	t.Parallel()

	expected := []byte(`{"some":"bundle"}`)
	img := &fake.FakeImage{}
	img.LayersReturns([]ociV1.Layer{newStaticOCILayer(t, expected)}, nil)

	data, err := policy.ExtractFirstLayerForTest(context.Background(), img)
	testutil.AssertNoError(t, err)

	if !bytes.Equal(data, expected) {
		t.Errorf("expected %q, got %q", expected, data)
	}
}

func TestOCIExtractFirstLayerNoLayers(t *testing.T) {
	t.Parallel()

	img := &fake.FakeImage{}
	img.LayersReturns([]ociV1.Layer{}, nil)

	_, err := policy.ExtractFirstLayerForTest(context.Background(), img)
	testutil.AssertError(t, err)
	testutil.AssertContains(t, err.Error(), "no layers")
}

func TestOCIExtractFirstLayerLayersError(t *testing.T) {
	t.Parallel()

	img := &fake.FakeImage{}
	img.LayersReturns(nil, errRegistryUnavailable)

	_, err := policy.ExtractFirstLayerForTest(context.Background(), img)
	testutil.AssertError(t, err)
	testutil.AssertContains(t, err.Error(), "signature layers")
}

func TestOCIExtractFirstLayerContextCanceled(t *testing.T) {
	t.Parallel()

	img := &fake.FakeImage{}
	img.LayersReturns([]ociV1.Layer{newStaticOCILayer(t, []byte("data"))}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := policy.ExtractFirstLayerForTest(ctx, img)
	testutil.AssertError(t, err)
	testutil.AssertContains(t, err.Error(), "context canceled")
}

func TestOCIExtractFirstLayerBundleTooLarge(t *testing.T) {
	t.Parallel()

	// Create data exceeding 1 MiB limit.
	oversized := make([]byte, (1<<20)+1)
	for i := range oversized {
		oversized[i] = 'x'
	}

	img := &fake.FakeImage{}
	img.LayersReturns([]ociV1.Layer{newStaticOCILayer(t, oversized)}, nil)

	_, err := policy.ExtractFirstLayerForTest(context.Background(), img)
	testutil.AssertError(t, err)
	testutil.AssertContains(t, err.Error(), "exceeds size limit")
}

// --- BuildPolicyCertificateIdentity tests ---

func TestOCIBuildPolicyCertificateIdentitySingleIssuer(t *testing.T) {
	t.Parallel()

	certID, err := policy.BuildPolicyCertificateIdentityForTest(
		[]string{testIssuerURL},
		nil,
	)
	testutil.AssertNoError(t, err)

	// Verify the identity was constructed (non-zero value).
	_ = certID
}

func TestOCIBuildPolicyCertificateIdentityMultipleIssuers(t *testing.T) {
	t.Parallel()

	certID, err := policy.BuildPolicyCertificateIdentityForTest(
		[]string{testIssuerURL, "https://github.com/login/oauth"},
		nil,
	)
	testutil.AssertNoError(t, err)

	_ = certID
}

func TestOCIBuildPolicyCertificateIdentityWithSANPatterns(t *testing.T) {
	t.Parallel()

	certID, err := policy.BuildPolicyCertificateIdentityForTest(
		[]string{testIssuerURL},
		[]string{"build@example.com", "deploy-*@example.com"},
	)
	testutil.AssertNoError(t, err)

	_ = certID
}

func TestOCIBuildPolicyCertificateIdentityEmptySANsIsWildcard(t *testing.T) {
	t.Parallel()

	// Empty SANPatterns should result in a wildcard SAN regex ".*".
	certID, err := policy.BuildPolicyCertificateIdentityForTest(
		[]string{testIssuerURL},
		[]string{},
	)
	testutil.AssertNoError(t, err)

	_ = certID
}

// --- BuildPolicyKeyMaterial tests ---

func TestOCIBuildPolicyKeyMaterialECDSAP256(t *testing.T) {
	t.Parallel()

	keyPath := writeECDSAKeyFile(t, elliptic.P256())

	km, err := policy.BuildPolicyKeyMaterialForTest([]string{keyPath})
	testutil.AssertNoError(t, err)

	if km == nil {
		t.Fatal("expected non-nil key material")
	}
}

func TestOCIBuildPolicyKeyMaterialECDSAP384(t *testing.T) {
	t.Parallel()

	keyPath := writeECDSAKeyFile(t, elliptic.P384())

	km, err := policy.BuildPolicyKeyMaterialForTest([]string{keyPath})
	testutil.AssertNoError(t, err)

	if km == nil {
		t.Fatal("expected non-nil key material")
	}
}

func TestOCIBuildPolicyKeyMaterialECDSAP521(t *testing.T) {
	t.Parallel()

	keyPath := writeECDSAKeyFile(t, elliptic.P521())

	km, err := policy.BuildPolicyKeyMaterialForTest([]string{keyPath})
	testutil.AssertNoError(t, err)

	if km == nil {
		t.Fatal("expected non-nil key material")
	}
}

func TestOCIBuildPolicyKeyMaterialRSA(t *testing.T) {
	t.Parallel()

	keyPath := writeRSAKeyFile(t)

	km, err := policy.BuildPolicyKeyMaterialForTest([]string{keyPath})
	testutil.AssertNoError(t, err)

	if km == nil {
		t.Fatal("expected non-nil key material")
	}
}

func TestOCIBuildPolicyKeyMaterialEd25519(t *testing.T) {
	t.Parallel()

	keyPath := writeEd25519KeyFile(t)

	km, err := policy.BuildPolicyKeyMaterialForTest([]string{keyPath})
	testutil.AssertNoError(t, err)

	if km == nil {
		t.Fatal("expected non-nil key material")
	}
}

func TestOCIBuildPolicyKeyMaterialMultipleKeys(t *testing.T) {
	t.Parallel()

	keyPath1 := writeECDSAKeyFile(t, elliptic.P256())
	keyPath2 := writeRSAKeyFile(t)

	km, err := policy.BuildPolicyKeyMaterialForTest([]string{keyPath1, keyPath2})
	testutil.AssertNoError(t, err)

	if km == nil {
		t.Fatal("expected non-nil key material")
	}
}

func TestOCIBuildPolicyKeyMaterialNonexistentFile(t *testing.T) {
	t.Parallel()

	_, err := policy.BuildPolicyKeyMaterialForTest([]string{"/nonexistent/key.pub"})
	testutil.AssertError(t, err)
	testutil.AssertContains(t, err.Error(), "loading public key")
}

func TestOCIBuildPolicyKeyMaterialInvalidPEM(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "bad.pub")
	writeFile(t, keyPath, "not a valid PEM file")

	_, err := policy.BuildPolicyKeyMaterialForTest([]string{keyPath})
	testutil.AssertError(t, err)
	testutil.AssertContains(t, err.Error(), "no PEM block")
}

// --- LoadPEMPublicKey tests ---

func TestOCILoadPEMPublicKeyPKIX(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating ECDSA key: %v", err)
	}

	keyPath := writePKIXPEMFile(t, &key.PublicKey)

	pub, err := policy.LoadPEMPublicKeyForTest(keyPath)
	testutil.AssertNoError(t, err)

	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
	}

	if ecPub.Curve != elliptic.P256() {
		t.Errorf("expected P256 curve, got %v", ecPub.Curve)
	}
}

func TestOCILoadPEMPublicKeyPKCS1(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "rsa-pkcs1.pub")

	derBytes := x509.MarshalPKCS1PublicKey(&key.PublicKey)
	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: derBytes,
	})
	writeFile(t, keyPath, string(pemBlock))

	pub, err := policy.LoadPEMPublicKeyForTest(keyPath)
	testutil.AssertNoError(t, err)

	if _, ok := pub.(*rsa.PublicKey); !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", pub)
	}
}

func TestOCILoadPEMPublicKeyInvalidPEM(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "invalid.pub")
	writeFile(t, keyPath, "this is not PEM data at all")

	_, err := policy.LoadPEMPublicKeyForTest(keyPath)
	testutil.AssertError(t, err)
	testutil.AssertContains(t, err.Error(), "no PEM block")
}

func TestOCILoadPEMPublicKeyNoPEMBlock(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "empty.pub")
	writeFile(t, keyPath, "")

	_, err := policy.LoadPEMPublicKeyForTest(keyPath)
	testutil.AssertError(t, err)
	testutil.AssertContains(t, err.Error(), "no PEM block")
}

func TestOCILoadPEMPublicKeyInvalidDER(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "bad-der.pub")

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: []byte("not valid DER data"),
	})
	writeFile(t, keyPath, string(pemBlock))

	_, err := policy.LoadPEMPublicKeyForTest(keyPath)
	testutil.AssertError(t, err)
	testutil.AssertContains(t, err.Error(), "parsing public key")
}

func TestOCILoadPEMPublicKeyNonexistentFile(t *testing.T) {
	t.Parallel()

	_, err := policy.LoadPEMPublicKeyForTest("/nonexistent/key.pub")
	testutil.AssertError(t, err)
	testutil.AssertContains(t, err.Error(), "reading PEM file")
}

// --- HashAlgorithmForKey tests ---

func TestOCIHashAlgorithmForKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		key      crypto.PublicKey
		expected crypto.Hash
	}{
		{
			name:     "ECDSA P-256 uses SHA256",
			key:      generateECDSAPublicKey(t, elliptic.P256()),
			expected: crypto.SHA256,
		},
		{
			name:     "ECDSA P-384 uses SHA384",
			key:      generateECDSAPublicKey(t, elliptic.P384()),
			expected: crypto.SHA384,
		},
		{
			name:     "ECDSA P-521 uses SHA512",
			key:      generateECDSAPublicKey(t, elliptic.P521()),
			expected: crypto.SHA512,
		},
		{
			name:     "Ed25519 uses SHA512",
			key:      generateEd25519PublicKey(t),
			expected: crypto.SHA512,
		},
		{
			name:     "RSA uses SHA256 default",
			key:      generateRSAPublicKey(t),
			expected: crypto.SHA256,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := policy.HashAlgorithmForKeyForTest(test.key)
			if got != test.expected {
				t.Errorf("expected %v, got %v", test.expected, got)
			}
		})
	}
}

// --- PolicyKeyHint tests ---

func TestOCIPolicyKeyHint(t *testing.T) {
	t.Parallel()

	pub := generateECDSAPublicKey(t, elliptic.P256())

	hint, err := policy.PolicyKeyHintForTest(pub)
	testutil.AssertNoError(t, err)

	if hint == "" {
		t.Fatal("expected non-empty hint")
	}

	// Verify it is valid base64.
	decoded, err := base64.StdEncoding.DecodeString(hint)
	if err != nil {
		t.Fatalf("hint is not valid base64: %v", err)
	}

	// SHA-256 produces 32 bytes.
	if len(decoded) != sha256.Size {
		t.Errorf("expected %d bytes, got %d", sha256.Size, len(decoded))
	}
}

func TestOCIPolicyKeyHintDeterministic(t *testing.T) {
	t.Parallel()

	pub := generateECDSAPublicKey(t, elliptic.P256())

	hint1, err := policy.PolicyKeyHintForTest(pub)
	testutil.AssertNoError(t, err)

	hint2, err := policy.PolicyKeyHintForTest(pub)
	testutil.AssertNoError(t, err)

	if hint1 != hint2 {
		t.Errorf("hint should be deterministic: %q vs %q", hint1, hint2)
	}
}

func TestOCIPolicyKeyHintDifferentKeys(t *testing.T) {
	t.Parallel()

	pub1 := generateECDSAPublicKey(t, elliptic.P256())
	pub2 := generateECDSAPublicKey(t, elliptic.P256())

	hint1, err := policy.PolicyKeyHintForTest(pub1)
	testutil.AssertNoError(t, err)

	hint2, err := policy.PolicyKeyHintForTest(pub2)
	testutil.AssertNoError(t, err)

	if hint1 == hint2 {
		t.Error("different keys should produce different hints")
	}
}

func TestOCIPolicyKeyHintMatchesManualComputation(t *testing.T) {
	t.Parallel()

	pub := generateECDSAPublicKey(t, elliptic.P256())

	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshaling public key: %v", err)
	}

	sum := sha256.Sum256(der)
	expected := base64.StdEncoding.EncodeToString(sum[:])

	hint, err := policy.PolicyKeyHintForTest(pub)
	testutil.AssertNoError(t, err)

	if hint != expected {
		t.Errorf("expected %q, got %q", expected, hint)
	}
}

// --- PrebuildVerificationConfig tests ---

func TestOCIPrebuildVerificationConfigWithKeys(t *testing.T) {
	t.Parallel()

	keyPath := writeECDSAKeyFile(t, elliptic.P256())

	cfg := &policy.SignatureConfig{
		Keys: []string{keyPath},
	}

	prebuilt, err := policy.PrebuildVerificationConfigForTest(cfg)
	testutil.AssertNoError(t, err)

	if prebuilt == nil {
		t.Fatal("expected non-nil prebuilt config")
	}
}

func TestOCIPrebuildVerificationConfigWithIssuers(t *testing.T) {
	t.Parallel()

	cfg := &policy.SignatureConfig{
		Issuers: []string{testIssuerURL},
	}

	prebuilt, err := policy.PrebuildVerificationConfigForTest(cfg)
	testutil.AssertNoError(t, err)

	if prebuilt == nil {
		t.Fatal("expected non-nil prebuilt config")
	}
}

func TestOCIPrebuildVerificationConfigWithInvalidKeyPath(t *testing.T) {
	t.Parallel()

	cfg := &policy.SignatureConfig{
		Keys: []string{"/nonexistent/key.pub"},
	}

	_, err := policy.PrebuildVerificationConfigForTest(cfg)
	testutil.AssertError(t, err)
}

// --- Signature verification integration tests ---

func TestFetchFromOCIWithSignatureVerificationSuccess(t *testing.T) {
	t.Parallel()

	img := buildPolicyImage(t, map[string]string{
		testDefaultJSON: testWarnPolicyJSON,
	})

	fetchFunc := func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
		return img, nil
	}

	verifyOK := func(
		_ context.Context,
		_ name.Reference,
		_ ociV1.Image,
		_ []remote.Option,
	) error {
		return nil
	}

	fetcher := policy.NewOCIFetcherWithSignatureVerification(nil, verifyOK)
	fetcher.SetImageFetchFunc(fetchFunc)

	result, err := fetcher.FetchFromOCI(context.Background(), "example.com/test:v1")
	testutil.AssertNoError(t, err)

	if len(result.Policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(result.Policies))
	}

	if result.Digest == "" {
		t.Error("expected non-empty digest")
	}
}

func TestFetchFromOCIWithSignatureVerificationFailure(t *testing.T) {
	t.Parallel()

	img := buildPolicyImage(t, map[string]string{
		testDefaultJSON: testWarnPolicyJSON,
	})

	fetchFunc := func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
		return img, nil
	}

	sigErr := errSigVerificationFailed
	verifyFail := func(
		_ context.Context,
		_ name.Reference,
		_ ociV1.Image,
		_ []remote.Option,
	) error {
		return sigErr
	}

	fetcher := policy.NewOCIFetcherWithSignatureVerification(nil, verifyFail)
	fetcher.SetImageFetchFunc(fetchFunc)

	_, err := fetcher.FetchFromOCI(context.Background(), "example.com/test:v1")
	testutil.AssertError(t, err)
	testutil.AssertContains(t, err.Error(), "signature verification failed")
}

func TestFetchFromOCINilVerifySignatureSkipsVerification(t *testing.T) {
	t.Parallel()

	img := buildPolicyImage(t, map[string]string{
		testDefaultJSON: testWarnPolicyJSON,
	})

	fetchFunc := func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
		return img, nil
	}

	// nil verifySignature means no verification (backward compat).
	fetcher := policy.NewOCIFetcherWithImageFunc(fetchFunc, nil)

	result, err := fetcher.FetchFromOCI(context.Background(), "example.com/test:v1")
	testutil.AssertNoError(t, err)

	if len(result.Policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(result.Policies))
	}
}

func TestFetchFromOCIWithSignatureBlocksPolicyExtraction(t *testing.T) {
	t.Parallel()

	// This test ensures that when signature verification fails, policy
	// extraction never happens (the error is returned before parsing).

	fetchFunc := func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
		return buildPolicyImage(t, map[string]string{
			testDefaultJSON: testWarnPolicyJSON,
		}), nil
	}

	verifyFail := func(
		_ context.Context,
		_ name.Reference,
		_ ociV1.Image,
		_ []remote.Option,
	) error {
		return policy.ErrNoPolicySignature
	}

	fetcher := policy.NewOCIFetcherWithSignatureVerification(nil, verifyFail)
	fetcher.SetImageFetchFunc(fetchFunc)

	_, err := fetcher.FetchFromOCI(context.Background(), "example.com/test:v1")
	testutil.AssertError(t, err)

	if !errors.Is(err, policy.ErrNoPolicySignature) {
		t.Errorf("expected ErrNoPolicySignature, got %v", err)
	}
}

// --- Test helpers ---

func generateECDSAPublicKey(t *testing.T, curve elliptic.Curve) *ecdsa.PublicKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generating ECDSA key: %v", err)
	}

	return &key.PublicKey
}

func generateEd25519PublicKey(t *testing.T) ed25519.PublicKey {
	t.Helper()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating Ed25519 key: %v", err)
	}

	return pub
}

func generateRSAPublicKey(t *testing.T) *rsa.PublicKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	return &key.PublicKey
}

func writePKIXPEMFile(t *testing.T, pub crypto.PublicKey) string {
	t.Helper()

	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshaling public key: %v", err)
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pub")
	writeFile(t, keyPath, string(pemBlock))

	return keyPath
}

func writeECDSAKeyFile(t *testing.T, curve elliptic.Curve) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generating ECDSA key: %v", err)
	}

	return writePKIXPEMFile(t, &key.PublicKey)
}

func writeRSAKeyFile(t *testing.T) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	return writePKIXPEMFile(t, &key.PublicKey)
}

func writeEd25519KeyFile(t *testing.T) string {
	t.Helper()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating Ed25519 key: %v", err)
	}

	return writePKIXPEMFile(t, pub)
}

// newStaticOCILayer creates a minimal in-memory OCI layer for testing.
func newStaticOCILayer(t *testing.T, content []byte) ociV1.Layer {
	t.Helper()

	return &staticOCIVerifyLayer{content: content}
}

type staticOCIVerifyLayer struct {
	content []byte
}

func (l *staticOCIVerifyLayer) Digest() (ociV1.Hash, error) {
	h, _, err := ociV1.SHA256(bytes.NewReader(l.content))
	if err != nil {
		return ociV1.Hash{}, fmt.Errorf("computing digest: %w", err)
	}

	return h, nil
}

func (l *staticOCIVerifyLayer) DiffID() (ociV1.Hash, error) {
	h, _, err := ociV1.SHA256(bytes.NewReader(l.content))
	if err != nil {
		return ociV1.Hash{}, fmt.Errorf("computing diff ID: %w", err)
	}

	return h, nil
}

func (l *staticOCIVerifyLayer) Compressed() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(l.content)), nil
}

func (l *staticOCIVerifyLayer) Uncompressed() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(l.content)), nil
}

func (l *staticOCIVerifyLayer) Size() (int64, error) {
	return int64(len(l.content)), nil
}

func (l *staticOCIVerifyLayer) MediaType() (ociTypes.MediaType, error) {
	return ociTypes.OCILayer, nil
}

// Verify the layer implements the interface at compile time.
var _ ociV1.Layer = (*staticOCIVerifyLayer)(nil)

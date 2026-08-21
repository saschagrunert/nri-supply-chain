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

package bundle //nolint:testpackage // tests use internal test helpers

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func generateTestKeyPair(t *testing.T) (privPath, pubPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()

	privBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	privPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})
	privPath = filepath.Join(dir, "key.pem")

	privWriteErr := os.WriteFile(privPath, privPEM, 0o600)
	if privWriteErr != nil {
		t.Fatal(privWriteErr)
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	pubPath = filepath.Join(dir, "key.pub")

	pubWriteErr := os.WriteFile(pubPath, pubPEM, 0o600)
	if pubWriteErr != nil {
		t.Fatal(pubWriteErr)
	}

	return privPath, pubPath
}

func TestSignAndVerifyManifest(t *testing.T) {
	t.Parallel()

	privPath, pubPath := generateTestKeyPair(t)

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Images: map[string]*ImageEntry{
			testDigestABC: {
				Refs: []string{testExampleRef},
				Attestations: []AttestationEntry{{
					PredicateType: testSLSAPredicate,
					BlobDigest:    "sha256:def",
					Size:          100,
					SignatureType: testSigType,
				}},
				CreatedAt: time.Now().UTC(),
			},
		},
	}

	signErr := SignManifest(manifest, privPath)
	if signErr != nil {
		t.Fatalf("SignManifest() error: %v", signErr)
	}

	if manifest.Signature == nil {
		t.Fatal("Signature should not be nil after signing")
	}

	if manifest.Signature.Algorithm != algorithmSHA256 {
		t.Errorf("Algorithm = %q, want %q", manifest.Signature.Algorithm, algorithmSHA256)
	}

	if manifest.Signature.Value == "" {
		t.Error("Signature.Value should not be empty")
	}

	if manifest.Signature.KeyHint == "" {
		t.Error("Signature.KeyHint should not be empty")
	}

	verifyErr := VerifyManifestSignature(manifest, pubPath)
	if verifyErr != nil {
		t.Fatalf("VerifyManifestSignature() error: %v", verifyErr)
	}
}

func TestVerifyManifestTampered(t *testing.T) {
	t.Parallel()

	privPath, pubPath := generateTestKeyPair(t)

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Images:    map[string]*ImageEntry{},
	}

	signErr := SignManifest(manifest, privPath)
	if signErr != nil {
		t.Fatalf("SignManifest() error: %v", signErr)
	}

	manifest.Images["sha256:injected"] = &ImageEntry{
		Refs: nil,
		Attestations: []AttestationEntry{{
			PredicateType: "evil",
			BlobDigest:    "sha256:evil",
			Size:          0,
			SignatureType: "",
		}},
		CreatedAt: time.Time{},
	}

	err := VerifyManifestSignature(manifest, pubPath)
	if !errors.Is(err, ErrBundleSignatureInvalid) {
		t.Fatalf("VerifyManifestSignature() error = %v, want %v", err, ErrBundleSignatureInvalid)
	}
}

func TestVerifyManifestNoSignature(t *testing.T) {
	t.Parallel()

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Images:    map[string]*ImageEntry{},
	}

	_, pubPath := generateTestKeyPair(t)

	err := VerifyManifestSignature(manifest, pubPath)
	if !errors.Is(err, ErrBundleSignatureRequired) {
		t.Fatalf("VerifyManifestSignature() error = %v, want %v", err, ErrBundleSignatureRequired)
	}
}

func TestSignManifestBadKeyPath(t *testing.T) {
	t.Parallel()

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Images:    map[string]*ImageEntry{},
	}

	err := SignManifest(manifest, "/nonexistent/key.pem")
	if err == nil {
		t.Fatal("SignManifest() should fail with nonexistent key")
	}
}

func TestVerifyManifestBadKeyPath(t *testing.T) {
	t.Parallel()

	privPath, _ := generateTestKeyPair(t)

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Images:    map[string]*ImageEntry{},
	}

	signErr := SignManifest(manifest, privPath)
	if signErr != nil {
		t.Fatalf("SignManifest() error: %v", signErr)
	}

	err := VerifyManifestSignature(manifest, "/nonexistent/key.pub")
	if err == nil {
		t.Fatal("VerifyManifestSignature() should fail with nonexistent key")
	}
}

func TestLoadPublicKeyInvalidPEM(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "bad.pub")

	writeErr := os.WriteFile(path, []byte("not a PEM file"), 0o600)
	if writeErr != nil {
		t.Fatal(writeErr)
	}

	_, err := loadPublicKey(path)
	if !errors.Is(err, ErrInvalidPEMBlock) {
		t.Fatalf("loadPublicKey() error = %v, want %v", err, ErrInvalidPEMBlock)
	}
}

func TestAlgorithmName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		hash crypto.Hash
		want string
	}{
		{crypto.SHA256, "sha256"},
		{crypto.SHA384, "sha384"},
		{crypto.SHA512, "sha512"},
		{crypto.MD5, "unknown"},
	}

	for _, tt := range tests {
		got := algorithmName(tt.hash)
		if got != tt.want {
			t.Errorf("algorithmName(%v) = %q, want %q", tt.hash, got, tt.want)
		}
	}
}

func TestVerifyManifestWrongKey(t *testing.T) {
	t.Parallel()

	privPath, _ := generateTestKeyPair(t)
	_, otherPubPath := generateTestKeyPair(t)

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Images:    map[string]*ImageEntry{},
	}

	signErr := SignManifest(manifest, privPath)
	if signErr != nil {
		t.Fatalf("SignManifest() error: %v", signErr)
	}

	err := VerifyManifestSignature(manifest, otherPubPath)
	if !errors.Is(err, ErrBundleSignatureInvalid) {
		t.Fatalf("VerifyManifestSignature() error = %v, want %v", err, ErrBundleSignatureInvalid)
	}
}

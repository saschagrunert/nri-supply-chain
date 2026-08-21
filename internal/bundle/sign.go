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

package bundle

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/saschagrunert/nri-supply-chain/internal/fileutil"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

// SignManifest signs the bundle manifest in place using the private key at keyPath.
func SignManifest(manifest *Manifest, keyPath string) error {
	signer, err := loadSignerWithKeyHash(keyPath)
	if err != nil {
		return fmt.Errorf("loading signing key: %w", err)
	}

	canonical, err := MarshalManifestForSigning(manifest)
	if err != nil {
		return fmt.Errorf("marshaling manifest for signing: %w", err)
	}

	sig, err := signer.SignMessage(bytes.NewReader(canonical))
	if err != nil {
		return fmt.Errorf("signing manifest: %w", err)
	}

	pubKey, err := signer.PublicKey()
	if err != nil {
		return fmt.Errorf("getting public key: %w", err)
	}

	keyHint, err := computePublicKeyHint(pubKey)
	if err != nil {
		return fmt.Errorf("computing key hint: %w", err)
	}

	hashAlg := types.HashAlgorithmForKey(pubKey)

	manifest.Signature = &ManifestSignature{
		Algorithm: algorithmName(hashAlg),
		Value:     base64.StdEncoding.EncodeToString(sig),
		KeyHint:   keyHint,
	}

	return nil
}

//nolint:ireturn // wraps sigstore signer
func loadSignerWithKeyHash(keyPath string) (signature.Signer, error) {
	data, err := fileutil.ReadLimited(keyPath, fileutil.MaxCredentialFileSize)
	if err != nil {
		return nil, fmt.Errorf("reading signing key file: %w", err)
	}

	priv, err := cryptoutils.UnmarshalPEMToPrivateKey(data, nil)
	if err != nil {
		return nil, fmt.Errorf("parsing signing key: %w", err)
	}

	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, ErrUnsupportedKeyType
	}

	hashAlg := types.HashAlgorithmForKey(signer.Public())

	s, loadErr := signature.LoadSigner(priv, hashAlg)
	if loadErr != nil {
		return nil, fmt.Errorf("loading signer: %w", loadErr)
	}

	return s, nil
}

// VerifyManifestSignature verifies the bundle manifest signature using the
// public key at keyPath.
func VerifyManifestSignature(manifest *Manifest, keyPath string) error {
	if manifest.Signature == nil {
		return ErrBundleSignatureRequired
	}

	pubKey, err := loadPublicKey(keyPath)
	if err != nil {
		return fmt.Errorf("loading verification key: %w", err)
	}

	hashAlg := types.HashAlgorithmForKey(pubKey)

	verifier, err := signature.LoadVerifier(pubKey, hashAlg)
	if err != nil {
		return fmt.Errorf("creating verifier: %w", err)
	}

	canonical, err := MarshalManifestForSigning(manifest)
	if err != nil {
		return fmt.Errorf("marshaling manifest for verification: %w", err)
	}

	sigBytes, err := base64.StdEncoding.DecodeString(manifest.Signature.Value)
	if err != nil {
		return fmt.Errorf("%w: invalid base64: %w", ErrBundleSignatureInvalid, err)
	}

	verifyErr := verifier.VerifySignature(
		bytes.NewReader(sigBytes),
		bytes.NewReader(canonical),
	)
	if verifyErr != nil {
		return fmt.Errorf("%w: %w", ErrBundleSignatureInvalid, verifyErr)
	}

	return nil
}

func loadPublicKey(path string) (crypto.PublicKey, error) {
	data, err := fileutil.ReadLimited(path, fileutil.MaxCredentialFileSize)
	if err != nil {
		return nil, fmt.Errorf("reading public key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidPEMBlock, path)
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}

	return pub, nil
}

func computePublicKeyHint(pubKey crypto.PublicKey) (string, error) {
	derBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", fmt.Errorf("marshaling public key: %w", err)
	}

	h := sha256.Sum256(derBytes)

	return hex.EncodeToString(h[:]), nil
}

const algorithmSHA256 = "sha256"

func algorithmName(h crypto.Hash) string {
	switch h { //nolint:exhaustive // only SHA-2 family is relevant for signing
	case crypto.SHA256:
		return algorithmSHA256
	case crypto.SHA384:
		return "sha384"
	case crypto.SHA512:
		return "sha512"
	default:
		return "unknown"
	}
}

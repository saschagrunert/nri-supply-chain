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

package attestation

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"

	"github.com/saschagrunert/nri-supply-chain/internal/fileutil"
)

// ErrNoPEMBlock indicates a public key file contains no PEM block.
var ErrNoPEMBlock = errors.New("no PEM block found")

var pemKeyCache sync.Map //nolint:gochecknoglobals // per-process key cache

// ResetPEMKeyCache clears cached PEM public keys so that rotated keys on disk
// are re-read on the next verification cycle. Call this after a config reload
// when policies have changed.
func ResetPEMKeyCache() {
	pemKeyCache.Clear()
}

// LoadPublicKey reads a PEM encoded public key in PKIX ("PUBLIC KEY") or
// PKCS #1 ("RSA PUBLIC KEY") form. Parsed keys are cached by path and file
// content, so a rotated key file is picked up on the next call.
func LoadPublicKey(path string) (crypto.PublicKey, error) {
	data, err := fileutil.ReadLimited(path, fileutil.MaxCredentialFileSize)
	if err != nil {
		return nil, fmt.Errorf("reading PEM file: %w", err)
	}

	contentHash := sha256.Sum256(data)
	cacheKey := path + "\x00" + hex.EncodeToString(contentHash[:])

	if cached, ok := pemKeyCache.Load(cacheKey); ok {
		key, castOK := cached.(crypto.PublicKey)
		if !castOK {
			pemKeyCache.Delete(cacheKey)
		} else {
			return key, nil
		}
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%w in %q", ErrNoPEMBlock, path)
	}

	pub, pkixErr := x509.ParsePKIXPublicKey(block.Bytes)
	if pkixErr == nil {
		pemKeyCache.Store(cacheKey, pub)

		return pub, nil
	}

	rsaKey, rsaErr := x509.ParsePKCS1PublicKey(block.Bytes)
	if rsaErr == nil {
		pemKeyCache.Store(cacheKey, rsaKey)

		return rsaKey, nil
	}

	return nil, fmt.Errorf("parsing public key: %w", pkixErr)
}

// PublicKeyDigest returns the SHA-256 digest of the PKIX DER encoding of pub,
// the fingerprint that key hints are derived from.
func PublicKeyDigest(pub crypto.PublicKey) ([sha256.Size]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("marshaling public key to PKIX: %w", err)
	}

	return sha256.Sum256(der), nil
}

// computeKeyHint returns the Sigstore bundle key hint of pub: the base64
// encoded public key digest.
func computeKeyHint(pub crypto.PublicKey) (string, error) {
	sum, err := PublicKeyDigest(pub)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(sum[:]), nil
}

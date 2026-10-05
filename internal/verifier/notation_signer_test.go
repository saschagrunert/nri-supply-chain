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

package verifier_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/signature/jws"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
)

const (
	notationPayloadContentType = "application/vnd.cncf.notary.payload.v1+json"
	notationSubjectSize        = 1234
)

// notationSigner holds a root CA in a PEM file and a code signing leaf
// certificate issued by it.
type notationSigner struct {
	rootPath string
	leaf     *x509.Certificate
	root     *x509.Certificate
	key      *ecdsa.PrivateKey
}

func newNotationSigner(t *testing.T) *notationSigner {
	t.Helper()

	now := time.Now()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test root", Organization: []string{"test"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	rootDER, err := x509.CreateCertificate(
		rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey,
	)
	if err != nil {
		t.Fatal(err)
	}

	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test signer", Organization: []string{"test"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}

	leafDER, err := x509.CreateCertificate(
		rand.Reader, leafTemplate, root, &leafKey.PublicKey, rootKey,
	)
	if err != nil {
		t.Fatal(err)
	}

	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	rootPath := filepath.Join(t.TempDir(), "root.pem")

	err = os.WriteFile(rootPath,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	return &notationSigner{rootPath: rootPath, leaf: leaf, root: root, key: leafKey}
}

// sign returns a Notation JWS signature over the image manifest digest, the
// way the attestation fetcher returns it.
func (s *notationSigner) sign(t *testing.T, digest string) attestation.VerifiedAttestation {
	t.Helper()

	payload, err := json.Marshal(map[string]any{
		"targetArtifact": map[string]any{
			"mediaType": ocispec.MediaTypeImageManifest,
			"digest":    digest,
			"size":      notationSubjectSize,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	localSigner, err := signature.NewLocalSigner([]*x509.Certificate{s.leaf, s.root}, s.key)
	if err != nil {
		t.Fatal(err)
	}

	envelope, err := signature.NewEnvelope(jws.MediaTypeEnvelope)
	if err != nil {
		t.Fatal(err)
	}

	sig, err := envelope.Sign(&signature.SignRequest{
		Payload:       signature.Payload{ContentType: notationPayloadContentType, Content: payload},
		Signer:        localSigner,
		SigningTime:   time.Now(),
		SigningScheme: signature.SigningSchemeX509,
		SigningAgent:  "nri-supply-chain-test",

		Expiry:                   time.Time{},
		ExtendedSignedAttributes: nil,
		Timestamper:              nil,
		TSARootCAs:               nil,
		TSARevocationValidator:   nil,
	})
	if err != nil {
		t.Fatal(err)
	}

	return attestation.VerifiedAttestation{
		PredicateType:            attestation.NotationSignatureMediaType,
		SignatureType:            attestation.SignatureTypeNotation,
		Payload:                  sig,
		Digest:                   digest,
		NotationMediaType:        jws.MediaTypeEnvelope,
		NotationSubjectDigest:    digest,
		NotationSubjectSize:      notationSubjectSize,
		NotationSubjectMediaType: ocispec.MediaTypeImageManifest,
		Signer: attestation.SignerIdentity{
			KeyPath: "", KeyPaths: nil, Issuer: "", SAN: "",
		},
	}
}

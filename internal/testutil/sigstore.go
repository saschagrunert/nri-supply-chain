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

package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/tlog"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	// SigstoreBundleMediaType is the Sigstore bundle v0.3 media type.
	SigstoreBundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"
	// SigstoreBundleMediaTypeV01 is the Sigstore bundle v0.1 media type, used for
	// bundles whose log entries carry only an inclusion promise.
	SigstoreBundleMediaTypeV01 = "application/vnd.dev.sigstore.bundle+json;version=0.1"
	// InTotoPayloadType is the DSSE payload type for in-toto statements.
	InTotoPayloadType = "application/vnd.in-toto+json"

	testFileMode = 0o600

	envelopeSignaturesKey = "signatures"
)

// KeySigner is an ECDSA P-256 key pair that signs DSSE envelopes into
// key-based Sigstore bundles for tests.
type KeySigner struct {
	// Private is the signing key.
	Private *ecdsa.PrivateKey
	// PublicKeyPath is a PEM file containing the public key.
	PublicKeyPath string
	// Hint is the Sigstore key hint (base64 SHA-256 of the PKIX public key).
	Hint string
	// PublicKeyPEM is the PEM encoded public key.
	PublicKeyPEM []byte
}

// NewKeySigner generates a key pair and writes the public key to a temporary
// PEM file.
func NewKeySigner(t *testing.T) *KeySigner {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating ECDSA key: %v", err)
	}

	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshaling public key: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Headers: nil, Bytes: der})
	path := filepath.Join(t.TempDir(), "key.pub")

	err = os.WriteFile(path, pemBytes, testFileMode)
	if err != nil {
		t.Fatalf("writing public key: %v", err)
	}

	sum := sha256.Sum256(der)

	return &KeySigner{
		Private:       priv,
		PublicKeyPath: path,
		Hint:          base64.StdEncoding.EncodeToString(sum[:]),
		PublicKeyPEM:  pemBytes,
	}
}

// Statement returns an in-toto v1 statement bound to digest.
func Statement(t *testing.T, digest, predicateType string, predicate any) []byte {
	t.Helper()

	return WrapInToto(t, predicate, digest, predicateType)
}

// SignBundle signs payload as a DSSE in-toto envelope and returns key-based
// Sigstore bundle JSON without transparency log entries.
func (s *KeySigner) SignBundle(t *testing.T, payload []byte) []byte {
	t.Helper()

	envelope, _ := s.signEnvelope(t, payload)

	return marshalBundle(t, &protobundle.Bundle{
		MediaType: SigstoreBundleMediaType,
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_PublicKey{
				PublicKey: &protocommon.PublicKeyIdentifier{Hint: s.Hint},
			},
			TlogEntries:               nil,
			TimestampVerificationData: nil,
		},
		Content: &protobundle.Bundle_DsseEnvelope{DsseEnvelope: envelope},
	})
}

// SignBundleWithTlog signs payload and returns key-based Sigstore bundle JSON
// with a Rekor v1 dsse entry (and inclusion promise) logged at integratedTime
// in the virtual Sigstore instance.
func (s *KeySigner) SignBundleWithTlog(
	t *testing.T, virtual *ca.VirtualSigstore, payload []byte, integratedTime time.Time,
) []byte {
	t.Helper()

	envelope, sig := s.signEnvelope(t, payload)

	envelopeJSON, err := json.Marshal(map[string]any{
		"payloadType": envelope.GetPayloadType(),
		"payload":     base64.StdEncoding.EncodeToString(envelope.GetPayload()),
		envelopeSignaturesKey: []map[string]string{
			{"keyid": "", "sig": base64.StdEncoding.EncodeToString(sig)},
		},
	})
	if err != nil {
		t.Fatalf("marshaling envelope: %v", err)
	}

	body := dsseRekorBody(t, envelopeJSON, envelope.GetPayload(), sig, s.PublicKeyPEM)
	entry := logEntry(t, virtual, body, integratedTime)

	return marshalBundle(t, &protobundle.Bundle{
		MediaType: SigstoreBundleMediaTypeV01,
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_PublicKey{
				PublicKey: &protocommon.PublicKeyIdentifier{Hint: s.Hint},
			},
			TlogEntries:               []*protorekor.TransparencyLogEntry{entry},
			TimestampVerificationData: nil,
		},
		Content: &protobundle.Bundle_DsseEnvelope{DsseEnvelope: envelope},
	})
}

func (s *KeySigner) signEnvelope(
	t *testing.T, payload []byte,
) (envelope *protodsse.Envelope, sig []byte) {
	t.Helper()

	digest := sha256.Sum256(pae(InTotoPayloadType, payload))

	sig, err := ecdsa.SignASN1(rand.Reader, s.Private, digest[:])
	if err != nil {
		t.Fatalf("signing envelope: %v", err)
	}

	envelope = &protodsse.Envelope{
		Payload:     payload,
		PayloadType: InTotoPayloadType,
		Signatures:  []*protodsse.Signature{{Sig: sig, Keyid: ""}},
	}

	return envelope, sig
}

// NewVirtualSigstore creates an in-memory Sigstore instance (Fulcio, Rekor,
// TSA) for tests.
func NewVirtualSigstore(t *testing.T) *ca.VirtualSigstore {
	t.Helper()

	virtual, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("creating virtual sigstore: %v", err)
	}

	return virtual
}

// VirtualTrustedRoot returns the trusted root of a virtual Sigstore instance.
func VirtualTrustedRoot(t *testing.T, virtual *ca.VirtualSigstore) *root.TrustedRoot {
	t.Helper()

	trustedRoot, err := root.NewTrustedRoot(
		root.TrustedRootMediaType01,
		virtual.FulcioCertificateAuthorities(),
		virtual.CTLogs(),
		virtual.TimestampingAuthorities(),
		virtual.RekorLogs(),
	)
	if err != nil {
		t.Fatalf("creating trusted root: %v", err)
	}

	return trustedRoot
}

// KeylessBundle signs payload with a Fulcio certificate for identity and
// issuer from the virtual Sigstore instance and returns Sigstore bundle JSON
// with a transparency log entry. The certificate carries no SCTs.
func KeylessBundle(
	t *testing.T, virtual *ca.VirtualSigstore, identity, issuer string, payload []byte,
) []byte {
	t.Helper()

	entity, err := virtual.AttestAtTime(
		identity,
		issuer,
		payload,
		time.Now().Add(time.Minute),
		false,
	)
	if err != nil {
		t.Fatalf("attesting payload: %v", err)
	}

	verificationContent, err := entity.VerificationContent()
	if err != nil {
		t.Fatalf("reading verification content: %v", err)
	}

	signatureContent, err := entity.SignatureContent()
	if err != nil {
		t.Fatalf("reading signature content: %v", err)
	}

	rawEnvelope := signatureContent.EnvelopeContent().RawEnvelope()
	signatures := make([]*protodsse.Signature, 0, len(rawEnvelope.Signatures))

	for _, sig := range rawEnvelope.Signatures {
		signatures = append(
			signatures,
			&protodsse.Signature{Sig: decodeBase64(t, sig.Sig), Keyid: sig.KeyID},
		)
	}

	entries, err := entity.TlogEntries()
	if err != nil || len(entries) == 0 {
		t.Fatalf("reading tlog entries: %v", err)
	}

	tle := entries[0].TransparencyLogEntry()
	entry := logEntry(t, virtual, tle.GetCanonicalizedBody(), time.Unix(tle.GetIntegratedTime(), 0))

	return marshalBundle(t, &protobundle.Bundle{
		MediaType: SigstoreBundleMediaTypeV01,
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_Certificate{
				Certificate: &protocommon.X509Certificate{
					RawBytes: verificationContent.Certificate().Raw,
				},
			},
			TlogEntries:               []*protorekor.TransparencyLogEntry{entry},
			TimestampVerificationData: nil,
		},
		Content: &protobundle.Bundle_DsseEnvelope{DsseEnvelope: &protodsse.Envelope{
			Payload:     payload,
			PayloadType: rawEnvelope.PayloadType,
			Signatures:  signatures,
		}},
	})
}

// logEntry signs body into a Rekor v1 transparency log entry with an
// inclusion promise from the virtual Rekor instance.
func logEntry(
	t *testing.T, virtual *ca.VirtualSigstore, body []byte, integratedTime time.Time,
) *protorekor.TransparencyLogEntry {
	t.Helper()

	logIDHex, err := virtual.RekorLogID()
	if err != nil {
		t.Fatalf("reading rekor log ID: %v", err)
	}

	logID, err := hex.DecodeString(logIDHex)
	if err != nil {
		t.Fatalf("decoding rekor log ID: %v", err)
	}

	set, err := virtual.RekorSignPayload(tlog.RekorPayload{
		Body:           base64.StdEncoding.EncodeToString(body),
		IntegratedTime: integratedTime.Unix(),
		LogIndex:       0,
		LogID:          logIDHex,
	})
	if err != nil {
		t.Fatalf("signing rekor payload: %v", err)
	}

	var kindVersion struct {
		Kind       string `json:"kind"`
		APIVersion string `json:"apiVersion"`
	}

	err = json.Unmarshal(body, &kindVersion)
	if err != nil {
		t.Fatalf("decoding rekor body: %v", err)
	}

	return &protorekor.TransparencyLogEntry{
		LogIndex: 0,
		LogId:    &protocommon.LogId{KeyId: logID},
		KindVersion: &protorekor.KindVersion{
			Kind:    kindVersion.Kind,
			Version: kindVersion.APIVersion,
		},
		IntegratedTime:    integratedTime.Unix(),
		InclusionPromise:  &protorekor.InclusionPromise{SignedEntryTimestamp: set},
		InclusionProof:    nil,
		CanonicalizedBody: body,
	}
}

// dsseRekorBody builds the canonicalized body of a Rekor dsse v0.0.1 entry.
func dsseRekorBody(t *testing.T, envelopeJSON, payload, sig, verifierPEM []byte) []byte {
	t.Helper()

	envelopeHash := sha256.Sum256(envelopeJSON)
	payloadHash := sha256.Sum256(payload)

	body, err := json.Marshal(map[string]any{
		"apiVersion": "0.0.1",
		"kind":       "dsse",
		"spec": map[string]any{
			"envelopeHash": map[string]string{
				"algorithm": "sha256",
				"value":     hex.EncodeToString(envelopeHash[:]),
			},
			"payloadHash": map[string]string{
				"algorithm": "sha256",
				"value":     hex.EncodeToString(payloadHash[:]),
			},
			envelopeSignaturesKey: []map[string]string{{
				"signature": base64.StdEncoding.EncodeToString(sig),
				"verifier":  base64.StdEncoding.EncodeToString(verifierPEM),
			}},
		},
	})
	if err != nil {
		t.Fatalf("marshaling rekor body: %v", err)
	}

	return body
}

// LegacyCosignLayer converts Sigstore bundle JSON with a DSSE envelope into a
// legacy cosign attestation layer (the DSSE envelope JSON) plus the layer
// annotations cosign uses for the signing material.
func LegacyCosignLayer(
	t *testing.T, bundleJSON []byte,
) (layer []byte, annotations map[string]string) {
	t.Helper()

	var protoBundle protobundle.Bundle

	err := protojson.Unmarshal(bundleJSON, &protoBundle)
	if err != nil {
		t.Fatalf("parsing bundle: %v", err)
	}

	envelope := protoBundle.GetDsseEnvelope()
	layer = MustMarshal(t, map[string]any{
		"payloadType": envelope.GetPayloadType(),
		"payload":     envelope.GetPayload(),
		envelopeSignaturesKey: []map[string]any{{
			"keyid": envelope.GetSignatures()[0].GetKeyid(),
			"sig":   envelope.GetSignatures()[0].GetSig(),
		}},
	})

	annotations = map[string]string{}

	if cert := protoBundle.GetVerificationMaterial().GetCertificate(); cert != nil {
		annotations["dev.sigstore.cosign/certificate"] = string(pem.EncodeToMemory(
			&pem.Block{Type: "CERTIFICATE", Headers: nil, Bytes: cert.GetRawBytes()},
		))
	}

	if entries := protoBundle.GetVerificationMaterial().GetTlogEntries(); len(entries) > 0 {
		entry := entries[0]
		annotations["dev.sigstore.cosign/bundle"] = string(MustMarshal(t, map[string]any{
			"SignedEntryTimestamp": entry.GetInclusionPromise().GetSignedEntryTimestamp(),
			"Payload": map[string]any{
				"body":           base64.StdEncoding.EncodeToString(entry.GetCanonicalizedBody()),
				"integratedTime": entry.GetIntegratedTime(),
				"logIndex":       entry.GetLogIndex(),
				"logID":          hex.EncodeToString(entry.GetLogId().GetKeyId()),
			},
		}))
	}

	return layer, annotations
}

func marshalBundle(t *testing.T, protoBundle *protobundle.Bundle) []byte {
	t.Helper()

	data, err := protojson.Marshal(protoBundle)
	if err != nil {
		t.Fatalf("marshaling bundle: %v", err)
	}

	return data
}

func decodeBase64(t *testing.T, value string) []byte {
	t.Helper()

	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("decoding base64: %v", err)
	}

	return data
}

// pae returns the DSSE v1 pre-authentication encoding.
func pae(payloadType string, payload []byte) []byte {
	var builder strings.Builder

	_, _ = fmt.Fprintf(&builder, "DSSEv1 %d %s %d ", len(payloadType), payloadType, len(payload))
	builder.Write(payload)

	return []byte(builder.String())
}

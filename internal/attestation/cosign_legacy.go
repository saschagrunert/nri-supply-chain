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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	// cosignAnnotationCertificate holds the PEM signing certificate of a
	// legacy cosign attestation layer.
	cosignAnnotationCertificate = "dev.sigstore.cosign/certificate"
	// cosignAnnotationBundle holds the Rekor SignedEntryTimestamp bundle of a
	// legacy cosign attestation layer.
	cosignAnnotationBundle = "dev.sigstore.cosign/bundle"
	// cosignAnnotationTimestamp holds the RFC 3161 timestamp of a legacy
	// cosign attestation layer.
	cosignAnnotationTimestamp = "dev.sigstore.cosign/rfc3161timestamp"
)

var (
	errLegacyEnvelope    = errors.New("invalid legacy cosign DSSE envelope")
	errLegacyCertificate = errors.New("invalid legacy cosign certificate annotation")
	errLegacyRekorBundle = errors.New("invalid legacy cosign rekor bundle annotation")

	// errNoLegacyVerificationMaterial reports a legacy cosign layer that
	// cannot be verified: it carries no certificate annotation and no
	// trusted key is configured to check its signature.
	errNoLegacyVerificationMaterial = fmt.Errorf(
		"%w: no certificate annotation and no trusted keys to verify legacy cosign attestation",
		errNoTrustedMaterial,
	)

	errNoCosignCandidates = errors.New("cosign attestation layer produced no bundle to verify")
)

// legacyRekorBundle is the JSON document cosign stores in the
// dev.sigstore.cosign/bundle annotation.
type legacyRekorBundle struct {
	//nolint:tagliatelle // cosign annotation format
	SignedEntryTimestamp []byte `json:"SignedEntryTimestamp"`
	//nolint:tagliatelle // cosign annotation format
	Payload legacyRekorPayload `json:"Payload"`
}

type legacyRekorPayload struct {
	Body           string `json:"body"`
	IntegratedTime int64  `json:"integratedTime"`
	LogIndex       int64  `json:"logIndex"`
	LogID          string `json:"logID"`
}

type legacyTimestamp struct {
	//nolint:tagliatelle // cosign annotation format
	SignedRFC3161Timestamp []byte `json:"SignedRFC3161Timestamp"`
}

type legacyEnvelope struct {
	PayloadType string                    `json:"payloadType"`
	Payload     []byte                    `json:"payload"`
	Signatures  []legacyEnvelopeSignature `json:"signatures"`
}

type legacyEnvelopeSignature struct {
	KeyID string `json:"keyid"`
	Sig   []byte `json:"sig"`
}

type rekorKindVersion struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"apiVersion"`
}

// legacyLayerToBundles converts a legacy cosign attestation layer (a DSSE
// envelope with signing material in layer annotations) into Sigstore bundle
// JSON documents that can be verified like any other bundle. Certificate
// signed layers produce a single bundle. Key signed layers carry no key hint,
// so one candidate bundle is produced per trusted key hint.
func legacyLayerToBundles(
	envelopeJSON []byte, annotations map[string]string, keyHints []string,
) ([][]byte, error) {
	envelope, err := parseLegacyEnvelope(envelopeJSON)
	if err != nil {
		return nil, err
	}

	tlogEntries, err := legacyTlogEntries(annotations[cosignAnnotationBundle])
	if err != nil {
		return nil, err
	}

	timestamps, err := legacyTimestamps(annotations[cosignAnnotationTimestamp])
	if err != nil {
		return nil, err
	}

	materials, err := legacyVerificationMaterials(
		annotations[cosignAnnotationCertificate],
		keyHints,
	)
	if err != nil {
		return nil, err
	}

	bundles := make([][]byte, 0, len(materials))

	for _, material := range materials {
		material.TlogEntries = tlogEntries
		material.TimestampVerificationData = timestamps

		protoBundle := &protobundle.Bundle{
			MediaType:            legacyBundleMediaType(tlogEntries),
			VerificationMaterial: material,
			Content:              &protobundle.Bundle_DsseEnvelope{DsseEnvelope: envelope},
		}

		data, marshalErr := protojson.Marshal(protoBundle)
		if marshalErr != nil {
			return nil, fmt.Errorf("marshaling converted bundle: %w", marshalErr)
		}

		bundles = append(bundles, data)
	}

	return bundles, nil
}

// legacyBundleMediaType picks the bundle version for converted layers. Legacy
// cosign layers carry a signed entry timestamp (inclusion promise) but no
// inclusion proof, which only bundle v0.1 accepts.
func legacyBundleMediaType(entries []*protorekor.TransparencyLogEntry) string {
	if len(entries) > 0 {
		return bundleMediaTypeV01
	}

	return bundleMediaType
}

func parseLegacyEnvelope(data []byte) (*protodsse.Envelope, error) {
	var envelope legacyEnvelope

	err := json.Unmarshal(data, &envelope)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errLegacyEnvelope, err)
	}

	if envelope.PayloadType == "" || len(envelope.Payload) == 0 || len(envelope.Signatures) == 0 {
		return nil, fmt.Errorf(
			"%w: missing payload type, payload, or signatures",
			errLegacyEnvelope,
		)
	}

	signatures := make([]*protodsse.Signature, 0, len(envelope.Signatures))
	for _, sig := range envelope.Signatures {
		signatures = append(signatures, &protodsse.Signature{Sig: sig.Sig, Keyid: sig.KeyID})
	}

	return &protodsse.Envelope{
		Payload:     envelope.Payload,
		PayloadType: envelope.PayloadType,
		Signatures:  signatures,
	}, nil
}

func legacyVerificationMaterials(
	certPEM string, keyHints []string,
) ([]*protobundle.VerificationMaterial, error) {
	if certPEM == "" {
		if len(keyHints) == 0 {
			return nil, errNoLegacyVerificationMaterial
		}

		materials := make([]*protobundle.VerificationMaterial, 0, len(keyHints))

		for _, hint := range keyHints {
			materials = append(materials, &protobundle.VerificationMaterial{
				Content: &protobundle.VerificationMaterial_PublicKey{
					PublicKey: &protocommon.PublicKeyIdentifier{Hint: hint},
				},
				TlogEntries:               nil,
				TimestampVerificationData: nil,
			})
		}

		return materials, nil
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("%w: no PEM block", errLegacyCertificate)
	}

	return []*protobundle.VerificationMaterial{{
		Content: &protobundle.VerificationMaterial_Certificate{
			Certificate: &protocommon.X509Certificate{RawBytes: block.Bytes},
		},
		TlogEntries:               nil,
		TimestampVerificationData: nil,
	}}, nil
}

func legacyTlogEntries(annotation string) ([]*protorekor.TransparencyLogEntry, error) {
	if annotation == "" {
		return nil, nil
	}

	var rekorBundle legacyRekorBundle

	err := json.Unmarshal([]byte(annotation), &rekorBundle)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errLegacyRekorBundle, err)
	}

	body, err := base64.StdEncoding.DecodeString(rekorBundle.Payload.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: decoding body: %w", errLegacyRekorBundle, err)
	}

	logID, err := hex.DecodeString(rekorBundle.Payload.LogID)
	if err != nil {
		return nil, fmt.Errorf("%w: decoding log ID: %w", errLegacyRekorBundle, err)
	}

	var kindVersion rekorKindVersion

	err = json.Unmarshal(body, &kindVersion)
	if err != nil || kindVersion.Kind == "" || kindVersion.APIVersion == "" {
		return nil, fmt.Errorf("%w: body has no kind or apiVersion", errLegacyRekorBundle)
	}

	return []*protorekor.TransparencyLogEntry{
		{
			LogIndex: rekorBundle.Payload.LogIndex,
			LogId:    &protocommon.LogId{KeyId: logID},
			KindVersion: &protorekor.KindVersion{
				Kind:    kindVersion.Kind,
				Version: kindVersion.APIVersion,
			},
			IntegratedTime: rekorBundle.Payload.IntegratedTime,
			InclusionPromise: &protorekor.InclusionPromise{
				SignedEntryTimestamp: rekorBundle.SignedEntryTimestamp,
			},
			InclusionProof:    nil,
			CanonicalizedBody: body,
		},
	}, nil
}

func legacyTimestamps(annotation string) (*protobundle.TimestampVerificationData, error) {
	if annotation == "" {
		return nil, nil //nolint:nilnil // absent timestamps are valid
	}

	var timestamp legacyTimestamp

	err := json.Unmarshal([]byte(annotation), &timestamp)
	if err != nil {
		return nil, fmt.Errorf("decoding legacy cosign timestamp annotation: %w", err)
	}

	return &protobundle.TimestampVerificationData{
		Rfc3161Timestamps: []*protocommon.RFC3161SignedTimestamp{
			{SignedTimestamp: timestamp.SignedRFC3161Timestamp},
		},
	}, nil
}

// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package plugin

// GenerateSignatureRequest contains the parameters passed in a
// generate-signature request.
type GenerateSignatureRequest struct {
	ContractVersion string            `json:"contractVersion"`
	KeyID           string            `json:"keyId"`
	KeySpec         KeySpec           `json:"keySpec"`
	Hash            HashAlgorithm     `json:"hashAlgorithm"`
	Payload         []byte            `json:"payload"`
	PluginConfig    map[string]string `json:"pluginConfig,omitempty"`
}

func (GenerateSignatureRequest) Command() Command {
	return CommandGenerateSignature
}

// Validate validates GenerateSignatureRequest struct
func (r GenerateSignatureRequest) Validate() error {
	if r.ContractVersion == "" {
		return NewValidationError("contractVersion cannot be empty")
	}

	if r.KeyID == "" {
		return NewValidationError("keyId cannot be empty")
	}

	if r.KeySpec == "" {
		return NewValidationError("keySpec cannot be empty")
	}

	if r.Hash == "" {
		return NewValidationError("hashAlgorithm cannot be empty")
	}

	if len(r.Payload) == 0 {
		return NewValidationError("payload cannot be empty")
	}

	return nil
}

// GenerateSignatureResponse is the response of a generate-signature request.
type GenerateSignatureResponse struct {
	KeyID            string             `json:"keyId"`
	Signature        []byte             `json:"signature"`
	SigningAlgorithm SignatureAlgorithm `json:"signingAlgorithm"`

	// Ordered list of certificates starting with leaf certificate
	// and ending with root certificate.
	CertificateChain [][]byte `json:"certificateChain"`
}

// GenerateEnvelopeRequest contains the parameters passed in a generate-envelope
// request.
type GenerateEnvelopeRequest struct {
	ContractVersion         string            `json:"contractVersion"`
	KeyID                   string            `json:"keyId"`
	PayloadType             string            `json:"payloadType"`
	SignatureEnvelopeType   string            `json:"signatureEnvelopeType"`
	Payload                 []byte            `json:"payload"`
	ExpiryDurationInSeconds uint64            `json:"expiryDurationInSeconds,omitempty"`
	PluginConfig            map[string]string `json:"pluginConfig,omitempty"`
}

func (GenerateEnvelopeRequest) Command() Command {
	return CommandGenerateEnvelope
}

// Validate validates GenerateEnvelopeRequest struct
func (r GenerateEnvelopeRequest) Validate() error {
	if r.ContractVersion == "" {
		return NewValidationError("contractVersion cannot be empty")
	}

	if r.KeyID == "" {
		return NewValidationError("keyId cannot be empty")
	}

	if r.PayloadType == "" {
		return NewValidationError("payloadType cannot be empty")
	}

	if r.SignatureEnvelopeType == "" {
		return NewValidationError("signatureEnvelopeType cannot be empty")
	}

	if len(r.Payload) == 0 {
		return NewValidationError("payload cannot be empty")
	}

	return nil
}

// GenerateEnvelopeResponse is the response of a generate-envelope request.
type GenerateEnvelopeResponse struct {
	SignatureEnvelope     []byte            `json:"signatureEnvelope"`
	SignatureEnvelopeType string            `json:"signatureEnvelopeType"`
	Annotations           map[string]string `json:"annotations,omitempty"`
}

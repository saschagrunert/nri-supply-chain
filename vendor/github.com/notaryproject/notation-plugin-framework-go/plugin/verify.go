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

import (
	"reflect"
	"time"
)

// VerifySignatureRequest contains the parameters passed in a verify-signature
// request.
type VerifySignatureRequest struct {
	ContractVersion string            `json:"contractVersion"`
	Signature       Signature         `json:"signature"`
	TrustPolicy     TrustPolicy       `json:"trustPolicy"`
	PluginConfig    map[string]string `json:"pluginConfig,omitempty"`
}

func (VerifySignatureRequest) Command() Command {
	return CommandVerifySignature
}

// Validate validates VerifySignatureRequest struct
func (r VerifySignatureRequest) Validate() error {
	if r.ContractVersion == "" {
		return NewValidationError("contractVersion cannot be empty")
	}

	if reflect.DeepEqual(r.Signature, Signature{}) {
		return NewValidationError("signature cannot be empty")
	}

	if reflect.DeepEqual(r.Signature.CriticalAttributes, CriticalAttributes{}) {
		return NewValidationError("signature's criticalAttributes cannot be empty")
	}

	if r.Signature.CriticalAttributes.ContentType == "" {
		return NewValidationError("signature's criticalAttributes's contentType cannot be empty")
	}

	if r.Signature.CriticalAttributes.SigningScheme == "" {
		return NewValidationError("signature's criticalAttributes's signingScheme cannot be empty")
	}

	if len(r.Signature.CertificateChain) == 0 {
		return NewValidationError("signature's criticalAttributes's certificateChain cannot be empty")
	}

	if reflect.DeepEqual(r.TrustPolicy, TrustPolicy{}) {
		return NewValidationError("signature's trustPolicy cannot be empty")
	}

	if len(r.TrustPolicy.SignatureVerification) == 0 {
		return NewValidationError("signature's trustPolicy's signatureVerification cannot be empty")
	}

	return nil
}

// Signature represents a signature pulled from the envelope
type Signature struct {
	CriticalAttributes    CriticalAttributes `json:"criticalAttributes"`
	UnprocessedAttributes []string           `json:"unprocessedAttributes"`
	CertificateChain      [][]byte           `json:"certificateChain"`
}

// CriticalAttributes contains all critical attributes and
// their values in the signature envelope
type CriticalAttributes struct {
	ContentType          string                 `json:"contentType"`
	SigningScheme        string                 `json:"signingScheme"`
	Expiry               *time.Time             `json:"expiry,omitempty"`
	AuthenticSigningTime *time.Time             `json:"authenticSigningTime,omitempty"`
	ExtendedAttributes   map[string]interface{} `json:"extendedAttributes,omitempty"`
}

// TrustPolicy represents trusted identities that sign the artifacts
type TrustPolicy struct {
	TrustedIdentities     []string     `json:"trustedIdentities"`
	SignatureVerification []Capability `json:"signatureVerification"`
}

// VerifySignatureResponse is the response of a verify-signature request.
type VerifySignatureResponse struct {
	VerificationResults map[Capability]*VerificationResult `json:"verificationResults"`
	ProcessedAttributes []interface{}                      `json:"processedAttributes"`
}

// VerificationResult is the result of a verification performed by the plugin
type VerificationResult struct {
	Success bool   `json:"success"`
	Reason  string `json:"reason,omitempty"`
}

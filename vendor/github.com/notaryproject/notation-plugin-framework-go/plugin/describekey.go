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

// DescribeKeyRequest contains the parameters passed in a describe-key request.
type DescribeKeyRequest struct {
	ContractVersion string            `json:"contractVersion"`
	KeyID           string            `json:"keyId"`
	PluginConfig    map[string]string `json:"pluginConfig,omitempty"`
}

func (DescribeKeyRequest) Command() Command {
	return CommandDescribeKey
}

// Validate validates DescribeKeyRequest struct
func (r DescribeKeyRequest) Validate() error {
	if r.ContractVersion == "" {
		return NewValidationError("contractVersion cannot be empty")
	}

	if r.KeyID == "" {
		return NewValidationError("keyId cannot be empty")
	}

	return nil
}

// DescribeKeyResponse is the response of a describe-key request.
type DescribeKeyResponse struct {
	// The same key id as passed in the request.
	KeyID string `json:"keyId"`

	// One of following supported key types:
	// https://github.com/notaryproject/notaryproject/blob/main/specs/signature-specification.md#algorithm-selection
	KeySpec KeySpec `json:"keySpec"`
}

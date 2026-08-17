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

// Package plugin provides the tooling to use the notation plugin.
//
// includes a CLIManager and a CLIPlugin implementation.
package plugin

import (
	"context"
)

// GenericPlugin is the base requirement to be a plugin.
type GenericPlugin interface {
	// GetMetadata returns the metadata information of the plugin.
	GetMetadata(ctx context.Context, req *GetMetadataRequest) (*GetMetadataResponse, error)
}

// SignPlugin defines the required methods to be a SignPlugin.
type SignPlugin interface {
	GenericPlugin

	// DescribeKey returns the KeySpec of a key.
	DescribeKey(ctx context.Context, req *DescribeKeyRequest) (*DescribeKeyResponse, error)

	// GenerateSignature generates the raw signature based on the request.
	GenerateSignature(ctx context.Context, req *GenerateSignatureRequest) (*GenerateSignatureResponse, error)

	// GenerateEnvelope generates the Envelope with signature based on the
	// request.
	GenerateEnvelope(ctx context.Context, req *GenerateEnvelopeRequest) (*GenerateEnvelopeResponse, error)
}

// VerifyPlugin defines the required method to be a VerifyPlugin.
type VerifyPlugin interface {
	GenericPlugin

	// VerifySignature validates the signature based on the request.
	VerifySignature(ctx context.Context, req *VerifySignatureRequest) (*VerifySignatureResponse, error)
}

// Plugin defines required methods to be a Plugin.
type Plugin interface {
	SignPlugin
	VerifyPlugin
}

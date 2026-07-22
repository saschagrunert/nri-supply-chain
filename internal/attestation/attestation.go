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

// Package attestation provides types and interfaces for discovering and verifying
// supply chain attestations attached to container images.
package attestation

import (
	"context"
	"errors"
	"time"
)

var (
	errEmptyAttestation    = errors.New("empty attestation")
	errAttestationTooLarge = errors.New("attestation exceeds maximum size")
	errInvalidPayloadType  = errors.New("invalid DSSE payload type")
	errNoTrustedMaterial   = errors.New("no trusted keys or issuers configured")
	errAllBundlesFailed    = errors.New("all bundle verifications failed")
	errNoIssuers           = errors.New("at least one issuer is required")
)

const (
	// PredicateSLSAProvenanceV1 is the in-toto predicate type for SLSA provenance v1.
	PredicateSLSAProvenanceV1 = "https://slsa.dev/provenance/v1"

	// PredicateVSA is the in-toto predicate type for SLSA Verification Summary Attestations.
	PredicateVSA = "https://slsa.dev/verification_summary/v1"

	// PredicateOpenVEX is the in-toto predicate type for OpenVEX documents.
	PredicateOpenVEX = "https://openvex.dev/ns"

	// BundleMediaType is the OCI artifact type for Sigstore bundles.
	BundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"

	// OCIEmptyMediaType is the fallback artifact type some registries
	// (notably GHCR) return for cosign-created attestations instead of
	// the Sigstore bundle media type.
	OCIEmptyMediaType = "application/vnd.oci.empty.v1+json"

	// AnnotationPredicateType is the annotation key for the predicate type in Sigstore bundles.
	AnnotationPredicateType = "dev.sigstore.bundle.predicateType"

	// DSSEPayloadType is the expected DSSE envelope payload type for in-toto statements.
	DSSEPayloadType = "application/vnd.in-toto+json"

	// CosignAttestationTagSuffix is the tag suffix cosign uses for attestation images.
	CosignAttestationTagSuffix = ".att"
)

// BundleVerifyFunc verifies a Sigstore bundle and returns the extracted DSSE payload.
type BundleVerifyFunc func(ctx context.Context, bundleBytes []byte, opts *FetchOptions) ([]byte, error)

// VerifiedAttestation holds a verified attestation with its parsed payload.
type VerifiedAttestation struct {
	PredicateType string
	Payload       []byte
	Digest        string
}

// Fetcher discovers and verifies attestations for a container image.
type Fetcher interface {
	Fetch(
		ctx context.Context, imageRef, digest string, opts *FetchOptions,
	) ([]VerifiedAttestation, error)
}

// FetchOptions configures attestation fetching behavior.
type FetchOptions struct {
	TrustedIssuers         []string
	TrustedKeys            []string
	SANPatterns            []string
	RequireTransparencyLog bool
	Timeout                time.Duration
	Digest                 string
}

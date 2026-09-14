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
	"fmt"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
)

// TrustedKeyRef holds a path to a public key file along with the enclosing
// verifier's optional validity period bounds. When NotBefore or NotAfter are
// non-zero, the key's validity is restricted to that time window.
type TrustedKeyRef struct {
	Path      string
	NotBefore time.Time
	NotAfter  time.Time
}

// ErrVerificationFailed indicates that signed attestation material was found
// for an image but none of it passed cryptographic verification. It is
// distinct from transport and registry errors, which never wrap it, so callers
// can deny instead of applying a lenient fetch failure policy.
var ErrVerificationFailed = errors.New("attestation verification failed")

// ErrTrustMaterialUnavailable indicates that the trust material needed to
// verify an attestation could not be loaded, for example because the Sigstore
// trusted root could not be fetched or a configured key file could not be
// read. It is an availability problem, not a verification failure, so it
// never wraps ErrVerificationFailed and the fetch failure policy applies.
var ErrTrustMaterialUnavailable = errors.New("attestation trust material unavailable")

// ErrIncompleteAttestationSet is wrapped together with ErrVerificationFailed
// when the attestations of an image could not all be evaluated, for example
// because a referrer count or size limit was exceeded or a stored bundle blob
// failed its integrity check. Unlike attestations that merely failed
// verification, such a set must deny: a dropped attestation could flip the
// decision.
var ErrIncompleteAttestationSet = errors.New("attestation set is incomplete")

var (
	errEmptyAttestation      = errors.New("empty attestation")
	errAttestationTooLarge   = errors.New("attestation exceeds maximum size")
	errAggregateSizeExceeded = errors.New("aggregate attestation size exceeded")
	errReferrerLimitExceeded = fmt.Errorf(
		"%w: referrer limit exceeded",
		ErrIncompleteAttestationSet,
	)
	errInvalidReferrer       = errors.New("invalid referrer content")
	errForeignLayer          = errors.New("layer references external URLs")
	errTruncatedResponse     = errors.New("truncated registry response")
	errDownloadLimitExceeded = errors.New("attestation download limit exceeded")
	errUnsupportedLayerCodec = errors.New("unsupported attestation layer compression")
	errInvalidPayloadType    = errors.New("invalid DSSE payload type")
	errNoTrustedMaterial     = errors.New("no trusted keys or issuers configured")
	errAllBundlesFailed      = errors.New("all bundle verifications failed")
	errNoIssuers             = errors.New("at least one issuer is required")
	errNoPEMBlock            = errors.New("no PEM block found")
	errNoTrustedRoot         = errors.New("no Sigstore trusted root available")
	errRootOutOfScope        = errors.New("trusted root is out of scope")
	errMissingPredicateType  = errors.New("signed statement has no predicate type")
	errNoTrustedKeys         = errors.New(
		"bundle is signed with a public key but no trusted keys are configured",
	)
	errNoTrustedIssuers = errors.New(
		"bundle is signed with a certificate but no trusted issuers are configured",
	)
	errUnsupportedSignature  = errors.New("bundle has neither a certificate nor a public key")
	errTransparencyLogNeeded = errors.New("transparency log entry required but bundle has none")
)

const (
	// PredicateSLSAProvenanceV1 is the in-toto predicate type for SLSA provenance v1.
	PredicateSLSAProvenanceV1 = "https://slsa.dev/provenance/v1"

	// PredicateVSA is the in-toto predicate type for SLSA Verification Summary Attestations.
	PredicateVSA = "https://slsa.dev/verification_summary/v1"

	// PredicateOpenVEX is the in-toto predicate type for OpenVEX documents.
	PredicateOpenVEX = "https://openvex.dev/ns"

	// PredicateSPDX is the in-toto predicate type for SPDX SBOM documents.
	PredicateSPDX = "https://spdx.dev/Document"

	// PredicateCycloneDX is the in-toto predicate type for CycloneDX BOM documents.
	PredicateCycloneDX = "https://cyclonedx.org/bom"

	// PredicateSCAI is the in-toto predicate type for SCAI attribute reports.
	PredicateSCAI = "https://in-toto.io/attestation/scai/v0.3"

	// PredicateSLSASourceV1 is the in-toto predicate type for SLSA source track v1.
	PredicateSLSASourceV1 = "https://slsa.dev/source/v1"

	// PredicateBuildEnv is the in-toto predicate type for build environment attestations.
	PredicateBuildEnv = "https://in-toto.io/attestation/build-env/v1"

	// PredicateVulnScan is the in-toto predicate type for vulnerability scan v0.1 attestations.
	PredicateVulnScan = "https://in-toto.io/attestation/vulns/v0.1"

	// PredicateVulnScanV02 is the in-toto predicate type for vulnerability scan v0.2 attestations.
	PredicateVulnScanV02 = "https://in-toto.io/attestation/vulns/v0.2"

	// PredicateTestResult is the in-toto predicate type for test result attestations.
	PredicateTestResult = "https://in-toto.io/attestation/test-result/v0.1"

	// PredicateRelease is the in-toto predicate type for release attestations.
	PredicateRelease = "https://in-toto.io/attestation/release/v0.1"

	// PredicateRuntimeTrace is the in-toto predicate type for runtime trace attestations.
	PredicateRuntimeTrace = "https://in-toto.io/attestation/runtime-trace/v0.1"

	// PredicateScorecard is the provisional in-toto predicate type for OpenSSF Scorecard results.
	PredicateScorecard = "https://scorecard.dev/result/v0.1"

	// PredicateSLSAProvenanceV02 is the in-toto predicate type for SLSA provenance v0.2.
	PredicateSLSAProvenanceV02 = "https://slsa.dev/provenance/v0.2"

	// PredicateCosignSignature is the predicate type for bare cosign signatures.
	PredicateCosignSignature = "https://sigstore.dev/cosign/sign/v1"

	// bundleMediaType is the OCI artifact type for Sigstore bundles.
	bundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"

	// bundleMediaTypeV01 is the Sigstore bundle v0.1 media type, which accepts
	// transparency log entries with only an inclusion promise.
	bundleMediaTypeV01 = "application/vnd.dev.sigstore.bundle+json;version=0.1"

	// ociEmptyMediaType is the fallback artifact type some registries
	// (notably GHCR) return for cosign-created attestations instead of
	// the Sigstore bundle media type.
	ociEmptyMediaType = "application/vnd.oci.empty.v1+json"

	// annotationPredicateType is the annotation key for the predicate type in Sigstore bundles.
	annotationPredicateType = "dev.sigstore.bundle.predicateType"

	// dssePayloadType is the expected DSSE envelope payload type for in-toto statements.
	dssePayloadType = "application/vnd.in-toto+json"

	// cosignAttestationTagSuffix is the tag suffix cosign uses for attestation images.
	cosignAttestationTagSuffix = ".att"

	// NotationSignatureMediaType is the OCI artifact type for Notation signatures.
	NotationSignatureMediaType = "application/vnd.cncf.notary.signature"

	// BaselineSBOMArtifactType is the OCI artifact type for baseline SBOM documents
	// used in drift detection.
	BaselineSBOMArtifactType = "application/vnd.nri-supply-chain.sbom-baseline.v1+json"

	// PredicateBaselineSBOM is the predicate type assigned to baseline SBOM attestations
	// collected from OCI referrers for drift detection.
	PredicateBaselineSBOM = "https://nri-supply-chain.dev/baseline-sbom/v1"
)

// SignatureType distinguishes signature formats for routing during verification.
type SignatureType string

const (
	// SignatureTypeSigstore indicates a Sigstore bundle signature.
	SignatureTypeSigstore SignatureType = "sigstore"
	// SignatureTypeNotation indicates a Notation/Notary v2 signature.
	SignatureTypeNotation SignatureType = "notation"
)

// BundleVerifyFunc verifies a Sigstore bundle and returns the extracted DSSE
// payload. It carries no signer identity; use SignedBundleVerifyFunc wherever
// the identity that signed an attestation matters.
type BundleVerifyFunc func(ctx context.Context, bundleBytes []byte, opts *FetchOptions) ([]byte, error)

// SignedBundleVerifyFunc verifies a Sigstore bundle and returns the verified
// payload together with the identity that signed it.
type SignedBundleVerifyFunc func(
	ctx context.Context, bundleBytes []byte, opts *FetchOptions,
) (*VerifiedBundle, error)

// SignerIdentity describes who signed a verified attestation.
type SignerIdentity struct {
	// KeyPath is the first entry of KeyPaths. Empty for keyless (certificate
	// based) signatures.
	KeyPath string
	// KeyPaths lists every configured trusted public key path that holds the
	// key which verified the signature and whose validity window contains the
	// verification time, in configuration order. The same key can be
	// configured at several paths (for example during key rotation or when
	// shared by a builder and a verifier).
	KeyPaths []string
	// Issuer is the OIDC issuer recorded in the Fulcio signing certificate.
	// Empty for key-based signatures.
	Issuer string
	// SAN is the Subject Alternative Name of the Fulcio signing certificate.
	// Empty for key-based signatures.
	SAN string
}

// MatchesAny reports whether match accepts the signer for any of its key
// paths. Keyless signers are matched once with an empty key path.
func (s *SignerIdentity) MatchesAny(match func(keyPath, issuer, san string) bool) bool {
	if len(s.KeyPaths) == 0 {
		return match(s.KeyPath, s.Issuer, s.SAN)
	}

	for _, keyPath := range s.KeyPaths {
		if match(keyPath, s.Issuer, s.SAN) {
			return true
		}
	}

	return false
}

// VerifiedBundle is the result of a successful Sigstore bundle verification.
type VerifiedBundle struct {
	// Payload is the verified DSSE payload (an in-toto statement).
	Payload []byte
	// PredicateType is the predicate type taken from the signed statement.
	PredicateType string
	// Signer is the identity whose signature was verified.
	Signer SignerIdentity
}

// VerifiedAttestation holds a verified attestation with its parsed payload.
type VerifiedAttestation struct {
	PredicateType string
	Payload       []byte
	Digest        string
	SignatureType SignatureType

	// Signer is the identity that signed the attestation. Zero for Notation
	// signatures (verified later by the Notation checker) and for fetchers
	// created with NewOCIFetcherWithVerifier, whose verify function does not
	// report a signer.
	Signer SignerIdentity
	// Bundle is the raw Sigstore bundle JSON the attestation was verified
	// from. Empty when the source was not a Sigstore bundle.
	Bundle []byte

	// Notation-specific fields (zero-valued for Sigstore attestations).
	NotationMediaType        string
	NotationSubjectDigest    string
	NotationSubjectSize      int64
	NotationSubjectMediaType string
}

// Fetcher discovers and verifies attestations for a container image.
type Fetcher interface {
	Fetch(
		ctx context.Context, imageRef string, opts *FetchOptions,
	) ([]VerifiedAttestation, error)
}

// FetchOptions configures attestation fetching behavior.
type FetchOptions struct {
	TrustedIssuers         []string
	TrustedKeys            []TrustedKeyRef
	SANPatterns            []string
	RequireTransparencyLog bool
	Timeout                time.Duration
	Digest                 string
	ParsedRef              name.Reference
}

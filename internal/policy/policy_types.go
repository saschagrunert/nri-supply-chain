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

package policy

import (
	"errors"
	"time"

	celengine "github.com/saschagrunert/nri-supply-chain/internal/cel"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	maxSLSALevel      = 3
	maxPolicyFileSize = 1 << 20
	maxPolicyFiles    = 1000

	// DefaultPolicyLabel is the display label used for the default (namespace-less) policy.
	DefaultPolicyLabel = "default"
)

var (
	// ErrDefaultCannotInherit indicates the default policy has inherits=true.
	ErrDefaultCannotInherit = errors.New(
		"default policy cannot set inherits=true",
	)

	// ErrBuilderIDRequired indicates a trusted builder is missing its ID.
	ErrBuilderIDRequired = errors.New("builder id is required")

	// ErrBuilderMaxLevel indicates a builder's maxLevel is out of range.
	ErrBuilderMaxLevel = errors.New("builder maxLevel must be 0-3")

	// ErrVerifierIDRequired indicates a trusted verifier is missing its ID.
	ErrVerifierIDRequired = errors.New("verifier id is required")

	// ErrKeylessVerifierRequiresIssuers indicates a verifier without a key
	// needs trust.issuers for keyless bundle verification.
	ErrKeylessVerifierRequiresIssuers = errors.New(
		"keyless verifier requires trust.issuers to be configured",
	)

	// ErrVerifierKeyNotAbsolute indicates a verifier key path is not absolute.
	ErrVerifierKeyNotAbsolute = errors.New(
		"verifier key must be an absolute path",
	)

	// ErrVSAMinimumLevel indicates an invalid VSA minimum level.
	ErrVSAMinimumLevel = errors.New(
		"invalid vsa minimum level, must be 0-3",
	)

	// ErrTrailingContent indicates a policy file has unexpected trailing content.
	ErrTrailingContent = errors.New(
		"unexpected trailing content in policy file",
	)

	// ErrEmptyValue indicates a list contains an empty string.
	ErrEmptyValue = errors.New("empty value")

	// ErrNotRegularFile indicates a path exists but is not a regular file.
	ErrNotRegularFile = errors.New("not a regular file")

	// ErrSANPatternsRequired indicates keyless verification requires SANPatterns.
	ErrSANPatternsRequired = errors.New(
		"trust.sanPatterns is required when trust.issuers is set in enforce mode",
	)

	// ErrDuplicateBuilderID indicates a duplicate builder ID in the trust policy.
	ErrDuplicateBuilderID = errors.New("duplicate builder id")

	// ErrDuplicateVerifierID indicates a duplicate verifier ID in the trust policy.
	ErrDuplicateVerifierID = errors.New("duplicate verifier id")

	// ErrDuplicateVerifierKey indicates a duplicate key path in a verifier's keys array.
	ErrDuplicateVerifierKey = errors.New("duplicate verifier key")

	// ErrVSAMaxAgeNotPositive indicates a non-positive VSA maxAge value.
	ErrVSAMaxAgeNotPositive = errors.New("vsa.maxAge must be positive")

	// ErrSLSAMaxAgeNotPositive indicates a non-positive SLSA maxAge value.
	ErrSLSAMaxAgeNotPositive = errors.New("slsa.maxAge must be positive")

	// ErrPolicyFileTooLarge indicates a policy file exceeds the size limit.
	ErrPolicyFileTooLarge = errors.New("policy file exceeds size limit")

	// ErrTooManyPolicyFiles indicates the policy directory contains more
	// files than the allowed maximum.
	ErrTooManyPolicyFiles = errors.New("policy directory contains too many files")

	// ErrInvalidPolicyMode indicates a policy has an unrecognized mode value.
	ErrInvalidPolicyMode = errors.New("invalid policy mode")

	// ErrModeNotStricter indicates a namespace policy mode is less strict
	// than the global verification mode.
	ErrModeNotStricter = errors.New(
		"namespace policy mode cannot be less strict than the global verification mode",
	)

	// ErrRuleImagesRequired indicates a rule has no images patterns.
	ErrRuleImagesRequired = errors.New(
		"rules[].images is required and must be non-empty",
	)

	// ErrNotationTrustStoreNameRequired indicates a trust store is missing its name.
	ErrNotationTrustStoreNameRequired = errors.New(
		"notation trust store name is required",
	)

	// ErrNotationTrustStoreTypeInvalid indicates an invalid trust store type.
	ErrNotationTrustStoreTypeInvalid = errors.New(
		"notation trust store type must be \"ca\" or \"signingAuthority\"",
	)

	// ErrNotationTrustStoreCertsRequired indicates a trust store has no certificates.
	ErrNotationTrustStoreCertsRequired = errors.New(
		"notation trust store must have at least one certificate",
	)

	// ErrNotationCertNotAbsolute indicates a certificate path is not absolute.
	ErrNotationCertNotAbsolute = errors.New(
		"notation certificate path must be absolute",
	)

	// ErrNotationTrustPolicyNameRequired indicates a trust policy rule is missing its name.
	ErrNotationTrustPolicyNameRequired = errors.New(
		"notation trust policy rule name is required",
	)

	// ErrNotationTrustPolicyScopesRequired indicates a trust policy rule has no registry scopes.
	ErrNotationTrustPolicyScopesRequired = errors.New(
		"notation trust policy rule must have at least one registry scope",
	)

	// ErrNotationTrustPolicyStoresRequired indicates a trust policy rule has no trust stores.
	ErrNotationTrustPolicyStoresRequired = errors.New(
		"notation trust policy rule must have at least one trust store",
	)

	// ErrNotationTrustPolicyIdentitiesRequired indicates a trust policy rule has no trusted identities.
	ErrNotationTrustPolicyIdentitiesRequired = errors.New(
		"notation trust policy rule must have at least one trusted identity",
	)

	// ErrNotationVerificationLevelInvalid indicates an invalid verification level.
	ErrNotationVerificationLevelInvalid = errors.New(
		"notation verification level must be \"strict\", \"permissive\", \"audit\", or \"skip\"",
	)

	// ErrNotationSkipInEnforceMode indicates that "skip" verification level
	// cannot be used in enforce mode because it disables all signature checks.
	ErrNotationSkipInEnforceMode = errors.New(
		"notation verification level \"skip\" is not allowed in enforce mode",
	)

	// ErrDuplicateNotationTrustStoreName indicates a duplicate trust store name.
	ErrDuplicateNotationTrustStoreName = errors.New(
		"duplicate notation trust store name",
	)

	// ErrDuplicateNotationTrustPolicyName indicates a duplicate trust policy rule name.
	ErrDuplicateNotationTrustPolicyName = errors.New(
		"duplicate notation trust policy rule name",
	)

	// ErrCELCompileFailed indicates a CEL expression failed to compile.
	ErrCELCompileFailed = errors.New("CEL compilation failed")

	// ErrInvalidSBOMFormat indicates an unrecognized SBOM format.
	ErrInvalidSBOMFormat = errors.New(
		"invalid sbom format, must be \"spdx\" or \"cyclonedx\"",
	)

	// ErrInvalidComponentPURL indicates a component list entry is not a valid PURL.
	ErrInvalidComponentPURL = errors.New(
		"invalid component entry, must be a valid PURL (pkg: scheme)",
	)
)

// Sections groups the verification settings that can be overridden
// per-image via ImageRule. Embedded in both Policy and ImageRule.
type Sections struct {
	// Trust contains trust roots for verification (builders, verifiers, issuers, etc.).
	Trust *TrustPolicy `json:"trust,omitempty"`
	// SLSA contains SLSA provenance verification settings.
	SLSA *SLSAPolicy `json:"slsa,omitempty"`
	// VEX contains VEX verification settings.
	VEX *VEXPolicy `json:"vex,omitempty"`
	// VSA contains Verification Summary Attestation settings.
	VSA *VSAPolicy `json:"vsa,omitempty"`
	// Signatures contains attestation signature verification settings.
	Signatures *SignaturesPolicy `json:"signatures,omitempty"`
	// Notation contains Notation/Notary v2 signature verification settings.
	Notation *NotationPolicy `json:"notation,omitempty"`
	// CEL contains custom CEL expression rules for verification.
	CEL *celengine.Policy `json:"cel,omitempty"`
	// SBOM contains SBOM attestation verification settings.
	SBOM *SBOMPolicy `json:"sbom,omitempty"`
}

// Policy defines the trust roots and per-namespace verification settings.
type Policy struct {
	Sections

	// Mode overrides the global verification mode for this namespace.
	// Valid values: "disabled", "warn", "enforce". When empty, the global mode applies.
	// The per-namespace mode can only be equal to or stricter than the global
	// mode (disabled < warn < enforce).
	Mode config.VerificationMode `json:"mode,omitempty" jsonschema:"enum=disabled,enum=warn,enum=enforce"`
	// Inherits, when true, causes this namespace policy to inherit unset
	// fields from the default policy. Only valid on namespace policies.
	Inherits *bool `json:"inherits,omitempty"`
	// Include is a list of glob patterns for images that require verification.
	// When set, only images matching at least one pattern are verified; all
	// others skip verification. When empty, all images are eligible for
	// verification (the default). If both Include and Exclude are set,
	// Exclude takes precedence: an image matching both is skipped.
	Include []string `json:"include,omitempty"`
	// Exclude is a list of glob patterns for images that skip verification.
	Exclude []string `json:"exclude,omitempty"`
	// Rules is an ordered list of per-image verification overrides. When an
	// image matches a rule's Images patterns, the rule's non-nil fields
	// override the base policy for that verification. First match wins.
	Rules []ImageRule `json:"rules,omitempty"`
	// CompiledCEL holds the compiled CEL programs, populated during Validate.
	CompiledCEL *celengine.CompiledPolicy `json:"-"`
}

// TrustPolicy contains trust roots for verification.
type TrustPolicy struct {
	// Builders is the list of trusted SLSA provenance builders.
	Builders []TrustedBuilder `json:"builders,omitempty"`
	// Verifiers is the list of trusted VSA verifiers.
	Verifiers []TrustedVerifier `json:"verifiers,omitempty"`
	// Issuers is the list of trusted signing identity issuers (Fulcio/OIDC).
	Issuers []string `json:"issuers,omitempty"`
	// SANPatterns restricts accepted certificate Subject Alternative Names.
	// When empty, any SAN from a trusted issuer is accepted.
	SANPatterns []string `json:"sanPatterns,omitempty"`
	// Sources is a list of allowed source repository patterns.
	Sources []string `json:"sources,omitempty"`
	// BuildTypes is a list of accepted build type URIs.
	BuildTypes []string `json:"buildTypes,omitempty"`
}

// TrustedBuilder represents a trusted SLSA provenance builder.
type TrustedBuilder struct {
	// ID is the builder identity URI.
	ID string `json:"id"`
	// MaxLevel is the maximum SLSA level this builder can attest to (0-3).
	// This field is only enforced by VSA verification (vsa.minimumLevel),
	// not during SLSA provenance checks, because provenance attestations
	// do not declare a build level.
	MaxLevel int `json:"maxLevel"`
}

// TrustedVerifier represents a trusted VSA verifier.
type TrustedVerifier struct {
	// ID is the verifier identity URI.
	ID string `json:"id"`
	// Keys is a list of absolute paths to verifier public key files
	// (PEM-encoded). Used for Sigstore bundle signature verification.
	// During key rotation both old and new keys can be listed so that
	// attestations signed by either key are accepted. Optional for
	// keyless verification; when empty, trust.issuers must be configured
	// so bundles can be verified via Fulcio/OIDC.
	Keys []string `json:"keys,omitempty"`
}

// SLSAPolicy contains SLSA provenance verification settings.
type SLSAPolicy struct {
	// MissingPolicy controls behavior when no provenance attestation is found.
	MissingPolicy types.Action `json:"missingPolicy,omitempty"`
	// RejectUnknownParameters rejects provenance with unrecognized externalParameters fields.
	RejectUnknownParameters bool `json:"rejectUnknownParameters,omitempty"`
	// KnownParameters lists recognized externalParameters keys when
	// RejectUnknownParameters is true. If empty, defaults to the GitHub
	// Actions parameter set (source, repository, ref, workflow, buildType).
	KnownParameters []string `json:"knownParameters,omitempty"`
	// MaxAge is the maximum age of a provenance build timestamp before it's considered stale.
	MaxAge string `json:"maxAge,omitempty"`
	// MaxAgeDuration is the parsed form of MaxAge, resolved after validation.
	MaxAgeDuration time.Duration `json:"-"`
}

// VEXPolicy contains VEX verification settings.
type VEXPolicy struct {
	// MissingPolicy controls behavior when no VEX attestation is found.
	MissingPolicy types.Action `json:"missingPolicy,omitempty"`
	// UnderInvestigationPolicy controls behavior for "under_investigation" status.
	UnderInvestigationPolicy types.Action `json:"underInvestigationPolicy,omitempty"`
}

// VSAPolicy contains Verification Summary Attestation settings.
type VSAPolicy struct {
	// MissingPolicy controls behavior when no VSA attestation is found.
	MissingPolicy types.Action `json:"missingPolicy,omitempty"`
	// MinimumLevel is the minimum SLSA level required in VSA verifiedLevels (0-3).
	MinimumLevel int `json:"minimumLevel,omitempty"`
	// MaxAge is the maximum age of a VSA's timeVerified before it's considered stale.
	MaxAge string `json:"maxAge,omitempty"`
	// MaxAgeDuration is the parsed form of MaxAge, resolved after validation.
	MaxAgeDuration time.Duration `json:"-"`
	// Policy is the expected policy URI in the VSA.
	Policy string `json:"policy,omitempty"`
}

// SignaturesPolicy contains attestation signature verification settings.
type SignaturesPolicy struct {
	// RequireTransparencyLog requires Rekor transparency log inclusion.
	RequireTransparencyLog bool `json:"requireTransparencyLog,omitempty"`
}

// NotationPolicy contains Notation/Notary v2 signature verification settings.
type NotationPolicy struct {
	// MissingPolicy controls behavior when no Notation signature is found.
	MissingPolicy types.Action `json:"missingPolicy,omitempty"`
	// TrustStores defines the certificate trust stores for signature verification.
	TrustStores []NotationTrustStore `json:"trustStores,omitempty"`
	// TrustPolicy defines the trust policy rules that map registry scopes to trust stores.
	TrustPolicy []NotationTrustPolicyRule `json:"trustPolicy,omitempty"`
	// VerificationLevel controls how strict verification is.
	// Valid values: "strict", "permissive", "audit", "skip". Defaults to "strict".
	VerificationLevel string `json:"verificationLevel,omitempty"`
}

// NotationTrustStore defines a named collection of certificates used for Notation verification.
type NotationTrustStore struct {
	// Name is the trust store name (referenced by trust policy rules as "type:name").
	Name string `json:"name"`
	// Type is the trust store type: "ca" or "signingAuthority".
	Type string `json:"type"`
	// Certificates is a list of absolute paths to PEM-encoded certificate files.
	Certificates []string `json:"certificates"`
}

// NotationTrustPolicyRule maps registry scopes to trust stores and trusted identities.
type NotationTrustPolicyRule struct {
	// Name is a human-readable name for this trust policy rule.
	Name string `json:"name"`
	// RegistryScopes is a list of registry scope patterns this rule applies to.
	RegistryScopes []string `json:"registryScopes"`
	// TrustStores references trust stores in "type:name" format.
	TrustStores []string `json:"trustStores"`
	// TrustedIdentities is a list of distinguished name patterns or "*" to trust all.
	TrustedIdentities []string `json:"trustedIdentities"`
}

// SBOMPolicy contains SBOM attestation verification settings.
type SBOMPolicy struct {
	// MissingPolicy controls behavior when no SBOM attestation is found.
	MissingPolicy types.Action `json:"missingPolicy,omitempty"`
	// Formats lists accepted SBOM formats: "spdx", "cyclonedx". When empty, both are accepted.
	Formats []string `json:"formats,omitempty"`
	// License contains license allow/deny list settings for SBOM verification.
	License *SBOMLicensePolicy `json:"license,omitempty"`
	// Component contains component allow/deny list settings for SBOM verification.
	Component *SBOMComponentPolicy `json:"component,omitempty"`
}

// SBOMLicensePolicy contains license allow/deny list settings.
type SBOMLicensePolicy struct {
	// Deny is a list of SPDX license identifiers to deny (case-insensitive match).
	Deny []string `json:"deny,omitempty"`
	// Allow is a list of SPDX license identifiers to allow. When non-empty,
	// any license not in this list is denied. Deny takes precedence over allow.
	Allow []string `json:"allow,omitempty"`
}

// SBOMComponentPolicy contains component allow/deny list settings.
type SBOMComponentPolicy struct {
	// Deny is a list of PURLs to deny (prefix match).
	Deny []string `json:"deny,omitempty"`
	// Allow is a list of PURLs to allow (prefix match). When non-empty,
	// any component not matching an allow entry is denied. Deny takes precedence over allow.
	Allow []string `json:"allow,omitempty"`
}

// ImageRule defines per-image verification overrides within a namespace policy.
// When an image matches the glob patterns in Images, the non-nil fields in this
// rule override the corresponding fields of the base policy. The first matching
// rule wins (rules are evaluated in array order).
type ImageRule struct {
	Sections

	// Images is a required list of glob patterns. An image matching any
	// pattern is considered a match for this rule.
	Images []string `json:"images"`
	// CompiledCEL holds the compiled CEL programs for this rule, populated
	// during Validate.
	CompiledCEL *celengine.CompiledPolicy `json:"-"`
}

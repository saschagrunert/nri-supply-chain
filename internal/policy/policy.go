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

// Package policy provides types and loading for supply chain verification policies.
package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/glob"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	maxSLSALevel      = 3
	maxPolicyFileSize = 1 << 20
	maxPolicyFiles    = 1000
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

// ImageRule defines per-image verification overrides within a namespace policy.
// When an image matches the glob patterns in Images, the non-nil fields in this
// rule override the corresponding fields of the base policy. The first matching
// rule wins (rules are evaluated in array order).
type ImageRule struct {
	Sections

	// Images is a required list of glob patterns. An image matching any
	// pattern is considered a match for this rule.
	Images []string `json:"images"`
}

// EffectiveMode returns the per-namespace mode if set, otherwise the global mode.
func (p *Policy) EffectiveMode(global config.VerificationMode) config.VerificationMode {
	if p.Mode != "" {
		return p.Mode
	}

	return global
}

// SLSAMissingPolicy returns the effective SLSA missing policy.
// Defaults to allow so that the plugin can be deployed in warn mode
// without requiring provenance from the start.
func (p *Policy) SLSAMissingPolicy() types.Action {
	if p.SLSA != nil && p.SLSA.MissingPolicy != "" {
		return p.SLSA.MissingPolicy
	}

	return types.ActionAllow
}

// VEXMissingPolicy returns the effective VEX missing policy.
// Defaults to allow so that the plugin can be deployed in warn mode
// without requiring VEX attestations from the start.
func (p *Policy) VEXMissingPolicy() types.Action {
	if p.VEX != nil && p.VEX.MissingPolicy != "" {
		return p.VEX.MissingPolicy
	}

	return types.ActionAllow
}

// VSAMissingPolicy returns the effective VSA missing policy.
// Defaults to allow so that the plugin falls through to direct SLSA+VEX
// verification when no VSA attestation is found.
func (p *Policy) VSAMissingPolicy() types.Action {
	if p.VSA != nil && p.VSA.MissingPolicy != "" {
		return p.VSA.MissingPolicy
	}

	return types.ActionAllow
}

// Builders returns the trusted builders list, or nil if trust is not configured.
func (p *Policy) Builders() []TrustedBuilder {
	if p.Trust != nil {
		return p.Trust.Builders
	}

	return nil
}

// Hash returns a SHA-256 hex digest of the policy's JSON representation.
func (p *Policy) Hash() (string, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("hashing policy: %w", err)
	}

	sum := sha256.Sum256(data)

	return hex.EncodeToString(sum[:]), nil
}

// MergeWithDefault creates a new policy by starting from a copy of the default
// policy and overriding fields that are set in the namespace policy. Each
// top-level section (Trust, Include, Exclude, SLSA, VEX, VSA, Signatures,
// Rules) is replaced entirely if set in the namespace policy. The Inherits
// field is cleared on the result. Inherited structs are shallow-copied to
// prevent mutations from affecting the default.
func MergeWithDefault(namespace, defaultPol *Policy) *Policy {
	merged := clonePolicy(defaultPol)

	if namespace.Mode != "" {
		merged.Mode = namespace.Mode
	}

	if namespace.Include != nil {
		merged.Include = slices.Clone(namespace.Include)
	}

	if namespace.Exclude != nil {
		merged.Exclude = slices.Clone(namespace.Exclude)
	}

	applySections(&merged.Sections, namespace.Sections)

	if namespace.Rules != nil {
		merged.Rules = cloneRules(namespace.Rules)
	}

	return merged
}

func clonePolicy(pol *Policy) *Policy {
	clone := &Policy{
		Mode:     pol.Mode,
		Include:  slices.Clone(pol.Include),
		Exclude:  slices.Clone(pol.Exclude),
		Sections: cloneSections(pol.Sections),
	}

	if pol.Rules != nil {
		clone.Rules = cloneRules(pol.Rules)
	}

	return clone
}

// ApplyRule creates a new policy by cloning the base and overriding fields
// that are set in the rule. The returned policy has Rules cleared.
func ApplyRule(base *Policy, rule *ImageRule) *Policy {
	resolved := clonePolicy(base)
	resolved.Rules = nil

	applySections(&resolved.Sections, rule.Sections)

	return resolved
}

func cloneRules(rules []ImageRule) []ImageRule {
	cloned := make([]ImageRule, len(rules))

	for idx, rule := range rules {
		cloned[idx] = ImageRule{
			Images:   slices.Clone(rule.Images),
			Sections: cloneSections(rule.Sections),
		}
	}

	return cloned
}

func cloneSections(src Sections) Sections {
	var dst Sections

	if src.Trust != nil {
		dst.Trust = cloneTrust(src.Trust)
	}

	if src.SLSA != nil {
		sp := *src.SLSA
		sp.KnownParameters = slices.Clone(sp.KnownParameters)
		dst.SLSA = &sp
	}

	if src.VEX != nil {
		v := *src.VEX
		dst.VEX = &v
	}

	if src.VSA != nil {
		v := *src.VSA
		dst.VSA = &v
	}

	if src.Signatures != nil {
		s := *src.Signatures
		dst.Signatures = &s
	}

	return dst
}

func applySections(dst *Sections, src Sections) {
	if src.Trust != nil {
		dst.Trust = cloneTrust(src.Trust)
	}

	if src.SLSA != nil {
		sp := *src.SLSA
		sp.KnownParameters = slices.Clone(sp.KnownParameters)
		dst.SLSA = &sp
	}

	if src.VEX != nil {
		v := *src.VEX
		dst.VEX = &v
	}

	if src.VSA != nil {
		v := *src.VSA
		dst.VSA = &v
	}

	if src.Signatures != nil {
		s := *src.Signatures
		dst.Signatures = &s
	}
}

func cloneTrust(tp *TrustPolicy) *TrustPolicy {
	trust := *tp
	trust.Builders = slices.Clone(trust.Builders)
	trust.Verifiers = slices.Clone(trust.Verifiers)

	for idx := range trust.Verifiers {
		trust.Verifiers[idx].Keys = slices.Clone(trust.Verifiers[idx].Keys)
	}

	trust.Issuers = slices.Clone(trust.Issuers)
	trust.SANPatterns = slices.Clone(trust.SANPatterns)
	trust.Sources = slices.Clone(trust.Sources)
	trust.BuildTypes = slices.Clone(trust.BuildTypes)

	return &trust
}

// ValidateModeStrictness checks that the per-namespace mode is at least as
// strict as the global verification mode. Returns nil if Mode is empty (no
// per-namespace override).
func (p *Policy) ValidateModeStrictness(global config.VerificationMode) error {
	if p.Mode == "" {
		return nil
	}

	if p.Mode.Strictness() < global.Strictness() {
		return fmt.Errorf(
			"%w: global %q, namespace %q",
			ErrModeNotStricter, global, p.Mode,
		)
	}

	return nil
}

// Validate checks the policy for invalid values.
func (p *Policy) Validate() error {
	var errs []error

	if p.Mode != "" && !p.Mode.IsValid() {
		errs = append(errs, fmt.Errorf("%w: %q", ErrInvalidPolicyMode, p.Mode))
	}

	err := p.validateTrust()
	if err != nil {
		errs = append(errs, err)
	}

	err = p.validateInclude()
	if err != nil {
		errs = append(errs, err)
	}

	err = p.validateExclude()
	if err != nil {
		errs = append(errs, err)
	}

	err = p.validateSLSA()
	if err != nil {
		errs = append(errs, err)
	}

	err = p.validateVEX()
	if err != nil {
		errs = append(errs, err)
	}

	err = p.validateVSA()
	if err != nil {
		errs = append(errs, err)
	} else {
		p.resolveVSADuration()
	}

	err = p.validateRules()
	if err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

// ValidateEnforce runs additional checks required for enforce mode.
// Keyless verification (issuers set) requires explicit SANPatterns.
// The mode parameter is the effective mode for this policy (per-namespace
// mode if set, otherwise the global mode).
func (p *Policy) ValidateEnforce() error {
	if p.Trust != nil {
		if len(p.Trust.Issuers) > 0 && len(p.Trust.SANPatterns) == 0 {
			return ErrSANPatternsRequired
		}
	}

	for idx, rule := range p.Rules {
		if rule.Trust == nil {
			continue
		}

		if len(rule.Trust.Issuers) > 0 && len(rule.Trust.SANPatterns) == 0 {
			return fmt.Errorf("rules[%d]: %w", idx, ErrSANPatternsRequired)
		}
	}

	return nil
}

// ValidateRuntime performs runtime checks that require filesystem access,
// such as verifying that verifier key files exist on disk. Uses Lstat to
// detect symlinks (Stat would silently follow them).
//
// TOCTOU: the file could change between Lstat and LoadVerifierFromPEMFile.
func (p *Policy) ValidateRuntime() error {
	var errs []error

	if p.Trust != nil {
		for idx, verif := range p.Trust.Verifiers {
			for kidx, key := range verif.Keys {
				prefix := fmt.Sprintf("trust.verifiers[%d]", idx)

				err := validateKeyFile(prefix, verif.ID, key, kidx)
				if err != nil {
					errs = append(errs, err)
				}
			}
		}
	}

	for rIdx, rule := range p.Rules {
		if rule.Trust == nil {
			continue
		}

		for idx, verif := range rule.Trust.Verifiers {
			for kidx, key := range verif.Keys {
				prefix := fmt.Sprintf("rules[%d].trust.verifiers[%d]", rIdx, idx)

				err := validateKeyFile(prefix, verif.ID, key, kidx)
				if err != nil {
					errs = append(errs, err)
				}
			}
		}
	}

	return errors.Join(errs...)
}

func validateKeyFile(prefix, verifierID, keyPath string, keyIdx int) error {
	label := fmt.Sprintf("%s %q: keys[%d] file %q", prefix, verifierID, keyIdx, keyPath)

	info, err := os.Lstat(keyPath)
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}

	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf(
			"%s: %w (symlinks are not allowed)", label, ErrNotRegularFile,
		)
	}

	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s: %w", label, ErrNotRegularFile)
	}

	return nil
}

// Load loads and validates a policy file from disk.
func Load(policyPath string) (*Policy, error) {
	file, err := os.Open(filepath.Clean(policyPath))
	if err != nil {
		return nil, fmt.Errorf("reading policy file %q: %w", policyPath, err)
	}
	defer func() { _ = file.Close() }()

	data, err := io.ReadAll(io.LimitReader(file, maxPolicyFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading policy file %q: %w", policyPath, err)
	}

	if int64(len(data)) > maxPolicyFileSize {
		return nil, fmt.Errorf(
			"%w: %q exceeds %d bytes", ErrPolicyFileTooLarge, policyPath, maxPolicyFileSize,
		)
	}

	var pol Policy

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	err = dec.Decode(&pol)
	if err != nil {
		return nil, fmt.Errorf(
			"parsing policy file %q: %w", policyPath, err,
		)
	}

	err = dec.Decode(&struct{}{})
	if !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("%w: %q", ErrTrailingContent, policyPath)
		}

		return nil, fmt.Errorf(
			"parsing policy file %q: unexpected trailing content: %w",
			policyPath, err,
		)
	}

	err = pol.Validate()
	if err != nil {
		return nil, fmt.Errorf(
			"invalid policy file %q: %w", policyPath, err,
		)
	}

	return &pol, nil
}

// LoadAll loads all policy files from the given directory.
// Returns a map keyed by namespace (empty string for default.json).
func LoadAll(policyDir string) (map[string]*Policy, error) {
	policies, err := loadPolicyFiles(policyDir)
	if err != nil {
		return nil, err
	}

	err = applyInheritance(policies)
	if err != nil {
		return nil, err
	}

	return policies, nil
}

func loadPolicyFiles(policyDir string) (map[string]*Policy, error) {
	policies := make(map[string]*Policy)

	if policyDir == "" {
		return policies, nil
	}

	entries, err := readPolicyDir(policyDir)
	if err != nil {
		return nil, err
	}

	var errs []error

	for i, entry := range entries {
		if i >= maxPolicyFiles {
			errs = append(errs, fmt.Errorf(
				"%w: %q contains more than %d JSON files",
				ErrTooManyPolicyFiles, policyDir, maxPolicyFiles,
			))

			break
		}

		fullPath := filepath.Join(policyDir, entry.Name())

		pol, loadErr := Load(fullPath)
		if loadErr != nil {
			errs = append(errs, loadErr)

			continue
		}

		namespace := strings.TrimSuffix(entry.Name(), ".json")
		if namespace == "default" {
			namespace = ""
		}

		policies[namespace] = pol
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	return policies, nil
}

func readPolicyDir(policyDir string) ([]os.DirEntry, error) {
	entries, err := os.ReadDir(policyDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}

		return nil, fmt.Errorf(
			"reading policy directory %q: %w", policyDir, err,
		)
	}

	var jsonEntries []os.DirEntry

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		jsonEntries = append(jsonEntries, entry)
	}

	return jsonEntries, nil
}

func applyInheritance(policies map[string]*Policy) error {
	defaultPol := policies[""]

	if defaultPol != nil && defaultPol.Inherits != nil && *defaultPol.Inherits {
		return ErrDefaultCannotInherit
	}

	if defaultPol == nil {
		return nil
	}

	for ns, pol := range policies {
		if ns == "" || pol.Inherits == nil || !*pol.Inherits {
			continue
		}

		policies[ns] = MergeWithDefault(pol, defaultPol)
	}

	return nil
}

func (p *Policy) validateTrust() error {
	if p.Trust == nil {
		return nil
	}

	warnEmptyTrust(p.Trust)

	var errs []error

	seenBuilders := make(map[string]bool, len(p.Trust.Builders))

	for idx, builder := range p.Trust.Builders {
		if builder.ID == "" {
			errs = append(errs, fmt.Errorf(
				"%w: trust.builders[%d]", ErrBuilderIDRequired, idx,
			))

			continue
		}

		if seenBuilders[builder.ID] {
			errs = append(errs, fmt.Errorf(
				"%w %q at trust.builders[%d]", ErrDuplicateBuilderID, builder.ID, idx,
			))

			continue
		}

		seenBuilders[builder.ID] = true

		if builder.MaxLevel < 0 || builder.MaxLevel > maxSLSALevel {
			errs = append(errs, fmt.Errorf(
				"%w: trust.builders[%d] %q: got %d",
				ErrBuilderMaxLevel, idx, builder.ID, builder.MaxLevel,
			))
		}
	}

	err := p.validateTrustStringFields()
	if err != nil {
		errs = append(errs, err)
	}

	err = p.validateVerifiers()
	if err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

func (p *Policy) validateTrustStringFields() error {
	var errs []error

	err := validateNonEmpty("trust.issuers", p.Trust.Issuers)
	if err != nil {
		errs = append(errs, err)
	}

	err = validateNonEmpty("trust.sources", p.Trust.Sources)
	if err != nil {
		errs = append(errs, err)
	}

	err = validateGlobPatterns("trust.sources", p.Trust.Sources)
	if err != nil {
		errs = append(errs, err)
	}

	err = validateNonEmpty("trust.buildTypes", p.Trust.BuildTypes)
	if err != nil {
		errs = append(errs, err)
	}

	err = validateNonEmpty("trust.sanPatterns", p.Trust.SANPatterns)
	if err != nil {
		errs = append(errs, err)
	}

	err = validateGlobPatterns("trust.sanPatterns", p.Trust.SANPatterns)
	if err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

func (p *Policy) validateVerifiers() error {
	var errs []error

	seenVerifiers := make(map[string]bool, len(p.Trust.Verifiers))

	for idx, verif := range p.Trust.Verifiers {
		if verif.ID == "" {
			errs = append(errs, fmt.Errorf(
				"%w: trust.verifiers[%d]", ErrVerifierIDRequired, idx,
			))

			continue
		}

		if seenVerifiers[verif.ID] {
			errs = append(errs, fmt.Errorf(
				"%w %q at trust.verifiers[%d]", ErrDuplicateVerifierID, verif.ID, idx,
			))

			continue
		}

		seenVerifiers[verif.ID] = true

		errs = append(errs, validateVerifierKeys(p, idx, &verif)...)
	}

	return errors.Join(errs...)
}

func validateVerifierKeys(
	pol *Policy, idx int, verif *TrustedVerifier,
) []error {
	var errs []error

	if len(verif.Keys) == 0 {
		if len(pol.Trust.Issuers) == 0 {
			errs = append(errs, fmt.Errorf(
				"%w: trust.verifiers[%d] %q",
				ErrKeylessVerifierRequiresIssuers, idx, verif.ID,
			))
		}

		return errs
	}

	seen := make(map[string]bool, len(verif.Keys))

	for kidx, key := range verif.Keys {
		if key == "" {
			errs = append(errs, fmt.Errorf(
				"%w in trust.verifiers[%d].keys[%d]",
				ErrEmptyValue, idx, kidx,
			))

			continue
		}

		if seen[key] {
			errs = append(errs, fmt.Errorf(
				"%w %q at trust.verifiers[%d].keys[%d]",
				ErrDuplicateVerifierKey, key, idx, kidx,
			))

			continue
		}

		seen[key] = true

		if !filepath.IsAbs(key) {
			errs = append(errs, fmt.Errorf(
				"%w: trust.verifiers[%d] %q: keys[%d] got %q",
				ErrVerifierKeyNotAbsolute, idx, verif.ID, kidx, key,
			))
		}
	}

	return errs
}

func validateGlobPatterns(field string, patterns []string) error {
	var errs []error

	for idx, pattern := range patterns {
		_, err := glob.Match(pattern, "")
		if err != nil {
			errs = append(errs, fmt.Errorf(
				"invalid %s[%d] pattern %q: %w", field, idx, pattern, err,
			))
		}
	}

	return errors.Join(errs...)
}

func validateNonEmpty(field string, values []string) error {
	var errs []error

	for idx, val := range values {
		if val == "" {
			errs = append(errs, fmt.Errorf("%w in %s[%d]", ErrEmptyValue, field, idx))
		}
	}

	return errors.Join(errs...)
}

func warnEmptyTrust(trust *TrustPolicy) {
	if len(trust.Builders) == 0 && len(trust.Verifiers) == 0 && len(trust.Issuers) == 0 {
		slog.Warn("trust section is configured but has no builders, verifiers, or issuers")
	}
}

func (p *Policy) validateInclude() error {
	return validateGlobPatterns("include", p.Include)
}

func (p *Policy) validateExclude() error {
	return validateGlobPatterns("exclude", p.Exclude)
}

func (p *Policy) validateSLSA() error {
	if p.SLSA == nil {
		return nil
	}

	var errs []error

	if p.SLSA.MissingPolicy != "" {
		err := types.ValidateAction(
			"slsa.missingPolicy", p.SLSA.MissingPolicy,
		)
		if err != nil {
			errs = append(errs, fmt.Errorf("validating slsa policy: %w", err))
		}
	}

	err := validateNonEmpty(
		"slsa.knownParameters", p.SLSA.KnownParameters,
	)
	if err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

func (p *Policy) validateVEX() error {
	if p.VEX == nil {
		return nil
	}

	var errs []error

	if p.VEX.MissingPolicy != "" {
		err := types.ValidateAction(
			"vex.missingPolicy", p.VEX.MissingPolicy,
		)
		if err != nil {
			errs = append(errs, fmt.Errorf("validating vex missing policy: %w", err))
		}
	}

	if p.VEX.UnderInvestigationPolicy != "" {
		err := types.ValidateAction(
			"vex.underInvestigationPolicy",
			p.VEX.UnderInvestigationPolicy,
		)
		if err != nil {
			errs = append(errs, fmt.Errorf(
				"validating vex under investigation policy: %w", err,
			))
		}
	}

	return errors.Join(errs...)
}

func (p *Policy) validateVSA() error {
	if p.VSA == nil {
		return nil
	}

	var errs []error

	if p.VSA.MissingPolicy != "" {
		err := types.ValidateAction(
			"vsa.missingPolicy", p.VSA.MissingPolicy,
		)
		if err != nil {
			errs = append(errs, fmt.Errorf("validating vsa missing policy: %w", err))
		}
	}

	if p.VSA.MinimumLevel < 0 || p.VSA.MinimumLevel > maxSLSALevel {
		errs = append(errs, fmt.Errorf(
			"%w: got %d", ErrVSAMinimumLevel, p.VSA.MinimumLevel,
		))
	}

	if p.VSA.MaxAge != "" {
		maxAge, err := time.ParseDuration(p.VSA.MaxAge)
		if err != nil {
			errs = append(errs, fmt.Errorf("invalid vsa.maxAge %q: %w", p.VSA.MaxAge, err))
		} else if maxAge <= 0 {
			errs = append(errs, fmt.Errorf("%w, got %q", ErrVSAMaxAgeNotPositive, p.VSA.MaxAge))
		}
	}

	return errors.Join(errs...)
}

func (p *Policy) validateRules() error {
	if len(p.Rules) == 0 {
		return nil
	}

	var errs []error

	for idx := range p.Rules {
		errs = append(errs, p.validateRule(idx)...)
	}

	return errors.Join(errs...)
}

func (p *Policy) validateRule(idx int) []error {
	rule := &p.Rules[idx]

	if len(rule.Images) == 0 {
		return []error{fmt.Errorf(
			"%w: rules[%d]", ErrRuleImagesRequired, idx,
		)}
	}

	var errs []error

	err := validateNonEmpty(fmt.Sprintf("rules[%d].images", idx), rule.Images)
	if err != nil {
		errs = append(errs, err)
	}

	err = validateGlobPatterns(fmt.Sprintf("rules[%d].images", idx), rule.Images)
	if err != nil {
		errs = append(errs, err)
	}

	rulePol := &Policy{
		Sections: rule.Sections,
	}

	err = rulePol.validateTrust()
	if err != nil {
		errs = append(errs, fmt.Errorf("rules[%d]: %w", idx, err))
	}

	err = rulePol.validateSLSA()
	if err != nil {
		errs = append(errs, fmt.Errorf("rules[%d]: %w", idx, err))
	}

	err = rulePol.validateVEX()
	if err != nil {
		errs = append(errs, fmt.Errorf("rules[%d]: %w", idx, err))
	}

	err = rulePol.validateVSA()
	if err != nil {
		errs = append(errs, fmt.Errorf("rules[%d]: %w", idx, err))
	} else {
		// resolveVSADuration mutates rulePol.VSA.MaxAgeDuration, which
		// is the same pointer as p.Rules[idx].VSA, so no copy-back needed.
		rulePol.resolveVSADuration()
	}

	return errs
}

// resolveVSADuration parses MaxAge into MaxAgeDuration. Safe to call only
// after validateVSA, which guarantees the duration string is valid.
func (p *Policy) resolveVSADuration() {
	if p.VSA == nil || p.VSA.MaxAge == "" {
		return
	}

	maxAge, err := time.ParseDuration(p.VSA.MaxAge)
	if err != nil {
		return
	}

	p.VSA.MaxAgeDuration = maxAge
}

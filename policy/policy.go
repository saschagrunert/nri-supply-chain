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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

const (
	maxSLSALevel = 3

	// ActionAllow permits the action.
	ActionAllow = "allow"
	// ActionWarn logs a warning but permits the action.
	ActionWarn = "warn"
	// ActionDeny rejects the action.
	ActionDeny = "deny"
)

var (
	// ErrBuilderIDRequired indicates a trusted builder is missing its ID.
	ErrBuilderIDRequired = errors.New("builder id is required")

	// ErrBuilderMaxLevel indicates a builder's maxLevel is out of range.
	ErrBuilderMaxLevel = errors.New("builder maxLevel must be 0-3")

	// ErrVerifierIDRequired indicates a trusted verifier is missing its ID.
	ErrVerifierIDRequired = errors.New("verifier id is required")

	// ErrVerifierKeyRequired indicates a trusted verifier is missing its key.
	ErrVerifierKeyRequired = errors.New("verifier key is required")

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

	// ErrInvalidAction indicates an unrecognized policy action value.
	ErrInvalidAction = errors.New("invalid policy action value")
)

// Policy defines the trust roots and per-namespace verification settings.
type Policy struct {
	// Trust contains trust roots for verification (builders, verifiers, issuers, etc.).
	Trust *TrustPolicy `json:"trust,omitempty"`
	// Exclude is a list of glob patterns for images that skip verification.
	Exclude []string `json:"exclude,omitempty"`
	// Provenance contains SLSA provenance verification settings.
	Provenance *ProvenancePolicy `json:"provenance,omitempty"`
	// VEX contains VEX verification settings.
	VEX *VEXPolicy `json:"vex,omitempty"`
	// VSA contains Verification Summary Attestation settings.
	VSA *VSAPolicy `json:"vsa,omitempty"`
	// Signatures contains attestation signature verification settings.
	Signatures *SignaturesPolicy `json:"signatures,omitempty"`
}

// TrustPolicy contains trust roots for verification.
type TrustPolicy struct {
	// Builders is the list of trusted SLSA provenance builders.
	Builders []TrustedBuilder `json:"builders"`
	// Verifiers is the list of trusted VSA verifiers.
	Verifiers []TrustedVerifier `json:"verifiers"`
	// Issuers is the list of trusted signing identity issuers (Fulcio/OIDC).
	Issuers []string `json:"issuers"`
	// SANPatterns restricts accepted certificate Subject Alternative Names.
	// When empty, any SAN from a trusted issuer is accepted.
	SANPatterns []string `json:"sanPatterns,omitempty"`
	// Sources is a list of allowed source repository patterns.
	Sources []string `json:"sources"`
	// BuildTypes is a list of accepted build type URIs.
	BuildTypes []string `json:"buildTypes"`
}

// TrustedBuilder represents a trusted SLSA provenance builder.
type TrustedBuilder struct {
	// ID is the builder identity URI.
	ID string `json:"id"`
	// MaxLevel is the maximum SLSA level this builder can attest to (0-3).
	MaxLevel int `json:"maxLevel"`
}

// TrustedVerifier represents a trusted VSA verifier.
type TrustedVerifier struct {
	// ID is the verifier identity URI.
	ID string `json:"id"`
	// Key is the absolute path to the verifier's public key file (PEM-encoded).
	// Used both for VSA verifier identity trust and for Sigstore bundle signature verification.
	Key string `json:"key"`
}

// ProvenancePolicy contains SLSA provenance verification settings.
type ProvenancePolicy struct {
	// MissingPolicy controls behavior when no provenance attestation is found.
	MissingPolicy string `json:"missingPolicy,omitempty"`
	// RejectUnknownParameters rejects provenance with unrecognized externalParameters fields.
	RejectUnknownParameters bool `json:"rejectUnknownParameters,omitempty"`
}

// VEXPolicy contains VEX verification settings.
type VEXPolicy struct {
	// MissingPolicy controls behavior when no VEX attestation is found.
	MissingPolicy string `json:"missingPolicy,omitempty"`
	// UnderInvestigationPolicy controls behavior for "under_investigation" status.
	UnderInvestigationPolicy string `json:"underInvestigationPolicy,omitempty"`
}

// VSAPolicy contains Verification Summary Attestation settings.
type VSAPolicy struct {
	// MinimumLevel is the minimum SLSA level required in VSA verifiedLevels (0-3).
	MinimumLevel int `json:"minimumLevel,omitempty"`
	// MaxAge is the maximum age of a VSA's timeVerified before it's considered stale.
	MaxAge string `json:"maxAge,omitempty"`
	// Policy is the expected policy URI in the VSA.
	Policy string `json:"policy,omitempty"`
}

// SignaturesPolicy contains attestation signature verification settings.
type SignaturesPolicy struct {
	// RequireTransparencyLog requires Rekor transparency log inclusion.
	RequireTransparencyLog bool `json:"requireTransparencyLog,omitempty"`
}

// ProvenanceMissingPolicy returns the effective provenance missing policy.
func (p *Policy) ProvenanceMissingPolicy() string {
	if p.Provenance != nil && p.Provenance.MissingPolicy != "" {
		return p.Provenance.MissingPolicy
	}

	return ActionAllow
}

// Builders returns the trusted builders list, or nil if trust is not configured.
func (p *Policy) Builders() []TrustedBuilder {
	if p.Trust != nil {
		return p.Trust.Builders
	}

	return nil
}

// Validate checks the policy for invalid values.
func (p *Policy) Validate() error {
	err := p.validateTrust()
	if err != nil {
		return err
	}

	err = p.validateExclude()
	if err != nil {
		return err
	}

	err = p.validateProvenance()
	if err != nil {
		return err
	}

	err = p.validateVEX()
	if err != nil {
		return err
	}

	return p.validateVSA()
}

// Load loads and validates a policy file from disk.
func Load(policyPath string) (*Policy, error) {
	data, err := os.ReadFile(filepath.Clean(policyPath))
	if err != nil {
		return nil, fmt.Errorf("reading policy file %q: %w", policyPath, err)
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
	policies := make(map[string]*Policy)

	if policyDir == "" {
		return policies, nil
	}

	entries, err := os.ReadDir(policyDir)
	if err != nil {
		if os.IsNotExist(err) {
			return policies, nil
		}

		return nil, fmt.Errorf(
			"reading policy directory %q: %w", policyDir, err,
		)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		fullPath := filepath.Join(policyDir, entry.Name())

		pol, err := Load(fullPath)
		if err != nil {
			return nil, err
		}

		namespace := strings.TrimSuffix(entry.Name(), ".json")
		if namespace == "default" {
			namespace = ""
		}

		policies[namespace] = pol
	}

	return policies, nil
}

func (p *Policy) validateTrust() error {
	if p.Trust == nil {
		return nil
	}

	for idx, builder := range p.Trust.Builders {
		if builder.ID == "" {
			return fmt.Errorf(
				"%w: trust.builders[%d]", ErrBuilderIDRequired, idx,
			)
		}

		if builder.MaxLevel < 0 || builder.MaxLevel > maxSLSALevel {
			return fmt.Errorf(
				"%w: trust.builders[%d] %q: got %d",
				ErrBuilderMaxLevel, idx, builder.ID, builder.MaxLevel,
			)
		}
	}

	err := validateGlobPatterns("trust.sources", p.Trust.Sources)
	if err != nil {
		return err
	}

	return p.validateVerifiers()
}

func (p *Policy) validateVerifiers() error {
	for idx, verif := range p.Trust.Verifiers {
		if verif.ID == "" {
			return fmt.Errorf(
				"%w: trust.verifiers[%d]", ErrVerifierIDRequired, idx,
			)
		}

		if verif.Key == "" {
			return fmt.Errorf(
				"%w: trust.verifiers[%d] %q",
				ErrVerifierKeyRequired, idx, verif.ID,
			)
		}

		if !filepath.IsAbs(verif.Key) {
			return fmt.Errorf(
				"%w: trust.verifiers[%d] %q: got %q",
				ErrVerifierKeyNotAbsolute, idx, verif.ID, verif.Key,
			)
		}
	}

	return nil
}

func validateGlobPatterns(field string, patterns []string) error {
	for idx, pattern := range patterns {
		_, err := path.Match(pattern, "")
		if err != nil {
			return fmt.Errorf(
				"invalid %s[%d] pattern %q: %w", field, idx, pattern, err,
			)
		}
	}

	return nil
}

func (p *Policy) validateExclude() error {
	return validateGlobPatterns("exclude", p.Exclude)
}

func (p *Policy) validateProvenance() error {
	if p.Provenance == nil {
		return nil
	}

	if p.Provenance.MissingPolicy != "" {
		err := ValidateAction(
			"provenance.missingPolicy", p.Provenance.MissingPolicy,
		)
		if err != nil {
			return fmt.Errorf("validating provenance policy: %w", err)
		}
	}

	return nil
}

func (p *Policy) validateVEX() error {
	if p.VEX == nil {
		return nil
	}

	if p.VEX.MissingPolicy != "" {
		err := ValidateAction(
			"vex.missingPolicy", p.VEX.MissingPolicy,
		)
		if err != nil {
			return fmt.Errorf("validating vex missing policy: %w", err)
		}
	}

	if p.VEX.UnderInvestigationPolicy != "" {
		err := ValidateAction(
			"vex.underInvestigationPolicy", p.VEX.UnderInvestigationPolicy,
		)
		if err != nil {
			return fmt.Errorf(
				"validating vex under investigation policy: %w", err,
			)
		}
	}

	return nil
}

func (p *Policy) validateVSA() error {
	if p.VSA == nil {
		return nil
	}

	if p.VSA.MinimumLevel < 0 || p.VSA.MinimumLevel > maxSLSALevel {
		return fmt.Errorf(
			"%w: got %d", ErrVSAMinimumLevel, p.VSA.MinimumLevel,
		)
	}

	if p.VSA.MaxAge != "" {
		_, err := time.ParseDuration(p.VSA.MaxAge)
		if err != nil {
			return fmt.Errorf("invalid vsa.maxAge %q: %w", p.VSA.MaxAge, err)
		}
	}

	return nil
}

// ValidateAction validates that the given value is a valid policy action.
func ValidateAction(name, value string) error {
	switch value {
	case ActionAllow, ActionWarn, ActionDeny:
		return nil
	default:
		return fmt.Errorf("%w: %s %q", ErrInvalidAction, name, value)
	}
}

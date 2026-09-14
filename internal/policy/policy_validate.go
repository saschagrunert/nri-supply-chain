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
	"fmt"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/fileutil"
	"github.com/saschagrunert/nri-supply-chain/internal/glob"
)

const (
	notationLevelSkip       = "skip"
	notationLevelAudit      = "audit"
	notationLevelPermissive = "permissive"

	revocationModeStrict = "strict"
	revocationModeSoft   = "soft"
	revocationModeSkip   = "skip"
)

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

	if p.Version < 0 || p.Version > LatestPolicyVersion {
		errs = append(errs, fmt.Errorf(
			"%w: got %d, max %d",
			ErrPolicyVersionTooNew, p.Version, LatestPolicyVersion,
		))
	}

	if p.Mode != "" && !p.Mode.IsValid() {
		errs = append(errs, fmt.Errorf("%w: %q", ErrInvalidPolicyMode, p.Mode))
	}

	errs = append(errs, p.validateInclude(), p.validateExclude())
	errs = append(errs, p.validateSections()...)

	err := p.validateRules()
	if err != nil {
		errs = append(errs, err)
	}

	// An inheriting policy may rely on the default policy's trust.issuers,
	// so its keyless verifiers are checked after merging (applyInheritance).
	if p.Inherits == nil || !*p.Inherits {
		errs = append(errs, p.validateKeylessVerifiers())
	}

	celErr := p.validateAndCompileCEL()
	if celErr != nil {
		errs = append(errs, celErr)
	}

	return errors.Join(errs...)
}

// ValidateEnforce runs additional checks required for enforce mode.
// Keyless verification (issuers set) requires explicit SANPatterns, and
// Notation verification levels that do not enforce authenticity ("skip" and
// "audit") are rejected.
func (p *Policy) ValidateEnforce() error {
	err := p.validateEnforce()
	if err != nil {
		return err
	}

	if len(p.Include) > 0 {
		slog.Warn("Policy uses include patterns in enforce mode; images that match "+
			"no include pattern are admitted without verification",
			"include", p.Include,
		)
	}

	// Rules are checked on the effective policy they produce, because a rule
	// only overrides the fields it sets: a rule clearing trust.sanPatterns
	// under base issuers weakens the base, while a rule setting only issuers
	// inherits the base SAN patterns.
	for idx := range p.Rules {
		p.Rules[idx].warnEnforce()

		effective := ApplyRule(p, &p.Rules[idx])

		err = effective.enforceError()
		if err != nil {
			return fmt.Errorf("rules[%d]: %w", idx, err)
		}
	}

	return nil
}

func (s *Sections) validateEnforce() error {
	s.warnEnforce()

	return s.enforceError()
}

func (s *Sections) warnEnforce() {
	if s.Notation != nil && s.Notation.VerificationLevel == notationLevelPermissive {
		slog.Warn("Notation verification level \"permissive\" in enforce mode " +
			"does not enforce expiry and revocation checks")
	}
}

func (s *Sections) enforceError() error {
	if s.Notation != nil {
		switch s.Notation.VerificationLevel {
		case notationLevelSkip:
			return ErrNotationSkipInEnforceMode
		case notationLevelAudit:
			return ErrNotationAuditInEnforceMode
		}
	}

	if s.Trust != nil && len(s.Trust.Issuers) > 0 && len(s.Trust.SANPatterns) == 0 {
		return ErrSANPatternsRequired
	}

	return nil
}

// ValidateRuntime performs runtime checks that require filesystem access,
// such as verifying that verifier and builder key files exist on disk.
// Symlinks are only followed when they resolve inside their own directory
// (Kubernetes Secret and ConfigMap volumes).
//
// TOCTOU: the file could change between this check and loadPublicKeyFromPEM.
func (p *Policy) ValidateRuntime() error {
	errs := p.validateRuntime("")

	for idx := range p.Rules {
		errs = append(errs, p.Rules[idx].validateRuntime(fmt.Sprintf("rules[%d].", idx))...)
	}

	return errors.Join(errs...)
}

func (s *Sections) validateRuntime(prefix string) []error {
	var errs []error

	if s.Trust != nil {
		for idx := range s.Trust.Verifiers {
			verif := &s.Trust.Verifiers[idx]
			label := fmt.Sprintf("%strust.verifiers[%d]", prefix, idx)

			for kidx, key := range verif.Keys {
				errs = append(errs, validateKeyFile(label, verif.ID, key, kidx))
			}
		}

		for idx := range s.Trust.Builders {
			builder := &s.Trust.Builders[idx]
			label := fmt.Sprintf("%strust.builders[%d]", prefix, idx)

			for kidx, key := range builder.Keys {
				errs = append(errs, validateKeyFile(label, builder.ID, key, kidx))
			}
		}
	}

	errs = append(errs, validateNotationCertFiles(prefix, s.Notation)...)

	return slices.DeleteFunc(errs, func(err error) bool { return err == nil })
}

// checkRegularFile verifies that path is a regular file. A symlink is accepted
// when it resolves inside the directory containing it (the layout of
// Kubernetes Secret and ConfigMap volumes), matching what fileutil.ReadLimited
// reads later; a symlink escaping that directory is rejected.
func checkRegularFile(path string) error {
	info, err := fileutil.StatContained(path)
	if errors.Is(err, fileutil.ErrSymlink) {
		return fmt.Errorf(
			"%w (symlinks must stay inside the file's directory): %w", ErrNotRegularFile, err,
		)
	}

	if err != nil {
		return fmt.Errorf("stat file: %w", err)
	}

	if !info.Mode().IsRegular() {
		return ErrNotRegularFile
	}

	return nil
}

func validateKeyFile(prefix, ownerID, keyPath string, keyIdx int) error {
	label := fmt.Sprintf("%s %q: keys[%d] file %q", prefix, ownerID, keyIdx, keyPath)

	err := checkRegularFile(keyPath)
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}

	permErr := fileutil.CheckCredentialPermissions(keyPath)
	if permErr != nil {
		slog.Warn("Key file has overly permissive mode bits", "path", keyPath, "error", permErr)
	}

	return nil
}

func (s *Sections) validateTrust() error {
	warnEmptyTrust(s.Trust)

	return errors.Join(
		s.validateBuilders(),
		s.validateTrustStringFields(),
		s.validateVerifiers(),
		validateNoDuplicateKeys(s.Trust),
	)
}

func (s *Sections) validateBuilders() error {
	var errs []error

	seenBuilders := make(map[string]bool, len(s.Trust.Builders))

	for idx := range s.Trust.Builders {
		builder := &s.Trust.Builders[idx]

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

		label := fmt.Sprintf("trust.builders[%d]", idx)

		errs = append(errs, validateKeyPaths(
			label, builder.ID, builder.Keys, ErrBuilderKeyNotAbsolute, ErrDuplicateBuilderKey,
		)...)
		errs = append(errs, validateIdentities(label, builder.Identities, s.Trust.Issuers)...)

		if !builder.Bound() {
			slog.Warn("Trusted builder has no keys or identities; provenance claiming "+
				"this builder is accepted from any trusted signer",
				"builder", builder.ID,
			)
		}
	}

	return errors.Join(errs...)
}

func (s *Sections) validateTrustStringFields() error {
	return errors.Join(
		validateNonEmpty("trust.issuers", s.Trust.Issuers),
		validateNonEmpty("trust.sources", s.Trust.Sources),
		validateGlobPatterns("trust.sources", s.Trust.Sources),
		validateNonEmpty("trust.buildTypes", s.Trust.BuildTypes),
		validateNonEmpty("trust.sanPatterns", s.Trust.SANPatterns),
		validateGlobPatterns("trust.sanPatterns", s.Trust.SANPatterns),
	)
}

func (s *Sections) validateVerifiers() error {
	var errs []error

	seenVerifiers := make(map[string]bool, len(s.Trust.Verifiers))

	for idx := range s.Trust.Verifiers {
		verif := &s.Trust.Verifiers[idx]

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

		errs = append(errs, validateVerifierKeys(idx, verif)...)
		errs = append(errs, validateIdentities(
			fmt.Sprintf("trust.verifiers[%d]", idx), verif.Identities, s.Trust.Issuers,
		)...)

		if !verif.Bound() {
			slog.Warn("Trusted verifier has no keys or identities; its VSAs are not "+
				"bound to a signer and never short-circuit verification",
				"verifier", verif.ID,
			)
		}
	}

	return errors.Join(errs...)
}

// validateNoDuplicateKeys checks that no key path used by a verifier appears
// in another verifier or in a builder. The same physical key used by two
// entries with different time bounds would cause one to silently overwrite the
// other in the key material map, and would make the VSA signer binding
// ambiguous. Builders may share a key with each other, since builder keys carry
// no time bounds and only bind provenance to the claimed builder.
func validateNoDuplicateKeys(trust *TrustPolicy) error {
	verifierOwners, errs := verifierKeyOwners(trust.Verifiers)

	for idx := range trust.Builders {
		builder := &trust.Builders[idx]

		for _, key := range builder.Keys {
			if verifierID, exists := verifierOwners[key]; exists {
				errs = append(errs, fmt.Errorf(
					"%w: key %q appears in verifier %q and builder %q",
					ErrDuplicateKeyAcrossVerifiers, key, verifierID, builder.ID,
				))
			}
		}
	}

	return errors.Join(errs...)
}

// verifierKeyOwners maps each verifier key path to the first verifier using
// it and reports keys shared by different verifiers.
func verifierKeyOwners(verifiers []TrustedVerifier) (owners map[string]string, errs []error) {
	owners = make(map[string]string)

	for idx := range verifiers {
		verif := &verifiers[idx]

		for _, key := range verif.Keys {
			if key == "" || verif.ID == "" {
				continue
			}

			firstID, exists := owners[key]
			if !exists {
				owners[key] = verif.ID

				continue
			}

			if firstID != verif.ID {
				errs = append(errs, fmt.Errorf(
					"%w: key %q appears in verifiers %q and %q",
					ErrDuplicateKeyAcrossVerifiers, key, firstID, verif.ID,
				))
			}
		}
	}

	return owners, errs
}

// validateKeylessVerifiers checks that verifiers without keys have
// trust.issuers for keyless bundle verification. Rules are checked on the
// effective policy they produce, because a rule that only sets
// trust.verifiers uses the base issuers, while a rule clearing
// trust.issuers leaves the base keyless verifiers without any.
func (p *Policy) validateKeylessVerifiers() error {
	errs := keylessVerifierErrors(p.Trust)

	for idx := range p.Rules {
		if p.Rules[idx].Trust == nil {
			continue
		}

		for _, err := range keylessVerifierErrors(ApplyRule(p, &p.Rules[idx]).Trust) {
			errs = append(errs, fmt.Errorf("rules[%d]: %w", idx, err))
		}
	}

	return errors.Join(errs...)
}

func keylessVerifierErrors(trust *TrustPolicy) []error {
	if trust == nil || len(trust.Issuers) > 0 {
		return nil
	}

	var errs []error

	for idx := range trust.Verifiers {
		verif := &trust.Verifiers[idx]

		if verif.ID != "" && len(verif.Keys) == 0 {
			errs = append(errs, fmt.Errorf(
				"%w: trust.verifiers[%d] %q",
				ErrKeylessVerifierRequiresIssuers, idx, verif.ID,
			))
		}
	}

	return errs
}

func validateVerifierKeys(idx int, verif *TrustedVerifier) []error {
	var errs []error

	if len(verif.Keys) == 0 {
		if verif.NotBefore != "" || verif.NotAfter != "" {
			errs = append(errs, fmt.Errorf(
				"%w: trust.verifiers[%d] %q",
				ErrTimeBoundsWithoutKeys, idx, verif.ID,
			))
		}

		return errs
	}

	errs = append(errs, validateKeyPaths(
		fmt.Sprintf("trust.verifiers[%d]", idx), verif.ID, verif.Keys,
		ErrVerifierKeyNotAbsolute, ErrDuplicateVerifierKey,
	)...)
	errs = append(errs, validateVerifierTimeBounds(idx, verif)...)

	return errs
}

func validateKeyPaths(
	label, ownerID string, keys []string, errNotAbsolute, errDuplicate error,
) []error {
	var errs []error

	seen := make(map[string]bool, len(keys))

	for kidx, key := range keys {
		if key == "" {
			errs = append(errs, fmt.Errorf("%w in %s.keys[%d]", ErrEmptyValue, label, kidx))

			continue
		}

		if seen[key] {
			errs = append(errs, fmt.Errorf(
				"%w %q at %s.keys[%d]", errDuplicate, key, label, kidx,
			))

			continue
		}

		seen[key] = true

		if !filepath.IsAbs(key) {
			errs = append(errs, fmt.Errorf(
				"%w: %s %q: keys[%d] got %q", errNotAbsolute, label, ownerID, kidx, key,
			))
		}
	}

	return errs
}

func validateIdentities(
	label string,
	identities []TrustedIdentity,
	trustedIssuers []string,
) []error {
	var errs []error

	for idx, identity := range identities {
		field := fmt.Sprintf("%s.identities[%d]", label, idx)

		if identity.Issuer == "" {
			errs = append(errs, fmt.Errorf("%w: %s", ErrIdentityIssuerRequired, field))
		} else if len(trustedIssuers) > 0 && !slices.Contains(trustedIssuers, identity.Issuer) {
			slog.Warn("Identity issuer is not listed in trust.issuers; certificates "+
				"from this issuer are not accepted, so the identity never matches",
				"identity", field, "issuer", identity.Issuer,
			)
		}

		if identity.SANPattern == "" {
			errs = append(errs, fmt.Errorf("%w: %s", ErrIdentitySANPatternRequired, field))

			continue
		}

		err := validateGlobPatterns(field+".sanPattern", []string{identity.SANPattern})
		if err != nil {
			errs = append(errs, err)
		}
	}

	return errs
}

func validateVerifierTimeBounds(idx int, verif *TrustedVerifier) []error {
	var errs []error

	if verif.NotBefore != "" {
		notBefore, err := time.Parse(time.RFC3339, verif.NotBefore)
		if err != nil {
			errs = append(errs, fmt.Errorf(
				"%w: trust.verifiers[%d] %q: got %q",
				ErrInvalidNotBefore, idx, verif.ID, verif.NotBefore,
			))
		} else {
			verif.NotBeforeTime = notBefore
		}
	}

	if verif.NotAfter != "" {
		notAfter, err := time.Parse(time.RFC3339, verif.NotAfter)
		if err != nil {
			errs = append(errs, fmt.Errorf(
				"%w: trust.verifiers[%d] %q: got %q",
				ErrInvalidNotAfter, idx, verif.ID, verif.NotAfter,
			))
		} else {
			verif.NotAfterTime = notAfter
		}
	}

	if len(errs) > 0 {
		return errs
	}

	if !verif.NotBeforeTime.IsZero() && !verif.NotAfterTime.IsZero() {
		if !verif.NotAfterTime.After(verif.NotBeforeTime) {
			errs = append(errs, fmt.Errorf(
				"%w: trust.verifiers[%d] %q: notBefore=%q notAfter=%q",
				ErrNotAfterBeforeNotBefore, idx, verif.ID,
				verif.NotBefore, verif.NotAfter,
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

			continue
		}

		if glob.HasBangNegation(pattern) {
			slog.Warn("Pattern uses a \"[!...]\" character class, which negates the class; "+
				"earlier releases matched \"!\" literally",
				"field", fmt.Sprintf("%s[%d]", field, idx),
				"pattern", pattern,
			)
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
	// A tag-scoped exclude fails safe: digest-pinned references are verified.
	for _, pattern := range tagScopedPatterns(p.Exclude) {
		slog.Info("Exclude pattern is scoped to a tag and does not match digest-pinned references",
			"pattern", pattern,
		)
	}

	return validateGlobPatterns("exclude", p.Exclude)
}

// tagScopedPatterns returns the image patterns that are scoped to a tag: a
// ":" in the last path segment (so a registry port does not count) and no
// digest part.
func tagScopedPatterns(patterns []string) []string {
	var scoped []string

	for _, pattern := range patterns {
		if strings.Contains(pattern, "@") {
			continue
		}

		lastSegment := pattern
		if idx := strings.LastIndex(pattern, "/"); idx >= 0 {
			lastSegment = pattern[idx+1:]
		}

		if strings.Contains(lastSegment, ":") {
			scoped = append(scoped, pattern)
		}
	}

	return scoped
}

// warnTagScopedPatterns warns about rule image patterns scoped to a tag. The
// runtime runs a digest-pinned reference by its digest and ignores the tag,
// which the pod author controls, so such patterns never match digest-pinned
// references: a tag-scoped rule cannot reliably tighten verification, since
// pinning a digest skips it.
func warnTagScopedPatterns(field string, patterns []string) {
	for _, pattern := range tagScopedPatterns(patterns) {
		// The rule also covers digest-pinned references of the repository.
		repository := pattern[:strings.LastIndex(pattern, ":")]

		if slices.ContainsFunc(patterns, func(other string) bool {
			return strings.HasPrefix(other, repository+"@")
		}) {
			continue
		}

		slog.Warn("Rule image pattern is scoped to a tag; it does not match digest-pinned "+
			"references, so it cannot be relied on to tighten verification",
			"field", field,
			"pattern", pattern,
		)
	}
}

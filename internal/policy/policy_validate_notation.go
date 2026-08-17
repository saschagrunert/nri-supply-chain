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
	"os"
	"path/filepath"

	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

func validateNotationCertFiles(
	prefix string, notationPolicy *NotationPolicy,
) []error {
	if notationPolicy == nil {
		return nil
	}

	var errs []error

	for idx, store := range notationPolicy.TrustStores {
		for cidx, certPath := range store.Certificates {
			label := fmt.Sprintf(
				"%snotation.trustStores[%d] %q: certificates[%d] file %q",
				prefix, idx, store.Name, cidx, certPath,
			)

			info, err := os.Lstat(certPath)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", label, err))

				continue
			}

			if info.Mode()&os.ModeSymlink != 0 {
				errs = append(errs, fmt.Errorf(
					"%s: %w (symlinks are not allowed)", label, ErrNotRegularFile,
				))

				continue
			}

			if !info.Mode().IsRegular() {
				errs = append(errs, fmt.Errorf("%s: %w", label, ErrNotRegularFile))
			}
		}
	}

	return errs
}

func (p *Policy) validateNotation() error {
	if p.Notation == nil {
		return nil
	}

	var errs []error

	if p.Notation.MissingPolicy != "" {
		err := types.ValidateAction(
			"notation.missingPolicy", p.Notation.MissingPolicy,
		)
		if err != nil {
			errs = append(errs, fmt.Errorf("validating notation policy: %w", err))
		}
	}

	errs = append(errs, validateNotationLevels(p.Notation)...)
	errs = append(errs, validateNotationTrustStores(p.Notation.TrustStores)...)
	errs = append(errs, validateNotationTrustPolicy(p.Notation.TrustPolicy)...)

	return errors.Join(errs...)
}

func validateNotationLevels(notation *NotationPolicy) []error {
	var errs []error

	if notation.VerificationLevel != "" {
		switch notation.VerificationLevel {
		case "strict", "permissive", "audit", notationLevelSkip:
		default:
			errs = append(errs, fmt.Errorf(
				"%w: got %q",
				ErrNotationVerificationLevelInvalid,
				notation.VerificationLevel,
			))
		}
	}

	if notation.RevocationMode != "" {
		switch notation.RevocationMode {
		case revocationModeStrict, revocationModeSoft, revocationModeSkip:
		default:
			errs = append(errs, fmt.Errorf(
				"%w: got %q",
				ErrNotationRevocationModeInvalid,
				notation.RevocationMode,
			))
		}
	}

	if notation.VerificationLevel == notationLevelSkip &&
		notation.RevocationMode != "" {
		errs = append(errs, ErrNotationRevocationWithSkipLevel)
	}

	return errs
}

func validateNotationTrustStores(stores []NotationTrustStore) []error {
	var errs []error

	seenNames := make(map[string]bool, len(stores))

	for idx, store := range stores {
		if store.Name == "" {
			errs = append(errs, fmt.Errorf(
				"%w: notation.trustStores[%d]",
				ErrNotationTrustStoreNameRequired, idx,
			))

			continue
		}

		if seenNames[store.Name] {
			errs = append(errs, fmt.Errorf(
				"%w %q at notation.trustStores[%d]",
				ErrDuplicateNotationTrustStoreName, store.Name, idx,
			))

			continue
		}

		seenNames[store.Name] = true

		if store.Type != "ca" && store.Type != "signingAuthority" {
			errs = append(errs, fmt.Errorf(
				"%w: notation.trustStores[%d] %q: got %q",
				ErrNotationTrustStoreTypeInvalid,
				idx, store.Name, store.Type,
			))
		}

		if len(store.Certificates) == 0 {
			errs = append(errs, fmt.Errorf(
				"%w: notation.trustStores[%d] %q",
				ErrNotationTrustStoreCertsRequired, idx, store.Name,
			))
		}

		errs = append(errs, validateNotationStoreCerts(idx, &store)...)
	}

	return errs
}

func validateNotationStoreCerts(idx int, store *NotationTrustStore) []error {
	var errs []error

	for cidx, cert := range store.Certificates {
		if cert == "" {
			errs = append(errs, fmt.Errorf(
				"%w in notation.trustStores[%d].certificates[%d]",
				ErrEmptyValue, idx, cidx,
			))

			continue
		}

		if !filepath.IsAbs(cert) {
			errs = append(errs, fmt.Errorf(
				"%w: notation.trustStores[%d] %q: certificates[%d] got %q",
				ErrNotationCertNotAbsolute, idx, store.Name, cidx, cert,
			))
		}
	}

	return errs
}

func validateNotationTrustPolicy(rules []NotationTrustPolicyRule) []error {
	errs := make([]error, 0, len(rules))

	seenNames := make(map[string]bool, len(rules))

	for idx, rule := range rules {
		errs = append(errs, validateSingleNotationTrustPolicy(
			idx, &rule, seenNames,
		)...)
	}

	return errs
}

func validateSingleNotationTrustPolicy(
	idx int, rule *NotationTrustPolicyRule, seenNames map[string]bool,
) []error {
	var errs []error

	if rule.Name == "" {
		return append(errs, fmt.Errorf(
			"%w: notation.trustPolicy[%d]",
			ErrNotationTrustPolicyNameRequired, idx,
		))
	}

	if seenNames[rule.Name] {
		return append(errs, fmt.Errorf(
			"%w %q at notation.trustPolicy[%d]",
			ErrDuplicateNotationTrustPolicyName, rule.Name, idx,
		))
	}

	seenNames[rule.Name] = true

	if len(rule.RegistryScopes) == 0 {
		errs = append(errs, fmt.Errorf(
			"%w: notation.trustPolicy[%d] %q",
			ErrNotationTrustPolicyScopesRequired, idx, rule.Name,
		))
	}

	if len(rule.TrustStores) == 0 {
		errs = append(errs, fmt.Errorf(
			"%w: notation.trustPolicy[%d] %q",
			ErrNotationTrustPolicyStoresRequired, idx, rule.Name,
		))
	}

	if len(rule.TrustedIdentities) == 0 {
		errs = append(errs, fmt.Errorf(
			"%w: notation.trustPolicy[%d] %q",
			ErrNotationTrustPolicyIdentitiesRequired, idx, rule.Name,
		))
	}

	errs = append(errs, validateNotationTrustPolicyFields(idx, rule)...)

	return errs
}

func validateNotationTrustPolicyFields(
	idx int, rule *NotationTrustPolicyRule,
) []error {
	var errs []error

	prefix := fmt.Sprintf("notation.trustPolicy[%d]", idx)

	err := validateNonEmpty(prefix+".registryScopes", rule.RegistryScopes)
	if err != nil {
		errs = append(errs, err)
	}

	err = validateNonEmpty(prefix+".trustStores", rule.TrustStores)
	if err != nil {
		errs = append(errs, err)
	}

	err = validateNonEmpty(prefix+".trustedIdentities", rule.TrustedIdentities)
	if err != nil {
		errs = append(errs, err)
	}

	return errs
}

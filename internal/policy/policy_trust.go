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
	"path/filepath"

	"github.com/saschagrunert/nri-supply-chain/internal/glob"
)

// Bound reports whether the verifier is bound to at least one signer (a key
// or a keyless identity). VSAs of unbound verifiers are never trusted.
func (v *TrustedVerifier) Bound() bool {
	return len(v.Keys) > 0 || len(v.Identities) > 0
}

// MatchesSigner reports whether an attestation signer is allowed to sign VSAs
// for this verifier. keyPath is the trusted key path that verified a
// key-based signature; issuer and san describe the certificate of a keyless
// signature. It returns false when the verifier is not bound to any signer.
func (v *TrustedVerifier) MatchesSigner(keyPath, issuer, san string) bool {
	return matchesSigner(v.Keys, v.Identities, keyPath, issuer, san)
}

// Bound reports whether the builder is bound to at least one signer (a key
// or a keyless identity). Provenance claiming an unbound builder is accepted
// from any trusted signer.
func (b *TrustedBuilder) Bound() bool {
	return len(b.Keys) > 0 || len(b.Identities) > 0
}

// MatchesSigner reports whether an attestation signer is allowed to sign
// provenance claiming this builder. It returns false when the builder is not
// bound; callers decide how to treat unbound builders using Bound.
func (b *TrustedBuilder) MatchesSigner(keyPath, issuer, san string) bool {
	return matchesSigner(b.Keys, b.Identities, keyPath, issuer, san)
}

func matchesSigner(
	keys []string, identities []TrustedIdentity, keyPath, issuer, san string,
) bool {
	return matchesKey(keys, keyPath) || matchesIdentity(identities, issuer, san)
}

func matchesKey(keys []string, keyPath string) bool {
	if keyPath == "" {
		return false
	}

	cleaned := filepath.Clean(keyPath)

	for _, key := range keys {
		if filepath.Clean(key) == cleaned {
			return true
		}
	}

	return false
}

func matchesIdentity(identities []TrustedIdentity, issuer, san string) bool {
	if issuer == "" || san == "" {
		return false
	}

	for _, identity := range identities {
		if identity.Issuer != issuer || identity.SANPattern == "" {
			continue
		}

		matched, err := glob.Match(identity.SANPattern, san)
		if err == nil && matched {
			return true
		}
	}

	return false
}

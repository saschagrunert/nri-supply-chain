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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

// EffectiveMode returns the per-namespace mode if set, otherwise the global mode.
func (p *Policy) EffectiveMode(global config.VerificationMode) config.VerificationMode {
	if p.Mode != "" {
		return p.Mode
	}

	return global
}

// MissingPolicyFor returns the effective missing-attestation policy for
// the given check type, defaulting to allow when the section or its
// missingPolicy is not set. New attestation types only need an entry in the
// section registry (and in AttestationCheckTypes).
func (p *Policy) MissingPolicyFor(ct types.CheckType) types.Action {
	spec := sectionForCheckType(ct)
	if spec == nil {
		return types.ActionAllow
	}

	if action := p.missingPolicy(spec); action != "" {
		return action
	}

	return types.ActionAllow
}

// SLSAMissingPolicy returns the effective SLSA missing policy.
func (p *Policy) SLSAMissingPolicy() types.Action { return p.MissingPolicyFor(types.CheckTypeSLSA) }

// VEXMissingPolicy returns the effective VEX missing policy.
func (p *Policy) VEXMissingPolicy() types.Action { return p.MissingPolicyFor(types.CheckTypeVEX) }

// VSAMissingPolicy returns the effective VSA missing policy.
func (p *Policy) VSAMissingPolicy() types.Action { return p.MissingPolicyFor(types.CheckTypeVSA) }

// NotationMissingPolicy returns the effective Notation missing policy.
func (p *Policy) NotationMissingPolicy() types.Action {
	return p.MissingPolicyFor(types.CheckTypeNotation)
}

// SBOMMissingPolicy returns the effective SBOM missing policy.
func (p *Policy) SBOMMissingPolicy() types.Action { return p.MissingPolicyFor(types.CheckTypeSBOM) }

// SCAIMissingPolicy returns the effective SCAI missing policy.
func (p *Policy) SCAIMissingPolicy() types.Action { return p.MissingPolicyFor(types.CheckTypeSCAI) }

// SourceMissingPolicy returns the effective source track missing policy.
func (p *Policy) SourceMissingPolicy() types.Action {
	return p.MissingPolicyFor(types.CheckTypeSource)
}

// BuildEnvMissingPolicy returns the effective build environment missing policy.
func (p *Policy) BuildEnvMissingPolicy() types.Action {
	return p.MissingPolicyFor(types.CheckTypeBuildEnv)
}

// VulnScanMissingPolicy returns the effective vulnerability scan missing policy.
func (p *Policy) VulnScanMissingPolicy() types.Action {
	return p.MissingPolicyFor(types.CheckTypeVulnScan)
}

// TestResultMissingPolicy returns the effective test result missing policy.
func (p *Policy) TestResultMissingPolicy() types.Action {
	return p.MissingPolicyFor(types.CheckTypeTestResult)
}

// ReleaseMissingPolicy returns the effective release missing policy.
func (p *Policy) ReleaseMissingPolicy() types.Action {
	return p.MissingPolicyFor(types.CheckTypeRelease)
}

// RuntimeTraceMissingPolicy returns the effective runtime trace missing policy.
func (p *Policy) RuntimeTraceMissingPolicy() types.Action {
	return p.MissingPolicyFor(types.CheckTypeRuntimeTrace)
}

// ScorecardMissingPolicy returns the effective OpenSSF Scorecard missing policy.
func (p *Policy) ScorecardMissingPolicy() types.Action {
	return p.MissingPolicyFor(types.CheckTypeScorecard)
}

// Builders returns the trusted builders list, or nil if trust is not configured.
func (p *Policy) Builders() []TrustedBuilder {
	if p.Trust != nil {
		return p.Trust.Builders
	}

	return nil
}

// Hash returns a SHA-256 hex digest of the policy's JSON representation and
// of the fields set explicitly in its document and rules. Merges treat an
// explicit zero value (e.g. false) differently from an omitted field, while
// the JSON representation omits both.
func (p *Policy) Hash() (string, error) {
	rulesExplicit := make([]map[string]bool, len(p.Rules))
	for idx := range p.Rules {
		rulesExplicit[idx] = p.Rules[idx].explicit
	}

	data, err := json.Marshal(struct {
		Policy        *Policy           `json:"policy"`
		Explicit      map[string]bool   `json:"explicit"`
		RulesExplicit []map[string]bool `json:"rulesExplicit"`
	}{
		Policy:        p,
		Explicit:      p.explicit,
		RulesExplicit: rulesExplicit,
	})
	if err != nil {
		return "", fmt.Errorf("hashing policy: %w", err)
	}

	sum := sha256.Sum256(data)

	return hex.EncodeToString(sum[:]), nil
}

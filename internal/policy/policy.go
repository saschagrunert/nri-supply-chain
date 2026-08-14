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

func missingPolicyOrAllow(action types.Action) types.Action {
	if action != "" {
		return action
	}

	return types.ActionAllow
}

// SLSAMissingPolicy returns the effective SLSA missing policy.
func (p *Policy) SLSAMissingPolicy() types.Action {
	if p.SLSA != nil {
		return missingPolicyOrAllow(p.SLSA.MissingPolicy)
	}

	return types.ActionAllow
}

// VEXMissingPolicy returns the effective VEX missing policy.
func (p *Policy) VEXMissingPolicy() types.Action {
	if p.VEX != nil {
		return missingPolicyOrAllow(p.VEX.MissingPolicy)
	}

	return types.ActionAllow
}

// VSAMissingPolicy returns the effective VSA missing policy.
func (p *Policy) VSAMissingPolicy() types.Action {
	if p.VSA != nil {
		return missingPolicyOrAllow(p.VSA.MissingPolicy)
	}

	return types.ActionAllow
}

// NotationMissingPolicy returns the effective Notation missing policy.
func (p *Policy) NotationMissingPolicy() types.Action {
	if p.Notation != nil {
		return missingPolicyOrAllow(p.Notation.MissingPolicy)
	}

	return types.ActionAllow
}

// SBOMMissingPolicy returns the effective SBOM missing policy.
func (p *Policy) SBOMMissingPolicy() types.Action {
	if p.SBOM != nil {
		return missingPolicyOrAllow(p.SBOM.MissingPolicy)
	}

	return types.ActionAllow
}

// SCAIMissingPolicy returns the effective SCAI missing policy.
func (p *Policy) SCAIMissingPolicy() types.Action {
	if p.SCAI != nil {
		return missingPolicyOrAllow(p.SCAI.MissingPolicy)
	}

	return types.ActionAllow
}

// SourceMissingPolicy returns the effective source track missing policy.
func (p *Policy) SourceMissingPolicy() types.Action {
	if p.Source != nil {
		return missingPolicyOrAllow(p.Source.MissingPolicy)
	}

	return types.ActionAllow
}

// BuildEnvMissingPolicy returns the effective build environment missing policy.
func (p *Policy) BuildEnvMissingPolicy() types.Action {
	if p.BuildEnv != nil {
		return missingPolicyOrAllow(p.BuildEnv.MissingPolicy)
	}

	return types.ActionAllow
}

// VulnScanMissingPolicy returns the effective vulnerability scan missing policy.
func (p *Policy) VulnScanMissingPolicy() types.Action {
	if p.VulnScan != nil {
		return missingPolicyOrAllow(p.VulnScan.MissingPolicy)
	}

	return types.ActionAllow
}

// TestResultMissingPolicy returns the effective test result missing policy.
func (p *Policy) TestResultMissingPolicy() types.Action {
	if p.TestResult != nil {
		return missingPolicyOrAllow(p.TestResult.MissingPolicy)
	}

	return types.ActionAllow
}

// ReleaseMissingPolicy returns the effective release missing policy.
func (p *Policy) ReleaseMissingPolicy() types.Action {
	if p.Release != nil {
		return missingPolicyOrAllow(p.Release.MissingPolicy)
	}

	return types.ActionAllow
}

// RuntimeTraceMissingPolicy returns the effective runtime trace missing policy.
func (p *Policy) RuntimeTraceMissingPolicy() types.Action {
	if p.RuntimeTrace != nil {
		return missingPolicyOrAllow(p.RuntimeTrace.MissingPolicy)
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

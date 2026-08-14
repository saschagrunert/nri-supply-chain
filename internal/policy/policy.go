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

// NotationMissingPolicy returns the effective Notation missing policy.
// Defaults to allow so that the plugin can be deployed in warn mode
// without requiring Notation signatures from the start.
func (p *Policy) NotationMissingPolicy() types.Action {
	if p.Notation != nil && p.Notation.MissingPolicy != "" {
		return p.Notation.MissingPolicy
	}

	return types.ActionAllow
}

// SBOMMissingPolicy returns the effective SBOM missing policy.
// Defaults to allow so that the plugin can be deployed in warn mode
// without requiring SBOM attestations from the start.
func (p *Policy) SBOMMissingPolicy() types.Action {
	if p.SBOM != nil && p.SBOM.MissingPolicy != "" {
		return p.SBOM.MissingPolicy
	}

	return types.ActionAllow
}

// SCAIMissingPolicy returns the effective SCAI missing policy.
// Defaults to allow so that the plugin can be deployed in warn mode
// without requiring SCAI attestations from the start.
func (p *Policy) SCAIMissingPolicy() types.Action {
	if p.SCAI != nil && p.SCAI.MissingPolicy != "" {
		return p.SCAI.MissingPolicy
	}

	return types.ActionAllow
}

// SourceMissingPolicy returns the effective source track missing policy.
func (p *Policy) SourceMissingPolicy() types.Action {
	if p.Source != nil && p.Source.MissingPolicy != "" {
		return p.Source.MissingPolicy
	}

	return types.ActionAllow
}

// BuildEnvMissingPolicy returns the effective build environment missing policy.
func (p *Policy) BuildEnvMissingPolicy() types.Action {
	if p.BuildEnv != nil && p.BuildEnv.MissingPolicy != "" {
		return p.BuildEnv.MissingPolicy
	}

	return types.ActionAllow
}

// VulnScanMissingPolicy returns the effective vulnerability scan missing policy.
func (p *Policy) VulnScanMissingPolicy() types.Action {
	if p.VulnScan != nil && p.VulnScan.MissingPolicy != "" {
		return p.VulnScan.MissingPolicy
	}

	return types.ActionAllow
}

// TestResultMissingPolicy returns the effective test result missing policy.
func (p *Policy) TestResultMissingPolicy() types.Action {
	if p.TestResult != nil && p.TestResult.MissingPolicy != "" {
		return p.TestResult.MissingPolicy
	}

	return types.ActionAllow
}

// ReleaseMissingPolicy returns the effective release missing policy.
func (p *Policy) ReleaseMissingPolicy() types.Action {
	if p.Release != nil && p.Release.MissingPolicy != "" {
		return p.Release.MissingPolicy
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

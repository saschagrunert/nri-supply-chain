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

// MissingPolicyFor returns the effective missing-attestation policy for
// the given check type. New attestation types only need a case here
// (and in AttestationCheckTypes) instead of a dedicated method.
func (p *Policy) MissingPolicyFor( //nolint:cyclop // one case per type
	ct types.CheckType,
) types.Action {
	switch ct { //nolint:exhaustive // only attestation types have missing policies
	case types.CheckTypeSLSA:
		if p.SLSA != nil {
			return missingPolicyOrAllow(p.SLSA.MissingPolicy)
		}
	case types.CheckTypeVEX:
		if p.VEX != nil {
			return missingPolicyOrAllow(p.VEX.MissingPolicy)
		}
	case types.CheckTypeVSA:
		if p.VSA != nil {
			return missingPolicyOrAllow(p.VSA.MissingPolicy)
		}
	case types.CheckTypeNotation:
		if p.Notation != nil {
			return missingPolicyOrAllow(p.Notation.MissingPolicy)
		}
	case types.CheckTypeSBOM:
		if p.SBOM != nil {
			return missingPolicyOrAllow(p.SBOM.MissingPolicy)
		}
	case types.CheckTypeSCAI:
		if p.SCAI != nil {
			return missingPolicyOrAllow(p.SCAI.MissingPolicy)
		}
	case types.CheckTypeSource:
		if p.Source != nil {
			return missingPolicyOrAllow(p.Source.MissingPolicy)
		}
	case types.CheckTypeBuildEnv:
		if p.BuildEnv != nil {
			return missingPolicyOrAllow(p.BuildEnv.MissingPolicy)
		}
	case types.CheckTypeVulnScan:
		if p.VulnScan != nil {
			return missingPolicyOrAllow(p.VulnScan.MissingPolicy)
		}
	case types.CheckTypeTestResult:
		if p.TestResult != nil {
			return missingPolicyOrAllow(p.TestResult.MissingPolicy)
		}
	case types.CheckTypeRelease:
		if p.Release != nil {
			return missingPolicyOrAllow(p.Release.MissingPolicy)
		}
	case types.CheckTypeRuntimeTrace:
		if p.RuntimeTrace != nil {
			return missingPolicyOrAllow(p.RuntimeTrace.MissingPolicy)
		}
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

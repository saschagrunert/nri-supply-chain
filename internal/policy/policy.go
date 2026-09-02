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

//nolint:gochecknoglobals // static accessor registry per check type
var missingPolicyAccessors = map[types.CheckType]func(*Sections) types.Action{
	types.CheckTypeSLSA: func(s *Sections) types.Action {
		if s.SLSA != nil {
			return s.SLSA.MissingPolicy
		}

		return ""
	},
	types.CheckTypeVEX: func(s *Sections) types.Action {
		if s.VEX != nil {
			return s.VEX.MissingPolicy
		}

		return ""
	},
	types.CheckTypeVSA: func(s *Sections) types.Action {
		if s.VSA != nil {
			return s.VSA.MissingPolicy
		}

		return ""
	},
	types.CheckTypeNotation: func(s *Sections) types.Action {
		if s.Notation != nil {
			return s.Notation.MissingPolicy
		}

		return ""
	},
	types.CheckTypeSBOM: func(s *Sections) types.Action {
		if s.SBOM != nil {
			return s.SBOM.MissingPolicy
		}

		return ""
	},
	types.CheckTypeSCAI: func(s *Sections) types.Action {
		if s.SCAI != nil {
			return s.SCAI.MissingPolicy
		}

		return ""
	},
	types.CheckTypeSource: func(s *Sections) types.Action {
		if s.Source != nil {
			return s.Source.MissingPolicy
		}

		return ""
	},
	types.CheckTypeBuildEnv: func(s *Sections) types.Action {
		if s.BuildEnv != nil {
			return s.BuildEnv.MissingPolicy
		}

		return ""
	},
	types.CheckTypeVulnScan: func(s *Sections) types.Action {
		if s.VulnScan != nil {
			return s.VulnScan.MissingPolicy
		}

		return ""
	},
	types.CheckTypeTestResult: func(s *Sections) types.Action {
		if s.TestResult != nil {
			return s.TestResult.MissingPolicy
		}

		return ""
	},
	types.CheckTypeRelease: func(s *Sections) types.Action {
		if s.Release != nil {
			return s.Release.MissingPolicy
		}

		return ""
	},
	types.CheckTypeRuntimeTrace: func(s *Sections) types.Action {
		if s.RuntimeTrace != nil {
			return s.RuntimeTrace.MissingPolicy
		}

		return ""
	},
	types.CheckTypeScorecard: func(s *Sections) types.Action {
		if s.Scorecard != nil {
			return s.Scorecard.MissingPolicy
		}

		return ""
	},
}

// MissingPolicyFor returns the effective missing-attestation policy for
// the given check type. New attestation types only need an entry in
// missingPolicyAccessors (and in AttestationCheckTypes).
func (p *Policy) MissingPolicyFor(ct types.CheckType) types.Action {
	if accessor, ok := missingPolicyAccessors[ct]; ok {
		return missingPolicyOrAllow(accessor(&p.Sections))
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

// Hash returns a SHA-256 hex digest of the policy's JSON representation.
func (p *Policy) Hash() (string, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("hashing policy: %w", err)
	}

	sum := sha256.Sum256(data)

	return hex.EncodeToString(sum[:]), nil
}

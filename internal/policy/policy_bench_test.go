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

package policy_test

import (
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

func BenchmarkMissingPolicyFor(b *testing.B) {
	pol := &policy.Policy{
		SLSA: &policy.SLSAPolicy{MissingPolicy: types.ActionDeny},
		VEX:  &policy.VEXPolicy{MissingPolicy: types.ActionWarn},
		SBOM: &policy.SBOMPolicy{MissingPolicy: types.ActionDeny},
	}

	b.ResetTimer()

	for range b.N {
		pol.MissingPolicyFor(types.CheckTypeSLSA)
	}
}

func BenchmarkMissingPolicyForUnset(b *testing.B) {
	pol := &policy.Policy{}

	b.ResetTimer()

	for range b.N {
		pol.MissingPolicyFor(types.CheckTypeSLSA)
	}
}

func BenchmarkEffectiveMode(b *testing.B) {
	pol := &policy.Policy{
		Mode: config.ModeEnforce,
	}

	b.ResetTimer()

	for range b.N {
		pol.EffectiveMode(config.ModeWarn)
	}
}

func BenchmarkEffectiveModeInherited(b *testing.B) {
	pol := &policy.Policy{}

	b.ResetTimer()

	for range b.N {
		pol.EffectiveMode(config.ModeWarn)
	}
}

func BenchmarkPolicyHash(b *testing.B) {
	pol := &policy.Policy{
		Trust: &policy.TrustPolicy{
			Builders: []policy.TrustedBuilder{{
				ID: "https://github.com/slsa-framework/slsa-github-generator/" +
					".github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0",
				MaxLevel: 3,
			}},
			Issuers:     []string{testGitHubIssuer},
			SANPatterns: []string{testGitHubSANPattern},
			Sources:     []string{testGitHubSANPattern},
		},
		SLSA: &policy.SLSAPolicy{MissingPolicy: types.ActionDeny},
		VEX:  &policy.VEXPolicy{MissingPolicy: types.ActionDeny},
		SBOM: &policy.SBOMPolicy{MissingPolicy: types.ActionDeny},
	}

	b.ResetTimer()

	for range b.N {
		_, _ = pol.Hash()
	}
}

func BenchmarkMergeWithDefault(b *testing.B) {
	defaultPol := &policy.Policy{
		Trust: &policy.TrustPolicy{
			Issuers:     []string{testGitHubIssuer},
			SANPatterns: []string{testGitHubSANPattern},
		},
		SLSA: &policy.SLSAPolicy{MissingPolicy: types.ActionDeny},
		VEX:  &policy.VEXPolicy{MissingPolicy: types.ActionWarn},
		SBOM: &policy.SBOMPolicy{MissingPolicy: types.ActionAllow},
	}

	nsPol := &policy.Policy{
		Mode: config.ModeEnforce,
		SLSA: &policy.SLSAPolicy{MissingPolicy: types.ActionDeny},
	}

	b.ResetTimer()

	for range b.N {
		policy.MergeWithDefault(nsPol, defaultPol)
	}
}

func BenchmarkApplyRule(b *testing.B) {
	base := &policy.Policy{
		Trust: &policy.TrustPolicy{
			Issuers:     []string{testGitHubIssuer},
			SANPatterns: []string{testGitHubSANPattern},
		},
		SLSA: &policy.SLSAPolicy{MissingPolicy: types.ActionDeny},
		VEX:  &policy.VEXPolicy{MissingPolicy: types.ActionWarn},
	}

	rule := &policy.ImageRule{
		Images: []string{"ghcr.io/saschagrunert/*"},
		SBOM:   &policy.SBOMPolicy{MissingPolicy: types.ActionDeny},
	}

	b.ResetTimer()

	for range b.N {
		policy.ApplyRule(base, rule)
	}
}

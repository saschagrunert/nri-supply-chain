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
	"slices"

	celengine "github.com/saschagrunert/nri-supply-chain/internal/cel"
)

// MergeWithDefault creates a new policy by starting from a copy of the default
// policy and overriding fields that are set in the namespace policy. Each
// top-level section (Trust, Include, Exclude, SLSA, VEX, VSA, Signatures,
// Notation, SBOM, SCAI, Source, BuildEnv, VulnScan, TestResult, CEL, Rules) is
// replaced entirely if set in the namespace policy. The Inherits field is
// cleared on the result. Inherited structs are shallow-copied to prevent
// mutations from affecting the default.
func MergeWithDefault(namespace, defaultPol *Policy) *Policy {
	merged := clonePolicy(defaultPol)

	if namespace.Mode != "" {
		merged.Mode = namespace.Mode
	}

	if namespace.Include != nil {
		merged.Include = slices.Clone(namespace.Include)
	}

	if namespace.Exclude != nil {
		merged.Exclude = slices.Clone(namespace.Exclude)
	}

	applySections(&merged.Sections, namespace.Sections)

	// When the namespace overrides CEL, use its compiled programs
	// instead of the default's. Both were compiled during Load().
	if namespace.CEL != nil {
		merged.CompiledCEL = namespace.CompiledCEL
	}

	if namespace.Rules != nil {
		merged.Rules = cloneRules(namespace.Rules)
	}

	return merged
}

func clonePolicy(pol *Policy) *Policy {
	clone := &Policy{
		Mode:        pol.Mode,
		Include:     slices.Clone(pol.Include),
		Exclude:     slices.Clone(pol.Exclude),
		Sections:    cloneSections(&pol.Sections),
		CompiledCEL: pol.CompiledCEL, // compiled programs are read-only, safe to share
	}

	if pol.Rules != nil {
		clone.Rules = cloneRules(pol.Rules)
	}

	return clone
}

// ApplyRule creates a new policy by cloning the base and overriding fields
// that are set in the rule. The returned policy has Rules cleared.
func ApplyRule(base *Policy, rule *ImageRule) *Policy {
	resolved := clonePolicy(base)
	resolved.Rules = nil

	applySections(&resolved.Sections, rule.Sections)

	// When the rule overrides CEL, use its compiled programs.
	if rule.CompiledCEL != nil {
		resolved.CompiledCEL = rule.CompiledCEL
	}

	return resolved
}

func cloneRules(rules []ImageRule) []ImageRule {
	cloned := make([]ImageRule, len(rules))

	for idx := range rules {
		cloned[idx] = ImageRule{
			Images:      slices.Clone(rules[idx].Images),
			Sections:    cloneSections(&rules[idx].Sections),
			CompiledCEL: rules[idx].CompiledCEL, // compiled programs are read-only, safe to share
		}
	}

	return cloned
}

func cloneSections(src *Sections) Sections {
	var dst Sections
	applySections(&dst, *src)

	return dst
}

//nolint:cyclop,funlen // one branch per section type
func applySections(dst *Sections, src Sections) { //nolint:gocritic // value param avoids nil checks
	if src.Trust != nil {
		dst.Trust = cloneTrust(src.Trust)
	}

	if src.SLSA != nil {
		sp := *src.SLSA
		sp.KnownParameters = slices.Clone(sp.KnownParameters)
		dst.SLSA = &sp
	}

	if src.VEX != nil {
		v := *src.VEX
		dst.VEX = &v
	}

	if src.VSA != nil {
		v := *src.VSA
		dst.VSA = &v
	}

	if src.Signatures != nil {
		s := *src.Signatures
		dst.Signatures = &s
	}

	if src.Notation != nil {
		dst.Notation = cloneNotation(src.Notation)
	}

	if src.CEL != nil {
		dst.CEL = cloneCEL(src.CEL)
	}

	if src.SBOM != nil {
		dst.SBOM = cloneSBOM(src.SBOM)
	}

	if src.SCAI != nil {
		dst.SCAI = cloneSCAI(src.SCAI)
	}

	if src.Source != nil {
		s := *src.Source
		dst.Source = &s
	}

	if src.BuildEnv != nil {
		dst.BuildEnv = cloneBuildEnv(src.BuildEnv)
	}

	if src.VulnScan != nil {
		dst.VulnScan = cloneVulnScan(src.VulnScan)
	}

	if src.TestResult != nil {
		dst.TestResult = cloneTestResult(src.TestResult)
	}

	if src.Release != nil {
		dst.Release = cloneRelease(src.Release)
	}
}

func cloneNotation(notationPolicy *NotationPolicy) *NotationPolicy {
	clone := *notationPolicy

	if notationPolicy.TrustStores != nil {
		clone.TrustStores = make([]NotationTrustStore, len(notationPolicy.TrustStores))

		for idx, ts := range notationPolicy.TrustStores {
			clone.TrustStores[idx] = NotationTrustStore{
				Name:         ts.Name,
				Type:         ts.Type,
				Certificates: slices.Clone(ts.Certificates),
			}
		}
	}

	if notationPolicy.TrustPolicy != nil {
		clone.TrustPolicy = make(
			[]NotationTrustPolicyRule, len(notationPolicy.TrustPolicy),
		)

		for idx, rule := range notationPolicy.TrustPolicy {
			clone.TrustPolicy[idx] = NotationTrustPolicyRule{
				Name:              rule.Name,
				RegistryScopes:    slices.Clone(rule.RegistryScopes),
				TrustStores:       slices.Clone(rule.TrustStores),
				TrustedIdentities: slices.Clone(rule.TrustedIdentities),
			}
		}
	}

	return &clone
}

func cloneTrust(tp *TrustPolicy) *TrustPolicy {
	trust := *tp
	trust.Builders = slices.Clone(trust.Builders)
	trust.Verifiers = slices.Clone(trust.Verifiers)

	for idx := range trust.Verifiers {
		trust.Verifiers[idx].Keys = slices.Clone(trust.Verifiers[idx].Keys)
	}

	trust.Issuers = slices.Clone(trust.Issuers)
	trust.SANPatterns = slices.Clone(trust.SANPatterns)
	trust.Sources = slices.Clone(trust.Sources)
	trust.BuildTypes = slices.Clone(trust.BuildTypes)

	return &trust
}

func cloneCEL(src *celengine.Policy) *celengine.Policy {
	cloned := &celengine.Policy{
		Rules: make([]celengine.Rule, len(src.Rules)),
	}

	copy(cloned.Rules, src.Rules)

	return cloned
}

func cloneSCAI(src *SCAIPolicy) *SCAIPolicy {
	clone := *src
	clone.RequiredAttributes = slices.Clone(clone.RequiredAttributes)
	clone.ForbiddenAttributes = slices.Clone(clone.ForbiddenAttributes)

	return &clone
}

func cloneSBOM(src *SBOMPolicy) *SBOMPolicy {
	clone := *src
	clone.Formats = slices.Clone(clone.Formats)

	if clone.License != nil {
		lic := *clone.License
		lic.Deny = slices.Clone(lic.Deny)
		lic.Allow = slices.Clone(lic.Allow)
		clone.License = &lic
	}

	if clone.Component != nil {
		comp := *clone.Component
		comp.Deny = slices.Clone(comp.Deny)
		comp.Allow = slices.Clone(comp.Allow)
		clone.Component = &comp
	}

	if clone.CVSS != nil {
		cvss := *clone.CVSS
		cvss.IgnoreCVEs = slices.Clone(cvss.IgnoreCVEs)

		if cvss.MaxScore != nil {
			score := *cvss.MaxScore
			cvss.MaxScore = &score
		}

		clone.CVSS = &cvss
	}

	return &clone
}

func cloneBuildEnv(src *BuildEnvPolicy) *BuildEnvPolicy {
	clone := *src
	clone.RequiredProperties = slices.Clone(clone.RequiredProperties)
	clone.ForbiddenProperties = slices.Clone(clone.ForbiddenProperties)

	return &clone
}

func cloneVulnScan(src *VulnScanPolicy) *VulnScanPolicy {
	clone := *src
	clone.IgnoreCVEs = slices.Clone(clone.IgnoreCVEs)

	if clone.MaxScore != nil {
		score := *clone.MaxScore
		clone.MaxScore = &score
	}

	return &clone
}

func cloneTestResult(src *TestResultPolicy) *TestResultPolicy {
	clone := *src
	clone.RequiredSuites = slices.Clone(clone.RequiredSuites)

	return &clone
}

func cloneRelease(src *ReleasePolicy) *ReleasePolicy {
	clone := *src
	clone.TrustedRegistries = slices.Clone(clone.TrustedRegistries)

	return &clone
}

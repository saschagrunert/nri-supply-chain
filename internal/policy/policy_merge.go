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
)

// MergeWithDefault creates a new policy by starting from a deep copy of the
// default policy and overlaying the namespace policy. Mode, Include, Exclude
// and Rules are replaced when set. Sections are merged field by field (see
// mergeSections): a field set in the namespace policy replaces the default
// value, while omitted fields keep it, so overriding slsa.maxAge keeps the
// default slsa.missingPolicy. The CEL section is replaced as a whole. The
// Inherits field is cleared on the result.
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

	mergeSections(&merged.Sections, &namespace.Sections)

	// When the namespace overrides CEL, use its compiled programs
	// instead of the default's. Both were compiled during Load().
	if namespace.CEL != nil {
		merged.CompiledCEL = namespace.CompiledCEL
	}

	if namespace.Rules != nil {
		merged.Rules = cloneRules(namespace.Rules)
	}

	merged.explicit = nil

	return merged
}

func clonePolicy(pol *Policy) *Policy {
	clone := &Policy{
		Version:     pol.Version,
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

// ApplyRule creates a new policy by cloning the base and overlaying the rule
// with the same field by field semantics as MergeWithDefault. The returned
// policy has Rules cleared.
func ApplyRule(base *Policy, rule *ImageRule) *Policy {
	resolved := clonePolicy(base)
	resolved.Rules = nil

	mergeSections(&resolved.Sections, &rule.Sections)

	// When the rule overrides CEL (even with an empty rule list), use its
	// compiled programs, matching MergeWithDefault.
	if rule.CEL != nil {
		resolved.CompiledCEL = rule.CompiledCEL
	}

	resolved.explicit = nil

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

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

//nolint:testpackage // testing unexported functions
package notation

import (
	"errors"
	"slices"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
)

const testNginxScope = "docker.io/library/nginx"

func scopeRule(name string, scopes ...string) policy.NotationTrustPolicyRule {
	return policy.NotationTrustPolicyRule{
		Name:              name,
		RegistryScopes:    scopes,
		TrustStores:       []string{testStoreRef},
		TrustedIdentities: []string{"*"},
	}
}

// TestNormalizedDuplicateScopesAreMerged checks that two spellings of the
// same repository in one rule do not make notation-go reject the trust
// policy, which would fail every Notation check of the loaded policy.
func TestNormalizedDuplicateScopesAreMerged(t *testing.T) {
	t.Parallel()

	notationPolicy := validNotationPolicy(t)
	notationPolicy.TrustPolicy = []policy.NotationTrustPolicyRule{
		scopeRule(testRuleName, "docker.io/nginx", testNginxScope, "index.docker.io/nginx"),
	}

	doc := buildTrustPolicyDocument(notationPolicy)

	got := doc.TrustPolicies[0].RegistryScopes
	if !slices.Equal(got, []string{testNginxScope}) {
		t.Errorf("registry scopes = %v, want [%s]", got, testNginxScope)
	}

	err := ValidatePolicy(notationPolicy)
	if err != nil {
		t.Fatalf("ValidatePolicy() error: %v", err)
	}

	_, trustPolicyName, err := buildVerifierForImage(notationPolicy, testNginxScope+"@"+testDigest)
	if err != nil {
		t.Fatalf("buildVerifierForImage() error: %v", err)
	}

	if trustPolicyName != testRuleName {
		t.Errorf("trust policy = %q, want %q", trustPolicyName, testRuleName)
	}
}

// TestValidatePolicyRejectsScopesSharedAcrossRules checks that two rules
// whose scopes normalize to the same repository are reported when the policy
// is validated.
func TestValidatePolicyRejectsScopesSharedAcrossRules(t *testing.T) {
	t.Parallel()

	err := ValidatePolicy(&policy.NotationPolicy{
		TrustPolicy: []policy.NotationTrustPolicyRule{
			scopeRule(testRuleName, "docker.io/nginx"),
			scopeRule("rule2", testNginxScope),
		},
	})
	if !errors.Is(err, ErrBuildTrustPolicy) {
		t.Fatalf("ValidatePolicy() error = %v, want %v", err, ErrBuildTrustPolicy)
	}

	err = ValidatePolicy(nil)
	if err != nil {
		t.Errorf("ValidatePolicy(nil) error: %v", err)
	}
}

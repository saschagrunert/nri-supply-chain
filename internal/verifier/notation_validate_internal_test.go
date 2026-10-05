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

package verifier

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/notation"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
)

// TestValidatePoliciesRuntimeRejectsCollidingNotationScopes checks that a
// Notation trust policy notation-go would reject, here two rules whose scopes
// normalize to the same repository, fails at policy load instead of failing
// every Notation check later.
func TestValidatePoliciesRuntimeRejectsCollidingNotationScopes(t *testing.T) {
	t.Parallel()

	const trustPolicy = `"trustPolicy": [
		{"name": "a", "registryScopes": ["docker.io/nginx"],
		 "trustStores": ["ca:store"], "trustedIdentities": ["*"]},
		{"name": "b", "registryScopes": ["docker.io/library/nginx"],
		 "trustStores": ["ca:store"], "trustedIdentities": ["*"]}
	]`

	for name, doc := range map[string]string{
		"base policy": `{"notation": {` + trustPolicy + `}}`,
		"rule":        `{"rules": [{"images": ["docker.io/*"], "notation": {` + trustPolicy + `}}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var pol policy.Policy

			err := json.Unmarshal([]byte(doc), &pol)
			if err != nil {
				t.Fatalf("decoding policy: %v", err)
			}

			err = validatePoliciesRuntime(map[string]*policy.Policy{"": &pol})
			if !errors.Is(err, notation.ErrBuildTrustPolicy) {
				t.Fatalf("validatePoliciesRuntime() error = %v, want %v",
					err, notation.ErrBuildTrustPolicy)
			}
		})
	}
}

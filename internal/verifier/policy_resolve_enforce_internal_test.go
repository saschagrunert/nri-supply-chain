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
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
)

func TestValidatePoliciesAgainstConfigPolicyEnforces(t *testing.T) {
	t.Parallel()

	enforcing := map[string]*policy.Policy{
		"":     {Mode: ""},
		"prod": {Mode: config.ModeEnforce},
	}
	warning := map[string]*policy.Policy{"": {Mode: ""}}

	issuersOnly := config.DefaultConfig()
	issuersOnly.Verification = config.ModeWarn
	issuersOnly.Policy.Source = config.PolicySourceOCI
	issuersOnly.Policy.OCIRef = "ghcr.io/org/policies:v1"
	issuersOnly.Policy.Issuers = []string{"https://token.actions.githubusercontent.com"}

	err := validatePoliciesAgainstConfig(issuersOnly, enforcing)
	testutil.AssertErrorIs(t, err, config.ErrIssuersWithoutSANPatternsInEnforce)

	err = validatePoliciesAgainstConfig(issuersOnly, warning)
	testutil.AssertNoError(t, err)

	issuersOnly.Policy.SANPatterns = []string{"https://github.com/org/policies/**"}

	err = validatePoliciesAgainstConfig(issuersOnly, enforcing)
	testutil.AssertNoError(t, err)

	cleartextGUAC := config.DefaultConfig()
	cleartextGUAC.Verification = config.ModeWarn
	cleartextGUAC.Guac.Endpoint = "http://guac.example.com/query"

	err = validatePoliciesAgainstConfig(cleartextGUAC, enforcing)
	testutil.AssertErrorIs(t, err, config.ErrGUACEndpointNotHTTPS)

	err = validatePoliciesAgainstConfig(cleartextGUAC, warning)
	testutil.AssertNoError(t, err)

	cleartextGUAC.Guac.Endpoint = "https://guac.example.com/query"

	err = validatePoliciesAgainstConfig(cleartextGUAC, enforcing)
	testutil.AssertNoError(t, err)
}

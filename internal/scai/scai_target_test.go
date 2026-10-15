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

package scai_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/scai"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
)

func TestVerifyTargetedAssertions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		assertion  string
		pol        *policy.SCAIPolicy
		wantPass   bool
		wantDetail string
	}{
		{
			name:       "assertion about another target does not satisfy required",
			assertion:  `{"attribute":"FUZZ_TESTED","target":{"name":"libfoo","digest":{"sha256":"abc"}}}`,
			pol:        &policy.SCAIPolicy{RequiredAttributes: []string{testAttrFuzzTested}},
			wantPass:   false,
			wantDetail: `"FUZZ_TESTED" (only asserted for another target)`,
		},
		{
			// The conditions describe how the attribute arose, as in the
			// WITH_STACK_PROTECTION example of the SCAI specification.
			name:       "assertion with conditions satisfies required",
			assertion:  `{"attribute":"FUZZ_TESTED","conditions":{"flags":"-fsanitize=fuzzer"}}`,
			pol:        &policy.SCAIPolicy{RequiredAttributes: []string{testAttrFuzzTested}},
			wantPass:   true,
			wantDetail: "",
		},
		{
			name:       "null target satisfies required",
			assertion:  `{"attribute":"FUZZ_TESTED","target":null}`,
			pol:        &policy.SCAIPolicy{RequiredAttributes: []string{testAttrFuzzTested}},
			wantPass:   true,
			wantDetail: "",
		},
		{
			name:       "empty target satisfies required",
			assertion:  `{"attribute":"FUZZ_TESTED","target":{}}`,
			pol:        &policy.SCAIPolicy{RequiredAttributes: []string{testAttrFuzzTested}},
			wantPass:   true,
			wantDetail: "",
		},
		{
			name:       "conditional assertion about another target does not satisfy required",
			assertion:  `{"attribute":"FUZZ_TESTED","target":{"name":"libfoo"},"conditions":{"a":"b"}}`,
			pol:        &policy.SCAIPolicy{RequiredAttributes: []string{testAttrFuzzTested}},
			wantPass:   false,
			wantDetail: "only asserted for another target",
		},
		{
			name:       "missing attribute is reported",
			assertion:  `{"attribute":"PASSED_TESTS"}`,
			pol:        &policy.SCAIPolicy{RequiredAttributes: []string{testAttrFuzzTested}},
			wantPass:   false,
			wantDetail: `required attribute missing: "FUZZ_TESTED"`,
		},
		{
			name:       "forbidden attribute about another target still fails",
			assertion:  `{"attribute":"KNOWN_VULNERABLE","target":{"name":"libfoo"}}`,
			pol:        &policy.SCAIPolicy{ForbiddenAttributes: []string{testAttrKnownVulnerable}},
			wantPass:   false,
			wantDetail: `forbidden attribute present: "KNOWN_VULNERABLE"`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			predicate := json.RawMessage(`{"attributes":[` + test.assertion + `]}`)
			att := testutil.WrapInToto(t, predicate, testDigest, testPredicateType)

			result, err := scai.VerifyMultiple(
				context.Background(), [][]byte{att}, &policy.Policy{SCAI: test.pol}, testDigest,
			)
			testutil.AssertNoError(t, err)

			if result.Passed != test.wantPass {
				t.Errorf(
					"expected Passed=%v, got %v (%s)",
					test.wantPass,
					result.Passed,
					result.Detail,
				)
			}

			if !strings.Contains(result.Detail, test.wantDetail) {
				t.Errorf("expected detail to contain %q, got %q", test.wantDetail, result.Detail)
			}
		})
	}
}

func TestVerifyMetadataListsSubjectAttributes(t *testing.T) {
	t.Parallel()

	predicate := json.RawMessage(`{"attributes":[{"attribute":"PASSED_TESTS"},` +
		`{"attribute":"FUZZ_TESTED","target":{"name":"libfoo"}}]}`)
	att := testutil.WrapInToto(t, predicate, testDigest, testPredicateType)

	result, err := scai.VerifyMultiple(
		context.Background(),
		[][]byte{att},
		&policy.Policy{},
		testDigest,
	)
	testutil.AssertNoError(t, err)
	testutil.AssertEqual[any](t, "PASSED_TESTS", result.Metadata["attributes"])
	testutil.AssertEqual[any](t, int64(1), result.Metadata["attributeCount"])
}

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

package slsa_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/slsa"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
)

// buildKitParametersV02 are the invocation.parameters of BuildKit v0.2
// provenance.
const buildKitParametersV02 = `{
	"frontend": "dockerfile.v0",
	"args": {"build-arg:VERSION": "1.0", "label:org.opencontainers.image.source": "x"},
	"locals": [{"name": "context"}, {"name": "dockerfile"}]
}`

func TestVerifyV02RejectsUnknownParameters(t *testing.T) {
	t.Parallel()

	t.Cleanup(slsa.ResetWarnings)

	tests := []struct {
		name       string
		parameters string
		reject     bool
		known      []string
		wantPass   bool
		wantDetail string
	}{
		{
			name:       "unknown parameter rejected",
			parameters: `{"extra":"x"}`,
			reject:     true,
			known:      nil,
			wantPass:   false,
			wantDetail: `unrecognized external parameters: "extra"`,
		},
		{
			name:       "known parameter accepted",
			parameters: `{"workflow":"build.yml"}`,
			reject:     true,
			known:      nil,
			wantPass:   true,
			wantDetail: "",
		},
		{
			name:       "empty parameters accepted",
			parameters: `{}`,
			reject:     true,
			known:      nil,
			wantPass:   true,
			wantDetail: "",
		},
		{
			name:       "missing parameters accepted",
			parameters: ``,
			reject:     true,
			known:      nil,
			wantPass:   true,
			wantDetail: "",
		},
		{
			name:       "non-object parameters rejected",
			parameters: `["extra"]`,
			reject:     true,
			known:      nil,
			wantPass:   false,
			wantDetail: "invocation.parameters is not an object",
		},
		{
			name:       "unknown parameter without rejection",
			parameters: `{"extra":"x"}`,
			reject:     false,
			known:      nil,
			wantPass:   true,
			wantDetail: "",
		},
		{
			name:       "BuildKit parameters rejected by the default set",
			parameters: buildKitParametersV02,
			reject:     true,
			known:      nil,
			wantPass:   false,
			// The first unknown key in sorted order is reported.
			wantDetail: `unrecognized external parameters: "args"`,
		},
		{
			name:       "BuildKit parameters accepted when known",
			parameters: buildKitParametersV02,
			reject:     true,
			known:      []string{"frontend", "args", "locals"},
			wantPass:   true,
			wantDetail: "",
		},
		{
			name:       "known parameters replace the default set",
			parameters: `{"workflow":"build.yml"}`,
			reject:     true,
			known:      []string{"frontend", "args", "locals"},
			wantPass:   false,
			wantDetail: `unrecognized external parameters: "workflow"`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			stmt := validStatementV02()
			if test.parameters != "" {
				stmt.Predicate.Invocation.Parameters = json.RawMessage(test.parameters)
			}

			pol := &policy.Policy{
				Trust: &policy.TrustPolicy{Builders: []policy.TrustedBuilder{{ID: testBuilderID}}},
				SLSA: &policy.SLSAPolicy{
					RejectUnknownParameters: test.reject,
					KnownParameters:         test.known,
				},
			}

			result, err := slsa.VerifyMultipleWithOptions(
				context.Background(),
				[]attestation.VerifiedAttestation{{Payload: testutil.MustMarshal(t, stmt)}},
				pol, testDigest, nil,
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

			if test.wantDetail != "" && !strings.Contains(result.Detail, test.wantDetail) {
				t.Errorf("expected detail to contain %q, got %q", test.wantDetail, result.Detail)
			}
		})
	}
}

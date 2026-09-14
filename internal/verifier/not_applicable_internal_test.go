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
	"context"
	"encoding/json"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

func TestVEXOnlyCycloneDXAppliesSBOMMissingPolicy(t *testing.T) {
	t.Parallel()

	vexOnly := testutil.WrapInToto(t, json.RawMessage(
		`{"bomFormat":"CycloneDX","vulnerabilities":[{"id":"CVE-2024-1",`+
			`"analysis":{"state":"not_affected"}}]}`,
	), benchDigest, attestation.PredicateCycloneDX)

	bins := binAttestations(context.Background(), []attestation.VerifiedAttestation{{
		PredicateType: attestation.PredicateCycloneDX,
		Payload:       vexOnly,
		Digest:        benchDigest,
	}}, "")

	var sbomSpec *checkSpec

	for idx := range checkSpecs {
		if checkSpecs[idx].checkType == types.CheckTypeSBOM {
			sbomSpec = &checkSpecs[idx]
		}
	}

	pol := &policy.Policy{SBOM: &policy.SBOMPolicy{MissingPolicy: types.ActionDeny}}

	result := runAttestationCheck(context.Background(), sbomSpec, &checkInput{
		bins: bins, pol: pol, imageRef: "ghcr.io/org/app:v1", digest: benchDigest,
		relatedDigests: nil, parsedRef: nil,
	}, metrics.New())

	if result.Passed || !result.Missing {
		t.Errorf("expected the SBOM missing policy (deny) to apply, got %+v", result)
	}
}

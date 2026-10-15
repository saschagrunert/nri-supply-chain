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

package cyclonedxvex_test

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
	"github.com/saschagrunert/nri-supply-chain/internal/vex/cyclonedxvex"
)

func TestVerifyRejectsComponentsNestedTooDeep(t *testing.T) {
	t.Parallel()

	const leafRef = "leaf"

	nested := cdx.Component{BOMRef: leafRef, Type: cdx.ComponentTypeLibrary, Name: leafRef}
	for range types.MaxComponentDepth + 1 {
		nested = cdx.Component{
			Type: cdx.ComponentTypeLibrary, Name: "n", Components: &[]cdx.Component{nested},
		}
	}

	bom := cdx.NewBOM()
	bom.Components = &[]cdx.Component{nested}
	bom.Vulnerabilities = &[]cdx.Vulnerability{{
		ID:       testCVE,
		Analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASResolved},
		Affects:  &[]cdx.Affects{{Ref: leafRef}},
	}}

	_, err := cyclonedxvex.Verify(testutil.MustMarshal(t, bom), testImage())
	testutil.AssertErrorIs(t, err, types.ErrComponentsTooDeep)
}

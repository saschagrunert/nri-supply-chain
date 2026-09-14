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
	"github.com/saschagrunert/nri-supply-chain/internal/vex/cyclonedxvex"
	"github.com/saschagrunert/nri-supply-chain/internal/vex/imagematch"
)

func TestVerifyLenientExcludesOtherImageNames(t *testing.T) {
	t.Parallel()

	multiImage := func(affectsRef string) *cdx.BOM {
		bom := cdx.NewBOM()
		bom.Components = &[]cdx.Component{{
			BOMRef: "app-b", Type: cdx.ComponentTypeContainer, Name: "app-b",
			PackageURL: "pkg:oci/app-b",
		}}
		bom.Vulnerabilities = &[]cdx.Vulnerability{{
			ID:       testCVE,
			Analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASExploitable},
			Affects:  &[]cdx.Affects{{Ref: affectsRef}},
		}}

		return bom
	}

	tests := []struct {
		name        string
		bom         *cdx.BOM
		wantMatched int
	}{
		{name: "component of another image", bom: multiImage("app-b"), wantMatched: 0},
		{
			name: "direct purl of another image", bom: multiImage("pkg:oci/app-b?tag=v1"),
			wantMatched: 0,
		},
		{
			name:        "direct purl of the image with another tag",
			bom:         multiImage("pkg:oci/app-a?tag=v9"),
			wantMatched: 1,
		},
		{
			name: "unknown bom-ref stays lenient", bom: multiImage("ref-from-separate-sbom"),
			wantMatched: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			image := imagematch.New("ghcr.io/team/app-a:v1", testDigest, nil)

			result, err := cyclonedxvex.Verify(testutil.MustMarshal(t, test.bom), image)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.MatchedVulnerabilities != test.wantMatched {
				t.Errorf("matched = %d, want %d (%+v)",
					result.MatchedVulnerabilities, test.wantMatched, result)
			}
		})
	}
}

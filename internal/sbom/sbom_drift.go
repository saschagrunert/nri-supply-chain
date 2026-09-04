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

package sbom

import (
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	driftWeightAdded    = 3
	driftWeightModified = 2
	driftWeightRemoved  = 1
)

type driftResult struct {
	Added         []sbomPackage
	Removed       []sbomPackage
	Modified      []sbomPackage
	AddedCount    int
	RemovedCount  int
	ModifiedCount int
	Score         float64
}

func computeDrift(baseline, current []sbomPackage) driftResult {
	baselineMap := indexByPURL(baseline)
	currentMap := indexByPURL(current)

	var result driftResult

	for purl, cur := range currentMap {
		base, exists := baselineMap[purl]
		if !exists {
			result.Added = append(result.Added, cur)

			continue
		}

		if packageModified(&base, &cur) {
			result.Modified = append(result.Modified, cur)
		}
	}

	for purl, base := range baselineMap {
		if _, exists := currentMap[purl]; !exists {
			result.Removed = append(result.Removed, base)
		}
	}

	slices.SortFunc(result.Added, cmpByPURL)
	slices.SortFunc(result.Removed, cmpByPURL)
	slices.SortFunc(result.Modified, cmpByPURL)

	result.AddedCount = len(result.Added)
	result.RemovedCount = len(result.Removed)
	result.ModifiedCount = len(result.Modified)

	if len(baselineMap) > 0 {
		numerator := float64(
			result.AddedCount*driftWeightAdded +
				result.ModifiedCount*driftWeightModified +
				result.RemovedCount*driftWeightRemoved,
		)
		result.Score = numerator / float64(len(baselineMap))
	}

	return result
}

func indexByPURL(pkgs []sbomPackage) map[string]sbomPackage {
	index := make(map[string]sbomPackage, len(pkgs))

	skipped := 0

	for idx := range pkgs {
		if pkgs[idx].PURL != "" {
			index[pkgs[idx].PURL] = pkgs[idx]
		} else {
			skipped++
		}
	}

	if skipped > 0 {
		slog.Warn("Packages without PURL excluded from drift tracking",
			"skipped", skipped, "total", len(pkgs))
	}

	return index
}

//nolint:gocritic // required by slices.SortFunc signature
func cmpByPURL(left, right sbomPackage) int {
	return strings.Compare(left.PURL, right.PURL)
}

func packageModified(base, cur *sbomPackage) bool {
	if base.Version != cur.Version {
		return true
	}

	if !checksumsEqual(base.Checksums, cur.Checksums) {
		return true
	}

	if !licensesEqual(base.Licenses, cur.Licenses) {
		return true
	}

	return false
}

func checksumsEqual(baseline, current map[string]string) bool {
	if len(baseline) == 0 && len(current) == 0 {
		return true
	}

	// Flag when baseline has checksums but current has none (stripping).
	if len(baseline) > 0 && len(current) == 0 {
		return false
	}

	// Flag when current has fewer algorithms than baseline (partial stripping).
	if len(current) < len(baseline) {
		return false
	}

	for algo, baseVal := range baseline {
		curVal, found := current[algo]
		if !found {
			return false
		}

		if !strings.EqualFold(baseVal, curVal) {
			return false
		}
	}

	return true
}

func licensesEqual(baseline, current []string) bool {
	if len(baseline) != len(current) {
		return false
	}

	sorted := func(s []string) []string {
		cp := make([]string, len(s))
		copy(cp, s)
		slices.Sort(cp)

		return cp
	}

	sortedBase, sortedCur := sorted(baseline), sorted(current)
	for i := range sortedBase {
		if !strings.EqualFold(sortedBase[i], sortedCur[i]) {
			return false
		}
	}

	return true
}

func (d *driftResult) ToMetadata() map[string]any {
	addedPURLs := make([]string, 0, d.AddedCount)
	for idx := range d.Added {
		addedPURLs = append(addedPURLs, d.Added[idx].PURL)
	}

	return map[string]any{
		"detected":      d.AddedCount > 0 || d.RemovedCount > 0 || d.ModifiedCount > 0,
		"addedCount":    int64(d.AddedCount),
		"removedCount":  int64(d.RemovedCount),
		"modifiedCount": int64(d.ModifiedCount),
		"addedPackages": addedPURLs,
		"score":         d.Score,
	}
}

func checkDriftThresholds(
	drift *driftResult, driftPolicy *policy.SBOMDriftPolicy,
) *types.CheckResult {
	if driftPolicy.MaxAdded != nil && drift.AddedCount > *driftPolicy.MaxAdded {
		return check.Fail(fmt.Sprintf(
			"SBOM drift: %d added packages exceed threshold of %d",
			drift.AddedCount, *driftPolicy.MaxAdded,
		))
	}

	if driftPolicy.MaxRemoved != nil && drift.RemovedCount > *driftPolicy.MaxRemoved {
		return check.Fail(fmt.Sprintf(
			"SBOM drift: %d removed packages exceed threshold of %d",
			drift.RemovedCount, *driftPolicy.MaxRemoved,
		))
	}

	if driftPolicy.MaxModified != nil && drift.ModifiedCount > *driftPolicy.MaxModified {
		return check.Fail(fmt.Sprintf(
			"SBOM drift: %d modified packages exceed threshold of %d",
			drift.ModifiedCount, *driftPolicy.MaxModified,
		))
	}

	if driftPolicy.MaxScore != nil && drift.Score > *driftPolicy.MaxScore {
		return check.Fail(fmt.Sprintf(
			"SBOM drift: score %.2f exceeds threshold of %.2f",
			drift.Score, *driftPolicy.MaxScore,
		))
	}

	return nil
}

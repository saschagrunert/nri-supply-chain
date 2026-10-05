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
	"github.com/saschagrunert/nri-supply-chain/internal/purl"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

// unparsedIdentityPrefix keys packages whose purl cannot be parsed. Identity
// keys never contain a colon before their first slash, so the keys of parsed
// and unparsed purls cannot collide.
const unparsedIdentityPrefix = "unparsed:"

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
	baselineIndex, baselineCount := indexByIdentity(baseline)
	currentIndex, _ := indexByIdentity(current)

	var result driftResult

	for identity, cur := range currentIndex {
		added, removed, modified := diffIdentity(baselineIndex[identity], cur)
		result.Added = append(result.Added, added...)
		result.Removed = append(result.Removed, removed...)
		result.Modified = append(result.Modified, modified...)
	}

	for identity, base := range baselineIndex {
		if _, exists := currentIndex[identity]; !exists {
			result.Removed = append(result.Removed, base...)
		}
	}

	slices.SortFunc(result.Added, cmpByPURL)
	slices.SortFunc(result.Removed, cmpByPURL)
	slices.SortFunc(result.Modified, cmpByPURL)

	result.AddedCount = len(result.Added)
	result.RemovedCount = len(result.Removed)
	result.ModifiedCount = len(result.Modified)

	if baselineCount > 0 {
		numerator := float64(
			result.AddedCount*driftWeightAdded +
				result.ModifiedCount*driftWeightModified +
				result.RemovedCount*driftWeightRemoved,
		)
		result.Score = numerator / float64(baselineCount)
	}

	return result
}

// diffIdentity compares the baseline and current packages sharing one
// versionless identity. Packages with the same purl are compared directly;
// the remaining ones are paired in purl order as modified (for example a
// version bump), and any surplus counts as added or removed.
func diffIdentity(baseline, current []sbomPackage) (added, removed, modified []sbomPackage) {
	var unmatchedBase, unmatchedCur []sbomPackage

	baseByPURL := make(map[string]*sbomPackage, len(baseline))
	for idx := range baseline {
		baseByPURL[baseline[idx].PURL] = &baseline[idx]
	}

	curByPURL := make(map[string]struct{}, len(current))

	for idx := range current {
		curByPURL[current[idx].PURL] = struct{}{}

		base, found := baseByPURL[current[idx].PURL]
		if !found {
			unmatchedCur = append(unmatchedCur, current[idx])

			continue
		}

		if packageModified(base, &current[idx]) {
			modified = append(modified, current[idx])
		}
	}

	for idx := range baseline {
		if _, found := curByPURL[baseline[idx].PURL]; !found {
			unmatchedBase = append(unmatchedBase, baseline[idx])
		}
	}

	paired := min(len(unmatchedBase), len(unmatchedCur))
	modified = append(modified, unmatchedCur[:paired]...)
	added = unmatchedCur[paired:]
	removed = unmatchedBase[paired:]

	return added, removed, modified
}

// indexByIdentity groups packages by their versionless purl identity
// (purl.PURL.Key), so a version change is detected as a modification rather
// than an addition and a removal. Packages with an unparsable purl are keyed
// by the purl itself. Duplicate purls are counted once. The second return
// value is the number of distinct purls.
func indexByIdentity(pkgs []sbomPackage) (index map[string][]sbomPackage, count int) {
	byPURL := make(map[string]sbomPackage, len(pkgs))

	skipped := 0

	for idx := range pkgs {
		if pkgs[idx].PURL != "" {
			byPURL[pkgs[idx].PURL] = pkgs[idx]
		} else {
			skipped++
		}
	}

	if skipped > 0 {
		slog.Warn("Packages without PURL excluded from drift tracking",
			"skipped", skipped, "total", len(pkgs))
	}

	index = make(map[string][]sbomPackage, len(byPURL))

	for purlValue, pkg := range byPURL {
		identity := unparsedIdentityPrefix + purlValue

		parsed, err := purl.Parse(purlValue)
		if err == nil {
			identity = parsed.Key()
		}

		index[identity] = append(index[identity], pkg)
	}

	for identity := range index {
		slices.SortFunc(index[identity], cmpByPURL)
	}

	return index, len(byPURL)
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

// checksumsEqual reports whether the current checksums cover the baseline
// ones. Algorithm names are compared without case and separators, since SPDX
// 2 ("SHA256"), SPDX 3 ("sha256"), and CycloneDX ("SHA-256") spell them
// differently.
func checksumsEqual(baseline, current map[string]string) bool {
	if len(baseline) == 0 && len(current) == 0 {
		return true
	}

	// Flag when baseline has checksums but current has none (stripping).
	if len(baseline) > 0 && len(current) == 0 {
		return false
	}

	baseline, current = normalizeChecksums(baseline), normalizeChecksums(current)

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

// checksumAlgorithmReplacer drops the separators of checksum algorithm names.
//
//nolint:gochecknoglobals // immutable replacer
var checksumAlgorithmReplacer = strings.NewReplacer("-", "", "_", "")

// normalizeChecksums keys checksums by their lowercase algorithm name without
// separators.
func normalizeChecksums(checksums map[string]string) map[string]string {
	normalized := make(map[string]string, len(checksums))

	for algo, value := range checksums {
		normalized[strings.ToLower(checksumAlgorithmReplacer.Replace(algo))] = value
	}

	return normalized
}

// licensesEqual compares two license lists as case-insensitive sets, so the
// order and repetitions (SPDX 2 lists the concluded and the declared license
// of a package) do not count as a change.
func licensesEqual(baseline, current []string) bool {
	return slices.Equal(licenseSet(baseline), licenseSet(current))
}

func licenseSet(licenses []string) []string {
	set := make([]string, 0, len(licenses))
	for _, license := range licenses {
		set = append(set, strings.ToLower(license))
	}

	slices.Sort(set)

	return slices.Compact(set)
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

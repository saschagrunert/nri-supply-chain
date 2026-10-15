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

// unparsedIdentityPrefix keys packages whose purl cannot be parsed, and
// namedIdentityPrefix packages without purl. Identity keys of parsed purls
// never contain a colon before their first slash, so the keys of parsed,
// unparsed and missing purls cannot collide.
const (
	unparsedIdentityPrefix = "unparsed:"
	namedIdentityPrefix    = "name:"
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

	slices.SortFunc(result.Added, cmpByKey)
	slices.SortFunc(result.Removed, cmpByKey)
	slices.SortFunc(result.Modified, cmpByKey)

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
// versionless identity. Packages with the same key are compared directly;
// the remaining ones are paired in key order as modified (for example a
// version bump), and any surplus counts as added or removed.
func diffIdentity(baseline, current []sbomPackage) (added, removed, modified []sbomPackage) {
	var unmatchedBase, unmatchedCur []sbomPackage

	baseByKey := make(map[string]*sbomPackage, len(baseline))
	for idx := range baseline {
		baseByKey[baseline[idx].driftKey()] = &baseline[idx]
	}

	curByKey := make(map[string]struct{}, len(current))

	for idx := range current {
		curByKey[current[idx].driftKey()] = struct{}{}

		base, found := baseByKey[current[idx].driftKey()]
		if !found {
			unmatchedCur = append(unmatchedCur, current[idx])

			continue
		}

		if packageModified(base, &current[idx]) {
			modified = append(modified, current[idx])
		}
	}

	for idx := range baseline {
		if _, found := curByKey[baseline[idx].driftKey()]; !found {
			unmatchedBase = append(unmatchedBase, baseline[idx])
		}
	}

	paired := min(len(unmatchedBase), len(unmatchedCur))
	modified = append(modified, unmatchedCur[:paired]...)
	added = unmatchedCur[paired:]
	removed = unmatchedBase[paired:]

	return added, removed, modified
}

// indexByIdentity groups packages by their versionless identity: the
// versionless purl (purl.PURL.Key), so a version change is detected as a
// modification rather than an addition and a removal. Packages with an
// unparsable purl are keyed by the purl itself, and packages without purl by
// their name, except exempt components (the document subject and components
// that are not packages). Duplicate keys are counted once. The second return
// value is the number of distinct keys.
func indexByIdentity(pkgs []sbomPackage) (index map[string][]sbomPackage, count int) {
	byKey := make(map[string]sbomPackage, len(pkgs))

	skipped := 0

	for idx := range pkgs {
		if pkgs[idx].PURL == "" && pkgs[idx].exempt {
			// Subjects and non-package components without purl were never
			// tracked: the subject of an image SBOM changes with every build.
			continue
		}

		if pkgs[idx].PURL == "" && pkgs[idx].Name == "" {
			skipped++

			continue
		}

		byKey[pkgs[idx].driftKey()] = pkgs[idx]
	}

	if skipped > 0 {
		slog.Warn("Packages without PURL and name excluded from drift tracking",
			"skipped", skipped, "total", len(pkgs))
	}

	index = make(map[string][]sbomPackage, len(byKey))

	for _, pkg := range byKey {
		identity := pkg.driftIdentity()
		index[identity] = append(index[identity], pkg)
	}

	for identity := range index {
		slices.SortFunc(index[identity], cmpByKey)
	}

	return index, len(byKey)
}

// driftKey identifies a package version: its purl, or for a package without
// purl its name and version.
func (p *sbomPackage) driftKey() string {
	if p.PURL != "" {
		return p.PURL
	}

	return namedIdentityPrefix + p.Name + "@" + p.Version
}

// driftIdentity identifies a package independently of its version.
func (p *sbomPackage) driftIdentity() string {
	if p.PURL == "" {
		return namedIdentityPrefix + p.Name
	}

	parsed, err := purl.Parse(p.PURL)
	if err != nil {
		return unparsedIdentityPrefix + p.PURL
	}

	return parsed.Key()
}

//nolint:gocritic // required by slices.SortFunc signature
func cmpByKey(left, right sbomPackage) int {
	return strings.Compare(left.driftKey(), right.driftKey())
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

// normalizeChecksums keys checksums by their lowercase algorithm name without
// separators.
func normalizeChecksums(checksums map[string]string) map[string]string {
	normalized := make(map[string]string, len(checksums))

	for algo, value := range checksums {
		normalized[types.NormalizeAlgorithm(algo)] = value
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
	// Packages without purl are listed by their name and version.
	addedPURLs := make([]string, 0, d.AddedCount)
	for idx := range d.Added {
		addedPURLs = append(addedPURLs, d.Added[idx].driftKey())
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

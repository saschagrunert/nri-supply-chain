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

package guac

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"

	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

var errGUACPartialFailure = errors.New("one or more GUAC queries failed")

// GUAC check type identifiers used in configuration.
const (
	CheckCertifyVuln      = "certify_vuln"
	CheckCertifyScorecard = "certify_scorecard"
	CheckIsDependency     = "is_dependency"
)

// Metadata keys exposed to CEL as guac.<key>.
const (
	MetaKeyAvailable                = "available"
	MetaKeyVulnerabilities          = "vulnerabilities"
	MetaKeyTransitiveVulns          = "transitive_vulns"
	MetaKeyVulnerabilitiesAvailable = "vulnerabilities_available"
	MetaKeyScorecard                = "scorecard"
	MetaKeyScorecardAvailable       = "scorecard_available"
	MetaKeyDependencies             = "dependencies"
	MetaKeyDependencyCount          = "dependency_count"
	MetaKeyDependenciesAvailable    = "dependencies_available"
)

// Scorecard map keys exposed to CEL as guac.scorecard.<key>.
const (
	ScorecardKeyAggregate = "aggregate"
	ScorecardKeyChecks    = "checks"
	ScorecardKeySource    = "source"
	ScorecardKeyTruncated = "truncated"
)

// fieldSource is the scorecard source key used in metadata, logs, and
// GraphQL filters.
const fieldSource = ScorecardKeySource

// Query runs the configured GUAC checks for the given image digest and
// returns a CheckResult with metadata populated for CEL evaluation. Results
// of queries that succeeded are kept even when another query fails.
func Query(
	ctx context.Context,
	client *Client,
	digest string,
	checks []string,
	maxDeps int,
) *types.CheckResult {
	result := &QueryResult{Available: true}

	var guard sync.Mutex

	var waitGroup sync.WaitGroup

	if slices.Contains(checks, CheckCertifyVuln) {
		waitGroup.Add(1)

		go queryVulns(ctx, client, digest, result, &guard, &waitGroup)
	}

	if slices.Contains(checks, CheckCertifyScorecard) {
		waitGroup.Add(1)

		go queryScorecard(ctx, client, digest, result, &guard, &waitGroup)
	}

	if slices.Contains(checks, CheckIsDependency) {
		waitGroup.Add(1)

		go queryDeps(ctx, client, digest, maxDeps, result, &guard, &waitGroup)
	}

	waitGroup.Wait()

	return buildCheckResult(result)
}

func recordFailure(result *QueryResult, guard *sync.Mutex, err error) {
	guard.Lock()
	result.Available = false
	result.Err = errors.Join(result.Err, err)
	guard.Unlock()
}

func queryVulns(
	ctx context.Context, client *Client, digest string,
	result *QueryResult, guard *sync.Mutex, waitGroup *sync.WaitGroup,
) {
	defer waitGroup.Done()

	direct, transitive, err := client.QueryVulnerabilities(ctx, digest, true)
	if err != nil {
		slog.WarnContext(ctx, "GUAC vulnerability query failed",
			"digest", digest, "error", err)

		recordFailure(result, guard, err)

		return
	}

	guard.Lock()
	result.Vulnerabilities = direct
	result.TransitiveVulns = transitive
	result.VulnerabilitiesAvailable = true
	guard.Unlock()
}

func queryScorecard(
	ctx context.Context, client *Client, digest string,
	result *QueryResult, guard *sync.Mutex, waitGroup *sync.WaitGroup,
) {
	defer waitGroup.Done()

	scorecard, err := client.QueryScorecard(ctx, digest)
	if err != nil {
		slog.WarnContext(ctx, "GUAC scorecard query failed", "error", err)

		recordFailure(result, guard, err)

		return
	}

	if scorecard.Source != "" {
		slog.DebugContext(ctx, "GUAC scorecard resolved",
			fieldSource, scorecard.Source,
			"aggregate", scorecard.Aggregate)
	}

	guard.Lock()
	result.Scorecard = scorecard
	result.ScorecardAvailable = true
	guard.Unlock()
}

func queryDeps(
	ctx context.Context, client *Client, digest string, maxDeps int,
	result *QueryResult, guard *sync.Mutex, waitGroup *sync.WaitGroup,
) {
	defer waitGroup.Done()

	deps, err := client.QueryDependencies(ctx, digest, maxDeps)
	if err != nil {
		slog.WarnContext(ctx, "GUAC dependency query failed",
			"digest", digest, "error", err)

		recordFailure(result, guard, err)

		return
	}

	guard.Lock()
	result.DependencyInfo = deps
	result.DependenciesAvailable = true
	guard.Unlock()
}

func buildCheckResult(queryResult *QueryResult) *types.CheckResult {
	meta := BuildMetadata(queryResult)

	if !queryResult.Available {
		err := errGUACPartialFailure
		if queryResult.Err != nil {
			err = fmt.Errorf("%w: %w", errGUACPartialFailure, queryResult.Err)
		}

		// Partial results stay in the metadata; failed queries are marked
		// unavailable and carry no data.
		result := types.SoftFailResult(types.CheckTypeGUAC,
			"GUAC queries partially failed", err)
		result.Metadata = meta

		return result
	}

	detail := fmt.Sprintf("GUAC: %d direct vulns, %d transitive vulns",
		len(queryResult.Vulnerabilities), len(queryResult.TransitiveVulns))

	result := types.PassResult(types.CheckTypeGUAC, detail)
	result.Metadata = meta

	return result
}

// BuildMetadata converts a query result into CEL metadata. Queries that did
// not succeed contribute only their *_available flag and no data, so CEL
// expressions reading that data fail evaluation instead of seeing defaults.
func BuildMetadata(queryResult *QueryResult) map[string]any {
	meta := UnavailableMetadata()
	meta[MetaKeyAvailable] = queryResult.Available

	if queryResult.VulnerabilitiesAvailable {
		meta[MetaKeyVulnerabilities] = vulnsToSlice(queryResult.Vulnerabilities)
		meta[MetaKeyTransitiveVulns] = vulnsToSlice(queryResult.TransitiveVulns)
		meta[MetaKeyVulnerabilitiesAvailable] = true
	}

	if queryResult.ScorecardAvailable {
		meta[MetaKeyScorecard] = scorecardToMap(queryResult.Scorecard)
		meta[MetaKeyScorecardAvailable] = true
	}

	if queryResult.DependenciesAvailable {
		deps, depCount := dependencyData(queryResult.DependencyInfo)
		meta[MetaKeyDependencies] = deps
		meta[MetaKeyDependencyCount] = depCount
		meta[MetaKeyDependenciesAvailable] = true
	}

	return meta
}

// UnavailableMetadata returns metadata describing GUAC data that is not
// available (GUAC not configured, query not enabled, or query failed): all
// availability flags are false and no data keys are present.
func UnavailableMetadata() map[string]any {
	return map[string]any{
		MetaKeyAvailable:                false,
		MetaKeyVulnerabilitiesAvailable: false,
		MetaKeyScorecardAvailable:       false,
		MetaKeyDependenciesAvailable:    false,
	}
}

// AvailabilityKey returns the availability flag guarding a GUAC data key
// (for example "scorecard_available" for "scorecard"), and false for keys
// that are not GUAC data keys.
func AvailabilityKey(dataKey string) (string, bool) {
	switch dataKey {
	case MetaKeyVulnerabilities, MetaKeyTransitiveVulns:
		return MetaKeyVulnerabilitiesAvailable, true
	case MetaKeyScorecard:
		return MetaKeyScorecardAvailable, true
	case MetaKeyDependencies, MetaKeyDependencyCount:
		return MetaKeyDependenciesAvailable, true
	default:
		return "", false
	}
}

// MetadataSchema returns metadata with every key GUAC can expose, filled
// with zero values. It describes the fields CEL expressions may select on
// the guac variable.
func MetadataSchema() map[string]any {
	meta := UnavailableMetadata()
	meta[MetaKeyVulnerabilities] = []any{}
	meta[MetaKeyTransitiveVulns] = []any{}
	meta[MetaKeyScorecard] = scorecardToMap(nil)
	meta[MetaKeyDependencies] = []any{}
	meta[MetaKeyDependencyCount] = int64(0)

	return meta
}

func vulnsToSlice(vulns []Vulnerability) []any {
	result := make([]any, 0, len(vulns))

	for idx := range vulns {
		result = append(result, map[string]any{
			"id":      vulns[idx].ID,
			"package": vulns[idx].Package,
		})
	}

	return result
}

func scorecardToMap(scorecard *ScorecardResult) map[string]any {
	if scorecard == nil {
		scorecard = &ScorecardResult{Aggregate: 0, Checks: nil, Source: ""}
	}

	checksMap := make(map[string]any, len(scorecard.Checks))
	for key, val := range scorecard.Checks {
		checksMap[key] = val
	}

	return map[string]any{
		ScorecardKeyAggregate: scorecard.Aggregate,
		ScorecardKeyChecks:    checksMap,
		ScorecardKeySource:    scorecard.Source,
		ScorecardKeyTruncated: scorecard.Truncated,
	}
}

func dependencyData(info *DependencyInfo) (deps []any, count int64) {
	if info == nil {
		return []any{}, 0
	}

	deps = make([]any, len(info.Dependencies))
	for idx, purl := range info.Dependencies {
		deps[idx] = purl
	}

	return deps, int64(info.DependencyCount)
}

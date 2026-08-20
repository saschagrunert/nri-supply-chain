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

// Query runs the configured GUAC checks for the given image digest and
// returns a CheckResult with metadata populated for CEL evaluation.
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

		go queryScorecard(ctx, client, result, &guard, &waitGroup)
	}

	if slices.Contains(checks, CheckIsDependency) {
		waitGroup.Add(1)

		go queryDeps(ctx, client, digest, maxDeps, result, &guard, &waitGroup)
	}

	waitGroup.Wait()

	return buildCheckResult(result)
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

		guard.Lock()
		result.Available = false
		result.Err = errors.Join(result.Err, err)
		guard.Unlock()

		return
	}

	guard.Lock()
	result.Vulnerabilities = direct
	result.TransitiveVulns = transitive
	guard.Unlock()
}

func queryScorecard(
	ctx context.Context, client *Client,
	result *QueryResult, guard *sync.Mutex, waitGroup *sync.WaitGroup,
) {
	defer waitGroup.Done()

	scorecard, err := client.QueryScorecard(ctx)
	if err != nil {
		slog.WarnContext(ctx, "GUAC scorecard query failed", "error", err)

		guard.Lock()
		result.Available = false
		result.Err = errors.Join(result.Err, err)
		guard.Unlock()

		return
	}

	if scorecard.Source != "" {
		slog.DebugContext(ctx, "GUAC scorecard resolved",
			"source", scorecard.Source,
			"aggregate", scorecard.Aggregate)
	}

	guard.Lock()
	result.Scorecard = scorecard
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

		guard.Lock()
		result.Available = false
		result.Err = errors.Join(result.Err, err)
		guard.Unlock()

		return
	}

	guard.Lock()
	result.DependencyInfo = deps
	guard.Unlock()
}

func buildCheckResult(queryResult *QueryResult) *types.CheckResult {
	meta := buildMetadata(queryResult)

	if !queryResult.Available {
		err := errGUACPartialFailure
		if queryResult.Err != nil {
			err = fmt.Errorf("%w: %w", errGUACPartialFailure, queryResult.Err)
		}

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

func buildMetadata(queryResult *QueryResult) map[string]any {
	deps, depCount := dependencyData(queryResult.DependencyInfo)

	return map[string]any{
		"available":        queryResult.Available,
		"vulnerabilities":  vulnsToSlice(queryResult.Vulnerabilities),
		"transitive_vulns": vulnsToSlice(queryResult.TransitiveVulns),
		"scorecard":        scorecardToMap(queryResult.Scorecard),
		"dependencies":     deps,
		"dependency_count": depCount,
	}
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
		return map[string]any{
			"aggregate": float64(0),
			"checks":    map[string]any{},
			"source":    "",
		}
	}

	checksMap := make(map[string]any, len(scorecard.Checks))
	for key, val := range scorecard.Checks {
		checksMap[key] = val
	}

	return map[string]any{
		"aggregate": scorecard.Aggregate,
		"checks":    checksMap,
		"source":    scorecard.Source,
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

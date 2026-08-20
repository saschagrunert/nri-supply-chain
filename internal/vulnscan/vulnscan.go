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

// Package vulnscan provides vulnerability scan attestation verification for supply chain checks.
package vulnscan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/intoto"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const checkType = types.CheckTypeVulnScan

var (
	// ErrInvalidVulnScan indicates the vulnerability scan document could not be parsed.
	ErrInvalidVulnScan = errors.New("invalid vulnerability scan document")

	// ErrStaleVulnScan indicates the scan is older than the maximum allowed age.
	ErrStaleVulnScan = errors.New("vulnerability scan is stale")

	// ErrFutureTimestamp indicates the scan timestamp is in the future.
	ErrFutureTimestamp = errors.New("vulnerability scan timestamp is in the future")
)

const (
	severityRankMedium   = 2
	severityRankHigh     = 3
	severityRankCritical = 4
)

// severityRank maps CVSS severity strings to numeric ranks for comparison.
var severityRank = map[string]int{ //nolint:gochecknoglobals // immutable lookup table
	"none":     0,
	"low":      1,
	"medium":   severityRankMedium,
	"high":     severityRankHigh,
	"critical": severityRankCritical,
}

// vulnScanPredicate represents the in-toto vulnerability scan predicate.
type vulnScanPredicate struct {
	Scanner  scanner       `json:"scanner"`
	Metadata *scanMetadata `json:"metadata,omitempty"`
	Result   scanResult    `json:"result"`
}

type scanner struct {
	URI     string `json:"uri,omitempty"`
	Version string `json:"version,omitempty"`
}

type scanMetadata struct {
	ScannedOn *time.Time `json:"scannedOn,omitempty"`
}

type scanResult struct {
	Vulnerabilities []vulnerability `json:"vulnerabilities,omitempty"`
}

type vulnerability struct {
	ID       string   `json:"id"`
	Severity string   `json:"severity,omitempty"`
	Score    *float64 `json:"score,omitempty"`
}

// Verify checks a single vulnerability scan attestation against the given policy.
func Verify(
	ctx context.Context,
	att []byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	ctxErr := ctx.Err()
	if ctxErr != nil {
		return nil, fmt.Errorf("verification cancelled: %w", ctxErr)
	}

	predicate, err := intoto.VerifySubjectAndExtractPredicate(att, imageDigest)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidVulnScan, err)
	}

	return verifyVulnScanPredicate(predicate, pol)
}

// VerifyMultiple checks multiple vulnerability scan attestations. Any policy
// violation in any document causes failure.
func VerifyMultiple(
	ctx context.Context,
	attestations [][]byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	//nolint:wrapcheck // VerifyMultipleWithMerge returns domain errors
	return types.VerifyMultipleWithMerge(
		ctx, checkType, "vulnerability scan", "vulnerability scan verification passed",
		attestations,
		func(att []byte) (*types.CheckResult, error) {
			return Verify(ctx, att, pol, imageDigest)
		},
		mergeVulnMeta,
	)
}

func verifyVulnScanPredicate(
	predicate []byte, pol *policy.Policy,
) (*types.CheckResult, error) {
	var pred vulnScanPredicate

	err := json.Unmarshal(predicate, &pred)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidVulnScan, err)
	}

	maxScore, maxSeverity := aggregateVulns(pred.Result.Vulnerabilities)

	meta := map[string]any{
		"scanner":       pred.Scanner.URI,
		"vulnCount":     int64(len(pred.Result.Vulnerabilities)),
		"maxScore":      maxScore,
		"maxSeverity":   maxSeverity,
		"criticalCount": countBySeverity(pred.Result.Vulnerabilities, "critical"),
		"highCount":     countBySeverity(pred.Result.Vulnerabilities, "high"),
	}

	if pol.VulnScan == nil {
		result := check.Pass()
		result.Metadata = meta

		return result, nil
	}

	var scannedOn *time.Time
	if pred.Metadata != nil {
		scannedOn = pred.Metadata.ScannedOn
	}

	err = verifyFreshness(scannedOn, pol)
	if err != nil {
		result := check.Fail(err.Error())
		result.Metadata = meta

		return result, nil
	}

	violation := checkThresholds(pred.Result.Vulnerabilities, pol.VulnScan)
	if violation != "" {
		result := check.Fail(violation)
		result.Metadata = meta

		return result, nil
	}

	result := check.Pass()
	result.Metadata = meta

	return result, nil
}

func aggregateVulns(vulns []vulnerability) (maxScore float64, maxSeverity string) {
	maxSevRank := -1

	for idx := range vulns {
		if vulns[idx].Score != nil && *vulns[idx].Score > maxScore {
			maxScore = *vulns[idx].Score
		}

		sev := strings.ToLower(vulns[idx].Severity)

		rank, known := severityRank[sev]
		if known && rank > maxSevRank {
			maxSevRank = rank
			maxSeverity = vulns[idx].Severity
		}
	}

	if maxSeverity == "" {
		maxSeverity = "none"
	}

	return maxScore, maxSeverity
}

func countBySeverity(vulns []vulnerability, severity string) int64 {
	var count int64

	targetRank := severityRank[severity]

	for idx := range vulns {
		sev := strings.ToLower(vulns[idx].Severity)
		if severityRank[sev] == targetRank {
			count++
		}
	}

	return count
}

//nolint:cyclop // threshold checks are sequential
func checkThresholds(
	vulns []vulnerability,
	pol *policy.VulnScanPolicy,
) string {
	ignoredCVEs := make(map[string]bool, len(pol.IgnoreCVEs))
	for _, cve := range pol.IgnoreCVEs {
		ignoredCVEs[cve] = true
	}

	minSeverityRank := 0
	if pol.MinSeverity != "" {
		minSeverityRank = severityRank[strings.ToLower(pol.MinSeverity)]
	}

	for idx := range vulns {
		if ignoredCVEs[vulns[idx].ID] {
			continue
		}

		exceeded := false

		if pol.MaxScore != nil && vulns[idx].Score != nil && *vulns[idx].Score > *pol.MaxScore {
			exceeded = true
		}

		vulnSevRank := severityRank[strings.ToLower(vulns[idx].Severity)]
		if pol.MinSeverity != "" && vulnSevRank >= minSeverityRank {
			exceeded = true
		}

		if exceeded {
			score := float64(0)
			if vulns[idx].Score != nil {
				score = *vulns[idx].Score
			}

			return fmt.Sprintf(
				"vulnerability threshold exceeded: %s (score %.1f, severity %s)",
				vulns[idx].ID, score, strings.ToLower(vulns[idx].Severity),
			)
		}
	}

	return ""
}

func verifyFreshness(scannedOn *time.Time, pol *policy.Policy) error {
	maxAgeConfigured := pol.VulnScan != nil && pol.VulnScan.MaxAge != ""

	if scannedOn == nil {
		if maxAgeConfigured {
			return fmt.Errorf("%w: no scan timestamp in attestation", ErrStaleVulnScan)
		}

		return nil
	}

	if !maxAgeConfigured {
		return nil
	}

	maxAge := &pol.VulnScan.MaxAgeDuration

	//nolint:wrapcheck // VerifyFreshness wraps the caller's sentinel errors
	return types.VerifyFreshness(
		*scannedOn,
		maxAge,
		"scanned",
		ErrFutureTimestamp,
		ErrStaleVulnScan,
		ErrStaleVulnScan,
	)
}

func mergeVulnMeta(dst, src map[string]any) {
	for key, val := range src {
		existing, hasPrev := dst[key]
		if !hasPrev {
			dst[key] = val

			continue
		}

		mergeVulnKey(dst, key, val, existing)
	}
}

//nolint:cyclop // type assertions on known keys
func mergeVulnKey(dst map[string]any, key string, val, existing any) {
	switch key {
	case "maxScore":
		if srcScore, ok := val.(float64); ok {
			if dstScore, ok := existing.(float64); ok && srcScore > dstScore {
				dst[key] = srcScore
			}
		}
	case "maxSeverity":
		if srcSev, ok := val.(string); ok {
			if dstSev, ok := existing.(string); ok {
				if severityRank[strings.ToLower(srcSev)] > severityRank[strings.ToLower(dstSev)] {
					dst[key] = srcSev
				}
			}
		}
	case "scanner":
		if srcScanner, ok := val.(string); ok {
			if dstScanner, ok := existing.(string); ok {
				dst[key] = types.MergeCommaSeparated(dstScanner, srcScanner)
			}
		}
	case "vulnCount", "criticalCount", "highCount":
		if srcCount, ok := val.(int64); ok {
			if dstCount, ok := existing.(int64); ok {
				dst[key] = dstCount + srcCount
			}
		}
	default:
	}
}

var check = types.Checker{ //nolint:gochecknoglobals // package-scoped helper
	Type:    checkType,
	PassMsg: "vulnerability scan verification passed",
}

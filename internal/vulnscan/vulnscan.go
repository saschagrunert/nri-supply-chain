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
//
// The in-toto vulnerability predicate layout (scanner.result[] with
// severity[]{method, score} entries and metadata.scanStartedOn and
// scanFinishedOn) is supported, as is the earlier layout that carries
// result.vulnerabilities[] with a textual severity and a numeric score.
package vulnscan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/checker"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

var (
	// ErrInvalidVulnScan indicates the vulnerability scan document could not be parsed.
	ErrInvalidVulnScan = errors.New("invalid vulnerability scan document")

	// ErrStaleVulnScan indicates the scan is older than the maximum allowed age.
	ErrStaleVulnScan = errors.New("vulnerability scan is stale")

	// ErrFutureTimestamp indicates the scan timestamp is in the future.
	ErrFutureTimestamp = errors.New("vulnerability scan timestamp is in the future")

	errMissingScanner     = errors.New("scanner is required")
	errMissingScannerURI  = errors.New("scanner.uri is required")
	errMissingResults     = errors.New("scanner.result is required")
	errMissingLegacyVulns = errors.New("result.vulnerabilities is required")
	errMissingVulnID      = errors.New("vulnerability id is required")
	errInvalidScore       = errors.New("invalid severity score")
)

// epssMethod identifies EPSS probabilities, which are not CVSS scores.
const epssMethod = "epss"

// vulnScanPredicate represents the in-toto vulnerability scan predicate.
type vulnScanPredicate struct {
	Scanner  *scanner      `json:"scanner"`
	Metadata *scanMetadata `json:"metadata,omitempty"`
	// Result is the legacy result container.
	Result *legacyResult `json:"result,omitempty"`

	// vulns holds the normalized findings of both layouts, set during validation.
	vulns []vulnerability
}

type scanner struct {
	URI     string        `json:"uri"`
	Version string        `json:"version,omitempty"`
	DB      *scannerDB    `json:"db,omitempty"`
	Result  *[]specResult `json:"result,omitempty"`
}

type scannerDB struct {
	URI     string `json:"uri,omitempty"`
	Version string `json:"version,omitempty"`
}

// specResult is one scanner.result entry. The specification's field table
// nests the finding under "vulnerability" while its example uses a flat
// entry; both layouts are accepted.
type specResult struct {
	ID            string             `json:"id"`
	Severity      severityList       `json:"severity,omitempty"`
	Vulnerability *specVulnerability `json:"vulnerability,omitempty"`
}

type specVulnerability struct {
	ID       string       `json:"id"`
	Severity severityList `json:"severity,omitempty"`
}

type severityScore struct {
	Method string    `json:"method,omitempty"`
	Score  flexScore `json:"score"`
}

// severityList accepts a list of severity entries or a single entry object.
type severityList []severityScore

// UnmarshalJSON decodes a severity list or a single severity object.
func (s *severityList) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var single severityScore

		err := json.Unmarshal(trimmed, &single)
		if err != nil {
			return fmt.Errorf("decoding severity: %w", err)
		}

		*s = severityList{single}

		return nil
	}

	var list []severityScore

	err := json.Unmarshal(trimmed, &list)
	if err != nil {
		return fmt.Errorf("decoding severity list: %w", err)
	}

	*s = list

	return nil
}

// flexScore accepts a severity score encoded as a JSON string or number.
type flexScore string

// UnmarshalJSON decodes a string or numeric score.
func (f *flexScore) UnmarshalJSON(data []byte) error {
	var text string

	err := json.Unmarshal(data, &text)
	if err == nil {
		*f = flexScore(text)

		return nil
	}

	var number float64

	err = json.Unmarshal(data, &number)
	if err != nil {
		return fmt.Errorf("%w: %s", errInvalidScore, data)
	}

	*f = flexScore(strconv.FormatFloat(number, 'f', -1, 64))

	return nil
}

type scanMetadata struct {
	ScanStartedOn  *time.Time `json:"scanStartedOn,omitempty"`
	ScanFinishedOn *time.Time `json:"scanFinishedOn,omitempty"`
	// ScannedOn is the legacy scan timestamp.
	ScannedOn *time.Time `json:"scannedOn,omitempty"`
}

type legacyResult struct {
	// Vulnerabilities is required when the legacy result container is
	// present, so that a report in another format (for example a raw
	// scanner report) is not mistaken for a clean scan.
	Vulnerabilities *[]legacyVulnerability `json:"vulnerabilities"`
}

type legacyVulnerability struct {
	ID       string   `json:"id"`
	Severity string   `json:"severity,omitempty"`
	Score    *float64 `json:"score,omitempty"`
}

// vulnerability is a finding normalized from either predicate layout.
type vulnerability struct {
	ID    string
	Score *float64
	Rank  int
}

//nolint:gochecknoglobals // immutable check declaration
var spec = &checker.Spec[vulnScanPredicate]{
	Info: checker.Info{
		Type:  types.CheckTypeVulnScan,
		Label: "vulnerability scan",
	},
	Aggregation: checker.AllMustPass,
	ErrInvalid:  ErrInvalidVulnScan,
	Validate:    validatePredicate,
	Meta:        predicateMeta,
	Freshness: &checker.Freshness[vulnScanPredicate]{
		Timestamp: scanTimestamp,
		MaxAge: func(pol *policy.Policy) *time.Duration {
			if pol.VulnScan == nil || pol.VulnScan.MaxAge == "" {
				return nil
			}

			return &pol.VulnScan.MaxAgeDuration
		},
		Label:     "scanned",
		ErrStale:  ErrStaleVulnScan,
		ErrFuture: ErrFutureTimestamp,
	},
	Rules: []checker.Rule[vulnScanPredicate]{checkThresholds},
	Merge: map[string]checker.MergeFunc{
		"scanner":       checker.CSV(),
		"vulnCount":     checker.Sum(),
		"criticalCount": checker.Sum(),
		"highCount":     checker.Sum(),
		"unknownCount":  checker.Sum(),
		"maxScore":      checker.Max(),
		"maxSeverity": checker.MaxBy(func(severity string) int {
			rank, _ := types.SeverityRankOf(severity)

			return severityOrder(rank)
		}),
	},
}

// severityOrder orders severity ranks for the maxSeverity summary. An
// unknown severity ranks above none so that a finding which could not be
// classified is never hidden behind a clean or informational result.
func severityOrder(rank int) int {
	if rank == types.SeverityRankUnknown {
		return types.SeverityRankNone*2 + 1
	}

	return rank * 2 //nolint:mnd // leaves a slot above none for unknown
}

// Info returns the check type and label of the vulnerability scan check.
func Info() checker.Info {
	return spec.Info
}

// Verify checks a single vulnerability scan attestation against the given policy.
func Verify(
	ctx context.Context,
	att []byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	//nolint:wrapcheck // the generic checker returns domain errors
	return spec.Verify(ctx, att, pol, imageDigest)
}

// VerifyMultiple checks multiple vulnerability scan attestations. Any policy
// violation or invalid document causes failure.
func VerifyMultiple(
	ctx context.Context,
	attestations [][]byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	//nolint:wrapcheck // the generic checker returns domain errors
	return spec.VerifyMultiple(ctx, attestations, pol, imageDigest)
}

func validatePredicate(pred *vulnScanPredicate) error {
	if pred.Scanner == nil {
		return errMissingScanner
	}

	if strings.TrimSpace(pred.Scanner.URI) == "" {
		return errMissingScannerURI
	}

	if pred.Scanner.Result == nil && pred.Result == nil {
		return errMissingResults
	}

	var specResults []specResult
	if pred.Scanner.Result != nil {
		specResults = *pred.Scanner.Result
	}

	for idx := range specResults {
		entry := &specResults[idx]
		if entry.Vulnerability != nil {
			if entry.ID == "" {
				entry.ID = entry.Vulnerability.ID
			}

			entry.Severity = append(entry.Severity, entry.Vulnerability.Severity...)
		}

		if strings.TrimSpace(entry.ID) == "" {
			return fmt.Errorf("%w: scanner.result[%d]", errMissingVulnID, idx)
		}

		pred.vulns = append(pred.vulns, normalizeSpecResult(entry))
	}

	return normalizeLegacyResults(pred)
}

func normalizeLegacyResults(pred *vulnScanPredicate) error {
	if pred.Result == nil {
		return nil
	}

	if pred.Result.Vulnerabilities == nil {
		return errMissingLegacyVulns
	}

	legacyVulns := *pred.Result.Vulnerabilities

	for idx := range legacyVulns {
		legacy := &legacyVulns[idx]
		if strings.TrimSpace(legacy.ID) == "" {
			return fmt.Errorf("%w: result.vulnerabilities[%d]", errMissingVulnID, idx)
		}

		pred.vulns = append(pred.vulns, normalizeLegacy(legacy))
	}

	return nil
}

// normalizeSpecResult derives the score and severity of a finding from all
// of its severity entries, keeping the most severe. Numeric scores are read
// as CVSS base scores; textual scores as qualitative severities. Entries that
// are neither (for example CVSS vectors) and EPSS probabilities are ignored.
func normalizeSpecResult(result *specResult) vulnerability {
	vuln := vulnerability{ID: result.ID, Score: nil, Rank: types.SeverityRankUnknown}

	for idx := range result.Severity {
		entry := &result.Severity[idx]
		if strings.Contains(strings.ToLower(entry.Method), epssMethod) {
			continue
		}

		raw := strings.TrimSpace(string(entry.Score))

		score, err := strconv.ParseFloat(raw, 64)
		if err == nil {
			vuln.addScore(score)

			continue
		}

		if rank, known := types.SeverityRankOf(raw); known {
			vuln.Rank = max(vuln.Rank, rank)
		}
	}

	return vuln
}

func normalizeLegacy(legacy *legacyVulnerability) vulnerability {
	vuln := vulnerability{ID: legacy.ID, Score: nil, Rank: types.SeverityRankUnknown}

	if rank, known := types.SeverityRankOf(legacy.Severity); known {
		vuln.Rank = rank
	}

	if legacy.Score != nil {
		vuln.addScore(*legacy.Score)
	}

	return vuln
}

func (v *vulnerability) addScore(score float64) {
	rank, valid := types.SeverityRankFromCVSS(score)
	if !valid {
		return
	}

	if v.Score == nil || score > *v.Score {
		v.Score = &score
	}

	v.Rank = max(v.Rank, rank)
}

func scanTimestamp(pred *vulnScanPredicate) *time.Time {
	if pred.Metadata == nil {
		return nil
	}

	// Zero times carry no information, so a later candidate is used instead.
	for _, candidate := range []*time.Time{
		pred.Metadata.ScanFinishedOn, pred.Metadata.ScannedOn, pred.Metadata.ScanStartedOn,
	} {
		if candidate != nil && !candidate.IsZero() {
			return candidate
		}
	}

	return nil
}

func predicateMeta(pred *vulnScanPredicate) map[string]any {
	var (
		maxScore      float64
		criticalCount int64
		highCount     int64
		unknownCount  int64
	)

	maxRank := types.SeverityRankNone

	for idx := range pred.vulns {
		vuln := &pred.vulns[idx]

		if vuln.Score != nil && *vuln.Score > maxScore {
			maxScore = *vuln.Score
		}

		if severityOrder(vuln.Rank) > severityOrder(maxRank) {
			maxRank = vuln.Rank
		}

		switch vuln.Rank {
		case types.SeverityRankCritical:
			criticalCount++
		case types.SeverityRankHigh:
			highCount++
		case types.SeverityRankUnknown:
			unknownCount++
		default:
		}
	}

	return map[string]any{
		"scanner":       pred.Scanner.URI,
		"vulnCount":     int64(len(pred.vulns)),
		"maxScore":      maxScore,
		"maxSeverity":   types.SeverityName(maxRank),
		"criticalCount": criticalCount,
		"highCount":     highCount,
		"unknownCount":  unknownCount,
	}
}

// checkThresholds applies maxScore, minSeverity, and ignoreCVEs. When a
// threshold is configured, a finding whose severity cannot be determined
// fails closed; it can be accepted explicitly through ignoreCVEs.
func checkThresholds(pred *vulnScanPredicate, pol *policy.Policy) string {
	if pol.VulnScan == nil || (pol.VulnScan.MaxScore == nil && pol.VulnScan.MinSeverity == "") {
		return ""
	}

	ignored := make(map[string]struct{}, len(pol.VulnScan.IgnoreCVEs))
	for _, cve := range pol.VulnScan.IgnoreCVEs {
		ignored[cve] = struct{}{}
	}

	for idx := range pred.vulns {
		vuln := &pred.vulns[idx]
		if _, skip := ignored[vuln.ID]; skip {
			continue
		}

		violation := vuln.thresholdViolation(pol.VulnScan)
		if violation != "" {
			return violation
		}
	}

	return ""
}

func (v *vulnerability) thresholdViolation(pol *policy.VulnScanPolicy) string {
	if v.Rank == types.SeverityRankUnknown {
		return fmt.Sprintf(
			"vulnerability threshold cannot be evaluated: %s has no recognizable severity or score",
			v.ID,
		)
	}

	minRank, minRankSet := types.SeverityRankOf(pol.MinSeverity)
	if !v.exceedsMaxScore(pol.MaxScore) && (!minRankSet || v.Rank < minRank) {
		return ""
	}

	score := float64(0)
	if v.Score != nil {
		score = *v.Score
	}

	return fmt.Sprintf(
		"vulnerability threshold exceeded: %s (score %.1f, severity %s)",
		v.ID, score, types.SeverityName(v.Rank),
	)
}

// exceedsMaxScore compares the score, or for findings without a numeric
// score the lowest score of their severity, against maxScore.
func (v *vulnerability) exceedsMaxScore(maxScore *float64) bool {
	if maxScore == nil {
		return false
	}

	if v.Score != nil {
		return *v.Score > *maxScore
	}

	return types.SeverityMinimumCVSS(v.Rank) > *maxScore
}

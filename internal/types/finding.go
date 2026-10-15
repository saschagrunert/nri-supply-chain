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

package types

import "fmt"

// Finding is a vulnerability finding rated for severity thresholds. Rank is
// the most severe of its textual severities and of the severities derived
// from its scores, and Score is its highest valid CVSS base score (nil when
// no rating carries one).
type Finding struct {
	ID    string
	Score *float64
	Rank  int
}

// NewFinding returns an unrated finding.
func NewFinding(id string) Finding {
	return Finding{ID: id, Score: nil, Rank: SeverityRankUnknown}
}

// AddScore rates the finding with a CVSS base score. Scores outside the CVSS
// range are ignored and reported as invalid.
func (f *Finding) AddScore(score float64) bool {
	rank, valid := SeverityRankFromCVSS(score)
	if !valid {
		return false
	}

	if f.Score == nil || score > *f.Score {
		f.Score = &score
	}

	f.Rank = max(f.Rank, rank)

	return true
}

// AddSeverity rates the finding with a textual severity. Unrecognized
// severities are ignored and reported as unknown.
func (f *Finding) AddSeverity(severity string) bool {
	rank, known := SeverityRankOf(severity)
	if !known {
		return false
	}

	f.Rank = max(f.Rank, rank)

	return true
}

// EffectiveScore returns the score compared against a maximum score: the
// highest score, raised to the lowest score of the finding's rank, so that a
// textual severity cannot be outweighed by a lower numeric score from another
// rating.
func (f *Finding) EffectiveScore() float64 {
	minimum := SeverityMinimumCVSS(f.Rank)
	if f.Score != nil {
		return max(*f.Score, minimum)
	}

	return minimum
}

// SeverityThresholds are the maximum score and minimum severity a set of
// findings is evaluated against. A finding is flagged when it exceeds
// MaxScore or meets MinSeverity.
type SeverityThresholds struct {
	// Label prefixes violation messages, for example "CVSS".
	Label       string
	MaxScore    *float64
	MinSeverity string
	IgnoreCVEs  []string
}

// Violation returns a description of the first finding that violates the
// thresholds, or an empty string. Findings listed in IgnoreCVEs are skipped.
// When a threshold is configured, a finding whose severity cannot be
// determined fails closed.
func (t *SeverityThresholds) Violation(findings []Finding) string {
	if t.MaxScore == nil && t.MinSeverity == "" {
		return ""
	}

	ignored := make(map[string]struct{}, len(t.IgnoreCVEs))
	for _, cve := range t.IgnoreCVEs {
		ignored[cve] = struct{}{}
	}

	for idx := range findings {
		if _, skip := ignored[findings[idx].ID]; skip {
			continue
		}

		violation := t.violation(&findings[idx])
		if violation != "" {
			return violation
		}
	}

	return ""
}

func (t *SeverityThresholds) violation(finding *Finding) string {
	if finding.Rank == SeverityRankUnknown {
		return fmt.Sprintf(
			"%s threshold cannot be evaluated: %s has no recognizable severity or score",
			t.Label, finding.ID,
		)
	}

	exceeded := t.MaxScore != nil && finding.EffectiveScore() > *t.MaxScore

	if t.MinSeverity != "" {
		// Policy validation rejects unknown severities; one that slips
		// through flags every finding.
		minRank, known := SeverityRankOf(t.MinSeverity)
		if !known || finding.Rank >= minRank {
			exceeded = true
		}
	}

	if !exceeded {
		return ""
	}

	return fmt.Sprintf(
		"%s threshold exceeded: %s (score %.1f, severity %s)",
		t.Label, finding.ID, finding.EffectiveScore(), SeverityName(finding.Rank),
	)
}

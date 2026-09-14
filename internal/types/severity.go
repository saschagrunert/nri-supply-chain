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

import (
	"math"
	"strings"
)

// Vulnerability severity ranks ordered from least to most severe.
const (
	// SeverityRankUnknown marks a severity that could not be determined.
	SeverityRankUnknown = -1
	// SeverityRankNone is the rank of the "none" severity.
	SeverityRankNone = 0
	// SeverityRankLow is the rank of the "low" severity.
	SeverityRankLow = 1
	// SeverityRankMedium is the rank of the "medium" severity.
	SeverityRankMedium = 2
	// SeverityRankHigh is the rank of the "high" severity.
	SeverityRankHigh = 3
	// SeverityRankCritical is the rank of the "critical" severity.
	SeverityRankCritical = 4
)

const (
	cvssMaxScore      = 10.0
	cvssLowMinimum    = 0.1
	cvssMediumMinimum = 4.0
	cvssHighMinimum   = 7.0
	cvssCritMinimum   = 9.0
)

// SeverityName returns the canonical lowercase name for a severity rank.
func SeverityName(rank int) string {
	switch rank {
	case SeverityRankNone:
		return "none"
	case SeverityRankLow:
		return "low"
	case SeverityRankMedium:
		return "medium"
	case SeverityRankHigh:
		return "high"
	case SeverityRankCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// SeverityRankOf returns the rank of a textual severity. Matching is
// case-insensitive and accepts common scanner aliases ("moderate",
// "important", "negligible", "informational"). The second return value is
// false when the severity is not recognized.
func SeverityRankOf(severity string) (int, bool) {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "none", "info", "informational":
		return SeverityRankNone, true
	case "low", "negligible":
		return SeverityRankLow, true
	case "medium", "moderate":
		return SeverityRankMedium, true
	case "high", "important":
		return SeverityRankHigh, true
	case "critical":
		return SeverityRankCritical, true
	default:
		return SeverityRankUnknown, false
	}
}

// SeverityMinimumCVSS returns the lowest CVSS base score of a qualitative
// severity rank. It returns 0 for none and unknown ranks.
func SeverityMinimumCVSS(rank int) float64 {
	switch rank {
	case SeverityRankLow:
		return cvssLowMinimum
	case SeverityRankMedium:
		return cvssMediumMinimum
	case SeverityRankHigh:
		return cvssHighMinimum
	case SeverityRankCritical:
		return cvssCritMinimum
	default:
		return 0
	}
}

// SeverityRankFromCVSS maps a CVSS v3/v4 base score to its qualitative
// severity rank (none 0.0, low 0.1 to 3.9, medium 4.0 to 6.9, high 7.0 to
// 8.9, critical 9.0 to 10.0). The second return value is false when the
// score is outside the valid range.
func SeverityRankFromCVSS(score float64) (int, bool) {
	switch {
	case math.IsNaN(score) || score < 0 || score > cvssMaxScore:
		return SeverityRankUnknown, false
	case score >= cvssCritMinimum:
		return SeverityRankCritical, true
	case score >= cvssHighMinimum:
		return SeverityRankHigh, true
	case score >= cvssMediumMinimum:
		return SeverityRankMedium, true
	case score >= cvssLowMinimum:
		return SeverityRankLow, true
	default:
		return SeverityRankNone, true
	}
}

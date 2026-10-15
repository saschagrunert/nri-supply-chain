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

package types_test

import (
	"math"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	testLabelCVSS   = "CVSS"
	testSeverityLow = "low"
)

func TestFindingEffectiveScore(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		scores     []float64
		severities []string
		want       float64
	}{
		{name: "score only", scores: []float64{5.3}, severities: nil, want: 5.3},
		{name: "severity only", scores: nil, severities: []string{"important"}, want: 7.0},
		{
			name:       "severity raises lower score",
			scores:     []float64{5.3},
			severities: []string{"CRITICAL"},
			want:       9.0,
		},
		{
			name:       "higher score kept",
			scores:     []float64{9.8},
			severities: []string{"HIGH"},
			want:       9.8,
		},
		{
			name:       "invalid score ignored",
			scores:     []float64{42, math.NaN()},
			severities: []string{testSeverityLow},
			want:       0.1,
		},
		{name: "unrated", scores: nil, severities: []string{"unknown"}, want: 0},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			finding := types.NewFinding("CVE-1")
			for _, score := range test.scores {
				finding.AddScore(score)
			}

			for _, severity := range test.severities {
				finding.AddSeverity(severity)
			}

			testutil.AssertEqual(t, test.want, finding.EffectiveScore())
		})
	}
}

func TestSeverityThresholdsViolation(t *testing.T) {
	t.Parallel()

	critical := types.NewFinding("CVE-1")
	critical.AddScore(5.3)
	critical.AddSeverity("critical")

	unrated := types.NewFinding("CVE-2")

	low := types.NewFinding("CVE-3")
	low.AddScore(2.0)

	tests := []struct {
		name       string
		thresholds types.SeverityThresholds
		findings   []types.Finding
		want       string
	}{
		{
			name: "no thresholds",
			thresholds: types.SeverityThresholds{
				Label:       testLabelCVSS,
				MaxScore:    nil,
				MinSeverity: "",
				IgnoreCVEs:  nil,
			},
			findings: []types.Finding{critical, unrated},
			want:     "",
		},
		{
			name: "max score uses severity floor",
			thresholds: types.SeverityThresholds{
				Label:       testLabelCVSS,
				MaxScore:    new(7.0),
				MinSeverity: "",
				IgnoreCVEs:  nil,
			},
			findings: []types.Finding{low, critical},
			want:     "CVSS threshold exceeded: CVE-1 (score 9.0, severity critical)",
		},
		{
			name: "unrated fails closed",
			thresholds: types.SeverityThresholds{
				Label: "vulnerability", MaxScore: nil, MinSeverity: "high", IgnoreCVEs: nil,
			},
			findings: []types.Finding{unrated},
			want:     "vulnerability threshold cannot be evaluated: CVE-2 has no recognizable severity or score",
		},
		{
			name: "ignored findings skipped",
			thresholds: types.SeverityThresholds{
				Label:       testLabelCVSS,
				MaxScore:    new(7.0),
				MinSeverity: "",
				IgnoreCVEs:  []string{"CVE-1", "CVE-2"},
			},
			findings: []types.Finding{critical, unrated, low},
			want:     "",
		},
		{
			name: "min severity met",
			thresholds: types.SeverityThresholds{
				Label: testLabelCVSS, MaxScore: nil, MinSeverity: testSeverityLow, IgnoreCVEs: nil,
			},
			findings: []types.Finding{low},
			want:     "CVSS threshold exceeded: CVE-3 (score 2.0, severity low)",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			testutil.AssertEqual(t, test.want, test.thresholds.Violation(test.findings))
		})
	}
}

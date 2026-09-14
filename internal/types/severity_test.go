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

func TestSeverityRankOf(t *testing.T) {
	t.Parallel()

	tests := []struct {
		severity  string
		wantRank  int
		wantKnown bool
	}{
		{severity: "CRITICAL", wantRank: types.SeverityRankCritical, wantKnown: true},
		{severity: " high ", wantRank: types.SeverityRankHigh, wantKnown: true},
		{severity: "Important", wantRank: types.SeverityRankHigh, wantKnown: true},
		{severity: "moderate", wantRank: types.SeverityRankMedium, wantKnown: true},
		{severity: "negligible", wantRank: types.SeverityRankLow, wantKnown: true},
		{severity: "informational", wantRank: types.SeverityRankNone, wantKnown: true},
		{severity: "UNKNOWN", wantRank: types.SeverityRankUnknown, wantKnown: false},
		{severity: "", wantRank: types.SeverityRankUnknown, wantKnown: false},
	}

	for _, tc := range tests {
		t.Run(tc.severity, func(t *testing.T) {
			t.Parallel()

			rank, known := types.SeverityRankOf(tc.severity)
			testutil.AssertEqual(t, tc.wantRank, rank)
			testutil.AssertEqual(t, tc.wantKnown, known)
		})
	}
}

func TestSeverityRankFromCVSS(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		score     float64
		wantRank  int
		wantValid bool
	}{
		{name: "zero", score: 0, wantRank: types.SeverityRankNone, wantValid: true},
		{name: "low", score: 3.9, wantRank: types.SeverityRankLow, wantValid: true},
		{name: "medium", score: 4.0, wantRank: types.SeverityRankMedium, wantValid: true},
		{name: "high", score: 8.9, wantRank: types.SeverityRankHigh, wantValid: true},
		{name: "critical", score: 9.0, wantRank: types.SeverityRankCritical, wantValid: true},
		{name: "max", score: 10, wantRank: types.SeverityRankCritical, wantValid: true},
		{name: "negative", score: -1, wantRank: types.SeverityRankUnknown, wantValid: false},
		{name: "too large", score: 10.1, wantRank: types.SeverityRankUnknown, wantValid: false},
		{name: "nan", score: math.NaN(), wantRank: types.SeverityRankUnknown, wantValid: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rank, valid := types.SeverityRankFromCVSS(tc.score)
			testutil.AssertEqual(t, tc.wantRank, rank)
			testutil.AssertEqual(t, tc.wantValid, valid)
		})
	}
}

func TestSeverityName(t *testing.T) {
	t.Parallel()

	testutil.AssertEqual(t, "none", types.SeverityName(types.SeverityRankNone))
	testutil.AssertEqual(t, "low", types.SeverityName(types.SeverityRankLow))
	testutil.AssertEqual(t, "medium", types.SeverityName(types.SeverityRankMedium))
	testutil.AssertEqual(t, "high", types.SeverityName(types.SeverityRankHigh))
	testutil.AssertEqual(t, "critical", types.SeverityName(types.SeverityRankCritical))
	testutil.AssertEqual(t, "unknown", types.SeverityName(types.SeverityRankUnknown))
}

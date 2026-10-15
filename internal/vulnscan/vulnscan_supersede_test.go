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

package vulnscan_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/vulnscan"
)

func scanAt(t *testing.T, doc vulnScanDoc, scanned time.Time) []byte {
	t.Helper()

	timestamp := scanned.UTC().Format(time.RFC3339)
	doc.Metadata = &scanMeta{ScannedOn: &timestamp}

	return testutil.WrapInToto(t, doc, testDigest, testPredicateType)
}

func maxAgePolicy() *policy.Policy {
	return &policy.Policy{
		VulnScan: &policy.VulnScanPolicy{
			MaxAge:         "24h",
			MaxAgeDuration: 24 * time.Hour,
			MaxScore:       new(7.0),
		},
	}
}

func TestVerifyMultipleFreshScanSupersedesStale(t *testing.T) {
	t.Parallel()

	now := time.Now()

	tests := []struct {
		name       string
		docs       [][]byte
		wantPassed bool
		wantDetail string
	}{
		{
			name: "stale critical scan is superseded by a fresh clean scan",
			docs: [][]byte{
				scanAt(t, criticalDoc(), now.Add(-72*time.Hour)),
				scanAt(t, cleanDoc(), now.Add(-time.Hour)),
			},
			wantPassed: true,
			wantDetail: "",
		},
		{
			name: "only stale scans fail",
			docs: [][]byte{
				scanAt(t, cleanDoc(), now.Add(-72*time.Hour)),
				scanAt(t, cleanDoc(), now.Add(-48*time.Hour)),
			},
			wantPassed: false,
			wantDetail: "stale",
		},
		{
			name: "fresh scan exceeding thresholds still fails",
			docs: [][]byte{
				scanAt(t, cleanDoc(), now.Add(-72*time.Hour)),
				scanAt(t, criticalDoc(), now.Add(-time.Hour)),
			},
			wantPassed: false,
			wantDetail: "threshold exceeded",
		},
		{
			name: "scan without timestamp is not superseded",
			docs: [][]byte{
				testutil.WrapInToto(t, cleanDoc(), testDigest, testPredicateType),
				scanAt(t, cleanDoc(), now.Add(-time.Hour)),
			},
			wantPassed: false,
			wantDetail: "no scanned timestamp",
		},
		{
			name: "invalid document is not superseded",
			docs: [][]byte{
				testutil.WrapInToto(t, json.RawMessage(`{}`), testDigest, testPredicateType),
				scanAt(t, cleanDoc(), now.Add(-time.Hour)),
			},
			wantPassed: false,
			wantDetail: "failed verification",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			result, err := vulnscan.VerifyMultiple(
				context.Background(), test.docs, maxAgePolicy(), testDigest,
			)
			testutil.AssertNoError(t, err)
			testutil.AssertEqual(t, test.wantPassed, result.Passed)

			if test.wantDetail != "" {
				testutil.AssertContains(t, result.Detail, test.wantDetail)
			}
		})
	}
}

func TestVerifyTextualSeverityNotOutweighedByScore(t *testing.T) {
	t.Parallel()

	predicate := `{"scanner":{"uri":"https://trivy.dev","result":[{"id":"CVE-1","severity":[` +
		`{"method":"nvd","score":"5.3"},{"method":"ghsa","score":"CRITICAL"}]}]}}`
	att := testutil.WrapInToto(t, json.RawMessage(predicate), testDigest, testPredicateType)

	result, err := vulnscan.VerifyMultiple(context.Background(), [][]byte{att}, &policy.Policy{
		VulnScan: &policy.VulnScanPolicy{MaxScore: new(7.0)},
	}, testDigest)
	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, false, result.Passed)
	testutil.AssertContains(t, result.Detail, "CVE-1 (score 9.0, severity critical)")
}

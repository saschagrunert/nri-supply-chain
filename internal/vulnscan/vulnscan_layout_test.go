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
	"errors"
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/vulnscan"
)

const (
	testSevNameUnknown = "unknown"
	testMaxSeverityKey = "maxSeverity"
)

// specExamplePredicate is the in-toto vulns v0.1 specification example with
// the flat result layout (the published example has a syntax error in the
// second severity entry, which is corrected here).
const specExamplePredicate = `{
  "invocation": {
    "parameters": [],
    "uri": "https://github.com/developer-guy/alpine/actions/runs/1071875574",
    "event_id": "1071875574",
    "builder.id": "GitHub Actions"
  },
  "scanner": {
    "uri": "pkg:github/aquasecurity/trivy@244fd47e07d1004f0aed9",
    "version": "0.19.2",
    "db": {
      "uri": "pkg:github/aquasecurity/trivy-db/commit/4c76bb580b2736d67751410fa4ab66d2b6b9b27d",
      "version": "v1-2021080612",
      "lastUpdate": "2021-08-06T17:45:50.52Z"
    },
    "result": [
      {
        "id": "CVE-123",
        "severity": [
          {"method": "nvd", "score": "medium"},
          {"method": "cvss_score", "score": "5.2"}
        ]
      }
    ]
  },
  "metadata": {
    "scanStartedOn": "2021-08-06T17:45:50.52Z",
    "scanFinishedOn": "2021-08-06T17:50:50.52Z"
  }
}`

// attestActionPredicate is the output of the vulnerability scan jq filter in
// .github/actions/attest/action.yml for a Trivy report that lists
// CVE-2024-1111 as HIGH (7.5) for one package and CRITICAL (9.8) for another.
const attestActionPredicate = `{
  "scanner": {
    "uri": "https://trivy.dev",
    "version": "0.74.0",
    "result": [
      {"id": "CVE-2024-1111", "severity": [
        {"method": "cvss_v3", "score": "7.5"},
        {"method": "cvss_v3", "score": "9.8"},
        {"method": "trivy", "score": "CRITICAL"},
        {"method": "trivy", "score": "HIGH"}
      ]},
      {"id": "CVE-2024-2222", "severity": [{"method": "trivy", "score": "LOW"}]},
      {"id": "CVE-2024-3333", "severity": [
        {"method": "cvss_v3", "score": "5.3"},
        {"method": "trivy", "score": "MEDIUM"}
      ]}
    ]
  },
  "metadata": {"scanFinishedOn": "2026-09-14T09:04:13Z"}
}`

func TestVerifyAttestActionPredicate(t *testing.T) {
	t.Parallel()

	att := testutil.WrapInToto(
		t, json.RawMessage(attestActionPredicate), testDigest, testPredicateType,
	)

	result, err := vulnscan.Verify(context.Background(), att, &policy.Policy{
		VulnScan: &policy.VulnScanPolicy{MinSeverity: testSevHigh},
	}, testDigest)
	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, false, result.Passed)
	testutil.AssertContains(t, result.Detail, "CVE-2024-1111 (score 9.8, severity critical)")
}

func TestVerifySpecExampleFixture(t *testing.T) {
	t.Parallel()

	att := testutil.WrapInToto(
		t, json.RawMessage(specExamplePredicate), testDigest, testPredicateType,
	)

	result, err := vulnscan.Verify(context.Background(), att, &policy.Policy{
		VulnScan: &policy.VulnScanPolicy{MinSeverity: testSevHigh},
	}, testDigest)
	testutil.AssertNoError(t, err)
	testutil.AssertTrue(t, result.Passed)
	testutil.AssertEqual[any](t, int64(1), result.Metadata["vulnCount"])
	testutil.AssertEqual[any](t, testSevMedium, result.Metadata[testMaxSeverityKey])
	testutil.AssertEqual[any](t, 5.2, result.Metadata["maxScore"])
}

func TestVerifyRejectsLegacyResultWithoutVulnerabilities(t *testing.T) {
	t.Parallel()

	tests := []string{
		`{"scanner":{"uri":"x"},"result":{"vulns":[{"id":"CVE-1","severity":"critical"}]}}`,
		`{"scanner":{"uri":"x"},"result":{"SchemaVersion":2,` +
			`"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-1"}]}]}}`,
		`{"scanner":{"uri":"x"},"result":{"vulnerabilities":null}}`,
	}

	for _, predicate := range tests {
		t.Run(predicate, func(t *testing.T) {
			t.Parallel()

			att := testutil.WrapInToto(t, json.RawMessage(predicate), testDigest, testPredicateType)
			maxScore := 5.0

			_, err := vulnscan.Verify(context.Background(), att, &policy.Policy{
				VulnScan: &policy.VulnScanPolicy{MaxScore: &maxScore},
			}, testDigest)
			if !errors.Is(err, vulnscan.ErrInvalidVulnScan) {
				t.Fatalf("expected ErrInvalidVulnScan, got %v", err)
			}
		})
	}
}

func TestVerifyNestedVulnerabilityLayout(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"severity list": `{"scanner":{"uri":"x","result":[{"vulnerability":` +
			`{"id":"CVE-2024-0001","severity":[{"method":"cvss_score","score":"9.8"}]}}]}}`,
		"severity object": `{"scanner":{"uri":"x","result":[{"vulnerability":` +
			`{"id":"CVE-2024-0001","severity":{"method":"nvd","score":"critical"}}}]}}`,
	}

	for name, predicate := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			att := testutil.WrapInToto(t, json.RawMessage(predicate), testDigest, testPredicateType)

			result, err := vulnscan.Verify(context.Background(), att, &policy.Policy{
				VulnScan: &policy.VulnScanPolicy{MinSeverity: testSevHigh},
			}, testDigest)
			testutil.AssertNoError(t, err)
			testutil.AssertEqual(t, false, result.Passed)
			testutil.AssertContains(t, result.Detail, "CVE-2024-0001")
			testutil.AssertEqual[any](t, int64(1), result.Metadata["criticalCount"])
		})
	}
}

func TestVerifyMultipleUnknownSeverityOutranksNone(t *testing.T) {
	t.Parallel()

	clean := `{"scanner":{"uri":"x","result":[]}}`
	unknown := `{"scanner":{"uri":"x","result":[` +
		`{"id":"CVE-2024-0002","severity":[{"method":"x","score":"weird"}]}]}}`

	for _, order := range [][]string{{clean, unknown}, {unknown, clean}} {
		attestations := [][]byte{
			testutil.WrapInToto(t, json.RawMessage(order[0]), testDigest, testPredicateType),
			testutil.WrapInToto(t, json.RawMessage(order[1]), testDigest, testPredicateType),
		}

		result, err := vulnscan.VerifyMultiple(
			context.Background(), attestations, &policy.Policy{}, testDigest,
		)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual[any](t, testSevNameUnknown, result.Metadata[testMaxSeverityKey])
		testutil.AssertEqual[any](t, int64(1), result.Metadata["unknownCount"])
	}

	mixed := `{"scanner":{"uri":"x","result":[` +
		`{"id":"CVE-2024-0003","severity":[{"method":"cvss_score","score":"0.0"}]},` +
		`{"id":"CVE-2024-0002","severity":[{"method":"x","score":"weird"}]}]}}`
	att := testutil.WrapInToto(t, json.RawMessage(mixed), testDigest, testPredicateType)

	result, err := vulnscan.Verify(context.Background(), att, &policy.Policy{}, testDigest)
	testutil.AssertNoError(t, err)
	testutil.AssertEqual[any](t, testSevNameUnknown, result.Metadata[testMaxSeverityKey])
}

func TestVerifyZeroTimestampTreatedAsAbsent(t *testing.T) {
	t.Parallel()

	t.Run("without maxAge", func(t *testing.T) {
		t.Parallel()

		predicate := `{"scanner":{"uri":"x","result":[]},` +
			`"metadata":{"scanFinishedOn":"0001-01-01T00:00:00Z"}}`
		att := testutil.WrapInToto(t, json.RawMessage(predicate), testDigest, testPredicateType)

		result, err := vulnscan.Verify(context.Background(), att, &policy.Policy{}, testDigest)
		testutil.AssertNoError(t, err)
		testutil.AssertTrue(t, result.Passed)
	})

	t.Run("falls back to valid timestamp", func(t *testing.T) {
		t.Parallel()

		started := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
		predicate := `{"scanner":{"uri":"x","result":[]},"metadata":{` +
			`"scanStartedOn":"` + started + `","scanFinishedOn":"0001-01-01T00:00:00Z"}}`
		att := testutil.WrapInToto(t, json.RawMessage(predicate), testDigest, testPredicateType)

		result, err := vulnscan.Verify(context.Background(), att, &policy.Policy{
			VulnScan: &policy.VulnScanPolicy{MaxAge: "1h", MaxAgeDuration: time.Hour},
		}, testDigest)
		testutil.AssertNoError(t, err)
		testutil.AssertTrue(t, result.Passed)
	})
}

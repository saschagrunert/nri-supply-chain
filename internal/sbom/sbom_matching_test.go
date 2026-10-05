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

package sbom_test

import (
	"strings"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
)

// emptyNamePURL is a purl without a name, which cannot be parsed.
const emptyNamePURL = "pkg:npm/"

func cvssThresholdPolicy(maxScore *float64, minSeverity string) *policy.Policy {
	return &policy.Policy{
		SBOM: &policy.SBOMPolicy{
			CVSS: &policy.SBOMCVSSPolicy{MaxScore: maxScore, MinSeverity: minSeverity},
		},
	}
}

func cyclonedxWithVulnerability(vulnerability string) string {
	return `{"bomFormat":"CycloneDX","components":[{"name":"a","purl":"pkg:npm/a@1"}],` +
		`"vulnerabilities":[` + vulnerability + `]}`
}

func TestVerifyCVSSPartialRatings(t *testing.T) {
	t.Parallel()

	maxScore := 7.0

	tests := []struct {
		name          string
		vulnerability string
		pol           *policy.Policy
		wantPass      bool
	}{
		{
			name:          "severity-only critical exceeds maxScore",
			vulnerability: `{"id":"CVE-1","ratings":[{"severity":"critical"}]}`,
			pol:           cvssThresholdPolicy(&maxScore, ""),
			wantPass:      false,
		},
		{
			name:          "severity-only high is within maxScore 7",
			vulnerability: `{"id":"CVE-1","ratings":[{"severity":"high"}]}`,
			pol:           cvssThresholdPolicy(&maxScore, ""),
			wantPass:      true,
		},
		{
			name:          "score-only 9.8 meets minSeverity high",
			vulnerability: `{"id":"CVE-1","ratings":[{"score":9.8}]}`,
			pol:           cvssThresholdPolicy(nil, "high"),
			wantPass:      false,
		},
		{
			name:          "score-only 5.0 is below minSeverity high",
			vulnerability: `{"id":"CVE-1","ratings":[{"score":5.0}]}`,
			pol:           cvssThresholdPolicy(nil, "high"),
			wantPass:      true,
		},
		{
			name:          "scanner alias important meets minSeverity high",
			vulnerability: `{"id":"CVE-1","ratings":[{"severity":"important"}]}`,
			pol:           cvssThresholdPolicy(nil, "high"),
			wantPass:      false,
		},
		{
			name:          "unknown severity without score is unrated",
			vulnerability: `{"id":"CVE-1","ratings":[{"severity":"unknown"}]}`,
			pol:           cvssThresholdPolicy(&maxScore, ""),
			wantPass:      true,
		},
		{
			name:          "uppercase UNKNOWN severity is unrated for minSeverity",
			vulnerability: `{"id":"CVE-1","ratings":[{"severity":"UNKNOWN"}]}`,
			pol:           cvssThresholdPolicy(nil, "low"),
			wantPass:      true,
		},
		{
			name:          "none severity without score is unrated",
			vulnerability: `{"id":"CVE-1","ratings":[{"severity":"None"},{"severity":"informational"}]}`,
			pol:           cvssThresholdPolicy(&maxScore, "low"),
			wantPass:      true,
		},
		{
			name:          "unknown severity next to a critical score still fails",
			vulnerability: `{"id":"CVE-1","ratings":[{"severity":"unknown"},{"score":9.8}]}`,
			pol:           cvssThresholdPolicy(&maxScore, ""),
			wantPass:      false,
		},
		{
			name:          "unrecognized severity fails closed",
			vulnerability: `{"id":"CVE-1","ratings":[{"severity":"urgent"}]}`,
			pol:           cvssThresholdPolicy(&maxScore, ""),
			wantPass:      false,
		},
		{
			name:          "out of range score fails closed",
			vulnerability: `{"id":"CVE-1","ratings":[{"score":42}]}`,
			pol:           cvssThresholdPolicy(nil, "critical"),
			wantPass:      false,
		},
		{
			name:          "unrecognized severity accepted through ignoreCVEs",
			vulnerability: `{"id":"CVE-1","ratings":[{"severity":"urgent"}]}`,
			pol: &policy.Policy{SBOM: &policy.SBOMPolicy{CVSS: &policy.SBOMCVSSPolicy{
				MaxScore: &maxScore, IgnoreCVEs: []string{"CVE-1"},
			}}},
			wantPass: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			passed, detail := verifyRaw(t, cyclonedxWithVulnerability(tc.vulnerability), tc.pol)
			if passed != tc.wantPass {
				t.Errorf("passed = %v, want %v (detail %q)", passed, tc.wantPass, detail)
			}
		})
	}
}

func TestVerifyCVSSIgnoresResolvedVulnerabilitiesInSBOM(t *testing.T) {
	t.Parallel()

	maxScore := 7.0

	for _, analysis := range []string{
		`{"state":"not_affected","justification":"code_not_reachable"}`,
		`{"state":"resolved"}`,
		`{"state":"false_positive"}`,
		`{"state":"resolved_with_pedigree"}`,
	} {
		vulnerability := `{"id":"CVE-1","ratings":[{"score":9.8,"severity":"critical"}],` +
			`"analysis":` + analysis + `}`

		passed, detail := verifyRaw(t, cyclonedxWithVulnerability(vulnerability),
			cvssThresholdPolicy(&maxScore, ""))
		if !passed {
			t.Errorf(
				"analysis %s: expected resolved vulnerability to be skipped, got %q",
				analysis,
				detail,
			)
		}
	}

	vulnerability := `{"id":"CVE-1","ratings":[{"score":9.8}],"analysis":{"state":"exploitable"}}`

	passed, _ := verifyRaw(
		t,
		cyclonedxWithVulnerability(vulnerability),
		cvssThresholdPolicy(&maxScore, ""),
	)
	if passed {
		t.Error("expected an exploitable vulnerability to exceed maxScore")
	}
}

func TestVerifyCVSSNotAffectedRequiresJustification(t *testing.T) {
	t.Parallel()

	maxScore := 7.0

	for _, analysis := range []string{
		`{"state":"not_affected"}`,
		`{"state":"not_affected","justification":""}`,
		`{"state":"not_affected","justification":"  "}`,
		`{"state":"NOT_AFFECTED"}`,
	} {
		vulnerability := `{"id":"CVE-1","ratings":[{"score":9.8,"severity":"critical"}],` +
			`"analysis":` + analysis + `}`

		passed, _ := verifyRaw(t, cyclonedxWithVulnerability(vulnerability),
			cvssThresholdPolicy(&maxScore, ""))
		if passed {
			t.Errorf(
				"analysis %s: expected an unjustified not_affected critical CVE to fail",
				analysis,
			)
		}
	}
}

func TestVerifyComponentDenyListWithInvalidPURL(t *testing.T) {
	t.Parallel()

	deny := []string{"pkg:npm/lodash"}

	// An unrelated malformed purl does not hide a denied valid one.
	passed, _ := verifyRaw(t,
		cyclonedxWithPURLs(emptyNamePURL, "pkg:npm/lodash@4.17.20"), componentListPolicy(deny, nil))
	if passed {
		t.Error("expected the denied component to fail next to a malformed purl")
	}

	passed, detail := verifyRaw(t,
		cyclonedxWithPURLs(emptyNamePURL, "pkg:npm/other@1"), componentListPolicy(deny, nil))
	if !passed {
		t.Errorf("expected a deny-only list to ignore an unrelated malformed purl, got %q", detail)
	}

	passed, detail = verifyRaw(t,
		cyclonedxWithPURLs("pkg:npm/lodash@%zz"), componentListPolicy(deny, nil))
	if passed || !strings.Contains(detail, "pkg:npm/lodash@%zz") {
		t.Errorf(
			"expected the malformed denied purl to be reported, got passed %v, %q",
			passed,
			detail,
		)
	}
}

func componentListPolicy(deny, allow []string) *policy.Policy {
	return &policy.Policy{
		SBOM: &policy.SBOMPolicy{
			Component: &policy.SBOMComponentPolicy{Deny: deny, Allow: allow},
		},
	}
}

func cyclonedxWithPURLs(purls ...string) string {
	components := make([]string, 0, len(purls))
	for _, purlValue := range purls {
		components = append(components, `{"name":"c","purl":"`+purlValue+`"}`)
	}

	return `{"bomFormat":"CycloneDX","components":[` + strings.Join(components, ",") + `]}`
}

func TestVerifyComponentListMatching(t *testing.T) {
	t.Parallel()

	const lodashVersioned = "pkg:npm/lodash@4.17.20"

	var (
		lodashEntry  = []string{"pkg:npm/lodash"}
		npmTypeEntry = []string{"pkg:npm"}

		eventStreamEntry = []string{"pkg:npm/event-stream@3.3"}
		dOneEntry        = []string{"pkg:npm/d@1"}
	)

	tests := []struct {
		name     string
		purl     string
		deny     []string
		allow    []string
		wantPass bool
	}{
		{"deny matches uppercase type", "pkg:NPM/lodash@4.17.20", lodashEntry, nil, false},
		{"deny matches percent-encoded name", "pkg:npm/%6Codash@4.17.20", lodashEntry, nil, false},
		{"deny matches qualified purl", "pkg:npm/lodash@4.17.20?arch=x", lodashEntry, nil, false},
		{"deny does not match name prefix", "pkg:npm/lodash-es@4.17.20", lodashEntry, nil, true},
		{"deny version matches exactly", lodashVersioned, []string{lodashVersioned}, nil, false},
		{
			"deny version is not a prefix",
			"pkg:npm/lodash@4.17.201",
			[]string{lodashVersioned},
			nil,
			true,
		},
		{
			"deny version prefix matches patch release",
			"pkg:npm/event-stream@3.3.6",
			eventStreamEntry,
			nil,
			false,
		},
		{
			"deny version prefix matches prerelease",
			"pkg:npm/event-stream@3.3-rc1",
			eventStreamEntry,
			nil,
			false,
		},
		{
			"deny version prefix matches build metadata",
			"pkg:npm/event-stream@3.3+build1",
			eventStreamEntry,
			nil,
			false,
		},
		{
			"deny version prefix matches exactly",
			"pkg:npm/event-stream@3.3",
			eventStreamEntry,
			nil,
			false,
		},
		{
			"deny version prefix needs a segment boundary",
			"pkg:npm/event-stream@3.30",
			eventStreamEntry,
			nil,
			true,
		},
		{
			"deny version prefix does not match shorter version",
			"pkg:npm/event-stream@3",
			eventStreamEntry,
			nil,
			true,
		},
		{
			"deny qualifier must match", "pkg:deb/debian/curl@8?arch=arm64",
			[]string{"pkg:deb/debian/curl?arch=amd64"},
			nil, true,
		},
		{
			"deny namespace covers packages",
			"pkg:maven/org.evil/lib@1",
			[]string{"pkg:maven/org.evil"},
			nil,
			false,
		},
		{
			"deny npm scope covers packages",
			"pkg:npm/%40evil/lib@1",
			[]string{"pkg:npm/@evil"},
			nil,
			false,
		},
		{"deny whole type", "pkg:npm/b@2", npmTypeEntry, nil, false},
		{"deny ignores unrelated invalid purl", emptyNamePURL, lodashEntry, nil, true},
		{
			"deny matches invalid purl of denied package",
			"pkg:npm/lodash@4.17.20?arch=%zz",
			lodashEntry,
			nil,
			false,
		},
		{
			"deny matches invalid percent-encoded purl",
			"pkg:NPM/%6Codash@%zz",
			lodashEntry,
			nil,
			false,
		},
		{
			"deny invalid purl needs a segment boundary",
			"pkg:npm/lodash-es@%zz",
			lodashEntry,
			nil,
			true,
		},
		{
			"deny invalid purl matches version prefix",
			"pkg:npm/event-stream@3.3.6?a=%zz",
			eventStreamEntry,
			nil,
			false,
		},
		{
			"deny invalid purl version boundary",
			"pkg:npm/event-stream@3.30?a=%zz",
			eventStreamEntry,
			nil,
			true,
		},
		{"deny whole type matches invalid purl", emptyNamePURL, npmTypeEntry, nil, false},
		{"invalid deny entry fails", "pkg:npm/c@3", []string{"pkg:npm/%zz"}, nil, false},
		{"allow rejects name prefix", "pkg:npm/lodash-evil@1", nil, lodashEntry, false},
		{"allow matches normalized identity", "pkg:NPM/%6Codash@1", nil, lodashEntry, true},
		{
			"allow pypi normalized name",
			"pkg:pypi/Django_Rest@1",
			nil,
			[]string{"pkg:pypi/django-rest"},
			true,
		},
		{
			"allow golang namespace",
			"pkg:golang/github.com/myorg/repo@v1",
			nil,
			[]string{"pkg:golang/github.com/myorg"},
			true,
		},
		{"allow rejects invalid purl", "not-a-purl", nil, npmTypeEntry, false},
		{"allow rejects invalid purl of allowed type", emptyNamePURL, nil, npmTypeEntry, false},
		{"allow version mismatch", "pkg:npm/d@2", nil, dOneEntry, false},
		{"allow version prefix", "pkg:npm/d@1.2.3", nil, dOneEntry, true},
		{"allow version prefix boundary", "pkg:npm/d@10", nil, dOneEntry, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			passed, detail := verifyRaw(
				t,
				cyclonedxWithPURLs(tc.purl),
				componentListPolicy(tc.deny, tc.allow),
			)
			if passed != tc.wantPass {
				t.Errorf("passed = %v, want %v (detail %q)", passed, tc.wantPass, detail)
			}
		})
	}
}

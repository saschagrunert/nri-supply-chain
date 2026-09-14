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
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/purl"
	"github.com/saschagrunert/nri-supply-chain/internal/sbom"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
)

func denyLicensePolicy(ids ...string) *policy.Policy {
	return &policy.Policy{
		SBOM: &policy.SBOMPolicy{
			License: &policy.SBOMLicensePolicy{Deny: ids},
		},
	}
}

func allowComponentPolicy(prefixes ...string) *policy.Policy {
	return &policy.Policy{
		SBOM: &policy.SBOMPolicy{
			Component: &policy.SBOMComponentPolicy{Allow: prefixes},
		},
	}
}

func verifyRaw(t *testing.T, predicate string, pol *policy.Policy) (passed bool, detail string) {
	t.Helper()

	att := testutil.WrapInToto(t, json.RawMessage(predicate), testDigest, testPredicateType)

	result, err := sbom.Verify(context.Background(), att, pol, testDigest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	return result.Passed, result.Detail
}

func TestVerifyLicenseExpressionsDenied(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		predicate string
	}{
		{
			name: "cyclonedx license expression",
			predicate: `{"bomFormat":"CycloneDX","components":[{"name":"a","purl":"pkg:npm/a@1",` +
				`"licenses":[{"expression":"MIT OR GPL-3.0-only"}]}]}`,
		},
		{
			name: "nested cyclonedx component license",
			predicate: `{"bomFormat":"CycloneDX","components":[{"name":"app","purl":"pkg:npm/app@1",` +
				`"components":[{"name":"b","purl":"pkg:npm/b@1",` +
				`"licenses":[{"license":{"id":"GPL-3.0-only"}}]}]}]}`,
		},
		{
			name: "spdx parenthesized identifier",
			predicate: `{"spdxVersion":"SPDX-2.3","packages":[{"name":"a",` +
				`"licenseConcluded":"(GPL-3.0-only)"}]}`,
		},
		{
			name: "spdx operator without whitespace before parenthesis",
			predicate: `{"spdxVersion":"SPDX-2.3","packages":[{"name":"a",` +
				`"licenseConcluded":"MIT AND(GPL-3.0-only)"}]}`,
		},
		{
			name: "spdx lowercase operator",
			predicate: `{"spdxVersion":"SPDX-2.3","packages":[{"name":"a",` +
				`"licenseDeclared":"MIT and GPL-3.0-only"}]}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			passed, detail := verifyRaw(t, test.predicate, denyLicensePolicy(testLicenseGPL3Only))
			if passed {
				t.Errorf("expected denied license to fail, got pass: %s", detail)
			}
		})
	}
}

func TestVerifyLicenseTokenizerBypasses(t *testing.T) {
	t.Parallel()

	spdxPackage := func(license string) string {
		return `{"spdxVersion":"SPDX-2.3","packages":[{"name":"a",` +
			`"licenseConcluded":` + string(testutil.MustMarshal(t, license)) + `}]}`
	}

	denyGPL := denyLicensePolicy("GPL-2.0", testLicenseGPL2Only, testLicenseGPL3Only)

	tests := []struct {
		name       string
		license    string
		pol        *policy.Policy
		wantPassed bool
	}{
		{
			name:       "plus suffix is denied by its base identifier",
			license:    testLicenseGPL2OrLater,
			pol:        denyGPL,
			wantPassed: false,
		},
		{
			name:       "plus suffix is denied by its or-later identifier",
			license:    testLicenseGPL2OrLater,
			pol:        denyLicensePolicy("GPL-2.0-or-later"),
			wantPassed: false,
		},
		{
			name:       "license identifier after WITH is still checked",
			license:    "MIT WITH GPL-3.0-only",
			pol:        denyGPL,
			wantPassed: false,
		},
		{
			name:       "non-breaking spaces separate tokens",
			license:    "MIT\u00a0AND\u00a0GPL-3.0-only",
			pol:        denyGPL,
			wantPassed: false,
		},
		{
			name:    "plus suffix is allowed by its or-later identifier",
			license: testLicenseGPL2OrLater,
			pol: &policy.Policy{SBOM: &policy.SBOMPolicy{
				License: &policy.SBOMLicensePolicy{Allow: []string{"GPL-2.0-or-later"}},
			}},
			wantPassed: true,
		},
		{
			name:    "plus suffix is not allowed by the narrower only identifier",
			license: testLicenseGPL2OrLater,
			pol: &policy.Policy{SBOM: &policy.SBOMPolicy{
				License: &policy.SBOMLicensePolicy{Allow: []string{testLicenseGPL2Only}},
			}},
			wantPassed: false,
		},
		{
			name:       "known exception after WITH is skipped",
			license:    "MIT WITH Classpath-exception-2.0",
			pol:        denyLicensePolicy("Classpath-exception-2.0"),
			wantPassed: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			passed, detail := verifyRaw(t, spdxPackage(test.license), test.pol)
			if passed != test.wantPassed {
				t.Errorf("expected passed=%v, got %v: %s", test.wantPassed, passed, detail)
			}
		})
	}
}

func TestVerifyLicenseWithExceptionUsesLicenseID(t *testing.T) {
	t.Parallel()

	predicate := `{"spdxVersion":"SPDX-2.3","packages":[{"name":"a",` +
		`"licenseConcluded":"GPL-2.0-only WITH Classpath-exception-2.0"}]}`

	pol := &policy.Policy{
		SBOM: &policy.SBOMPolicy{
			License: &policy.SBOMLicensePolicy{Allow: []string{testLicenseGPL2Only}},
		},
	}

	passed, detail := verifyRaw(t, predicate, pol)
	if !passed {
		t.Errorf("expected exception identifier to be skipped, got: %s", detail)
	}
}

func TestVerifyCycloneDXLicenseNameNotTokenized(t *testing.T) {
	t.Parallel()

	predicate := `{"bomFormat":"CycloneDX","components":[{"name":"a","purl":"pkg:npm/a@1",` +
		`"licenses":[{"license":{"name":"Apache License 2.0 or later"}}]}]}`

	pol := &policy.Policy{
		SBOM: &policy.SBOMPolicy{
			License: &policy.SBOMLicensePolicy{
				Allow: []string{"Apache License 2.0 or later"},
			},
		},
	}

	passed, detail := verifyRaw(t, predicate, pol)
	if !passed {
		t.Errorf("expected free-text license name to match verbatim, got: %s", detail)
	}
}

func TestVerifyComponentAllowListRequiresPURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		predicate  string
		wantPassed bool
	}{
		{
			name: "cyclonedx library without purl fails",
			predicate: `{"bomFormat":"CycloneDX","components":[` +
				`{"type":"library","name":"a","purl":"pkg:npm/a@1"},` +
				`{"type":"library","name":"sneaky"}]}`,
			wantPassed: false,
		},
		{
			name: "cyclonedx nested library without purl fails",
			predicate: `{"bomFormat":"CycloneDX","components":[` +
				`{"type":"application","name":"a","purl":"pkg:npm/a@1",` +
				`"components":[{"type":"library","name":"hidden"}]}]}`,
			wantPassed: false,
		},
		{
			name: "cyclonedx operating system and file components are exempt",
			predicate: `{"bomFormat":"CycloneDX","components":[` +
				`{"type":"library","name":"a","purl":"pkg:npm/a@1"},` +
				`{"type":"operating-system","name":"alpine"},` +
				`{"type":"file","name":"/etc/passwd"}]}`,
			wantPassed: true,
		},
		{
			name: "spdx described root package is exempt",
			predicate: `{"spdxVersion":"SPDX-2.3","documentDescribes":["SPDXRef-root"],` +
				`"packages":[{"SPDXID":"SPDXRef-root","name":"image"},` +
				`{"SPDXID":"SPDXRef-a","name":"a","externalRefs":[` +
				`{"referenceType":"purl","referenceLocator":"pkg:npm/a@1"}]}]}`,
			wantPassed: true,
		},
		{
			name: "spdx package without purl fails",
			predicate: `{"spdxVersion":"SPDX-2.3","packages":[` +
				`{"SPDXID":"SPDXRef-a","name":"a","externalRefs":[` +
				`{"referenceType":"purl","referenceLocator":"pkg:npm/a@1"}]},` +
				`{"SPDXID":"SPDXRef-b","name":"b"}]}`,
			wantPassed: false,
		},
		{
			name: "cyclonedx trivy lock file application component is exempt",
			predicate: `{"bomFormat":"CycloneDX","components":[` +
				`{"type":"application","name":"usr/src/app/package-lock.json",` +
				`"properties":[{"name":"aquasecurity:trivy:Class","value":"lang-pkgs"},` +
				`{"name":"aquasecurity:trivy:Type","value":"npm"}]},` +
				`{"type":"library","name":"a","purl":"pkg:npm/a@1"}]}`,
			wantPassed: true,
		},
		{
			name: "cyclonedx versionless application without purl is exempt",
			predicate: `{"bomFormat":"CycloneDX","components":[` +
				`{"type":"application","name":"go.mod"},` +
				`{"type":"library","name":"a","purl":"pkg:npm/a@1"}]}`,
			wantPassed: true,
		},
		{
			name: "cyclonedx versioned application without purl still fails",
			predicate: `{"bomFormat":"CycloneDX","components":[` +
				`{"type":"application","name":"sneaky","version":"1.0.0"}]}`,
			wantPassed: false,
		},
		{
			name: "spdx versionless application package without purl is exempt",
			predicate: `{"spdxVersion":"SPDX-2.3","packages":[` +
				`{"SPDXID":"SPDXRef-lock","name":"package-lock.json",` +
				`"primaryPackagePurpose":"APPLICATION"},` +
				`{"SPDXID":"SPDXRef-a","name":"a","externalRefs":[` +
				`{"referenceType":"purl","referenceLocator":"pkg:npm/a@1"}]}]}`,
			wantPassed: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			passed, detail := verifyRaw(t, test.predicate, allowComponentPolicy("pkg:npm/"))
			if passed != test.wantPassed {
				t.Errorf("expected passed=%v, got %v: %s", test.wantPassed, passed, detail)
			}
		})
	}
}

const spdx301Document = `{
  "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
  "@graph": [
    {"type": "CreationInfo", "@id": "_:ci", "specVersion": "3.0.1"},
    {"type": "SpdxDocument", "spdxId": "urn:doc", "rootElement": ["urn:sbom"]},
    {"type": "software_Sbom", "spdxId": "urn:sbom", "rootElement": ["urn:image"]},
    {"type": "software_Package", "spdxId": "urn:image", "name": "image",
     "software_primaryPurpose": "container"},
    {"type": "software_Package", "spdxId": "urn:pkg-a", "name": "a",
     "software_packageVersion": "1.0.0", "software_packageUrl": "pkg:npm/a@1.0.0",
     "verifiedUsing": [{"type": "Hash", "algorithm": "sha256", "hashValue": "abc"}]},
    {"type": "software_Package", "spdxId": "urn:pkg-b", "name": "b",
     "externalIdentifier": [{"type": "ExternalIdentifier",
       "externalIdentifierType": "packageUrl", "identifier": "pkg:npm/b@2.0.0"}]},
    {"type": "simplelicensing_LicenseExpression", "spdxId": "urn:lic-expr",
     "simplelicensing_licenseExpression": "MIT AND GPL-3.0-only"},
    {"type": "Relationship", "spdxId": "urn:rel-1", "from": "urn:pkg-a",
     "relationshipType": "hasConcludedLicense", "to": ["urn:lic-expr"]},
    {"type": "Relationship", "spdxId": "urn:rel-2", "from": "urn:pkg-b",
     "relationshipType": "hasDeclaredLicense", "to": ["https://spdx.org/licenses/Apache-2.0"]}
  ]
}`

func TestVerifySPDX301(t *testing.T) {
	t.Parallel()

	t.Run("relationship licenses are resolved", func(t *testing.T) {
		t.Parallel()

		passed, detail := verifyRaw(t, spdx301Document, denyLicensePolicy(testLicenseGPL3Only))
		if passed {
			t.Errorf("expected license from Relationship element to be denied, got %s", detail)
		}

		passed, detail = verifyRaw(t, spdx301Document, denyLicensePolicy(testLicenseApache2))
		if passed {
			t.Errorf("expected listed license IRI to be denied, got %s", detail)
		}
	})

	t.Run("packages, purls, and exempt root", func(t *testing.T) {
		t.Parallel()

		att := testutil.WrapInToto(
			t,
			json.RawMessage(spdx301Document),
			testDigest,
			testPredicateType,
		)

		result, err := sbom.Verify(
			context.Background(), att, allowComponentPolicy("pkg:npm/"), testDigest,
		)
		testutil.AssertNoError(t, err)

		if !result.Passed {
			t.Fatalf("expected pass, got %s", result.Detail)
		}

		testutil.AssertEqual[any](t, int64(3), result.Metadata["componentCount"])

		purls, ok := result.Metadata["purls"].([]string)
		if !ok || len(purls) != 2 {
			t.Errorf("expected two purls, got %v", result.Metadata["purls"])
		}
	})
}

func TestVerifyCycloneDXDocumentSubject(t *testing.T) {
	t.Parallel()

	t.Run("metadata component license is checked", func(t *testing.T) {
		t.Parallel()

		predicate := `{"bomFormat":"CycloneDX","metadata":{"component":{"type":"container",` +
			`"name":"app","licenses":[{"license":{"id":"GPL-3.0-only"}}]}},` +
			`"components":[{"type":"library","name":"a","purl":"pkg:npm/a@1"}]}`

		passed, detail := verifyRaw(t, predicate, denyLicensePolicy(testLicenseGPL3Only))
		if passed {
			t.Errorf("expected metadata component license to be denied, got %s", detail)
		}
	})

	t.Run("empty components array is valid", func(t *testing.T) {
		t.Parallel()

		predicate := `{"bomFormat":"CycloneDX","specVersion":"1.5",` +
			`"metadata":{"component":{"type":"container","name":"scratch"}},"components":[]}`

		passed, detail := verifyRaw(t, predicate, denyLicensePolicy(testLicenseGPL3Only))
		if !passed {
			t.Errorf("expected empty CycloneDX BOM to pass, got %s", detail)
		}
	})
}

func spdx301LicenseDocument(licenseElements string) string {
	return `{
  "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
  "@graph": [
    {"type": "SpdxDocument", "spdxId": "urn:doc", "rootElement": ["urn:image"]},
    {"type": "software_Package", "spdxId": "urn:image", "name": "image",
     "software_primaryPurpose": "container"},
    {"type": "software_Package", "spdxId": "urn:pkg-a", "name": "a",
     "software_packageUrl": "pkg:npm/a@1.0.0"},
    {"type": "Relationship", "spdxId": "urn:rel", "from": "urn:pkg-a",
     "relationshipType": "hasConcludedLicense", "to": ["urn:lic"]},
    ` + licenseElements + `
  ]
}`
}

func TestVerifySPDX301ExpandedLicensing(t *testing.T) {
	t.Parallel()

	withAddition := spdx301LicenseDocument(`
    {"type": "expandedlicensing_WithAdditionOperator", "spdxId": "urn:lic",
     "expandedlicensing_subjectExtendableLicense": "https://spdx.org/licenses/GPL-3.0-only",
     "expandedlicensing_subjectAddition": "https://spdx.org/licenses/Classpath-exception-2.0"}`)

	orLater := spdx301LicenseDocument(`
    {"type": "expandedlicensing_OrLaterOperator", "spdxId": "urn:lic",
     "expandedlicensing_subjectLicense": "urn:gpl2"},
    {"type": "expandedlicensing_ListedLicense", "spdxId": "urn:gpl2",
     "name": "GPL-2.0-only"}`)

	unresolved := spdx301LicenseDocument(`
    {"type": "Relationship", "spdxId": "urn:rel-2", "from": "urn:pkg-a",
     "relationshipType": "hasDeclaredLicense", "to": ["urn:missing-license"]},
    {"type": "expandedlicensing_ListedLicense", "spdxId": "urn:lic", "name": "MIT"}`)

	allow := func(ids ...string) *policy.Policy {
		return &policy.Policy{SBOM: &policy.SBOMPolicy{
			License: &policy.SBOMLicensePolicy{Allow: ids},
		}}
	}

	tests := []struct {
		name       string
		document   string
		pol        *policy.Policy
		wantPassed bool
	}{
		{
			name:       "with addition operator subject is denied",
			document:   withAddition,
			pol:        denyLicensePolicy(testLicenseGPL3Only),
			wantPassed: false,
		},
		{
			name:       "with addition operator subject fails allow list",
			document:   withAddition,
			pol:        allow(testLicenseMIT),
			wantPassed: false,
		},
		{
			name:       "with addition operator subject passes matching allow list",
			document:   withAddition,
			pol:        allow(testLicenseGPL3Only),
			wantPassed: true,
		},
		{
			name:       "or later operator subject is denied",
			document:   orLater,
			pol:        denyLicensePolicy(testLicenseGPL2Only),
			wantPassed: false,
		},
		{
			name:       "or later operator subject fails allow list",
			document:   orLater,
			pol:        allow(testLicenseMIT),
			wantPassed: false,
		},
		{
			name:       "unresolved license reference fails allow list",
			document:   unresolved,
			pol:        allow(testLicenseMIT),
			wantPassed: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			passed, detail := verifyRaw(t, test.document, test.pol)
			if passed != test.wantPassed {
				t.Errorf("expected passed=%v, got %v: %s", test.wantPassed, passed, detail)
			}
		})
	}
}

func TestVerifyMetadataPURLsCompacted(t *testing.T) {
	t.Parallel()

	predicate := `{"bomFormat":"CycloneDX","components":[` +
		`{"name":"a","purl":"pkg:npm/a@1?arch=amd64"},` +
		`{"name":"a2","purl":"pkg:npm/a@1#sub"},` +
		`{"name":"b","purl":"pkg:npm/b@2"}]}`

	att := testutil.WrapInToto(t, json.RawMessage(predicate), testDigest, testPredicateType)

	result, err := sbom.Verify(context.Background(), att, &policy.Policy{}, testDigest)
	testutil.AssertNoError(t, err)

	purls, ok := result.Metadata["purls"].([]string)
	if !ok || strings.Join(purls, ",") != "pkg:npm/a@1,pkg:npm/b@2" {
		t.Errorf("expected compacted purls, got %v", result.Metadata["purls"])
	}
}

func TestVerifyMetadataPURLsKeepUpstream(t *testing.T) {
	t.Parallel()

	predicate := `{"bomFormat":"CycloneDX","components":[` +
		`{"name":"libc6","purl":"pkg:deb/debian/libc6@2.36-9?arch=amd64&upstream=glibc&distro=debian-12"}]}`

	att := testutil.WrapInToto(t, json.RawMessage(predicate), testDigest, testPredicateType)

	result, err := sbom.Verify(context.Background(), att, &policy.Policy{}, testDigest)
	testutil.AssertNoError(t, err)

	purls, ok := result.Metadata["purls"].([]string)
	if !ok || strings.Join(purls, ",") != "pkg:deb/debian/libc6@2.36-9?upstream=glibc" {
		t.Errorf("expected compacted purl to keep the upstream qualifier, got %v",
			result.Metadata["purls"])
	}
}

func TestVerifyMetadataPURLsCapped(t *testing.T) {
	t.Parallel()

	var builder strings.Builder

	builder.WriteString(`{"bomFormat":"CycloneDX","components":[`)

	total := sbom.MaxMetadataPURLs + 5
	for idx := range total {
		if idx > 0 {
			builder.WriteByte(',')
		}

		fmt.Fprintf(&builder, `{"name":"p%d","purl":"pkg:npm/p%d@1"}`, idx, idx)
	}

	builder.WriteString(`]}`)

	att := testutil.WrapInToto(t, json.RawMessage(builder.String()), testDigest, testPredicateType)

	result, err := sbom.VerifyMultiple(
		context.Background(), [][]byte{att}, &policy.Policy{}, testDigest,
	)
	testutil.AssertNoError(t, err)

	purls, ok := result.Metadata["purls"].([]string)
	if !ok || len(purls) != sbom.MaxMetadataPURLs+1 {
		t.Fatalf("expected capped purl list, got %d entries", len(purls))
	}

	testutil.AssertEqual(t, purl.TruncatedMarker, purls[len(purls)-1])
}

func TestVerifyDriftRequiresBaseline(t *testing.T) {
	t.Parallel()

	maxAdded := 0
	thresholdPolicy := &policy.Policy{
		SBOM: &policy.SBOMPolicy{Drift: &policy.SBOMDriftPolicy{MaxAdded: &maxAdded}},
	}

	current := testutil.WrapInToto(t, validSPDXDoc(), testDigest, testPredicateType)
	baseline := testutil.MustMarshal(t, validSPDXDoc())

	tests := []struct {
		name       string
		baselines  [][]byte
		pol        *policy.Policy
		wantPassed bool
	}{
		{
			name:       "thresholds without baseline fail",
			baselines:  nil,
			pol:        thresholdPolicy,
			wantPassed: false,
		},
		{
			name:       "unparsable baseline fails with thresholds",
			baselines:  [][]byte{baseline, []byte("not json")},
			pol:        thresholdPolicy,
			wantPassed: false,
		},
		{
			name:       "matching baseline passes",
			baselines:  [][]byte{baseline},
			pol:        thresholdPolicy,
			wantPassed: true,
		},
		{
			name:       "no thresholds and no baseline pass",
			baselines:  nil,
			pol:        &policy.Policy{},
			wantPassed: true,
		},
		{
			name:       "no thresholds skip unparsable baseline",
			baselines:  [][]byte{[]byte("not json")},
			pol:        &policy.Policy{},
			wantPassed: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			result, err := sbom.VerifyMultipleWithBaseline(
				context.Background(), [][]byte{current}, test.baselines, test.pol, testDigest,
			)
			testutil.AssertNoError(t, err)

			if result.Passed != test.wantPassed {
				t.Errorf(
					"expected passed=%v, got %v: %s",
					test.wantPassed,
					result.Passed,
					result.Detail,
				)
			}
		})
	}
}

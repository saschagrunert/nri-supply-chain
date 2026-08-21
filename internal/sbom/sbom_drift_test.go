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

package sbom //nolint:testpackage // needs access to unexported drift types

import (
	"encoding/json"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
)

const (
	testLodashPURL  = "pkg:npm/lodash@4.17.21"
	testLodashVer   = "4.17.21"
	testExpressPURL = "pkg:npm/express@4.18.0"
	testExpressVer  = "4.18.0"
	testRemovedPURL = "pkg:npm/removed-pkg@1.0.0"
	testLodashName  = "lodash"
	testExpressName = "express"
	testRemovedName = "removed-pkg"
	testVer10       = "1.0"
	testVer100      = "1.0.0"
	testAlgoSHA256  = "SHA256"
	testHashABC123  = "abc123"
	testHashABC     = "abc"
	testHashDef     = "def"
	testAlgoSHA512  = "SHA512"
	testLicMIT      = "MIT"
	testLicApache   = "Apache-2.0"
	testLibName     = "mylib"
)

func testPkg(purl, name, version string) sbomPackage {
	return sbomPackage{
		PURL:      purl,
		Name:      name,
		Version:   version,
		Licenses:  nil,
		Checksums: nil,
	}
}

func testPkgWithLicenses(
	purl, name, version string,
	licenses []string, checksums map[string]string,
) sbomPackage {
	return sbomPackage{
		PURL:      purl,
		Name:      name,
		Version:   version,
		Licenses:  licenses,
		Checksums: checksums,
	}
}

func driftBaseline() []sbomPackage {
	return []sbomPackage{
		testPkgWithLicenses(
			testLodashPURL, testLodashName, testLodashVer,
			[]string{testLicMIT},
			map[string]string{testAlgoSHA256: testHashABC123},
		),
		testPkgWithLicenses(
			testExpressPURL, testExpressName, testExpressVer,
			[]string{testLicMIT}, nil,
		),
		testPkg(testRemovedPURL, testRemovedName, testVer100),
	}
}

func zeroDrift() driftResult {
	return driftResult{
		Added:         nil,
		Removed:       nil,
		Modified:      nil,
		AddedCount:    0,
		RemovedCount:  0,
		ModifiedCount: 0,
		Score:         0,
	}
}

func TestComputeDrift(t *testing.T) {
	t.Parallel()

	baseline := driftBaseline()

	tests := []struct {
		name              string
		current           []sbomPackage
		useNilBaseline    bool
		wantAdded         int
		wantRemoved       int
		wantModified      int
		wantScorePositive bool
	}{
		{
			name:              "identical packages produce no drift",
			current:           baseline,
			useNilBaseline:    false,
			wantAdded:         0,
			wantRemoved:       0,
			wantModified:      0,
			wantScorePositive: false,
		},
		{
			name: "added package detected",
			current: append(
				append([]sbomPackage{}, baseline...),
				testPkg("pkg:npm/malicious@0.1.0", "malicious", "0.1.0"),
			),
			useNilBaseline:    false,
			wantAdded:         1,
			wantRemoved:       0,
			wantModified:      0,
			wantScorePositive: true,
		},
		{
			name:              "removed package detected",
			current:           []sbomPackage{baseline[0], baseline[1]},
			useNilBaseline:    false,
			wantAdded:         0,
			wantRemoved:       1,
			wantModified:      0,
			wantScorePositive: true,
		},
		{
			name: "version change detected as modified",
			current: []sbomPackage{
				testPkgWithLicenses(
					testLodashPURL, testLodashName, "4.17.22",
					[]string{testLicMIT},
					map[string]string{testAlgoSHA256: testHashABC123},
				),
				baseline[1], baseline[2],
			},
			useNilBaseline:    false,
			wantAdded:         0,
			wantRemoved:       0,
			wantModified:      1,
			wantScorePositive: true,
		},
		{
			name: "checksum mismatch detected as modified",
			current: []sbomPackage{
				testPkgWithLicenses(
					testLodashPURL, testLodashName, testLodashVer,
					[]string{testLicMIT},
					map[string]string{testAlgoSHA256: "def456"},
				),
				baseline[1], baseline[2],
			},
			useNilBaseline:    false,
			wantAdded:         0,
			wantRemoved:       0,
			wantModified:      1,
			wantScorePositive: true,
		},
		{
			name: "license change detected as modified",
			current: []sbomPackage{
				testPkgWithLicenses(
					testLodashPURL, testLodashName, testLodashVer,
					[]string{"GPL-3.0"},
					map[string]string{testAlgoSHA256: testHashABC123},
				),
				baseline[1], baseline[2],
			},
			useNilBaseline:    false,
			wantAdded:         0,
			wantRemoved:       0,
			wantModified:      1,
			wantScorePositive: true,
		},
		{
			name: "combined drift: added, removed, and modified",
			current: []sbomPackage{
				testPkgWithLicenses(
					testLodashPURL, testLodashName, "4.17.22",
					[]string{testLicMIT},
					map[string]string{testAlgoSHA256: testHashABC123},
				),
				testPkg("pkg:npm/new-dep@1.0.0", "new-dep", testVer100),
			},
			useNilBaseline:    false,
			wantAdded:         1,
			wantRemoved:       2,
			wantModified:      1,
			wantScorePositive: true,
		},
		{
			name:              "empty baseline treats all current as added",
			current:           baseline,
			useNilBaseline:    true,
			wantAdded:         3,
			wantRemoved:       0,
			wantModified:      0,
			wantScorePositive: false,
		},
		{
			name:              "packages without PURLs are ignored",
			current:           []sbomPackage{testPkg("", "no-purl", testVer10)},
			useNilBaseline:    false,
			wantAdded:         0,
			wantRemoved:       3,
			wantModified:      0,
			wantScorePositive: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			bl := baseline
			if tc.useNilBaseline {
				bl = nil
			}

			result := computeDrift(bl, tc.current)

			testutil.AssertEqual(t, result.AddedCount, tc.wantAdded)
			testutil.AssertEqual(t, result.RemovedCount, tc.wantRemoved)
			testutil.AssertEqual(t, result.ModifiedCount, tc.wantModified)

			if tc.wantScorePositive {
				if result.Score <= 0 {
					t.Errorf("expected positive score, got %f", result.Score)
				}
			} else {
				if result.Score != 0 {
					t.Errorf("expected zero score, got %f", result.Score)
				}
			}
		})
	}
}

func TestComputeDriftScore(t *testing.T) {
	t.Parallel()

	baseline := []sbomPackage{
		testPkg("pkg:npm/a@1.0", "a", testVer10),
		testPkg("pkg:npm/b@1.0", "b", testVer10),
		testPkg("pkg:npm/c@1.0", "c", testVer10),
		testPkg("pkg:npm/d@1.0", "d", testVer10),
	}

	current := []sbomPackage{
		testPkg("pkg:npm/a@1.0", "a", testVer10),
		testPkg("pkg:npm/b@1.0", "b", "2.0"),
		testPkg("pkg:npm/e@1.0", "e", testVer10),
	}

	result := computeDrift(baseline, current)

	testutil.AssertEqual(t, result.AddedCount, 1)
	testutil.AssertEqual(t, result.RemovedCount, 2)
	testutil.AssertEqual(t, result.ModifiedCount, 1)

	// score = (1*3 + 1*2 + 2*1) / 4 = 7/4 = 1.75
	expectedScore := 1.75
	if result.Score != expectedScore {
		t.Errorf("expected score %f, got %f", expectedScore, result.Score)
	}
}

func TestDriftResultToMetadata(t *testing.T) {
	t.Parallel()

	result := driftResult{
		Added:         []sbomPackage{testPkg("pkg:npm/new@1.0", "", "")},
		Removed:       []sbomPackage{testPkg("pkg:npm/old@1.0", "", "")},
		Modified:      []sbomPackage{testPkg("pkg:npm/changed@1.0", "", "")},
		AddedCount:    1,
		RemovedCount:  1,
		ModifiedCount: 1,
		Score:         2.5,
	}

	meta := result.ToMetadata()

	if detected, ok := meta["detected"].(bool); !ok || !detected {
		t.Error("expected detected=true")
	}

	if addedVal, ok := meta["addedCount"].(int64); !ok || addedVal != 1 {
		t.Errorf("expected addedCount=1, got %v", meta["addedCount"])
	}

	if removedVal, ok := meta["removedCount"].(int64); !ok || removedVal != 1 {
		t.Errorf("expected removedCount=1, got %v", meta["removedCount"])
	}

	if modifiedVal, ok := meta["modifiedCount"].(int64); !ok || modifiedVal != 1 {
		t.Errorf("expected modifiedCount=1, got %v", meta["modifiedCount"])
	}

	if scoreVal, ok := meta["score"].(float64); !ok || scoreVal != 2.5 {
		t.Errorf("expected score=2.5, got %v", meta["score"])
	}

	addedPkgs, ok := meta["addedPackages"].([]string)
	if !ok {
		t.Fatal("addedPackages should be []string")
	}

	testutil.AssertEqual(t, len(addedPkgs), 1)
	testutil.AssertEqual(t, addedPkgs[0], "pkg:npm/new@1.0")
}

func TestDriftResultToMetadataNoDrift(t *testing.T) {
	t.Parallel()

	result := zeroDrift()
	meta := result.ToMetadata()

	if detected, ok := meta["detected"].(bool); !ok || detected {
		t.Error("expected detected=false")
	}

	if addedVal, ok := meta["addedCount"].(int64); !ok || addedVal != 0 {
		t.Errorf("expected addedCount=0, got %v", meta["addedCount"])
	}

	if scoreVal, ok := meta["score"].(float64); !ok || scoreVal != 0 {
		t.Errorf("expected score=0, got %v", meta["score"])
	}
}

func TestCheckDriftThresholds(t *testing.T) {
	t.Parallel()

	intPtr := func(val int) *int { return &val }
	floatPtr := func(val float64) *float64 { return &val }

	newDrift := func(added, removed, modified int, score float64) driftResult {
		return driftResult{
			Added:         nil,
			Removed:       nil,
			Modified:      nil,
			AddedCount:    added,
			RemovedCount:  removed,
			ModifiedCount: modified,
			Score:         score,
		}
	}

	tests := []struct {
		name       string
		drift      driftResult
		pol        *policy.SBOMDriftPolicy
		wantPassed bool
	}{
		{
			name:       "no thresholds configured always passes",
			drift:      newDrift(10, 5, 3, 5.0),
			pol:        &policy.SBOMDriftPolicy{},
			wantPassed: true,
		},
		{
			name:       "added count within threshold passes",
			drift:      newDrift(2, 0, 0, 0),
			pol:        &policy.SBOMDriftPolicy{MaxAdded: intPtr(5)},
			wantPassed: true,
		},
		{
			name:       "added count exceeds threshold fails",
			drift:      newDrift(6, 0, 0, 0),
			pol:        &policy.SBOMDriftPolicy{MaxAdded: intPtr(5)},
			wantPassed: false,
		},
		{
			name:       "removed count exceeds threshold fails",
			drift:      newDrift(0, 3, 0, 0),
			pol:        &policy.SBOMDriftPolicy{MaxRemoved: intPtr(2)},
			wantPassed: false,
		},
		{
			name:       "modified count exceeds threshold fails",
			drift:      newDrift(0, 0, 4, 0),
			pol:        &policy.SBOMDriftPolicy{MaxModified: intPtr(3)},
			wantPassed: false,
		},
		{
			name:       "score exceeds threshold fails",
			drift:      newDrift(0, 0, 0, 2.5),
			pol:        &policy.SBOMDriftPolicy{MaxScore: floatPtr(2.0)},
			wantPassed: false,
		},
		{
			name:       "score within threshold passes",
			drift:      newDrift(0, 0, 0, 1.5),
			pol:        &policy.SBOMDriftPolicy{MaxScore: floatPtr(2.0)},
			wantPassed: true,
		},
		{
			name:       "zero threshold fails on any drift",
			drift:      newDrift(1, 0, 0, 0),
			pol:        &policy.SBOMDriftPolicy{MaxAdded: intPtr(0)},
			wantPassed: false,
		},
		{
			name:  "zero drift passes zero threshold",
			drift: zeroDrift(),
			pol: &policy.SBOMDriftPolicy{
				MaxAdded:    intPtr(0),
				MaxRemoved:  intPtr(0),
				MaxModified: intPtr(0),
				MaxScore:    floatPtr(0),
			},
			wantPassed: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			result := checkDriftThresholds(&tc.drift, tc.pol)

			if tc.wantPassed {
				if result != nil {
					t.Errorf("expected pass (nil), got fail: %s", result.Detail)
				}
			} else {
				if result == nil {
					t.Error("expected failure, got nil (pass)")
				} else if result.Passed {
					t.Error("expected failure, got passed=true")
				}
			}
		})
	}
}

func TestChecksumsEqual(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		left     map[string]string
		right    map[string]string
		expected bool
	}{
		{
			name:     "both nil",
			left:     nil,
			right:    nil,
			expected: true,
		},
		{
			name:     "identical",
			left:     map[string]string{testAlgoSHA256: testHashABC},
			right:    map[string]string{testAlgoSHA256: testHashABC},
			expected: true,
		},
		{
			name:     "different value same algorithm",
			left:     map[string]string{testAlgoSHA256: testHashABC},
			right:    map[string]string{testAlgoSHA256: testHashDef},
			expected: false,
		},
		{
			name:     "case insensitive value comparison",
			left:     map[string]string{testAlgoSHA256: "ABC"},
			right:    map[string]string{testAlgoSHA256: testHashABC},
			expected: true,
		},
		{
			name:     "different algorithm sets (non-overlapping)",
			left:     map[string]string{testAlgoSHA256: testHashABC},
			right:    map[string]string{testAlgoSHA512: testHashDef},
			expected: true,
		},
		{
			name:     "overlapping algorithm mismatch with different lengths",
			left:     map[string]string{testAlgoSHA256: testHashABC, testAlgoSHA512: testHashDef},
			right:    map[string]string{testAlgoSHA256: "different"},
			expected: false,
		},
		{
			name:     "overlapping algorithm match with different lengths",
			left:     map[string]string{testAlgoSHA256: testHashABC, testAlgoSHA512: testHashDef},
			right:    map[string]string{testAlgoSHA256: testHashABC},
			expected: true,
		},
		{
			name:     "baseline has checksums but current has none (stripping)",
			left:     map[string]string{testAlgoSHA256: testHashABC},
			right:    nil,
			expected: false,
		},
		{
			name:     "baseline has no checksums but current does",
			left:     nil,
			right:    map[string]string{testAlgoSHA256: testHashABC},
			expected: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := checksumsEqual(tc.left, tc.right)
			testutil.AssertEqual(t, got, tc.expected)
		})
	}
}

func TestLicensesEqual(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		left     []string
		right    []string
		expected bool
	}{
		{
			name:     "both nil",
			left:     nil,
			right:    nil,
			expected: true,
		},
		{
			name:     "identical",
			left:     []string{testLicMIT},
			right:    []string{testLicMIT},
			expected: true,
		},
		{
			name:     "different count",
			left:     []string{testLicMIT},
			right:    []string{testLicMIT, testLicApache},
			expected: false,
		},
		{
			name:     "different order same content",
			left:     []string{testLicApache, testLicMIT},
			right:    []string{testLicMIT, testLicApache},
			expected: true,
		},
		{
			name:     "case insensitive",
			left:     []string{"mit"},
			right:    []string{testLicMIT},
			expected: true,
		},
		{
			name:     "different licenses",
			left:     []string{testLicMIT},
			right:    []string{"GPL-3.0"},
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := licensesEqual(tc.left, tc.right)
			testutil.AssertEqual(t, got, tc.expected)
		})
	}
}

func TestParseSPDXExtractsVersionAndChecksums(t *testing.T) {
	t.Parallel()

	doc := spdxDocument{
		SPDXVersion: "SPDX-2.3",
		Packages: []spdxPackage{
			{
				Name:             testLibName,
				VersionInfo:      "1.2.3",
				LicenseConcluded: testLicMIT,
				LicenseDeclared:  "",
				ExternalRefs: []spdxExternalRef{
					{
						ReferenceCategory: "",
						ReferenceType:     refTypePURL,
						ReferenceLocator:  "pkg:npm/mylib@1.2.3",
					},
				},
				Checksums: []spdxChecksum{
					{Algorithm: testAlgoSHA256, Value: testHashABC123},
					{Algorithm: testAlgoSHA512, Value: "def456"},
				},
			},
		},
	}

	data, err := parseSPDX(mustMarshalDrift(t, doc))
	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, len(data.Packages), 1)

	pkg := data.Packages[0]
	testutil.AssertEqual(t, pkg.PURL, "pkg:npm/mylib@1.2.3")
	testutil.AssertEqual(t, pkg.Name, testLibName)
	testutil.AssertEqual(t, pkg.Version, "1.2.3")
	testutil.AssertEqual(t, pkg.Checksums[testAlgoSHA256], testHashABC123)
	testutil.AssertEqual(t, pkg.Checksums[testAlgoSHA512], "def456")
	testutil.AssertEqual(t, len(pkg.Licenses), 1)
	testutil.AssertEqual(t, pkg.Licenses[0], testLicMIT)
}

func TestParseSPDX3ExtractsVersionAndChecksums(t *testing.T) {
	t.Parallel()

	doc := spdx3Document{
		Context: "https://spdx.org/rdf/3.0.0/terms",
		Type:    "",
		SpdxID:  "",
		SpecVer: "",
		Elements: []spdx3Element{
			{
				Type:            "software_SoftwarePackage",
				Name:            testLibName,
				SoftwareVersion: "2.0.0",
				ExternalIdentifiers: []spdx3ExtIdentifier{
					{
						Type:       "",
						IDType:     "packageUrl",
						Identifier: "pkg:npm/mylib@2.0.0",
					},
				},
				DeclaredLicense:  "",
				ConcludedLicense: testLicApache,
				VerifiedUsing: []spdx3Verification{
					{Type: "", Algorithm: "sha256", Value: "aabbcc"},
				},
			},
		},
	}

	data, err := parseSPDX3(mustMarshalDrift(t, doc))
	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, len(data.Packages), 1)

	pkg := data.Packages[0]
	testutil.AssertEqual(t, pkg.PURL, "pkg:npm/mylib@2.0.0")
	testutil.AssertEqual(t, pkg.Name, testLibName)
	testutil.AssertEqual(t, pkg.Version, "2.0.0")
	testutil.AssertEqual(t, pkg.Checksums["sha256"], "aabbcc")
	testutil.AssertEqual(t, len(pkg.Licenses), 1)
	testutil.AssertEqual(t, pkg.Licenses[0], testLicApache)
}

func TestParseCycloneDXExtractsVersionAndHashes(t *testing.T) {
	t.Parallel()

	doc := cyclonedxBOM{
		Components: []cyclonedxComponent{
			{
				Name:    testLibName,
				Version: "3.0.0",
				PURL:    "pkg:npm/mylib@3.0.0",
				Licenses: []cyclonedxLicense{
					{License: &cyclonedxLicenseRef{
						ID:   testLicMIT,
						Name: "",
					}},
				},
				Hashes: []cyclonedxHash{
					{Algorithm: "SHA-256", Content: "112233"},
				},
			},
		},
		Vulnerabilities: nil,
	}

	data, err := parseCycloneDX(mustMarshalDrift(t, doc))
	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, len(data.Packages), 1)

	pkg := data.Packages[0]
	testutil.AssertEqual(t, pkg.PURL, "pkg:npm/mylib@3.0.0")
	testutil.AssertEqual(t, pkg.Name, testLibName)
	testutil.AssertEqual(t, pkg.Version, "3.0.0")
	testutil.AssertEqual(t, pkg.Checksums["SHA-256"], "112233")
	testutil.AssertEqual(t, len(pkg.Licenses), 1)
	testutil.AssertEqual(t, pkg.Licenses[0], testLicMIT)
}

func mustMarshalDrift(t *testing.T, v any) []byte {
	t.Helper()

	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	return data
}

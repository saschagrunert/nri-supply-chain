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
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/sbom"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	testImageRef        = "docker.io/library/nginx:latest"
	testDigest          = "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	testDigestAlgo      = "sha256"
	testInTotoType      = "https://in-toto.io/Statement/v1"
	testSubjectName     = "test-image"
	testPredicateType   = "https://spdx.dev/Document"
	testSPDXVersion     = "SPDX-2.3"
	testCycloneDXBOM    = "CycloneDX"
	testLibName         = "mylib"
	testLibPURL         = "pkg:npm/mylib@1.0.0"
	testLicenseNone     = "NOASSERTION"
	testLicenseMIT      = "MIT"
	testFormatCycloneDX = "cyclonedx"
	testFormatSPDX      = "spdx"
	testLicenseGPL3Only = "GPL-3.0-only"
	testLicenseGPL2Only = "GPL-2.0-only"
)

type inTotoWrapper struct {
	Type          string          `json:"_type"` //nolint:tagliatelle // In-toto spec field name.
	Subject       []inTotoSubj    `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

type inTotoSubj struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

func validSPDXDoc() spdxDoc {
	return spdxDoc{
		SPDXVersion: testSPDXVersion,
		Packages: []spdxPkg{
			{
				Name:             testLibName,
				LicenseConcluded: testLicenseMIT,
				LicenseDeclared:  "",
				ExternalRefs: []spdxExtRef{
					{
						ReferenceCategory: "PACKAGE-MANAGER",
						ReferenceType:     "purl",
						ReferenceLocator:  testLibPURL,
					},
				},
			},
		},
	}
}

func validCycloneDXDoc() cyclonedxDoc {
	return cyclonedxDoc{
		BOMFormat: testCycloneDXBOM,
		Components: []cdxComponent{
			{
				Name: testLibName,
				PURL: testLibPURL,
				Licenses: []cdxLicenseWrapper{
					{License: &cdxLicense{ID: testLicenseMIT, Name: ""}},
				},
			},
		},
	}
}

type spdxDoc struct {
	SPDXVersion string    `json:"spdxVersion"`
	Packages    []spdxPkg `json:"packages"`
}

type spdxPkg struct {
	Name             string       `json:"name"`
	LicenseConcluded string       `json:"licenseConcluded"`
	LicenseDeclared  string       `json:"licenseDeclared"`
	ExternalRefs     []spdxExtRef `json:"externalRefs"`
}

type spdxExtRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type cyclonedxDoc struct {
	BOMFormat  string         `json:"bomFormat"`
	Components []cdxComponent `json:"components"`
}

type cdxComponent struct {
	Name     string              `json:"name"`
	PURL     string              `json:"purl"`
	Licenses []cdxLicenseWrapper `json:"licenses"`
}

type cdxLicenseWrapper struct {
	License *cdxLicense `json:"license,omitempty"`
}

type cdxLicense struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func wrapInToto(t *testing.T, doc any, digest string) []byte {
	t.Helper()

	predBytes := testutil.MustMarshal(t, doc)

	wrapper := inTotoWrapper{
		Type: testInTotoType,
		Subject: []inTotoSubj{
			{
				Name:   testSubjectName,
				Digest: map[string]string{testDigestAlgo: digest[len(testDigestAlgo)+1:]},
			},
		},
		PredicateType: testPredicateType,
		Predicate:     predBytes,
	}

	return testutil.MustMarshal(t, wrapper)
}

func TestVerify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		doc        any
		pol        *policy.Policy
		wantPassed bool
		wantStatus types.CheckStatus
	}{
		{
			name:       "SPDX with allowed license passes",
			doc:        validSPDXDoc(),
			pol:        &policy.Policy{},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name:       "CycloneDX with allowed license passes",
			doc:        validCycloneDXDoc(),
			pol:        &policy.Policy{},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name: "SPDX with denied license fails",
			doc:  validSPDXDoc(),
			pol: &policy.Policy{
				Sections: policy.Sections{
					SBOM: &policy.SBOMPolicy{
						License: &policy.SBOMLicensePolicy{
							Deny: []string{testLicenseMIT},
						},
					},
				},
			},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name: "license deny list is case-insensitive",
			doc:  validSPDXDoc(),
			pol: &policy.Policy{
				Sections: policy.Sections{
					SBOM: &policy.SBOMPolicy{
						License: &policy.SBOMLicensePolicy{
							Deny: []string{"mit"},
						},
					},
				},
			},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name: "SPDX with denied component fails",
			doc:  validSPDXDoc(),
			pol: &policy.Policy{
				Sections: policy.Sections{
					SBOM: &policy.SBOMPolicy{
						Component: &policy.SBOMComponentPolicy{
							Deny: []string{testLibPURL},
						},
					},
				},
			},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name: "component deny list uses prefix match",
			doc:  validSPDXDoc(),
			pol: &policy.Policy{
				Sections: policy.Sections{
					SBOM: &policy.SBOMPolicy{
						Component: &policy.SBOMComponentPolicy{
							Deny: []string{"pkg:npm/mylib"},
						},
					},
				},
			},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name: "non-matching component deny list passes",
			doc:  validSPDXDoc(),
			pol: &policy.Policy{
				Sections: policy.Sections{
					SBOM: &policy.SBOMPolicy{
						Component: &policy.SBOMComponentPolicy{
							Deny: []string{"pkg:npm/other@2.0.0"},
						},
					},
				},
			},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name: "non-matching license deny list passes",
			doc:  validSPDXDoc(),
			pol: &policy.Policy{
				Sections: policy.Sections{
					SBOM: &policy.SBOMPolicy{
						License: &policy.SBOMLicensePolicy{
							Deny: []string{"AGPL-3.0"},
						},
					},
				},
			},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name: "CycloneDX with denied license fails",
			doc:  validCycloneDXDoc(),
			pol: &policy.Policy{
				Sections: policy.Sections{
					SBOM: &policy.SBOMPolicy{
						License: &policy.SBOMLicensePolicy{
							Deny: []string{testLicenseMIT},
						},
					},
				},
			},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name: "CycloneDX with denied component fails",
			doc:  validCycloneDXDoc(),
			pol: &policy.Policy{
				Sections: policy.Sections{
					SBOM: &policy.SBOMPolicy{
						Component: &policy.SBOMComponentPolicy{
							Deny: []string{testLibPURL},
						},
					},
				},
			},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name: "SPDX denied when format restricted to cyclonedx",
			doc:  validSPDXDoc(),
			pol: &policy.Policy{
				Sections: policy.Sections{
					SBOM: &policy.SBOMPolicy{
						Formats: []string{testFormatCycloneDX},
					},
				},
			},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name: "CycloneDX denied when format restricted to spdx",
			doc:  validCycloneDXDoc(),
			pol: &policy.Policy{
				Sections: policy.Sections{
					SBOM: &policy.SBOMPolicy{
						Formats: []string{testFormatSPDX},
					},
				},
			},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name: "SPDX allowed when format list includes spdx",
			doc:  validSPDXDoc(),
			pol: &policy.Policy{
				Sections: policy.Sections{
					SBOM: &policy.SBOMPolicy{
						Formats: []string{testFormatSPDX, testFormatCycloneDX},
					},
				},
			},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			att := wrapInToto(t, test.doc, testDigest)

			result, err := sbom.Verify(att, test.pol, testDigest)

			if test.wantPassed {
				testutil.AssertNoError(t, err)

				if !result.Passed {
					t.Errorf("expected pass, got fail (detail: %s)", result.Detail)
				}
			} else {
				// Format restriction errors surface as errors, not results.
				if err != nil {
					return
				}

				if result.Passed {
					t.Error("expected fail, got pass")
				}
			}

			if err == nil {
				testutil.AssertEqual(t, test.wantStatus, result.Status)
			}
		})
	}
}

func TestVerifyMalformedPayloads(t *testing.T) {
	t.Parallel()

	t.Run("empty payload", func(t *testing.T) {
		t.Parallel()

		_, err := sbom.Verify([]byte{}, &policy.Policy{}, testDigest)
		if !errors.Is(err, sbom.ErrInvalidSBOM) {
			t.Errorf("expected ErrInvalidSBOM, got %v", err)
		}
	})

	t.Run("nil payload", func(t *testing.T) {
		t.Parallel()

		_, err := sbom.Verify(nil, &policy.Policy{}, testDigest)
		if !errors.Is(err, sbom.ErrInvalidSBOM) {
			t.Errorf("expected ErrInvalidSBOM, got %v", err)
		}
	})

	t.Run("truncated JSON", func(t *testing.T) {
		t.Parallel()

		_, err := sbom.Verify([]byte(`{"subject":[`), &policy.Policy{}, testDigest)
		if !errors.Is(err, sbom.ErrInvalidSBOM) {
			t.Errorf("expected ErrInvalidSBOM, got %v", err)
		}
	})

	t.Run("empty JSON object with digest triggers empty subjects", func(t *testing.T) {
		t.Parallel()

		_, err := sbom.Verify([]byte("{}"), &policy.Policy{}, testDigest)
		if !errors.Is(err, sbom.ErrEmptySubjects) {
			t.Errorf("expected ErrEmptySubjects, got %v", err)
		}
	})

	t.Run("empty JSON object without digest skips subject check", func(t *testing.T) {
		t.Parallel()

		// Without a digest, subject binding is skipped. The bare {} is not
		// a valid SPDX or CycloneDX document, so it fails to parse.
		_, err := sbom.Verify([]byte("{}"), &policy.Policy{}, "")
		if err == nil {
			t.Error("expected parse error for empty object, got nil")
		}
	})
}

func TestVerifySubjectEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("subject with mismatched digest", func(t *testing.T) {
		t.Parallel()

		doc := validSPDXDoc()
		att := wrapInToto(t, doc, testDigest)

		_, err := sbom.Verify(
			att, &policy.Policy{},
			"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		)
		if !errors.Is(err, sbom.ErrSubjectMismatch) {
			t.Errorf("expected ErrSubjectMismatch, got %v", err)
		}
	})

	t.Run("subject with invalid digest format", func(t *testing.T) {
		t.Parallel()

		doc := validSPDXDoc()
		att := wrapInToto(t, doc, testDigest)

		_, err := sbom.Verify(att, &policy.Policy{}, "nocolon")
		if !errors.Is(err, sbom.ErrSubjectMismatch) {
			t.Errorf("expected ErrSubjectMismatch for invalid digest, got %v", err)
		}
	})

	t.Run("empty digest skips subject binding", func(t *testing.T) {
		t.Parallel()

		doc := validSPDXDoc()
		att := wrapInToto(t, doc, testDigest)

		result, err := sbom.Verify(att, &policy.Policy{}, "")
		testutil.AssertNoError(t, err)

		if !result.Passed {
			t.Errorf("expected pass when digest is empty, got: %s", result.Detail)
		}
	})

	t.Run("multiple subjects with one matching", func(t *testing.T) {
		t.Parallel()

		doc := validSPDXDoc()
		predBytes := testutil.MustMarshal(t, doc)

		wrapper := inTotoWrapper{
			Type: testInTotoType,
			Subject: []inTotoSubj{
				{
					Name:   "other-image",
					Digest: map[string]string{testDigestAlgo: "000000"},
				},
				{
					Name:   testSubjectName,
					Digest: map[string]string{testDigestAlgo: testDigest[len(testDigestAlgo)+1:]},
				},
			},
			PredicateType: testPredicateType,
			Predicate:     predBytes,
		}

		att := testutil.MustMarshal(t, wrapper)

		result, err := sbom.Verify(att, &policy.Policy{}, testDigest)
		testutil.AssertNoError(t, err)

		if !result.Passed {
			t.Errorf("expected pass with one matching subject, got: %s", result.Detail)
		}
	})
}

func TestVerifySPDXLicenseFields(t *testing.T) {
	t.Parallel()

	t.Run("licenseDeclared is also checked", func(t *testing.T) {
		t.Parallel()

		doc := spdxDoc{
			SPDXVersion: testSPDXVersion,
			Packages: []spdxPkg{
				{
					Name:             testLibName,
					LicenseConcluded: testLicenseNone,
					LicenseDeclared:  "GPL-3.0",
					ExternalRefs:     nil,
				},
			},
		}

		att := wrapInToto(t, doc, testDigest)

		result, err := sbom.Verify(att, &policy.Policy{
			Sections: policy.Sections{
				SBOM: &policy.SBOMPolicy{
					License: &policy.SBOMLicensePolicy{
						Deny: []string{"GPL-3.0"},
					},
				},
			},
		}, testDigest)
		testutil.AssertNoError(t, err)

		if result.Passed {
			t.Error("expected fail for denied licenseDeclared")
		}
	})

	t.Run("NOASSERTION is ignored", func(t *testing.T) {
		t.Parallel()

		doc := spdxDoc{
			SPDXVersion: testSPDXVersion,
			Packages: []spdxPkg{
				{
					Name:             testLibName,
					LicenseConcluded: testLicenseNone,
					LicenseDeclared:  testLicenseNone,
					ExternalRefs:     nil,
				},
			},
		}

		att := wrapInToto(t, doc, testDigest)

		result, err := sbom.Verify(att, &policy.Policy{
			Sections: policy.Sections{
				SBOM: &policy.SBOMPolicy{
					License: &policy.SBOMLicensePolicy{
						Deny: []string{testLicenseNone},
					},
				},
			},
		}, testDigest)
		testutil.AssertNoError(t, err)

		if !result.Passed {
			t.Errorf("expected pass, NOASSERTION should be ignored, got: %s", result.Detail)
		}
	})

	t.Run("compound expression is split", func(t *testing.T) {
		t.Parallel()

		doc := spdxDoc{
			SPDXVersion: testSPDXVersion,
			Packages: []spdxPkg{
				{
					Name:             testLibName,
					LicenseConcluded: "MIT AND GPL-3.0-only",
					LicenseDeclared:  testLicenseNone,
					ExternalRefs:     nil,
				},
			},
		}

		att := wrapInToto(t, doc, testDigest)

		result, err := sbom.Verify(att, &policy.Policy{
			Sections: policy.Sections{
				SBOM: &policy.SBOMPolicy{
					License: &policy.SBOMLicensePolicy{
						Deny: []string{testLicenseGPL3Only},
					},
				},
			},
		}, testDigest)
		testutil.AssertNoError(t, err)

		if result.Passed {
			t.Error("expected fail for denied license in compound expression")
		}
	})

	t.Run("OR expression is split", func(t *testing.T) {
		t.Parallel()

		doc := spdxDoc{
			SPDXVersion: testSPDXVersion,
			Packages: []spdxPkg{
				{
					Name:             testLibName,
					LicenseConcluded: "MIT OR GPL-3.0-only",
					LicenseDeclared:  testLicenseNone,
					ExternalRefs:     nil,
				},
			},
		}

		att := wrapInToto(t, doc, testDigest)

		result, err := sbom.Verify(att, &policy.Policy{
			Sections: policy.Sections{
				SBOM: &policy.SBOMPolicy{
					License: &policy.SBOMLicensePolicy{
						Deny: []string{testLicenseGPL3Only},
					},
				},
			},
		}, testDigest)
		testutil.AssertNoError(t, err)

		if result.Passed {
			t.Error("expected fail for denied license in OR expression")
		}
	})

	t.Run("WITH expression is split", func(t *testing.T) {
		t.Parallel()

		doc := spdxDoc{
			SPDXVersion: testSPDXVersion,
			Packages: []spdxPkg{
				{
					Name:             testLibName,
					LicenseConcluded: "GPL-2.0-only WITH Classpath-exception-2.0",
					LicenseDeclared:  testLicenseNone,
					ExternalRefs:     nil,
				},
			},
		}

		att := wrapInToto(t, doc, testDigest)

		result, err := sbom.Verify(att, &policy.Policy{
			Sections: policy.Sections{
				SBOM: &policy.SBOMPolicy{
					License: &policy.SBOMLicensePolicy{
						Deny: []string{testLicenseGPL2Only},
					},
				},
			},
		}, testDigest)
		testutil.AssertNoError(t, err)

		if result.Passed {
			t.Error("expected fail for denied license in WITH expression")
		}
	})

	t.Run("WITH exception is not treated as license for allow list", func(t *testing.T) {
		t.Parallel()

		doc := spdxDoc{
			SPDXVersion: testSPDXVersion,
			Packages: []spdxPkg{
				{
					Name:             testLibName,
					LicenseConcluded: "GPL-2.0-only WITH Classpath-exception-2.0",
					LicenseDeclared:  testLicenseNone,
					ExternalRefs:     nil,
				},
			},
		}

		att := wrapInToto(t, doc, testDigest)

		result, err := sbom.Verify(att, &policy.Policy{
			Sections: policy.Sections{
				SBOM: &policy.SBOMPolicy{
					License: &policy.SBOMLicensePolicy{
						Allow: []string{testLicenseGPL2Only},
					},
				},
			},
		}, testDigest)
		testutil.AssertNoError(t, err)

		if !result.Passed {
			t.Error("expected pass: exception after WITH should not be checked against allow list")
		}
	})

	t.Run("parenthesized compound expression is split", func(t *testing.T) {
		t.Parallel()

		doc := spdxDoc{
			SPDXVersion: testSPDXVersion,
			Packages: []spdxPkg{
				{
					Name:             testLibName,
					LicenseConcluded: "(MIT AND GPL-3.0-only)",
					LicenseDeclared:  testLicenseNone,
					ExternalRefs:     nil,
				},
			},
		}

		att := wrapInToto(t, doc, testDigest)

		result, err := sbom.Verify(att, &policy.Policy{
			Sections: policy.Sections{
				SBOM: &policy.SBOMPolicy{
					License: &policy.SBOMLicensePolicy{
						Deny: []string{testLicenseGPL3Only},
					},
				},
			},
		}, testDigest)
		testutil.AssertNoError(t, err)

		if result.Passed {
			t.Error("expected fail for denied license in parenthesized expression")
		}
	})
}

func TestVerifyCycloneDXLicenseName(t *testing.T) {
	t.Parallel()

	doc := cyclonedxDoc{
		BOMFormat: testCycloneDXBOM,
		Components: []cdxComponent{
			{
				Name: testLibName,
				PURL: "",
				Licenses: []cdxLicenseWrapper{
					{License: &cdxLicense{ID: "", Name: "GNU General Public License v3.0"}},
				},
			},
		},
	}

	att := wrapInToto(t, doc, testDigest)

	result, err := sbom.Verify(att, &policy.Policy{
		Sections: policy.Sections{
			SBOM: &policy.SBOMPolicy{
				License: &policy.SBOMLicensePolicy{
					Deny: []string{"GNU General Public License v3.0"},
				},
			},
		},
	}, testDigest)
	testutil.AssertNoError(t, err)

	if result.Passed {
		t.Error("expected fail for denied license name in CycloneDX")
	}
}

func TestVerifyCheckType(t *testing.T) {
	t.Parallel()

	att := wrapInToto(t, validSPDXDoc(), testDigest)

	result, err := sbom.Verify(att, &policy.Policy{}, testDigest)
	testutil.AssertNoError(t, err)

	testutil.AssertEqual(t, types.CheckType("sbom"), result.Type)
}

func TestVerifyMultiple(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		docs       []any
		pol        *policy.Policy
		wantPassed bool
		wantStatus types.CheckStatus
	}{
		{
			name:       "all pass",
			docs:       []any{validSPDXDoc(), validCycloneDXDoc()},
			pol:        &policy.Policy{},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name: "any denied license fails",
			docs: []any{validSPDXDoc(), validCycloneDXDoc()},
			pol: &policy.Policy{
				Sections: policy.Sections{
					SBOM: &policy.SBOMPolicy{
						License: &policy.SBOMLicensePolicy{
							Deny: []string{testLicenseMIT},
						},
					},
				},
			},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name:       "empty attestation list",
			docs:       []any{},
			pol:        &policy.Policy{},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			attestations := make([][]byte, len(test.docs))
			for idx := range test.docs {
				attestations[idx] = wrapInToto(t, test.docs[idx], testDigest)
			}

			result, err := sbom.VerifyMultiple(attestations, test.pol, testDigest)
			testutil.AssertNoError(t, err)

			testutil.AssertEqual(t, test.wantPassed, result.Passed)
			testutil.AssertEqual(t, test.wantStatus, result.Status)
		})
	}
}

func TestVerifyMultipleEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("nil attestation slice", func(t *testing.T) {
		t.Parallel()

		result, err := sbom.VerifyMultiple(nil, &policy.Policy{}, testDigest)
		testutil.AssertNoError(t, err)

		if !result.Passed {
			t.Errorf("expected pass for nil attestation slice, got: %s", result.Detail)
		}
	})

	t.Run("all invalid returns fail with parse errors", func(t *testing.T) {
		t.Parallel()

		attestations := [][]byte{
			[]byte("bad json 1"),
			[]byte("bad json 2"),
		}

		result, err := sbom.VerifyMultiple(attestations, &policy.Policy{}, testDigest)
		testutil.AssertNoError(t, err)

		if result.Passed {
			t.Error("expected fail when all documents are invalid")
		}

		testutil.AssertEqual(t, types.StatusFail, result.Status)
	})

	t.Run("format restriction rejects all valid documents", func(t *testing.T) {
		t.Parallel()

		attestations := [][]byte{
			wrapInToto(t, validSPDXDoc(), testDigest),
			wrapInToto(t, validSPDXDoc(), testDigest),
		}

		result, err := sbom.VerifyMultiple(attestations, &policy.Policy{
			Sections: policy.Sections{
				SBOM: &policy.SBOMPolicy{
					Formats: []string{testFormatCycloneDX},
				},
			},
		}, testDigest)
		testutil.AssertNoError(t, err)

		if result.Passed {
			t.Error("expected fail when format is restricted to cyclonedx but only SPDX provided")
		}

		testutil.AssertEqual(t, types.StatusFail, result.Status)

		if !strings.Contains(result.Detail, "failed verification") {
			t.Errorf("expected detail to mention failed verification, got %q", result.Detail)
		}
	})

	t.Run("mix of valid and invalid with valid passing", func(t *testing.T) {
		t.Parallel()

		attestations := [][]byte{
			[]byte("invalid json"),
			wrapInToto(t, validSPDXDoc(), testDigest),
		}

		result, err := sbom.VerifyMultiple(attestations, &policy.Policy{}, testDigest)
		testutil.AssertNoError(t, err)

		if !result.Passed {
			t.Errorf("expected pass with valid doc, got: %s", result.Detail)
		}
	})
}

func TestVerifyCycloneDXNilLicense(t *testing.T) {
	t.Parallel()

	doc := cyclonedxDoc{
		BOMFormat: testCycloneDXBOM,
		Components: []cdxComponent{
			{
				Name:     testLibName,
				PURL:     testLibPURL,
				Licenses: []cdxLicenseWrapper{{License: nil}},
			},
		},
	}

	att := wrapInToto(t, doc, testDigest)

	result, err := sbom.Verify(att, &policy.Policy{}, testDigest)
	testutil.AssertNoError(t, err)

	if !result.Passed {
		t.Errorf("expected pass with nil license entry, got: %s", result.Detail)
	}
}

func TestVerifyLicenseAllowList(t *testing.T) {
	t.Parallel()

	t.Run("license in allow list passes", func(t *testing.T) {
		t.Parallel()

		att := wrapInToto(t, validSPDXDoc(), testDigest)

		result, err := sbom.Verify(att, &policy.Policy{
			Sections: policy.Sections{
				SBOM: &policy.SBOMPolicy{
					License: &policy.SBOMLicensePolicy{
						Allow: []string{testLicenseMIT, "Apache-2.0"},
					},
				},
			},
		}, testDigest)
		testutil.AssertNoError(t, err)

		if !result.Passed {
			t.Errorf("expected pass, got: %s", result.Detail)
		}
	})

	t.Run("license not in allow list fails", func(t *testing.T) {
		t.Parallel()

		att := wrapInToto(t, validSPDXDoc(), testDigest)

		result, err := sbom.Verify(att, &policy.Policy{
			Sections: policy.Sections{
				SBOM: &policy.SBOMPolicy{
					License: &policy.SBOMLicensePolicy{
						Allow: []string{"Apache-2.0", "BSD-3-Clause"},
					},
				},
			},
		}, testDigest)
		testutil.AssertNoError(t, err)

		if result.Passed {
			t.Error("expected fail for license not in allow list")
		}

		if !strings.Contains(result.Detail, "not in allow list") {
			t.Errorf("expected detail to mention allow list, got %q", result.Detail)
		}
	})

	t.Run("deny takes precedence over allow", func(t *testing.T) {
		t.Parallel()

		att := wrapInToto(t, validSPDXDoc(), testDigest)

		result, err := sbom.Verify(att, &policy.Policy{
			Sections: policy.Sections{
				SBOM: &policy.SBOMPolicy{
					License: &policy.SBOMLicensePolicy{
						Deny:  []string{testLicenseMIT},
						Allow: []string{testLicenseMIT},
					},
				},
			},
		}, testDigest)
		testutil.AssertNoError(t, err)

		if result.Passed {
			t.Error("expected fail: deny should take precedence over allow")
		}

		if !strings.Contains(result.Detail, "denied license") {
			t.Errorf("expected detail to mention denied license, got %q", result.Detail)
		}
	})

	t.Run("empty allow list does not restrict", func(t *testing.T) {
		t.Parallel()

		att := wrapInToto(t, validSPDXDoc(), testDigest)

		result, err := sbom.Verify(att, &policy.Policy{
			Sections: policy.Sections{
				SBOM: &policy.SBOMPolicy{
					License: &policy.SBOMLicensePolicy{
						Allow: []string{},
					},
				},
			},
		}, testDigest)
		testutil.AssertNoError(t, err)

		if !result.Passed {
			t.Errorf("expected pass with empty allow list, got: %s", result.Detail)
		}
	})

	t.Run("allow list is case-insensitive", func(t *testing.T) {
		t.Parallel()

		att := wrapInToto(t, validSPDXDoc(), testDigest)

		result, err := sbom.Verify(att, &policy.Policy{
			Sections: policy.Sections{
				SBOM: &policy.SBOMPolicy{
					License: &policy.SBOMLicensePolicy{
						Allow: []string{"mit"},
					},
				},
			},
		}, testDigest)
		testutil.AssertNoError(t, err)

		if !result.Passed {
			t.Errorf("expected pass with case-insensitive allow, got: %s", result.Detail)
		}
	})
}

func TestVerifyComponentAllowList(t *testing.T) {
	t.Parallel()

	t.Run("component in allow list passes", func(t *testing.T) {
		t.Parallel()

		att := wrapInToto(t, validSPDXDoc(), testDigest)

		result, err := sbom.Verify(att, &policy.Policy{
			Sections: policy.Sections{
				SBOM: &policy.SBOMPolicy{
					Component: &policy.SBOMComponentPolicy{
						Allow: []string{testLibPURL},
					},
				},
			},
		}, testDigest)
		testutil.AssertNoError(t, err)

		if !result.Passed {
			t.Errorf("expected pass, got: %s", result.Detail)
		}
	})

	t.Run("component not in allow list fails", func(t *testing.T) {
		t.Parallel()

		att := wrapInToto(t, validSPDXDoc(), testDigest)

		result, err := sbom.Verify(att, &policy.Policy{
			Sections: policy.Sections{
				SBOM: &policy.SBOMPolicy{
					Component: &policy.SBOMComponentPolicy{
						Allow: []string{"pkg:npm/other@2.0.0"},
					},
				},
			},
		}, testDigest)
		testutil.AssertNoError(t, err)

		if result.Passed {
			t.Error("expected fail for component not in allow list")
		}

		if !strings.Contains(result.Detail, "not in allow list") {
			t.Errorf("expected detail to mention allow list, got %q", result.Detail)
		}
	})

	t.Run("deny takes precedence over allow", func(t *testing.T) {
		t.Parallel()

		att := wrapInToto(t, validSPDXDoc(), testDigest)

		result, err := sbom.Verify(att, &policy.Policy{
			Sections: policy.Sections{
				SBOM: &policy.SBOMPolicy{
					Component: &policy.SBOMComponentPolicy{
						Deny:  []string{testLibPURL},
						Allow: []string{testLibPURL},
					},
				},
			},
		}, testDigest)
		testutil.AssertNoError(t, err)

		if result.Passed {
			t.Error("expected fail: deny should take precedence over allow")
		}

		if !strings.Contains(result.Detail, "denied component") {
			t.Errorf("expected detail to mention denied component, got %q", result.Detail)
		}
	})

	t.Run("allow list uses prefix match", func(t *testing.T) {
		t.Parallel()

		att := wrapInToto(t, validSPDXDoc(), testDigest)

		result, err := sbom.Verify(att, &policy.Policy{
			Sections: policy.Sections{
				SBOM: &policy.SBOMPolicy{
					Component: &policy.SBOMComponentPolicy{
						Allow: []string{"pkg:npm/mylib"},
					},
				},
			},
		}, testDigest)
		testutil.AssertNoError(t, err)

		if !result.Passed {
			t.Errorf("expected pass with prefix allow, got: %s", result.Detail)
		}
	})

	t.Run("empty allow list does not restrict", func(t *testing.T) {
		t.Parallel()

		att := wrapInToto(t, validSPDXDoc(), testDigest)

		result, err := sbom.Verify(att, &policy.Policy{
			Sections: policy.Sections{
				SBOM: &policy.SBOMPolicy{
					Component: &policy.SBOMComponentPolicy{
						Allow: []string{},
					},
				},
			},
		}, testDigest)
		testutil.AssertNoError(t, err)

		if !result.Passed {
			t.Errorf("expected pass with empty allow list, got: %s", result.Detail)
		}
	})
}

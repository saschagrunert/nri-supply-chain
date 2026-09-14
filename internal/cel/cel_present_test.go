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

package cel_test

import (
	"errors"
	"strings"
	"testing"

	celengine "github.com/saschagrunert/nri-supply-chain/internal/cel"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

func TestEvaluateMissingAttestationIsNotVerified(t *testing.T) {
	t.Parallel()

	missing := types.PassResult(types.CheckTypeSLSA, "no provenance attestation found")
	missing.Missing = true

	vars := celengine.BuildVars(
		testImageRef, testRegistry, testRepository, testDigest, testNamespace,
		map[types.CheckType]*types.CheckResult{types.CheckTypeSLSA: missing},
	)

	tests := []struct {
		name    string
		require string
		pass    bool
	}{
		{name: "verified is false", require: exprSLSAVerified, pass: false},
		{name: "present is false", require: "slsa.present == false", pass: true},
		{name: "data field access fails closed", require: `slsa.builderID != "evil"`, pass: false},
		{
			name:    "guarded data field access",
			require: `!slsa.present || slsa.builderID != "evil"`,
			pass:    true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			compiled, err := celengine.Compile([]celengine.Rule{{Require: test.require}})
			if err != nil {
				t.Fatalf("compile error: %v", err)
			}

			result := celengine.Evaluate(compiled, vars)
			if result.Passed != test.pass {
				t.Errorf("expected passed=%v, got %v: %s", test.pass, result.Passed, result.Detail)
			}
		})
	}
}

func TestEvaluatePresentAttestation(t *testing.T) {
	t.Parallel()

	compiled, err := celengine.Compile([]celengine.Rule{
		{Require: "slsa.present && slsa.verified && sbom.present && !vsa.present"},
	})
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	result := celengine.Evaluate(compiled, defaultVars())
	if !result.Passed {
		t.Errorf("expected pass, got: %s", result.Detail)
	}
}

func TestCompileRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		expr    string
		wantErr bool
	}{
		{name: "image typo", expr: "image.registryx == 'ghcr.io'", wantErr: true},
		{name: "attestation typo", expr: "slsa.buildrID == ''", wantErr: true},
		{name: "index typo", expr: "sbom['formatx'] == ''", wantErr: true},
		{name: "presence test typo", expr: "has(vex.statusx)", wantErr: true},
		{name: "nested fixed map typo", expr: "sbom.drift.addedCountx == 0", wantErr: true},
		{name: "nested fixed map", expr: "sbom.drift.addedCount == 0", wantErr: false},
		{
			name:    "guac nested fixed map typo",
			expr:    "guac.scorecard.aggregatex > 5.0",
			wantErr: true,
		},
		{name: "guac nested fixed map", expr: "guac.scorecard.aggregate > 5.0", wantErr: false},
		{
			name:    "dynamic key map",
			expr:    "buildenv.propertyValues.HERMETIC == 'true'",
			wantErr: false,
		},
		{
			name:    "dynamic key map index",
			expr:    "scorecard.checks['Code-Review'] > 5",
			wantErr: false,
		},
		{name: "present field", expr: "scai.present == true", wantErr: false},
		{name: "typo inside macro", expr: "[1].all(x, image.namespacex != '')", wantErr: true},
		{
			name:    "comprehension variable shadows variable name",
			expr:    "guac.vulnerabilities.all(image, image.anything != '')",
			wantErr: false,
		},
		{
			name:    "typo as function argument",
			expr:    "image.ref.startsWith(image.registryx)",
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := celengine.Compile([]celengine.Rule{{Require: test.expr}})
			if test.wantErr {
				if !errors.Is(err, celengine.ErrUnknownField) {
					t.Fatalf("expected ErrUnknownField, got %v", err)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestEvaluatePresentHintOnlyForAbsentAttestations(t *testing.T) {
	t.Parallel()

	missing := types.PassResult(types.CheckTypeSLSA, "no provenance attestation found")
	missing.Missing = true

	scorecard := types.PassResult(types.CheckTypeScorecard, "scorecard verified")

	vars := celengine.BuildVars(
		testImageRef, testRegistry, testRepository, testDigest, testNamespace,
		map[types.CheckType]*types.CheckResult{
			types.CheckTypeSLSA:      missing,
			types.CheckTypeScorecard: scorecard,
		},
	)

	tests := []struct {
		name     string
		require  string
		wantHint bool
	}{
		{
			name:     "absent attestation data field",
			require:  `slsa.builderID != "evil"`,
			wantHint: true,
		},
		{
			name:     "dynamic lookup on present attestation",
			require:  `scorecard.checks["Fuzzing"] > 5`,
			wantHint: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			compiled, err := celengine.Compile([]celengine.Rule{{Require: test.require}})
			if err != nil {
				t.Fatalf("compile error: %v", err)
			}

			result := celengine.Evaluate(compiled, vars)
			if result.Passed {
				t.Fatal("expected evaluation error, got pass")
			}

			if hint := strings.Contains(result.Detail, ".present"); hint != test.wantHint {
				t.Errorf("expected present hint=%v, got detail %q", test.wantHint, result.Detail)
			}
		})
	}
}

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

const (
	testImageRef   = "ghcr.io/myorg/myapp:latest"
	testRegistry   = "ghcr.io"
	testRepository = "myorg/myapp"
	testDigest     = "sha256:abc123"
	testNamespace  = "production"

	metaBuilderID  = "builderID"
	metaBuildType  = "buildType"
	metaSource     = "source"
	testSourceRepo = "https://github.com/myorg/myrepo"
	testRunnerURL  = "https://github.com/actions/runner"

	testSignerDN    = "CN=test"
	testTrustPolicy = "prod-ca"

	metaSignerDN    = "signerDN"
	metaTrustPolicy = "trustPolicy"

	metaFormat            = "format"
	metaComponentCount    = "componentCount"
	metaLicenseCount      = "licenseCount"
	metaCVSSMax           = "cvssMax"
	metaCVSSCriticalCount = "cvssCriticalCount"
	metaCVSSHighCount     = "cvssHighCount"
	metaCVSSMediumCount   = "cvssMediumCount"
	testFormatCycloneDX   = "cyclonedx"

	metaAttributes     = "attributes"
	metaAttributeCount = "attributeCount"
	metaHasEvidence    = "hasEvidence"
	testTwoAttrs       = "PASSED_CODE_REVIEW,PASSED_TESTS"
	testOneAttr        = "PASSED_CODE_REVIEW"

	exprMatchGHCR        = "image.registry == 'ghcr.io'"
	exprSLSAVerified     = "slsa.verified == true"
	exprVEXVerified      = "vex.verified == true"
	exprSBOMVerified     = "sbom.verified == true"
	exprNotationVerified = "notation.verified == true"
	exprTrue             = "true"
	exprFalse            = "false"
	exprImageRef         = "image.ref"
	msgGHCRSLSA          = "GHCR images must have SLSA provenance"
	msgVEXMustBeVerified = "VEX must be verified"
)

func defaultVars() map[string]any {
	return celengine.BuildVars(
		testImageRef, testRegistry, testRepository, testDigest, testNamespace,
		types.PassResult(types.CheckTypeSLSA, "ok"),
		types.PassResult(types.CheckTypeVEX, "ok"),
		nil,
		types.PassResult(types.CheckTypeSBOM, "ok"),
		nil,
		nil,
	)
}

func TestCompileValidExpressions(t *testing.T) {
	t.Parallel()

	rules := []celengine.Rule{
		{
			Match:   exprMatchGHCR,
			Require: exprSLSAVerified,
			Message: msgGHCRSLSA,
		},
		{
			Require: exprVEXVerified,
			Message: msgVEXMustBeVerified,
		},
	}

	compiled, err := celengine.Compile(rules)
	if err != nil {
		t.Fatalf("unexpected compile error: %v", err)
	}

	if len(compiled.Rules) != len(rules) {
		t.Errorf("expected %d compiled rules, got %d", len(rules), len(compiled.Rules))
	}
}

func TestCompileEmptyRequire(t *testing.T) {
	t.Parallel()

	rules := []celengine.Rule{
		{Require: ""},
	}

	_, err := celengine.Compile(rules)
	if err == nil {
		t.Fatal("expected error for empty require")
	}

	if !errors.Is(err, celengine.ErrRequireEmpty) {
		t.Errorf("expected ErrRequireEmpty, got: %v", err)
	}
}

func TestCompileSyntaxError(t *testing.T) {
	t.Parallel()

	rules := []celengine.Rule{
		{Require: "invalid +++"},
	}

	_, err := celengine.Compile(rules)
	if err == nil {
		t.Fatal("expected compile error for invalid expression")
	}

	if !errors.Is(err, celengine.ErrCompileFailed) {
		t.Errorf("expected ErrCompileFailed, got: %v", err)
	}
}

func TestCompileTypeError(t *testing.T) {
	t.Parallel()

	rules := []celengine.Rule{
		{Require: exprImageRef},
	}

	_, err := celengine.Compile(rules)
	if err == nil {
		t.Fatal("expected type error for non-boolean expression")
	}

	if !errors.Is(err, celengine.ErrNotBool) {
		t.Errorf("expected ErrNotBool, got: %v", err)
	}
}

func TestCompileExpressionTooLarge(t *testing.T) {
	t.Parallel()

	bigExpr := "true" + strings.Repeat(" || true", celengine.MaxExpressionSize/8)

	rules := []celengine.Rule{
		{Require: bigExpr},
	}

	_, err := celengine.Compile(rules)
	if err == nil {
		t.Fatal("expected error for oversized expression")
	}

	if !errors.Is(err, celengine.ErrExpressionTooLarge) {
		t.Errorf("expected ErrExpressionTooLarge, got: %v", err)
	}
}

func TestCompileMatchExpressionTooLarge(t *testing.T) {
	t.Parallel()

	bigExpr := "true" + strings.Repeat(" || true", celengine.MaxExpressionSize/8)

	rules := []celengine.Rule{
		{Match: bigExpr, Require: exprTrue},
	}

	_, err := celengine.Compile(rules)
	if err == nil {
		t.Fatal("expected error for oversized match expression")
	}

	if !errors.Is(err, celengine.ErrExpressionTooLarge) {
		t.Errorf("expected ErrExpressionTooLarge, got: %v", err)
	}
}

func TestCompileTooManyRules(t *testing.T) {
	t.Parallel()

	rules := make([]celengine.Rule, celengine.MaxRules+1)
	for idx := range rules {
		rules[idx] = celengine.Rule{Require: exprTrue}
	}

	_, err := celengine.Compile(rules)
	if err == nil {
		t.Fatal("expected error for too many rules")
	}

	if !errors.Is(err, celengine.ErrTooManyRules) {
		t.Errorf("expected ErrTooManyRules, got: %v", err)
	}
}

func TestEvaluateAllPass(t *testing.T) {
	t.Parallel()

	rules := []celengine.Rule{
		{Require: exprSLSAVerified},
		{Require: exprVEXVerified},
	}

	compiled, err := celengine.Compile(rules)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	result := celengine.Evaluate(compiled, defaultVars())

	if !result.Passed {
		t.Errorf("expected pass, got fail: %s", result.Detail)
	}

	if result.Type != types.CheckTypeCEL {
		t.Errorf("expected check type CEL, got %s", result.Type)
	}
}

func TestEvaluateRequireFails(t *testing.T) {
	t.Parallel()

	rules := []celengine.Rule{
		{
			Require: "slsa.verified == false",
			Message: "SLSA must not be verified",
		},
	}

	compiled, err := celengine.Compile(rules)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	result := celengine.Evaluate(compiled, defaultVars())

	if result.Passed {
		t.Error("expected fail, got pass")
	}

	if result.Detail != "SLSA must not be verified" {
		t.Errorf("expected custom message, got: %s", result.Detail)
	}
}

func TestEvaluateRequireFailsDefaultMessage(t *testing.T) {
	t.Parallel()

	rules := []celengine.Rule{
		{Require: "slsa.verified == false"},
	}

	compiled, err := celengine.Compile(rules)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	result := celengine.Evaluate(compiled, defaultVars())

	if result.Passed {
		t.Error("expected fail, got pass")
	}

	if !strings.Contains(result.Detail, "CEL rule 0 failed") {
		t.Errorf("expected default message containing 'CEL rule 0 failed', got: %s", result.Detail)
	}
}

func TestEvaluateMatchFiltering(t *testing.T) {
	t.Parallel()

	rules := []celengine.Rule{
		{
			Match:   "image.registry == 'docker.io'",
			Require: exprFalse,
			Message: "should not fire for ghcr.io",
		},
	}

	compiled, err := celengine.Compile(rules)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	result := celengine.Evaluate(compiled, defaultVars())

	if !result.Passed {
		t.Errorf("expected pass (match should filter out), got fail: %s", result.Detail)
	}
}

func TestEvaluateMatchMatches(t *testing.T) {
	t.Parallel()

	rules := []celengine.Rule{
		{
			Match:   exprMatchGHCR,
			Require: exprSLSAVerified,
			Message: "GHCR images must have SLSA",
		},
	}

	compiled, err := celengine.Compile(rules)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	result := celengine.Evaluate(compiled, defaultVars())

	if !result.Passed {
		t.Errorf("expected pass, got fail: %s", result.Detail)
	}
}

func TestEvaluateNilCompiled(t *testing.T) {
	t.Parallel()

	result := celengine.Evaluate(nil, defaultVars())

	if !result.Passed {
		t.Error("expected pass for nil compiled policy")
	}
}

func TestEvaluateEmptyRules(t *testing.T) {
	t.Parallel()

	compiled := &celengine.CompiledPolicy{Rules: nil}

	result := celengine.Evaluate(compiled, defaultVars())

	if !result.Passed {
		t.Error("expected pass for empty rules")
	}
}

func TestEvaluateImageVariables(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		require string
		pass    bool
	}{
		{"image.ref", "image.ref == '" + testImageRef + "'", true},
		{"image.registry", "image.registry == '" + testRegistry + "'", true},
		{"image.repository", "image.repository == '" + testRepository + "'", true},
		{"image.digest", "image.digest == '" + testDigest + "'", true},
		{"image.namespace", "image.namespace == '" + testNamespace + "'", true},
		{"image.ref wrong", "image.ref == 'wrong'", false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			rules := []celengine.Rule{{Require: test.require}}

			compiled, err := celengine.Compile(rules)
			if err != nil {
				t.Fatalf("compile error: %v", err)
			}

			result := celengine.Evaluate(compiled, defaultVars())

			if result.Passed != test.pass {
				t.Errorf("expected passed=%v, got passed=%v: %s",
					test.pass, result.Passed, result.Detail)
			}
		})
	}
}

func TestEvaluateSLSAVariables(t *testing.T) {
	t.Parallel()

	rules := []celengine.Rule{
		{Require: exprSLSAVerified},
	}

	compiled, err := celengine.Compile(rules)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// Test with verified SLSA.
	vars := defaultVars()
	result := celengine.Evaluate(compiled, vars)

	if !result.Passed {
		t.Errorf("expected pass with verified SLSA, got: %s", result.Detail)
	}

	// Test with unverified SLSA.
	varsUnverified := celengine.BuildVars(
		testImageRef, testRegistry, testRepository, testDigest, testNamespace,
		types.FailResult(types.CheckTypeSLSA, "fail", nil),
		types.PassResult(types.CheckTypeVEX, "ok"),
		nil,
		types.PassResult(types.CheckTypeSBOM, "ok"),
		nil,
		nil,
	)

	result = celengine.Evaluate(compiled, varsUnverified)

	if result.Passed {
		t.Error("expected fail with unverified SLSA")
	}
}

func TestEvaluateVEXVariables(t *testing.T) {
	t.Parallel()

	rules := []celengine.Rule{
		{Require: exprVEXVerified},
	}

	compiled, err := celengine.Compile(rules)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// Test with unverified VEX.
	vars := celengine.BuildVars(
		testImageRef, testRegistry, testRepository, testDigest, testNamespace,
		types.PassResult(types.CheckTypeSLSA, "ok"),
		types.FailResult(types.CheckTypeVEX, "fail", nil),
		nil,
		types.PassResult(types.CheckTypeSBOM, "ok"),
		nil,
		nil,
	)

	result := celengine.Evaluate(compiled, vars)

	if result.Passed {
		t.Error("expected fail with unverified VEX")
	}
}

func TestEvaluateVSAVariables(t *testing.T) {
	t.Parallel()

	rules := []celengine.Rule{
		{Require: "vsa.verified == false"},
	}

	compiled, err := celengine.Compile(rules)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	result := celengine.Evaluate(compiled, defaultVars())

	if !result.Passed {
		t.Errorf("expected pass (VSA defaults to unverified), got: %s", result.Detail)
	}
}

func TestEvaluateSBOMVariables(t *testing.T) {
	t.Parallel()

	rules := []celengine.Rule{
		{Require: exprSBOMVerified},
	}

	compiled, err := celengine.Compile(rules)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// Test with verified SBOM.
	vars := defaultVars()
	result := celengine.Evaluate(compiled, vars)

	if !result.Passed {
		t.Errorf("expected pass with verified SBOM, got: %s", result.Detail)
	}

	// Test with unverified SBOM.
	varsUnverified := celengine.BuildVars(
		testImageRef, testRegistry, testRepository, testDigest, testNamespace,
		types.PassResult(types.CheckTypeSLSA, "ok"),
		types.PassResult(types.CheckTypeVEX, "ok"),
		nil,
		types.FailResult(types.CheckTypeSBOM, "fail", nil),
		nil,
		nil,
	)

	result = celengine.Evaluate(compiled, varsUnverified)

	if result.Passed {
		t.Error("expected fail with unverified SBOM")
	}
}

func TestEvaluateNilResults(t *testing.T) {
	t.Parallel()

	rules := []celengine.Rule{
		{
			Require: "slsa.verified == false && vex.verified == false && " +
				"sbom.verified == false && notation.verified == false",
		},
	}

	compiled, err := celengine.Compile(rules)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	vars := celengine.BuildVars(
		testImageRef, testRegistry, testRepository, testDigest, testNamespace,
		nil, nil, nil, nil, nil, nil,
	)

	result := celengine.Evaluate(compiled, vars)

	if !result.Passed {
		t.Errorf("expected pass with nil results (defaults to false), got: %s", result.Detail)
	}
}

func TestEvaluateStringFunctions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		require string
		pass    bool
	}{
		{"startsWith", "image.ref.startsWith('ghcr.io')", true},
		{"endsWith", "image.ref.endsWith(':latest')", true},
		{"contains", "image.ref.contains('myorg')", true},
		{"matches", "image.ref.matches('ghcr\\\\.io.*')", true},
		{"startsWith false", "image.ref.startsWith('docker.io')", false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			rules := []celengine.Rule{{Require: test.require}}

			compiled, err := celengine.Compile(rules)
			if err != nil {
				t.Fatalf("compile error: %v", err)
			}

			result := celengine.Evaluate(compiled, defaultVars())

			if result.Passed != test.pass {
				t.Errorf("expected passed=%v, got passed=%v: %s",
					test.pass, result.Passed, result.Detail)
			}
		})
	}
}

func TestCompileMatchSyntaxError(t *testing.T) {
	t.Parallel()

	rules := []celengine.Rule{
		{Match: "bad +++", Require: exprTrue},
	}

	_, err := celengine.Compile(rules)
	if err == nil {
		t.Fatal("expected compile error for invalid match expression")
	}

	if !errors.Is(err, celengine.ErrCompileFailed) {
		t.Errorf("expected ErrCompileFailed, got: %v", err)
	}
}

func TestCompileMatchTypeError(t *testing.T) {
	t.Parallel()

	rules := []celengine.Rule{
		{Match: exprImageRef, Require: exprTrue},
	}

	_, err := celengine.Compile(rules)
	if err == nil {
		t.Fatal("expected type error for non-boolean match expression")
	}

	if !errors.Is(err, celengine.ErrNotBool) {
		t.Errorf("expected ErrNotBool, got: %v", err)
	}
}

func TestBuildVarsTypes(t *testing.T) {
	t.Parallel()

	vars := defaultVars()

	imageMap, ok := vars["image"].(map[string]any)
	if !ok {
		t.Fatal("image vars should be map[string]any")
	}

	if _, ok := imageMap["ref"].(string); !ok {
		t.Error("image.ref should be a string")
	}

	slsaMap, ok := vars["slsa"].(map[string]any)
	if !ok {
		t.Fatal("slsa vars should be map[string]any")
	}

	if _, ok := slsaMap["verified"].(bool); !ok {
		t.Error("slsa.verified should be a bool")
	}

	vsaMap, ok := vars["vsa"].(map[string]any)
	if !ok {
		t.Fatal("vsa vars should be map[string]any")
	}

	if _, ok := vsaMap["level"].(int64); !ok {
		t.Error("vsa.level should be an int64")
	}

	sbomMap, ok := vars["sbom"].(map[string]any)
	if !ok {
		t.Fatal("sbom vars should be map[string]any")
	}

	if _, ok := sbomMap["verified"].(bool); !ok {
		t.Error("sbom.verified should be a bool")
	}

	if _, ok := sbomMap[metaFormat].(string); !ok {
		t.Error("sbom.format should be a string")
	}

	if _, ok := sbomMap[metaComponentCount].(int64); !ok {
		t.Error("sbom.componentCount should be an int64")
	}

	if _, ok := sbomMap[metaLicenseCount].(int64); !ok {
		t.Error("sbom.licenseCount should be an int64")
	}

	if _, ok := sbomMap[metaCVSSMax].(float64); !ok {
		t.Error("sbom.cvssMax should be a float64")
	}

	if _, ok := sbomMap[metaCVSSCriticalCount].(int64); !ok {
		t.Error("sbom.cvssCriticalCount should be an int64")
	}

	if _, ok := sbomMap[metaCVSSHighCount].(int64); !ok {
		t.Error("sbom.cvssHighCount should be an int64")
	}

	if _, ok := sbomMap[metaCVSSMediumCount].(int64); !ok {
		t.Error("sbom.cvssMediumCount should be an int64")
	}

	notationMap, ok := vars["notation"].(map[string]any)
	if !ok {
		t.Fatal("notation vars should be map[string]any")
	}

	if _, ok := notationMap["verified"].(bool); !ok {
		t.Error("notation.verified should be a bool")
	}

	if _, ok := notationMap[metaSignerDN].(string); !ok {
		t.Error("notation.signerDN should be a string")
	}

	if _, ok := notationMap[metaTrustPolicy].(string); !ok {
		t.Error("notation.trustPolicy should be a string")
	}
}

func TestBuildVarsPopulatesMetadata(t *testing.T) {
	t.Parallel()

	slsa := types.PassResult(types.CheckTypeSLSA, "ok")
	slsa.Metadata = map[string]any{
		metaBuilderID: testRunnerURL,
		metaBuildType: "https://actions.github.io/buildtypes/workflow/v1",
		metaSource:    testSourceRepo,
	}

	vex := types.PassResult(types.CheckTypeVEX, "ok")
	vex.Metadata = map[string]any{"status": "not_affected"}

	vsa := types.PassResult(types.CheckTypeVSA, "ok")
	vsa.Metadata = map[string]any{
		"verifierID": "https://verifier.example.com",
		"result":     "PASSED",
		"level":      int64(3),
	}

	vars := celengine.BuildVars(
		testImageRef, testRegistry, testRepository, testDigest, testNamespace,
		slsa, vex, vsa, types.PassResult(types.CheckTypeSBOM, "ok"), nil, nil,
	)

	slsaVars, ok := vars["slsa"].(map[string]any)
	if !ok {
		t.Fatal("slsa vars should be map[string]any")
	}

	if slsaVars[metaBuilderID] != testRunnerURL {
		t.Errorf("slsa.builderID = %q, want runner URL", slsaVars[metaBuilderID])
	}

	if slsaVars[metaBuildType] != "https://actions.github.io/buildtypes/workflow/v1" {
		t.Errorf("slsa.buildType = %q", slsaVars[metaBuildType])
	}

	if slsaVars[metaSource] != testSourceRepo {
		t.Errorf("slsa.source = %q", slsaVars[metaSource])
	}

	vexVars, ok := vars["vex"].(map[string]any)
	if !ok {
		t.Fatal("vex vars should be map[string]any")
	}

	if vexVars["status"] != "not_affected" {
		t.Errorf("vex.status = %q, want not_affected", vexVars["status"])
	}

	vsaVars, ok := vars["vsa"].(map[string]any)
	if !ok {
		t.Fatal("vsa vars should be map[string]any")
	}

	if vsaVars["verifierID"] != "https://verifier.example.com" {
		t.Errorf("vsa.verifierID = %q", vsaVars["verifierID"])
	}

	if vsaVars["result"] != "PASSED" {
		t.Errorf("vsa.result = %q", vsaVars["result"])
	}

	if vsaVars["level"] != int64(3) {
		t.Errorf("vsa.level = %v", vsaVars["level"])
	}

	if vsaVars["verified"] != true {
		t.Error("vsa.verified should be true")
	}
}

func TestEvaluateMetadataInCELExpression(t *testing.T) {
	t.Parallel()

	rules := []celengine.Rule{
		{Require: `slsa.builderID == "` + testRunnerURL + `"`},
	}

	compiled, err := celengine.Compile(rules)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	slsa := types.PassResult(types.CheckTypeSLSA, "ok")
	slsa.Metadata = map[string]any{
		metaBuilderID: testRunnerURL,
		metaBuildType: "workflow",
		metaSource:    testSourceRepo,
	}

	vars := celengine.BuildVars(
		testImageRef, testRegistry, testRepository, testDigest, testNamespace,
		slsa, types.PassResult(types.CheckTypeVEX, "ok"),
		nil, types.PassResult(types.CheckTypeSBOM, "ok"), nil, nil,
	)

	result := celengine.Evaluate(compiled, vars)
	if !result.Passed {
		t.Errorf("expected pass with matching builderID, got: %s", result.Detail)
	}

	slsaWrong := types.PassResult(types.CheckTypeSLSA, "ok")
	slsaWrong.Metadata = map[string]any{
		metaBuilderID: "https://other-builder.example.com",
		metaBuildType: "workflow",
		metaSource:    "",
	}

	varsWrong := celengine.BuildVars(
		testImageRef, testRegistry, testRepository, testDigest, testNamespace,
		slsaWrong, types.PassResult(types.CheckTypeVEX, "ok"),
		nil, types.PassResult(types.CheckTypeSBOM, "ok"), nil, nil,
	)

	result = celengine.Evaluate(compiled, varsWrong)
	if result.Passed {
		t.Error("expected fail with non-matching builderID")
	}
}

func TestEvaluateMultipleRulesFirstFails(t *testing.T) {
	t.Parallel()

	rules := []celengine.Rule{
		{
			Require: exprFalse,
			Message: "first rule always fails",
		},
		{
			Require: "true",
			Message: "second rule always passes",
		},
	}

	compiled, err := celengine.Compile(rules)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	result := celengine.Evaluate(compiled, defaultVars())

	if result.Passed {
		t.Error("expected fail because first rule fails")
	}

	if result.Detail != "first rule always fails" {
		t.Errorf("expected first rule message, got: %s", result.Detail)
	}
}

func TestEvaluateMultipleRulesAllPass(t *testing.T) {
	t.Parallel()

	rules := []celengine.Rule{
		{Require: exprTrue},
		{Require: exprTrue},
		{Require: exprTrue},
	}

	compiled, err := celengine.Compile(rules)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	result := celengine.Evaluate(compiled, defaultVars())

	if !result.Passed {
		t.Errorf("expected pass, got fail: %s", result.Detail)
	}
}

func TestCompileMultipleErrors(t *testing.T) {
	t.Parallel()

	rules := []celengine.Rule{
		{Require: "invalid +++"},
		{Require: "also invalid ---"},
	}

	_, err := celengine.Compile(rules)
	if err == nil {
		t.Fatal("expected compile errors")
	}

	errStr := err.Error()
	if !strings.Contains(errStr, "rules[0]") {
		t.Errorf("expected error mentioning rules[0], got: %s", errStr)
	}

	if !strings.Contains(errStr, "rules[1]") {
		t.Errorf("expected error mentioning rules[1], got: %s", errStr)
	}
}

func TestEvaluateNotationVariables(t *testing.T) {
	t.Parallel()

	celengine.ResetEnvironmentForTest()

	tests := []struct {
		name    string
		require string
		result  *types.CheckResult
		pass    bool
	}{
		{
			name:    "notation.verified true",
			require: exprNotationVerified,
			result: func() *types.CheckResult {
				r := types.PassResult(types.CheckTypeNotation, "ok")
				r.Metadata = map[string]any{
					metaSignerDN:    testSignerDN,
					metaTrustPolicy: testTrustPolicy,
				}

				return r
			}(),
			pass: true,
		},
		{
			name:    "notation.signerDN match",
			require: `notation.signerDN == "CN=test"`,
			result: func() *types.CheckResult {
				r := types.PassResult(types.CheckTypeNotation, "ok")
				r.Metadata = map[string]any{
					metaSignerDN:    testSignerDN,
					metaTrustPolicy: testTrustPolicy,
				}

				return r
			}(),
			pass: true,
		},
		{
			name:    "notation.trustPolicy match",
			require: `notation.trustPolicy == "prod-ca"`,
			result: func() *types.CheckResult {
				r := types.PassResult(types.CheckTypeNotation, "ok")
				r.Metadata = map[string]any{
					metaSignerDN:    testSignerDN,
					metaTrustPolicy: testTrustPolicy,
				}

				return r
			}(),
			pass: true,
		},
		{
			name:    "notation defaults with nil result",
			require: `notation.verified == false && notation.signerDN == "" && notation.trustPolicy == ""`,
			result:  nil,
			pass:    true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			rules := []celengine.Rule{{Require: test.require}}

			compiled, err := celengine.Compile(rules)
			if err != nil {
				t.Fatalf("compile error: %v", err)
			}

			vars := celengine.BuildVars(
				testImageRef, testRegistry, testRepository, testDigest, testNamespace,
				types.PassResult(types.CheckTypeSLSA, "ok"),
				types.PassResult(types.CheckTypeVEX, "ok"),
				nil,
				types.PassResult(types.CheckTypeSBOM, "ok"),
				test.result,
				nil,
			)

			result := celengine.Evaluate(compiled, vars)

			if result.Passed != test.pass {
				t.Errorf("expected passed=%v, got passed=%v: %s",
					test.pass, result.Passed, result.Detail)
			}
		})
	}
}

func TestEvaluateExtendedSBOMVariables(t *testing.T) {
	t.Parallel()

	celengine.ResetEnvironmentForTest()

	tests := []struct {
		name    string
		require string
		result  *types.CheckResult
		pass    bool
	}{
		{
			name:    "sbom.format cyclonedx",
			require: `sbom.format == "cyclonedx"`,
			result: func() *types.CheckResult {
				r := types.PassResult(types.CheckTypeSBOM, "ok")
				r.Metadata = map[string]any{
					metaFormat:         testFormatCycloneDX,
					metaComponentCount: int64(15),
					metaLicenseCount:   int64(3),
				}

				return r
			}(),
			pass: true,
		},
		{
			name:    "sbom.componentCount greater than",
			require: "sbom.componentCount > 10",
			result: func() *types.CheckResult {
				r := types.PassResult(types.CheckTypeSBOM, "ok")
				r.Metadata = map[string]any{
					metaFormat:         "spdx",
					metaComponentCount: int64(15),
					metaLicenseCount:   int64(1),
				}

				return r
			}(),
			pass: true,
		},
		{
			name:    "sbom.licenseCount at least 1",
			require: "sbom.licenseCount >= 1",
			result: func() *types.CheckResult {
				r := types.PassResult(types.CheckTypeSBOM, "ok")
				r.Metadata = map[string]any{
					metaFormat:         "spdx",
					metaComponentCount: int64(5),
					metaLicenseCount:   int64(1),
				}

				return r
			}(),
			pass: true,
		},
		{
			name:    "sbom.cvssMax threshold",
			require: "sbom.cvssMax <= 7.0",
			result: func() *types.CheckResult {
				r := types.PassResult(types.CheckTypeSBOM, "ok")
				r.Metadata = map[string]any{
					metaFormat:            testFormatCycloneDX,
					metaComponentCount:    int64(5),
					metaLicenseCount:      int64(1),
					metaCVSSMax:           float64(5.5),
					metaCVSSCriticalCount: int64(0),
					metaCVSSHighCount:     int64(1),
				}

				return r
			}(),
			pass: true,
		},
		{
			name:    "sbom.cvssCriticalCount zero",
			require: "sbom.cvssCriticalCount == 0",
			result: func() *types.CheckResult {
				r := types.PassResult(types.CheckTypeSBOM, "ok")
				r.Metadata = map[string]any{
					metaFormat:            testFormatCycloneDX,
					metaComponentCount:    int64(5),
					metaLicenseCount:      int64(1),
					metaCVSSMax:           float64(5.5),
					metaCVSSCriticalCount: int64(0),
					metaCVSSHighCount:     int64(1),
				}

				return r
			}(),
			pass: true,
		},
		{
			name: "sbom defaults with nil result",
			require: `sbom.format == "" && sbom.componentCount == 0 && sbom.licenseCount == 0` +
				` && sbom.cvssMax == 0.0 && sbom.cvssCriticalCount == 0 && sbom.cvssHighCount == 0` +
				` && sbom.cvssMediumCount == 0`,
			result: nil,
			pass:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			rules := []celengine.Rule{{Require: test.require}}

			compiled, err := celengine.Compile(rules)
			if err != nil {
				t.Fatalf("compile error: %v", err)
			}

			vars := celengine.BuildVars(
				testImageRef, testRegistry, testRepository, testDigest, testNamespace,
				types.PassResult(types.CheckTypeSLSA, "ok"),
				types.PassResult(types.CheckTypeVEX, "ok"),
				nil,
				test.result,
				nil,
				nil,
			)

			result := celengine.Evaluate(compiled, vars)

			if result.Passed != test.pass {
				t.Errorf("expected passed=%v, got passed=%v: %s",
					test.pass, result.Passed, result.Detail)
			}
		})
	}
}

func TestEvaluateMapAccess(t *testing.T) {
	t.Parallel()

	rules := []celengine.Rule{
		{Require: "image.registry == 'ghcr.io' && slsa.builderID == ''"},
	}

	compiled, err := celengine.Compile(rules)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	result := celengine.Evaluate(compiled, defaultVars())

	if !result.Passed {
		t.Errorf("expected pass, got fail: %s", result.Detail)
	}
}

func TestCompileMaxRulesExact(t *testing.T) {
	t.Parallel()

	rules := make([]celengine.Rule, celengine.MaxRules)
	for idx := range rules {
		rules[idx] = celengine.Rule{Require: exprTrue}
	}

	compiled, err := celengine.Compile(rules)
	if err != nil {
		t.Fatalf("unexpected error at max rules: %v", err)
	}

	if len(compiled.Rules) != celengine.MaxRules {
		t.Errorf("expected %d rules, got %d", celengine.MaxRules, len(compiled.Rules))
	}
}

func TestEvaluateNoMatchSkipsRequire(t *testing.T) {
	t.Parallel()

	rules := []celengine.Rule{
		{
			Match:   "image.namespace == 'staging'",
			Require: exprFalse,
			Message: "should never reach require",
		},
		{
			Match:   "image.namespace == 'production'",
			Require: "true",
			Message: "production rule passes",
		},
	}

	compiled, err := celengine.Compile(rules)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	result := celengine.Evaluate(compiled, defaultVars())

	if !result.Passed {
		t.Errorf("expected pass (staging rule skipped, production passes), got fail: %s",
			result.Detail)
	}
}

func TestEvaluateSBOMCVSSVariables(t *testing.T) {
	t.Parallel()

	t.Run("cvssMax threshold rule", func(t *testing.T) {
		t.Parallel()

		rules := []celengine.Rule{
			{Require: "sbom.cvssMax <= 7.0", Message: "max CVSS must be <= 7.0"},
		}

		compiled, err := celengine.Compile(rules)
		if err != nil {
			t.Fatalf("compile error: %v", err)
		}

		sbomResult := types.PassResult(types.CheckTypeSBOM, "ok")
		sbomResult.Metadata = map[string]any{
			"cvssMax":           float64(9.8),
			"cvssCriticalCount": int64(1),
			"cvssHighCount":     int64(2),
		}

		vars := celengine.BuildVars(
			testImageRef, testRegistry, testRepository, testDigest, testNamespace,
			types.PassResult(types.CheckTypeSLSA, "ok"),
			types.PassResult(types.CheckTypeVEX, "ok"),
			nil,
			sbomResult,
			nil,
			nil,
		)

		result := celengine.Evaluate(compiled, vars)
		if result.Passed {
			t.Error("expected fail: cvssMax 9.8 exceeds 7.0")
		}

		if result.Detail != "max CVSS must be <= 7.0" {
			t.Errorf("expected custom message, got: %s", result.Detail)
		}
	})

	t.Run("cvssCriticalCount zero rule", func(t *testing.T) {
		t.Parallel()

		rules := []celengine.Rule{
			{Require: "sbom.cvssCriticalCount == 0", Message: "no critical vulns allowed"},
		}

		compiled, err := celengine.Compile(rules)
		if err != nil {
			t.Fatalf("compile error: %v", err)
		}

		sbomResult := types.PassResult(types.CheckTypeSBOM, "ok")
		sbomResult.Metadata = map[string]any{
			"cvssMax":           float64(5.0),
			"cvssCriticalCount": int64(0),
			"cvssHighCount":     int64(1),
		}

		vars := celengine.BuildVars(
			testImageRef, testRegistry, testRepository, testDigest, testNamespace,
			types.PassResult(types.CheckTypeSLSA, "ok"),
			types.PassResult(types.CheckTypeVEX, "ok"),
			nil,
			sbomResult,
			nil,
			nil,
		)

		result := celengine.Evaluate(compiled, vars)
		if !result.Passed {
			t.Errorf("expected pass: cvssCriticalCount is 0, got: %s", result.Detail)
		}
	})

	t.Run("cvss defaults when no metadata", func(t *testing.T) {
		t.Parallel()

		rules := []celengine.Rule{
			{
				Require: "sbom.cvssMax == 0.0 && sbom.cvssCriticalCount == 0" +
					" && sbom.cvssHighCount == 0 && sbom.cvssMediumCount == 0",
			},
		}

		compiled, err := celengine.Compile(rules)
		if err != nil {
			t.Fatalf("compile error: %v", err)
		}

		vars := celengine.BuildVars(
			testImageRef, testRegistry, testRepository, testDigest, testNamespace,
			types.PassResult(types.CheckTypeSLSA, "ok"),
			types.PassResult(types.CheckTypeVEX, "ok"),
			nil,
			types.PassResult(types.CheckTypeSBOM, "ok"),
			nil,
			nil,
		)

		result := celengine.Evaluate(compiled, vars)
		if !result.Passed {
			t.Errorf("expected pass with default CVSS values, got: %s", result.Detail)
		}
	})
}

func TestEvaluateSCAIVariables(t *testing.T) {
	t.Parallel()

	celengine.ResetEnvironmentForTest()

	tests := []struct {
		name    string
		require string
		result  *types.CheckResult
		pass    bool
	}{
		{
			name:    "scai.verified true",
			require: "scai.verified == true",
			result: func() *types.CheckResult {
				r := types.PassResult(types.CheckTypeSCAI, "ok")
				r.Metadata = map[string]any{
					metaAttributes:     testTwoAttrs,
					metaAttributeCount: int64(2),
					metaHasEvidence:    true,
				}

				return r
			}(),
			pass: true,
		},
		{
			name:    "scai.attributeCount greater than",
			require: "scai.attributeCount > 1",
			result: func() *types.CheckResult {
				r := types.PassResult(types.CheckTypeSCAI, "ok")
				r.Metadata = map[string]any{
					metaAttributes:     testTwoAttrs,
					metaAttributeCount: int64(2),
					metaHasEvidence:    true,
				}

				return r
			}(),
			pass: true,
		},
		{
			name:    "scai.hasEvidence check",
			require: "scai.hasEvidence == true",
			result: func() *types.CheckResult {
				r := types.PassResult(types.CheckTypeSCAI, "ok")
				r.Metadata = map[string]any{
					metaAttributes:     testOneAttr,
					metaAttributeCount: int64(1),
					metaHasEvidence:    true,
				}

				return r
			}(),
			pass: true,
		},
		{
			name:    "scai.attributes contains check",
			require: `scai.attributes.contains("PASSED_CODE_REVIEW")`,
			result: func() *types.CheckResult {
				r := types.PassResult(types.CheckTypeSCAI, "ok")
				r.Metadata = map[string]any{
					metaAttributes:     testTwoAttrs,
					metaAttributeCount: int64(2),
					metaHasEvidence:    false,
				}

				return r
			}(),
			pass: true,
		},
		{
			name: "scai defaults with nil result",
			require: `scai.verified == false && scai.attributes == "" ` +
				`&& scai.attributeCount == 0 && scai.hasEvidence == false`,
			result: nil,
			pass:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			rules := []celengine.Rule{{Require: test.require}}

			compiled, err := celengine.Compile(rules)
			if err != nil {
				t.Fatalf("compile error: %v", err)
			}

			vars := celengine.BuildVars(
				testImageRef, testRegistry, testRepository, testDigest, testNamespace,
				types.PassResult(types.CheckTypeSLSA, "ok"),
				types.PassResult(types.CheckTypeVEX, "ok"),
				nil,
				types.PassResult(types.CheckTypeSBOM, "ok"),
				nil,
				test.result,
			)

			result := celengine.Evaluate(compiled, vars)

			if result.Passed != test.pass {
				t.Errorf("expected passed=%v, got passed=%v: %s",
					test.pass, result.Passed, result.Detail)
			}
		})
	}
}

var (
	errUnrelated          = errors.New("something else")
	errCostLimitSubstring = errors.New(
		"actual cost limit exceeded for expression",
	)
)

func TestIsCostError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "unrelated error",
			err:  errUnrelated,
			want: false,
		},
		{
			name: "cost limit exceeded sentinel",
			err:  celengine.ErrCostLimitExceeded,
			want: true,
		},
		{
			name: "wrapped cost limit exceeded",
			err:  errors.Join(celengine.ErrCostLimitExceeded, errUnrelated),
			want: true,
		},
		{
			name: "actual cost limit exceeded string",
			err:  errCostLimitSubstring,
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := celengine.ExportIsCostError(tc.err); got != tc.want {
				t.Errorf("isCostError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

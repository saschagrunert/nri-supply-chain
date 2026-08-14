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

	metaResult        = "result"
	metaLevel         = "level"
	metaBranch        = "branch"
	metaProperties    = "properties"
	metaPropertyCount = "propertyCount"
	metaScanner       = "scanner"
	metaVulnCount     = "vulnCount"
	metaMaxScore      = "maxScore"
	metaMaxSeverity   = "maxSeverity"
	metaCriticalCount = "criticalCount"
	metaHighCount     = "highCount"
	metaSuiteCount    = "suiteCount"
	metaSuites        = "suites"
	metaPassed        = "passed"
	metaFailed        = "failed"

	testScannerURI = "https://scanner.example.com"
	testSourceURI  = "https://github.com/example/repo"
	testBranchMain = "main"
	testSevHigh    = "high"
	testResultPass = "pass"

	metaPurl            = "purl"
	metaPackageID       = "packageId"
	metaMonitorType     = "monitorType"
	metaProcessCount    = "processCount"
	metaNetworkCount    = "networkCount"
	metaFileAccessCount = "fileAccessCount"
	metaFileNames       = "fileNames"
	testPurl            = "pkg:oci/ghcr.io/myorg/myapp@sha256:abc123"
	testMonitorFalco    = "falco"

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
		map[types.CheckType]*types.CheckResult{
			types.CheckTypeSLSA: types.PassResult(types.CheckTypeSLSA, "ok"),
			types.CheckTypeVEX:  types.PassResult(types.CheckTypeVEX, "ok"),
			types.CheckTypeSBOM: types.PassResult(types.CheckTypeSBOM, "ok"),
		},
	)
}

type celVarTest struct {
	name    string
	require string
	result  *types.CheckResult
	pass    bool
}

func runCELVarTests(t *testing.T, checkType types.CheckType, tests []celVarTest) {
	t.Helper()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			rules := []celengine.Rule{{Require: test.require}}

			compiled, err := celengine.Compile(rules)
			if err != nil {
				t.Fatalf("compile error: %v", err)
			}

			results := map[types.CheckType]*types.CheckResult{
				types.CheckTypeSLSA: types.PassResult(types.CheckTypeSLSA, "ok"),
				types.CheckTypeVEX:  types.PassResult(types.CheckTypeVEX, "ok"),
				types.CheckTypeSBOM: types.PassResult(types.CheckTypeSBOM, "ok"),
			}
			results[checkType] = test.result

			vars := celengine.BuildVars(
				testImageRef, testRegistry, testRepository, testDigest, testNamespace,
				results,
			)

			result := celengine.Evaluate(compiled, vars)

			if result.Passed != test.pass {
				t.Errorf("expected passed=%v, got passed=%v: %s",
					test.pass, result.Passed, result.Detail)
			}
		})
	}
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
		map[types.CheckType]*types.CheckResult{
			types.CheckTypeSLSA: types.FailResult(types.CheckTypeSLSA, "fail", nil),
			types.CheckTypeVEX:  types.PassResult(types.CheckTypeVEX, "ok"),
			types.CheckTypeSBOM: types.PassResult(types.CheckTypeSBOM, "ok"),
		},
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
		map[types.CheckType]*types.CheckResult{
			types.CheckTypeSLSA: types.PassResult(types.CheckTypeSLSA, "ok"),
			types.CheckTypeVEX:  types.FailResult(types.CheckTypeVEX, "fail", nil),
			types.CheckTypeSBOM: types.PassResult(types.CheckTypeSBOM, "ok"),
		},
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
		map[types.CheckType]*types.CheckResult{
			types.CheckTypeSLSA: types.PassResult(types.CheckTypeSLSA, "ok"),
			types.CheckTypeVEX:  types.PassResult(types.CheckTypeVEX, "ok"),
			types.CheckTypeSBOM: types.FailResult(types.CheckTypeSBOM, "fail", nil),
		},
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
		nil,
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
		metaResult:   "PASSED",
		metaLevel:    int64(3),
	}

	vars := celengine.BuildVars(
		testImageRef, testRegistry, testRepository, testDigest, testNamespace,
		map[types.CheckType]*types.CheckResult{
			types.CheckTypeSLSA: slsa,
			types.CheckTypeVEX:  vex,
			types.CheckTypeVSA:  vsa,
			types.CheckTypeSBOM: types.PassResult(types.CheckTypeSBOM, "ok"),
		},
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

	if vsaVars[metaResult] != "PASSED" {
		t.Errorf("vsa.result = %q", vsaVars[metaResult])
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
		map[types.CheckType]*types.CheckResult{
			types.CheckTypeSLSA: slsa,
			types.CheckTypeVEX:  types.PassResult(types.CheckTypeVEX, "ok"),
			types.CheckTypeSBOM: types.PassResult(types.CheckTypeSBOM, "ok"),
		},
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
		map[types.CheckType]*types.CheckResult{
			types.CheckTypeSLSA: slsaWrong,
			types.CheckTypeVEX:  types.PassResult(types.CheckTypeVEX, "ok"),
			types.CheckTypeSBOM: types.PassResult(types.CheckTypeSBOM, "ok"),
		},
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

	tests := []celVarTest{
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

	runCELVarTests(t, types.CheckTypeNotation, tests)
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
				map[types.CheckType]*types.CheckResult{
					types.CheckTypeSLSA: types.PassResult(types.CheckTypeSLSA, "ok"),
					types.CheckTypeVEX:  types.PassResult(types.CheckTypeVEX, "ok"),
					types.CheckTypeSBOM: test.result,
				},
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
			map[types.CheckType]*types.CheckResult{
				types.CheckTypeSLSA: types.PassResult(types.CheckTypeSLSA, "ok"),
				types.CheckTypeVEX:  types.PassResult(types.CheckTypeVEX, "ok"),
				types.CheckTypeSBOM: sbomResult,
			},
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
			map[types.CheckType]*types.CheckResult{
				types.CheckTypeSLSA: types.PassResult(types.CheckTypeSLSA, "ok"),
				types.CheckTypeVEX:  types.PassResult(types.CheckTypeVEX, "ok"),
				types.CheckTypeSBOM: sbomResult,
			},
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
			map[types.CheckType]*types.CheckResult{
				types.CheckTypeSLSA: types.PassResult(types.CheckTypeSLSA, "ok"),
				types.CheckTypeVEX:  types.PassResult(types.CheckTypeVEX, "ok"),
				types.CheckTypeSBOM: types.PassResult(types.CheckTypeSBOM, "ok"),
			},
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

	tests := []celVarTest{
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

	runCELVarTests(t, types.CheckTypeSCAI, tests)
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

func TestEvaluateSourceVariables(t *testing.T) {
	t.Parallel()

	celengine.ResetEnvironmentForTest()

	tests := []celVarTest{
		{
			name:    "source.verified true",
			require: "source.verified == true",
			result: func() *types.CheckResult {
				r := types.PassResult(types.CheckTypeSource, "ok")
				r.Metadata = map[string]any{
					metaSource: testSourceURI,
					metaBranch: testBranchMain,
					metaLevel:  int64(2),
				}

				return r
			}(),
			pass: true,
		},
		{
			name:    "source.source match",
			require: `source.source == "https://github.com/example/repo"`,
			result: func() *types.CheckResult {
				r := types.PassResult(types.CheckTypeSource, "ok")
				r.Metadata = map[string]any{
					metaSource: testSourceURI,
					metaBranch: testBranchMain,
					metaLevel:  int64(2),
				}

				return r
			}(),
			pass: true,
		},
		{
			name:    "source.branch match",
			require: `source.branch == "main"`,
			result: func() *types.CheckResult {
				r := types.PassResult(types.CheckTypeSource, "ok")
				r.Metadata = map[string]any{
					metaSource: testSourceURI,
					metaBranch: testBranchMain,
					metaLevel:  int64(2),
				}

				return r
			}(),
			pass: true,
		},
		{
			name:    "source.level check",
			require: "source.level >= 2",
			result: func() *types.CheckResult {
				r := types.PassResult(types.CheckTypeSource, "ok")
				r.Metadata = map[string]any{
					metaSource: testSourceURI,
					metaBranch: testBranchMain,
					metaLevel:  int64(2),
				}

				return r
			}(),
			pass: true,
		},
		{
			name: "source defaults with nil result",
			require: `source.verified == false && source.source == "" ` +
				`&& source.branch == "" && source.level == 0`,
			result: nil,
			pass:   true,
		},
	}

	runCELVarTests(t, types.CheckTypeSource, tests)
}

func TestEvaluateBuildEnvVariables(t *testing.T) {
	t.Parallel()

	celengine.ResetEnvironmentForTest()

	tests := []celVarTest{
		{
			name:    "buildenv.verified true",
			require: "buildenv.verified == true",
			result: func() *types.CheckResult {
				r := types.PassResult(types.CheckTypeBuildEnv, "ok")
				r.Metadata = map[string]any{
					metaProperties:    "os,arch",
					metaPropertyCount: int64(2),
				}

				return r
			}(),
			pass: true,
		},
		{
			name:    "buildenv.properties contains",
			require: `buildenv.properties.contains("os")`,
			result: func() *types.CheckResult {
				r := types.PassResult(types.CheckTypeBuildEnv, "ok")
				r.Metadata = map[string]any{
					metaProperties:    "os,arch",
					metaPropertyCount: int64(2),
				}

				return r
			}(),
			pass: true,
		},
		{
			name:    "buildenv.propertyCount greater than",
			require: "buildenv.propertyCount > 0",
			result: func() *types.CheckResult {
				r := types.PassResult(types.CheckTypeBuildEnv, "ok")
				r.Metadata = map[string]any{
					metaProperties:    "os",
					metaPropertyCount: int64(1),
				}

				return r
			}(),
			pass: true,
		},
		{
			name: "buildenv defaults with nil result",
			require: `buildenv.verified == false && buildenv.properties == "" ` +
				`&& buildenv.propertyCount == 0`,
			result: nil,
			pass:   true,
		},
	}

	runCELVarTests(t, types.CheckTypeBuildEnv, tests)
}

func TestEvaluateVulnScanVariables(t *testing.T) {
	t.Parallel()

	celengine.ResetEnvironmentForTest()

	tests := []celVarTest{
		{
			name:    "vulnscan.verified true",
			require: "vulnscan.verified == true",
			result: func() *types.CheckResult {
				r := types.PassResult(types.CheckTypeVulnScan, "ok")
				r.Metadata = map[string]any{
					metaScanner:       testScannerURI,
					metaVulnCount:     int64(3),
					metaMaxScore:      float64(5.5),
					metaMaxSeverity:   testSevHigh,
					metaCriticalCount: int64(0),
					metaHighCount:     int64(1),
				}

				return r
			}(),
			pass: true,
		},
		{
			name:    "vulnscan.scanner match",
			require: `vulnscan.scanner == "https://scanner.example.com"`,
			result: func() *types.CheckResult {
				r := types.PassResult(types.CheckTypeVulnScan, "ok")
				r.Metadata = map[string]any{
					metaScanner:       testScannerURI,
					metaVulnCount:     int64(3),
					metaMaxScore:      float64(5.5),
					metaMaxSeverity:   testSevHigh,
					metaCriticalCount: int64(0),
					metaHighCount:     int64(1),
				}

				return r
			}(),
			pass: true,
		},
		{
			name:    "vulnscan.maxScore threshold",
			require: "vulnscan.maxScore <= 7.0",
			result: func() *types.CheckResult {
				r := types.PassResult(types.CheckTypeVulnScan, "ok")
				r.Metadata = map[string]any{
					metaScanner:       testScannerURI,
					metaVulnCount:     int64(1),
					metaMaxScore:      float64(5.5),
					metaMaxSeverity:   "medium",
					metaCriticalCount: int64(0),
					metaHighCount:     int64(0),
				}

				return r
			}(),
			pass: true,
		},
		{
			name:    "vulnscan.maxSeverity check",
			require: `vulnscan.maxSeverity == "high"`,
			result: func() *types.CheckResult {
				r := types.PassResult(types.CheckTypeVulnScan, "ok")
				r.Metadata = map[string]any{
					metaScanner:       testScannerURI,
					metaVulnCount:     int64(2),
					metaMaxScore:      float64(7.5),
					metaMaxSeverity:   testSevHigh,
					metaCriticalCount: int64(0),
					metaHighCount:     int64(1),
				}

				return r
			}(),
			pass: true,
		},
		{
			name:    "vulnscan.criticalCount zero",
			require: "vulnscan.criticalCount == 0",
			result: func() *types.CheckResult {
				r := types.PassResult(types.CheckTypeVulnScan, "ok")
				r.Metadata = map[string]any{
					metaScanner:       testScannerURI,
					metaVulnCount:     int64(1),
					metaMaxScore:      float64(5.0),
					metaMaxSeverity:   "medium",
					metaCriticalCount: int64(0),
					metaHighCount:     int64(0),
				}

				return r
			}(),
			pass: true,
		},
		{
			name: "vulnscan defaults with nil result",
			require: `vulnscan.verified == false && vulnscan.scanner == "" ` +
				`&& vulnscan.vulnCount == 0 && vulnscan.maxScore == 0.0 ` +
				`&& vulnscan.maxSeverity == "" && vulnscan.criticalCount == 0 ` +
				`&& vulnscan.highCount == 0`,
			result: nil,
			pass:   true,
		},
	}

	runCELVarTests(t, types.CheckTypeVulnScan, tests)
}

func TestEvaluateTestResultVariables(t *testing.T) {
	t.Parallel()

	celengine.ResetEnvironmentForTest()

	tests := []celVarTest{
		{
			name:    "testresult.verified true",
			require: "testresult.verified == true",
			result: func() *types.CheckResult {
				r := types.PassResult(types.CheckTypeTestResult, "ok")
				r.Metadata = map[string]any{
					metaResult:     testResultPass,
					metaSuiteCount: int64(2),
					metaSuites:     "unit,integration",
					metaPassed:     int64(42),
					metaFailed:     int64(0),
				}

				return r
			}(),
			pass: true,
		},
		{
			name:    "testresult.result pass",
			require: `testresult.result == "pass"`,
			result: func() *types.CheckResult {
				r := types.PassResult(types.CheckTypeTestResult, "ok")
				r.Metadata = map[string]any{
					metaResult:     testResultPass,
					metaSuiteCount: int64(1),
					metaSuites:     "unit",
					metaPassed:     int64(10),
					metaFailed:     int64(0),
				}

				return r
			}(),
			pass: true,
		},
		{
			name:    "testresult.suiteCount check",
			require: "testresult.suiteCount >= 2",
			result: func() *types.CheckResult {
				r := types.PassResult(types.CheckTypeTestResult, "ok")
				r.Metadata = map[string]any{
					metaResult:     testResultPass,
					metaSuiteCount: int64(3),
					metaSuites:     "unit,integration,e2e",
					metaPassed:     int64(100),
					metaFailed:     int64(0),
				}

				return r
			}(),
			pass: true,
		},
		{
			name:    "testresult.suites contains",
			require: `testresult.suites.contains("unit")`,
			result: func() *types.CheckResult {
				r := types.PassResult(types.CheckTypeTestResult, "ok")
				r.Metadata = map[string]any{
					metaResult:     testResultPass,
					metaSuiteCount: int64(2),
					metaSuites:     "unit,integration",
					metaPassed:     int64(50),
					metaFailed:     int64(0),
				}

				return r
			}(),
			pass: true,
		},
		{
			name:    "testresult.passed count",
			require: "testresult.passed > 0",
			result: func() *types.CheckResult {
				r := types.PassResult(types.CheckTypeTestResult, "ok")
				r.Metadata = map[string]any{
					metaResult:     testResultPass,
					metaSuiteCount: int64(1),
					metaSuites:     "unit",
					metaPassed:     int64(25),
					metaFailed:     int64(0),
				}

				return r
			}(),
			pass: true,
		},
		{
			name: "testresult defaults with nil result",
			require: `testresult.verified == false && testresult.result == "" ` +
				`&& testresult.suiteCount == 0 && testresult.suites == "" ` +
				`&& testresult.passed == 0 && testresult.failed == 0`,
			result: nil,
			pass:   true,
		},
	}

	runCELVarTests(t, types.CheckTypeTestResult, tests)
}

func TestEvaluateReleaseVariables(t *testing.T) {
	t.Parallel()

	celengine.ResetEnvironmentForTest()

	tests := []celVarTest{
		{
			name:    "release.verified true",
			require: "release.verified == true",
			result: func() *types.CheckResult {
				r := types.PassResult(types.CheckTypeRelease, "ok")
				r.Metadata = map[string]any{
					metaPurl:      testPurl,
					metaPackageID: "myapp-1.0.0",
				}

				return r
			}(),
			pass: true,
		},
		{
			name:    "release.purl check",
			require: `release.purl.contains("ghcr.io")`,
			result: func() *types.CheckResult {
				r := types.PassResult(types.CheckTypeRelease, "ok")
				r.Metadata = map[string]any{
					metaPurl:      testPurl,
					metaPackageID: "",
				}

				return r
			}(),
			pass: true,
		},
		{
			name:    "release.packageId check",
			require: `release.packageId == "myapp-1.0.0"`,
			result: func() *types.CheckResult {
				r := types.PassResult(types.CheckTypeRelease, "ok")
				r.Metadata = map[string]any{
					metaPurl:      testPurl,
					metaPackageID: "myapp-1.0.0",
				}

				return r
			}(),
			pass: true,
		},
		{
			name: "release defaults with nil result",
			require: `release.verified == false && release.purl == "" ` +
				`&& release.packageId == ""`,
			result: nil,
			pass:   true,
		},
	}

	runCELVarTests(t, types.CheckTypeRelease, tests)
}

func TestEvaluateRuntimeTraceVariables(t *testing.T) {
	t.Parallel()

	celengine.ResetEnvironmentForTest()

	tests := []celVarTest{
		{
			name:    "runtimetrace.verified true",
			require: "runtimetrace.verified == true",
			result: func() *types.CheckResult {
				r := types.PassResult(types.CheckTypeRuntimeTrace, "ok")
				r.Metadata = map[string]any{
					metaMonitorType:     testMonitorFalco,
					metaProcessCount:    int64(10),
					metaNetworkCount:    int64(5),
					metaFileAccessCount: int64(3),
					metaFileNames:       "/usr/bin/gcc,/tmp/build.o",
				}

				return r
			}(),
			pass: true,
		},
		{
			name:    "runtimetrace.monitorType check",
			require: `runtimetrace.monitorType == "falco"`,
			result: func() *types.CheckResult {
				r := types.PassResult(types.CheckTypeRuntimeTrace, "ok")
				r.Metadata = map[string]any{
					metaMonitorType:     testMonitorFalco,
					metaProcessCount:    int64(0),
					metaNetworkCount:    int64(0),
					metaFileAccessCount: int64(0),
					metaFileNames:       "",
				}

				return r
			}(),
			pass: true,
		},
		{
			name:    "runtimetrace.processCount check",
			require: "runtimetrace.processCount > 5",
			result: func() *types.CheckResult {
				r := types.PassResult(types.CheckTypeRuntimeTrace, "ok")
				r.Metadata = map[string]any{
					metaMonitorType:     "tetragon",
					metaProcessCount:    int64(10),
					metaNetworkCount:    int64(0),
					metaFileAccessCount: int64(0),
					metaFileNames:       "",
				}

				return r
			}(),
			pass: true,
		},
		{
			name:    "runtimetrace.fileNames contains",
			require: `runtimetrace.fileNames.contains("/usr/bin/gcc")`,
			result: func() *types.CheckResult {
				r := types.PassResult(types.CheckTypeRuntimeTrace, "ok")
				r.Metadata = map[string]any{
					metaMonitorType:     testMonitorFalco,
					metaProcessCount:    int64(0),
					metaNetworkCount:    int64(0),
					metaFileAccessCount: int64(1),
					metaFileNames:       "/usr/bin/gcc",
				}

				return r
			}(),
			pass: true,
		},
		{
			name: "runtimetrace defaults with nil result",
			require: `runtimetrace.verified == false && runtimetrace.monitorType == "" ` +
				`&& runtimetrace.processCount == 0 && runtimetrace.networkCount == 0 ` +
				`&& runtimetrace.fileAccessCount == 0 && runtimetrace.fileNames == ""`,
			result: nil,
			pass:   true,
		},
	}

	runCELVarTests(t, types.CheckTypeRuntimeTrace, tests)
}

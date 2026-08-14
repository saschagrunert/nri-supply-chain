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

// Package cel provides CEL expression compilation and evaluation for custom policy rules.
package cel

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"

	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	// MaxExpressionSize is the maximum allowed size of a single CEL expression in bytes.
	MaxExpressionSize = 4096

	// MaxRules is the maximum number of CEL rules allowed in a policy.
	MaxRules = 64

	// costLimit bounds the runtime cost of evaluating a single CEL expression.
	costLimit = 100_000

	// varVerified is the key used for the "verified" boolean in CEL variable maps.
	varVerified = "verified"
)

var (
	// ErrExpressionTooLarge indicates a CEL expression exceeds the size limit.
	ErrExpressionTooLarge = errors.New("CEL expression exceeds maximum size")

	// ErrTooManyRules indicates the CEL policy has too many rules.
	ErrTooManyRules = errors.New("CEL policy exceeds maximum number of rules")

	// ErrRequireEmpty indicates a CEL rule has an empty require expression.
	ErrRequireEmpty = errors.New("CEL rule require expression is empty")

	// ErrCompileFailed indicates a CEL expression failed to compile.
	ErrCompileFailed = errors.New("CEL expression compilation failed")

	// ErrNotBool indicates a CEL expression did not evaluate to a boolean.
	ErrNotBool = errors.New("CEL expression must evaluate to a boolean")

	// ErrCostLimitExceeded indicates a CEL expression exceeded the cost limit.
	ErrCostLimitExceeded = errors.New("CEL expression exceeded cost limit")

	envMu    sync.Mutex //nolint:gochecknoglobals // guards CEL singleton reset in tests
	envOnce  sync.Once  //nolint:gochecknoglobals // singleton CEL environment
	envVal   *cel.Env   //nolint:gochecknoglobals // singleton CEL environment
	errEnvCE error      //nolint:gochecknoglobals // singleton CEL environment init error
)

// Rule defines a single CEL policy rule with an optional match filter
// and a required condition expression.
type Rule struct {
	// Match is an optional CEL expression that determines whether this rule
	// applies to the current image. When empty, the rule always applies.
	Match string `json:"match,omitempty"`
	// Require is a CEL expression that must evaluate to true for the check to pass.
	Require string `json:"require"`
	// Message is an optional human-readable description shown on failure.
	Message string `json:"message,omitempty"`
}

// Policy groups CEL rules within a verification policy.
type Policy struct {
	// Rules is the list of CEL rules to evaluate.
	Rules []Rule `json:"rules"`
}

// CompiledRule holds the compiled programs for a single CEL rule.
type CompiledRule struct {
	MatchProgram   cel.Program
	RequireProgram cel.Program
	Message        string
}

// CompiledPolicy holds all compiled CEL rules ready for evaluation.
type CompiledPolicy struct {
	Rules []CompiledRule
}

func initEnvironment() (*cel.Env, error) {
	envMu.Lock()
	defer envMu.Unlock()

	envOnce.Do(func() {
		envVal, errEnvCE = cel.NewEnv(
			cel.Variable("image", cel.MapType(cel.StringType, cel.DynType)),
			cel.Variable("slsa", cel.MapType(cel.StringType, cel.DynType)),
			cel.Variable("vex", cel.MapType(cel.StringType, cel.DynType)),
			cel.Variable("vsa", cel.MapType(cel.StringType, cel.DynType)),
			cel.Variable("sbom", cel.MapType(cel.StringType, cel.DynType)),
			cel.Variable("notation", cel.MapType(cel.StringType, cel.DynType)),
			cel.Variable("scai", cel.MapType(cel.StringType, cel.DynType)),
			cel.Variable("source", cel.MapType(cel.StringType, cel.DynType)),
			cel.Variable("buildenv", cel.MapType(cel.StringType, cel.DynType)),
			cel.Variable("vulnscan", cel.MapType(cel.StringType, cel.DynType)),
			cel.Variable("testresult", cel.MapType(cel.StringType, cel.DynType)),
			cel.Variable("runtimetrace", cel.MapType(cel.StringType, cel.DynType)),
			ext.Strings(),
		)
	})

	if errEnvCE != nil {
		return nil, fmt.Errorf("initializing CEL environment: %w", errEnvCE)
	}

	return envVal, nil
}

func resetEnvironment() {
	envMu.Lock()
	defer envMu.Unlock()

	envOnce = sync.Once{}
	envVal = nil
	errEnvCE = nil
}

// Compile compiles all rules in a CEL policy. Returns an error if any
// expression fails to compile, exceeds size limits, or has the wrong type.
func Compile(rules []Rule) (*CompiledPolicy, error) {
	if len(rules) > MaxRules {
		return nil, fmt.Errorf(
			"%w: got %d, maximum %d", ErrTooManyRules, len(rules), MaxRules,
		)
	}

	env, err := initEnvironment()
	if err != nil {
		return nil, fmt.Errorf("creating CEL environment: %w", err)
	}

	compiled := &CompiledPolicy{
		Rules: make([]CompiledRule, 0, len(rules)),
	}

	var errs []error

	for idx := range rules {
		rule, compileErr := compileRule(env, &rules[idx], idx)
		if compileErr != nil {
			errs = append(errs, compileErr)

			continue
		}

		compiled.Rules = append(compiled.Rules, *rule)
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	return compiled, nil
}

func compileRule(env *cel.Env, rule *Rule, idx int) (*CompiledRule, error) {
	if rule.Require == "" {
		return nil, fmt.Errorf("rules[%d]: %w", idx, ErrRequireEmpty)
	}

	var errs []error

	if len(rule.Require) > MaxExpressionSize {
		errs = append(errs, fmt.Errorf(
			"rules[%d].require: %w (%d bytes, max %d)",
			idx, ErrExpressionTooLarge, len(rule.Require), MaxExpressionSize,
		))
	}

	if len(rule.Match) > MaxExpressionSize {
		errs = append(errs, fmt.Errorf(
			"rules[%d].match: %w (%d bytes, max %d)",
			idx, ErrExpressionTooLarge, len(rule.Match), MaxExpressionSize,
		))
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	compiled := &CompiledRule{Message: rule.Message}

	if rule.Match != "" {
		matchProg, err := compileExpression(env, rule.Match, fmt.Sprintf("rules[%d].match", idx))
		if err != nil {
			errs = append(errs, err)
		} else {
			compiled.MatchProgram = matchProg
		}
	}

	requireProg, err := compileExpression(
		env, rule.Require, fmt.Sprintf("rules[%d].require", idx),
	)
	if err != nil {
		errs = append(errs, err)
	} else {
		compiled.RequireProgram = requireProg
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	return compiled, nil
}

//nolint:ireturn // cel.Program is the API type returned by cel-go.
func compileExpression(env *cel.Env, expr, label string) (cel.Program, error) {
	ast, issues := env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("%s: %w: %w", label, ErrCompileFailed, issues.Err())
	}

	if ast.OutputType() != cel.BoolType {
		return nil, fmt.Errorf("%s: %w, got %s", label, ErrNotBool, ast.OutputType())
	}

	prog, err := env.Program(ast, cel.CostLimit(costLimit))
	if err != nil {
		return nil, fmt.Errorf("%s: creating program: %w", label, err)
	}

	return prog, nil
}

// Evaluate runs all compiled CEL rules against the provided variables.
// All rules must pass (all-must-pass semantics). A rule whose match
// expression evaluates to false is skipped. Returns a passing CheckResult
// if all applicable rules pass, or a failing one on the first failure.
func Evaluate(compiled *CompiledPolicy, vars map[string]any) *types.CheckResult {
	if compiled == nil || len(compiled.Rules) == 0 {
		return types.PassResult(types.CheckTypeCEL, "no CEL rules to evaluate")
	}

	for idx := range compiled.Rules {
		rule := &compiled.Rules[idx]

		if rule.MatchProgram != nil {
			matched, err := evalBool(rule.MatchProgram, vars)
			if err != nil {
				return types.FailResult(
					types.CheckTypeCEL,
					fmt.Sprintf("CEL match evaluation error in rule %d: %s", idx, err),
					err,
				)
			}

			if !matched {
				continue
			}
		}

		passed, err := evalBool(rule.RequireProgram, vars)
		if err != nil {
			return types.FailResult(
				types.CheckTypeCEL,
				fmt.Sprintf("CEL require evaluation error in rule %d: %s", idx, err),
				err,
			)
		}

		if !passed {
			detail := fmt.Sprintf("CEL rule %d failed", idx)
			if rule.Message != "" {
				detail = rule.Message
			}

			return types.FailResult(types.CheckTypeCEL, detail, nil)
		}
	}

	return types.PassResult(types.CheckTypeCEL, "all CEL rules passed")
}

func evalBool(prog cel.Program, vars map[string]any) (bool, error) {
	out, _, err := prog.Eval(vars)
	if err != nil {
		if isCostError(err) {
			return false, fmt.Errorf("%w: %w", ErrCostLimitExceeded, err)
		}

		return false, fmt.Errorf("evaluating expression: %w", err)
	}

	val, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("%w, got %T", ErrNotBool, out.Value())
	}

	return val, nil
}

func isCostError(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "actual cost limit exceeded") ||
		errors.Is(err, ErrCostLimitExceeded))
}

// BuildVars constructs the CEL variable map from check results and image context.
func BuildVars(
	imageRef, registry, repository, digest, namespace string,
	slsaResult, vexResult, vsaResult, sbomResult, notationResult, scaiResult *types.CheckResult,
	sourceResult, buildenvResult, vulnscanResult, testresultResult *types.CheckResult,
	runtimetraceResult *types.CheckResult,
) map[string]any {
	imageVars := map[string]any{
		"ref":        imageRef,
		"registry":   registry,
		"repository": repository,
		"digest":     digest,
		"namespace":  namespace,
	}

	return map[string]any{
		"image":        imageVars,
		"slsa":         buildSLSAVars(slsaResult),
		"vex":          buildVEXVars(vexResult),
		"vsa":          buildVSAVars(vsaResult),
		"sbom":         buildSBOMVars(sbomResult),
		"notation":     buildNotationVars(notationResult),
		"scai":         buildSCAIVars(scaiResult),
		"source":       buildSourceVars(sourceResult), //nolint:goconst // map key
		"buildenv":     buildBuildEnvVars(buildenvResult),
		"vulnscan":     buildVulnScanVars(vulnscanResult),
		"testresult":   buildTestResultVars(testresultResult),
		"runtimetrace": buildRuntimeTraceVars(runtimetraceResult),
	}
}

func buildSLSAVars(result *types.CheckResult) map[string]any {
	vars := map[string]any{
		"builderID": "",
		"buildType": "",
		"source":    "",
		varVerified: false,
	}

	if result != nil {
		vars[varVerified] = result.Passed
		extractStringMeta(result.Metadata, vars, "builderID", "buildType", "source")
	}

	return vars
}

func buildVEXVars(result *types.CheckResult) map[string]any {
	vars := map[string]any{
		"status":    "",
		varVerified: false,
	}

	if result != nil {
		vars[varVerified] = result.Passed
		extractStringMeta(result.Metadata, vars, "status")
	}

	return vars
}

func buildVSAVars(result *types.CheckResult) map[string]any {
	vars := map[string]any{
		"verifierID": "",
		"result":     "",
		"level":      int64(0),
		varVerified:  false,
	}

	if result != nil {
		vars[varVerified] = result.Passed
		extractStringMeta(result.Metadata, vars, "verifierID", "result")
		extractInt64Meta(result.Metadata, vars, "level")
	}

	return vars
}

func extractStringMeta(meta, vars map[string]any, keys ...string) {
	if meta == nil {
		return
	}

	for _, key := range keys {
		if v, ok := meta[key].(string); ok {
			vars[key] = v
		}
	}
}

func extractInt64Meta(meta, vars map[string]any, keys ...string) {
	if meta == nil {
		return
	}

	for _, key := range keys {
		if v, ok := meta[key].(int64); ok {
			vars[key] = v
		}
	}
}

func extractFloat64Meta(meta, vars map[string]any, keys ...string) {
	if meta == nil {
		return
	}

	for _, key := range keys {
		if v, ok := meta[key].(float64); ok {
			vars[key] = v
		}
	}
}

func buildSBOMVars(result *types.CheckResult) map[string]any {
	vars := map[string]any{
		varVerified:         false,
		"format":            "",
		"componentCount":    int64(0),
		"licenseCount":      int64(0),
		"cvssMax":           float64(0),
		"cvssCriticalCount": int64(0),
		"cvssHighCount":     int64(0),
		"cvssMediumCount":   int64(0),
	}

	if result != nil {
		vars[varVerified] = result.Passed
		extractStringMeta(result.Metadata, vars, "format")
		extractInt64Meta(result.Metadata, vars, "componentCount", "licenseCount",
			"cvssCriticalCount", "cvssHighCount", "cvssMediumCount")
		extractFloat64Meta(result.Metadata, vars, "cvssMax")
	}

	return vars
}

func buildNotationVars(result *types.CheckResult) map[string]any {
	vars := map[string]any{
		varVerified:   false,
		"signerDN":    "",
		"trustPolicy": "",
	}

	if result != nil {
		vars[varVerified] = result.Passed
		extractStringMeta(result.Metadata, vars, "signerDN", "trustPolicy")
	}

	return vars
}

func buildSCAIVars(result *types.CheckResult) map[string]any {
	vars := map[string]any{
		varVerified:      false,
		"attributes":     "",
		"attributeCount": int64(0),
		"hasEvidence":    false,
	}

	if result != nil {
		vars[varVerified] = result.Passed
		extractStringMeta(result.Metadata, vars, "attributes")
		extractInt64Meta(result.Metadata, vars, "attributeCount")
		extractBoolMeta(result.Metadata, vars, "hasEvidence")
	}

	return vars
}

func extractBoolMeta(meta, vars map[string]any, keys ...string) {
	if meta == nil {
		return
	}

	for _, key := range keys {
		if v, ok := meta[key].(bool); ok {
			vars[key] = v
		}
	}
}

func buildSourceVars(result *types.CheckResult) map[string]any {
	vars := map[string]any{
		varVerified: false,
		"source":    "",
		"branch":    "",
		"level":     int64(0),
	}

	if result != nil {
		vars[varVerified] = result.Passed
		extractStringMeta(result.Metadata, vars, "source", "branch")
		extractInt64Meta(result.Metadata, vars, "level")
	}

	return vars
}

func buildBuildEnvVars(result *types.CheckResult) map[string]any {
	vars := map[string]any{
		varVerified:     false,
		"properties":    "",
		"propertyCount": int64(0),
	}

	if result != nil {
		vars[varVerified] = result.Passed
		extractStringMeta(result.Metadata, vars, "properties")
		extractInt64Meta(result.Metadata, vars, "propertyCount")
	}

	return vars
}

func buildVulnScanVars(result *types.CheckResult) map[string]any {
	vars := map[string]any{
		varVerified:     false,
		"scanner":       "",
		"vulnCount":     int64(0),
		"maxScore":      float64(0),
		"maxSeverity":   "",
		"criticalCount": int64(0),
		"highCount":     int64(0),
	}

	if result != nil {
		vars[varVerified] = result.Passed
		extractStringMeta(result.Metadata, vars, "scanner", "maxSeverity")
		extractInt64Meta(result.Metadata, vars, "vulnCount", "criticalCount", "highCount")
		extractFloat64Meta(result.Metadata, vars, "maxScore")
	}

	return vars
}

func buildTestResultVars(result *types.CheckResult) map[string]any {
	vars := map[string]any{
		varVerified:  false,
		"result":     "",
		"suiteCount": int64(0),
		"suites":     "",
		"passed":     int64(0),
		"failed":     int64(0),
	}

	if result != nil {
		vars[varVerified] = result.Passed
		extractStringMeta(result.Metadata, vars, "result", "suites")
		extractInt64Meta(result.Metadata, vars, "suiteCount", "passed", "failed")
	}

	return vars
}

func buildRuntimeTraceVars(result *types.CheckResult) map[string]any {
	vars := map[string]any{
		varVerified:       false,
		"monitorType":     "",
		"processCount":    int64(0),
		"networkCount":    int64(0),
		"fileAccessCount": int64(0),
		"fileNames":       "",
	}

	if result != nil {
		vars[varVerified] = result.Passed
		extractStringMeta(result.Metadata, vars, "monitorType", "fileNames")
		extractInt64Meta(result.Metadata, vars, "processCount", "networkCount", "fileAccessCount")
	}

	return vars
}

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

	envOnce  sync.Once //nolint:gochecknoglobals // singleton CEL environment
	envVal   *cel.Env  //nolint:gochecknoglobals // singleton CEL environment
	errEnvCE error     //nolint:gochecknoglobals // singleton CEL environment init error
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
	envOnce.Do(func() {
		envVal, errEnvCE = cel.NewEnv(
			cel.Variable("image", cel.MapType(cel.StringType, cel.DynType)),
			cel.Variable("slsa", cel.MapType(cel.StringType, cel.DynType)),
			cel.Variable("vex", cel.MapType(cel.StringType, cel.DynType)),
			cel.Variable("vsa", cel.MapType(cel.StringType, cel.DynType)),
			cel.Variable("sbom", cel.MapType(cel.StringType, cel.DynType)),
			ext.Strings(),
		)
	})

	if errEnvCE != nil {
		return nil, fmt.Errorf("initializing CEL environment: %w", errEnvCE)
	}

	return envVal, nil
}

func resetEnvironment() {
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
	slsaResult, vexResult, sbomResult *types.CheckResult,
) map[string]any {
	imageVars := map[string]any{
		"ref":        imageRef,
		"registry":   registry,
		"repository": repository,
		"digest":     digest,
		"namespace":  namespace,
	}

	slsaVars := buildSLSAVars(slsaResult)
	vexVars := buildVEXVars(vexResult)
	vsaVars := buildDefaultVSAVars()
	sbomVars := buildSBOMVars(sbomResult)

	return map[string]any{
		"image": imageVars,
		"slsa":  slsaVars,
		"vex":   vexVars,
		"vsa":   vsaVars,
		"sbom":  sbomVars,
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
	}

	return vars
}

func buildDefaultVSAVars() map[string]any {
	return map[string]any{
		"verifierID": "",
		"result":     "",
		"level":      int64(0),
		varVerified:  false,
	}
}

func buildSBOMVars(result *types.CheckResult) map[string]any {
	vars := map[string]any{
		varVerified: false,
	}

	if result != nil {
		vars[varVerified] = result.Passed
	}

	return vars
}

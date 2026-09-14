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
	"slices"
	"strings"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/ext"

	"github.com/saschagrunert/nri-supply-chain/internal/guac"
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

	// varPresent is the key used for the "present" boolean in attestation
	// variable maps. It is false when no attestation of the type was found.
	varPresent = "present"

	varImage = "image"
	varGUAC  = "guac"

	indexFunction         = "_[_]"
	optionalIndexFunction = "_[?_]"
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

	// ErrUnknownField indicates a CEL expression selects a field that is not
	// provided by the variable (usually a typo).
	ErrUnknownField = errors.New("CEL expression references unknown field")

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
		opts := make([]cel.EnvOption, 0, len(variableSchemas())+1)

		for name := range variableSchemas() {
			opts = append(opts, cel.Variable(name, cel.MapType(cel.StringType, cel.DynType)))
		}

		opts = append(opts, ext.Strings())

		envVal, errEnvCE = cel.NewEnv(opts...)
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
	checked, issues := env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("%s: %w: %w", label, ErrCompileFailed, issues.Err())
	}

	if checked.OutputType() != cel.BoolType {
		return nil, fmt.Errorf("%s: %w, got %s", label, ErrNotBool, checked.OutputType())
	}

	fieldErr := checkFieldSelections(checked.NativeRep().Expr(), nil)
	if fieldErr != nil {
		return nil, fmt.Errorf("%s: %w", label, fieldErr)
	}

	prog, err := env.Program(checked, cel.CostLimit(costLimit))
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

		if absent := absentVariablesWithKey(err, vars); len(absent) > 0 {
			return false, fmt.Errorf(
				"evaluating expression (attestation data is not available when "+
					"the attestation is missing; guard with %s): %w",
				strings.Join(absent, " or "), err,
			)
		}

		if guard := unavailableGUACGuard(err, vars); guard != "" {
			return false, fmt.Errorf(
				"evaluating expression (GUAC data is not available when its query "+
					"did not succeed; guard with %s): %w",
				guard, err,
			)
		}

		return false, fmt.Errorf("evaluating expression: %w", err)
	}

	val, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("%w, got %T", ErrNotBool, out.Value())
	}

	return val, nil
}

// absentVariablesWithKey returns "<type>.present" for each missing
// attestation variable whose data fields include the key of a "no such key"
// evaluation error. Other lookup failures, such as a dynamic map index on a
// present attestation, return nothing so the hint is not misleading.
func absentVariablesWithKey(err error, vars map[string]any) []string {
	_, key, found := strings.Cut(err.Error(), "no such key: ")
	if !found {
		return nil
	}

	key = strings.TrimSpace(key)

	var absent []string

	for idx := range attestationVariables {
		name := attestationVariables[idx].name

		values, isMap := vars[name].(map[string]any)
		if !isMap || values[varPresent] == true {
			continue
		}

		schema, _ := variableSchemas()[name].(map[string]any)
		if _, known := schema[key]; known {
			absent = append(absent, name+"."+varPresent)
		}
	}

	return absent
}

// unavailableGUACGuard returns "guac.<query>_available" when a "no such key"
// evaluation error names GUAC data that is absent because its query did not
// succeed, or "" otherwise.
func unavailableGUACGuard(err error, vars map[string]any) string {
	_, key, found := strings.Cut(err.Error(), "no such key: ")
	if !found {
		return ""
	}

	key = strings.TrimSpace(key)

	guacVars, isMap := vars[varGUAC].(map[string]any)
	if !isMap {
		return ""
	}

	if _, present := guacVars[key]; present {
		return ""
	}

	flag, isData := guac.AvailabilityKey(key)
	if !isData {
		return ""
	}

	return varGUAC + "." + flag
}

func isCostError(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "actual cost limit exceeded") ||
		errors.Is(err, ErrCostLimitExceeded))
}

// attestationVariable binds a CEL variable name to its check type and the
// function that renders a check result into the variable map. Calling build
// with a nil result yields every data field with its default value, which
// also defines the field names expressions are allowed to select.
type attestationVariable struct {
	name      string
	checkType types.CheckType
	build     func(*types.CheckResult) map[string]any
}

//nolint:gochecknoglobals // immutable registry of attestation CEL variables
var attestationVariables = []attestationVariable{
	{"slsa", types.CheckTypeSLSA, buildSLSAVars},
	{"vex", types.CheckTypeVEX, buildVEXVars},
	{"vsa", types.CheckTypeVSA, buildVSAVars},
	{"sbom", types.CheckTypeSBOM, buildSBOMVars},
	{"notation", types.CheckTypeNotation, buildNotationVars},
	{"scai", types.CheckTypeSCAI, buildSCAIVars},
	{"source", types.CheckTypeSource, buildSourceVars}, //nolint:goconst // CEL variable name
	{"buildenv", types.CheckTypeBuildEnv, buildBuildEnvVars},
	{"vulnscan", types.CheckTypeVulnScan, buildVulnScanVars},
	{"testresult", types.CheckTypeTestResult, buildTestResultVars},
	{"release", types.CheckTypeRelease, buildReleaseVars},
	{"runtimetrace", types.CheckTypeRuntimeTrace, buildRuntimeTraceVars},
	{"scorecard", types.CheckTypeScorecard, buildScorecardVars},
}

var (
	schemasOnce sync.Once      //nolint:gochecknoglobals // lazily built immutable schema
	schemas     map[string]any //nolint:gochecknoglobals // lazily built immutable schema
)

// variableSchemas returns the default value map for every CEL variable. The
// keys of each map are the fields expressions may select on that variable.
func variableSchemas() map[string]any {
	schemasOnce.Do(func() {
		schemas = map[string]any{
			varImage: buildImageVars("", "", "", "", ""),
			varGUAC:  guac.MetadataSchema(),
		}

		for idx := range attestationVariables {
			vars := attestationVariables[idx].build(nil)
			vars[varPresent] = false

			schemas[attestationVariables[idx].name] = vars
		}
	})

	return schemas
}

// BuildVars constructs the CEL variable map from check results and image context.
//
// Attestation variables always provide "verified" and "present". When the
// attestation is missing (no result, or a result flagged as Missing), both are
// false and no data fields are provided, so an expression that reads data
// (e.g. sbom.cvssCriticalCount == 0) fails evaluation instead of seeing clean
// defaults. Guard such expressions with "<type>.present".
func BuildVars(
	imageRef, registry, repository, digest, namespace string,
	results map[types.CheckType]*types.CheckResult,
) map[string]any {
	vars := map[string]any{
		varImage: buildImageVars(imageRef, registry, repository, digest, namespace),
		varGUAC:  buildGUACVars(results[types.CheckTypeGUAC]),
	}

	for idx := range attestationVariables {
		variable := &attestationVariables[idx]
		vars[variable.name] = buildAttestationVars(results[variable.checkType], variable.build)
	}

	return vars
}

func buildImageVars(imageRef, registry, repository, digest, namespace string) map[string]any {
	return map[string]any{
		"ref":        imageRef,
		"registry":   registry,
		"repository": repository,
		"digest":     digest,
		"namespace":  namespace,
	}
}

func buildAttestationVars(
	result *types.CheckResult, build func(*types.CheckResult) map[string]any,
) map[string]any {
	if result == nil || result.Missing {
		return map[string]any{
			varVerified: false,
			varPresent:  false,
		}
	}

	vars := build(result)
	vars[varPresent] = true

	return vars
}

// checkFieldSelections walks a checked CEL expression and verifies that every
// field selected on a known variable (either "var.field" or var["field"])
// exists in that variable's schema, including nested maps with a fixed set of
// keys. Identifiers bound by comprehensions shadow variables and are skipped.
func checkFieldSelections(expr ast.Expr, shadowed []string) error {
	switch expr.Kind() {
	case ast.SelectKind, ast.CallKind:
		if root, fields, ok := selectionPath(expr); ok {
			if slices.Contains(shadowed, root) {
				return nil
			}

			return validateSelection(root, fields)
		}

		return checkChildren(expr, shadowed)
	case ast.ComprehensionKind:
		comp := expr.AsComprehension()

		inner := append(slices.Clone(shadowed), comp.IterVar(), comp.AccuVar())
		if comp.HasIterVar2() {
			inner = append(inner, comp.IterVar2())
		}

		return errors.Join(
			checkFieldSelections(comp.IterRange(), shadowed),
			checkFieldSelections(comp.AccuInit(), shadowed),
			checkFieldSelections(comp.LoopCondition(), inner),
			checkFieldSelections(comp.LoopStep(), inner),
			checkFieldSelections(comp.Result(), inner),
		)
	case ast.ListKind, ast.MapKind, ast.StructKind:
		return checkChildren(expr, shadowed)
	case ast.UnspecifiedExprKind, ast.IdentKind, ast.LiteralKind:
		return nil
	default:
		return nil
	}
}

func checkChildren(expr ast.Expr, shadowed []string) error {
	children := childExpressions(expr)
	errs := make([]error, 0, len(children))

	for _, child := range children {
		errs = append(errs, checkFieldSelections(child, shadowed))
	}

	return errors.Join(errs...)
}

// childExpressions returns the direct sub-expressions of non-comprehension
// nodes that are evaluated in the same scope as the node itself.
func childExpressions(expr ast.Expr) []ast.Expr {
	switch expr.Kind() {
	case ast.SelectKind:
		return []ast.Expr{expr.AsSelect().Operand()}
	case ast.CallKind:
		call := expr.AsCall()
		if call.IsMemberFunction() {
			return append([]ast.Expr{call.Target()}, call.Args()...)
		}

		return call.Args()
	case ast.ListKind:
		return expr.AsList().Elements()
	case ast.MapKind, ast.StructKind:
		return entryExpressions(expr)
	case ast.UnspecifiedExprKind, ast.ComprehensionKind, ast.IdentKind, ast.LiteralKind:
		return nil
	default:
		return nil
	}
}

func entryExpressions(expr ast.Expr) []ast.Expr {
	var children []ast.Expr

	if expr.Kind() == ast.MapKind {
		for _, entry := range expr.AsMap().Entries() {
			children = append(children, entry.AsMapEntry().Key(), entry.AsMapEntry().Value())
		}

		return children
	}

	for _, field := range expr.AsStruct().Fields() {
		children = append(children, field.AsStructField().Value())
	}

	return children
}

// selectionPath resolves a chain of field selections and constant string
// index operations rooted at an identifier, e.g. sbom.drift["score"] yields
// ("sbom", ["drift", "score"]). It returns ok=false for any other shape.
func selectionPath(expr ast.Expr) (root string, fields []string, ok bool) {
	current := expr

	for {
		switch current.Kind() {
		case ast.SelectKind:
			sel := current.AsSelect()
			fields = append(fields, sel.FieldName())
			current = sel.Operand()
		case ast.CallKind:
			key, operand, isIndex := constantIndex(current)
			if !isIndex {
				return "", nil, false
			}

			fields = append(fields, key)
			current = operand
		case ast.IdentKind:
			if len(fields) == 0 {
				return "", nil, false
			}

			slices.Reverse(fields)

			return current.AsIdent(), fields, true
		case ast.UnspecifiedExprKind, ast.ComprehensionKind, ast.ListKind,
			ast.LiteralKind, ast.MapKind, ast.StructKind:
			return "", nil, false
		default:
			return "", nil, false
		}
	}
}

//nolint:ireturn // ast.Expr is the cel-go AST node interface.
func constantIndex(expr ast.Expr) (key string, operand ast.Expr, ok bool) {
	call := expr.AsCall()

	name := call.FunctionName()
	if name != indexFunction && name != optionalIndexFunction {
		return "", nil, false
	}

	args := call.Args()
	if len(args) != 2 || args[1].Kind() != ast.LiteralKind {
		return "", nil, false
	}

	key, isString := args[1].AsLiteral().Value().(string)
	if !isString {
		return "", nil, false
	}

	return key, args[0], true
}

func validateSelection(root string, fields []string) error {
	schema, known := variableSchemas()[root].(map[string]any)
	if !known {
		return nil
	}

	current := schema
	path := root

	for _, field := range fields {
		value, exists := current[field]
		if !exists {
			available := make([]string, 0, len(current))
			for key := range current {
				available = append(available, key)
			}

			slices.Sort(available)

			return fmt.Errorf(
				"%w: %q has no field %q (available: %s)",
				ErrUnknownField, path, field, strings.Join(available, ", "),
			)
		}

		nested, isMap := value.(map[string]any)
		if !isMap || len(nested) == 0 {
			// Scalars, lists, and maps with dynamic keys end the check.
			return nil
		}

		current = nested
		path += "." + field
	}

	return nil
}

func buildSLSAVars(result *types.CheckResult) map[string]any {
	vars := map[string]any{
		"builderID":       "",
		"buildType":       "",
		"source":          "",
		"sourceRef":       "",
		"sourceDigest":    "",
		"trustConfigured": false,
		varVerified:       false,
	}

	if result != nil {
		vars[varVerified] = result.Passed
		extractStringMeta(result.Metadata, vars,
			"builderID", "buildType", "source", "sourceRef", "sourceDigest")
		extractBoolMeta(result.Metadata, vars, "trustConfigured")
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
		"drift":             defaultDriftVars(),
	}

	if result != nil {
		vars[varVerified] = result.Passed
		extractStringMeta(result.Metadata, vars, "format")
		extractInt64Meta(result.Metadata, vars, "componentCount", "licenseCount",
			"cvssCriticalCount", "cvssHighCount", "cvssMediumCount")
		extractFloat64Meta(result.Metadata, vars, "cvssMax")
		extractDriftMeta(result.Metadata, vars)
	}

	return vars
}

func defaultDriftVars() map[string]any {
	return map[string]any{
		"detected":      false,
		"addedCount":    int64(0),
		"removedCount":  int64(0),
		"modifiedCount": int64(0),
		"addedPackages": []string{},
		"score":         float64(0),
	}
}

func extractDriftMeta(meta, vars map[string]any) {
	if meta == nil {
		return
	}

	driftRaw, hasDrift := meta["drift"]
	if !hasDrift {
		return
	}

	driftMap, isMap := driftRaw.(map[string]any)
	if !isMap {
		return
	}

	result := defaultDriftVars()

	if v, ok := driftMap["detected"].(bool); ok {
		result["detected"] = v
	}

	for _, key := range []string{"addedCount", "removedCount", "modifiedCount"} {
		if v, ok := driftMap[key].(int64); ok {
			result[key] = v
		}
	}

	if v, ok := driftMap["score"].(float64); ok {
		result["score"] = v
	}

	if v, ok := driftMap["addedPackages"].([]string); ok {
		result["addedPackages"] = v
	}

	vars["drift"] = result
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
		varVerified:      false,
		"properties":     "",
		"propertyCount":  int64(0),
		"propertyValues": map[string]string{},
		"conflicts":      []string{},
	}

	if result != nil {
		vars[varVerified] = result.Passed
		extractStringMeta(result.Metadata, vars, "properties")
		extractInt64Meta(result.Metadata, vars, "propertyCount")

		if pv, ok := result.Metadata["propertyValues"].(map[string]string); ok {
			vars["propertyValues"] = pv
		}

		if conflicting, ok := result.Metadata["conflicts"].([]string); ok {
			vars["conflicts"] = conflicting
		}
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
		"unknownCount":  int64(0),
	}

	if result != nil {
		vars[varVerified] = result.Passed
		extractStringMeta(result.Metadata, vars, "scanner", "maxSeverity")
		extractInt64Meta(result.Metadata, vars,
			"vulnCount", "criticalCount", "highCount", "unknownCount")
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

func buildReleaseVars(result *types.CheckResult) map[string]any {
	vars := map[string]any{
		varVerified: false,
		"purl":      "",
		"packageId": "",
	}

	if result != nil {
		vars[varVerified] = result.Passed
		extractStringMeta(result.Metadata, vars, "purl", "packageId")
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

// buildGUACVars exposes GUAC data to CEL. The availability flags are always
// present. Data from a query that succeeded is exposed; when GUAC is not
// configured, a query is not enabled, or a query failed, its data fields are
// absent so any expression reading them fails evaluation (fail closed), just
// like attestation variables without data. Guard rules with the *_available
// flags or has().
func buildGUACVars(result *types.CheckResult) map[string]any {
	vars := guac.UnavailableMetadata()

	if result == nil || result.Metadata == nil {
		return vars
	}

	extractBoolMeta(result.Metadata, vars, guac.MetaKeyAvailable)

	if available, _ := result.Metadata[guac.MetaKeyVulnerabilitiesAvailable].(bool); available {
		vars[guac.MetaKeyVulnerabilitiesAvailable] = true

		copyGUACData[[]any](result.Metadata, vars,
			guac.MetaKeyVulnerabilities, guac.MetaKeyTransitiveVulns)
	}

	if available, _ := result.Metadata[guac.MetaKeyScorecardAvailable].(bool); available {
		vars[guac.MetaKeyScorecardAvailable] = true

		copyGUACData[map[string]any](result.Metadata, vars, guac.MetaKeyScorecard)
	}

	if available, _ := result.Metadata[guac.MetaKeyDependenciesAvailable].(bool); available {
		vars[guac.MetaKeyDependenciesAvailable] = true

		copyGUACData[[]any](result.Metadata, vars, guac.MetaKeyDependencies)
		copyGUACData[int64](result.Metadata, vars, guac.MetaKeyDependencyCount)
	}

	return vars
}

// copyGUACData copies metadata values of type T into vars.
func copyGUACData[T any](meta, vars map[string]any, keys ...string) {
	for _, key := range keys {
		if value, ok := meta[key].(T); ok {
			vars[key] = value
		}
	}
}

func buildScorecardVars(result *types.CheckResult) map[string]any {
	vars := map[string]any{
		varVerified: false,
		"repo":      "",
		"version":   "",
		"score":     float64(0),
		"checks":    map[string]int64{},
	}

	if result != nil {
		vars[varVerified] = result.Passed
		extractStringMeta(result.Metadata, vars, "repo", "version")
		extractFloat64Meta(result.Metadata, vars, "score")

		if checks, ok := result.Metadata["checks"].(map[string]int64); ok {
			vars["checks"] = checks
		}
	}

	return vars
}

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

package cel

import (
	"maps"
	"reflect"
	"sync"

	"github.com/saschagrunert/nri-supply-chain/internal/guac"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

// attestationVariable binds a CEL variable name to its check type and the
// metadata fields of its check results. Each field maps to its default
// value; a metadata value of the same type replaces the default, and a nested
// map declares the fields of a nested object. The fields also define the
// names expressions are allowed to select.
type attestationVariable struct {
	name      string
	checkType types.CheckType
	fields    map[string]any
	// extend, when set, derives further values from the check result after
	// the fields are copied.
	extend func(result *types.CheckResult, vars map[string]any)
}

// fieldSource is the source repository field of the slsa and source
// variables, and the name of the source variable.
const fieldSource = "source"

//nolint:gochecknoglobals // immutable registry of attestation CEL variables
var attestationVariables = []attestationVariable{
	{
		name: "slsa", checkType: types.CheckTypeSLSA, extend: nil,
		fields: map[string]any{
			"builderID":       "",
			"buildType":       "",
			fieldSource:       "",
			"sourceRef":       "",
			"sourceDigest":    "",
			"trustConfigured": false,
		},
	},
	{
		name: "vex", checkType: types.CheckTypeVEX, extend: nil,
		fields: map[string]any{"status": ""},
	},
	{
		name: "vsa", checkType: types.CheckTypeVSA, extend: nil,
		fields: map[string]any{
			"verifierID": "",
			"result":     "",
			"level":      int64(0),
		},
	},
	{
		name: "sbom", checkType: types.CheckTypeSBOM, extend: nil,
		fields: map[string]any{
			"format":            "",
			"componentCount":    int64(0),
			"licenseCount":      int64(0),
			"cvssMax":           float64(0),
			"cvssCriticalCount": int64(0),
			"cvssHighCount":     int64(0),
			"cvssMediumCount":   int64(0),
			"drift": map[string]any{
				"detected":      false,
				"addedCount":    int64(0),
				"removedCount":  int64(0),
				"modifiedCount": int64(0),
				"addedPackages": []string{},
				"score":         float64(0),
			},
		},
	},
	{
		name: "notation", checkType: types.CheckTypeNotation, extend: nil,
		fields: map[string]any{
			"signerDN":    "",
			"trustPolicy": "",
		},
	},
	{
		name: "scai", checkType: types.CheckTypeSCAI, extend: nil,
		fields: map[string]any{
			"attributes":     "",
			"attributeCount": int64(0),
			"hasEvidence":    false,
		},
	},
	{
		name: fieldSource, checkType: types.CheckTypeSource, extend: extendSourceVars,
		fields: map[string]any{
			fieldSource: "",
			"branch":    "",
			"locations": []map[string]string{},
			"level":     int64(0),
		},
	},
	{
		name: "buildenv", checkType: types.CheckTypeBuildEnv, extend: nil,
		fields: map[string]any{
			"properties":     "",
			"propertyCount":  int64(0),
			"propertyValues": map[string]string{},
			"conflicts":      []string{},
		},
	},
	{
		name: "vulnscan", checkType: types.CheckTypeVulnScan, extend: nil,
		fields: map[string]any{
			"scanner":       "",
			"vulnCount":     int64(0),
			"maxScore":      float64(0),
			"maxSeverity":   "",
			"criticalCount": int64(0),
			"highCount":     int64(0),
			"unknownCount":  int64(0),
		},
	},
	{
		name: "testresult", checkType: types.CheckTypeTestResult, extend: nil,
		fields: map[string]any{
			"result":     "",
			"suiteCount": int64(0),
			"suites":     "",
			"passed":     int64(0),
			"failed":     int64(0),
			"warned":     int64(0),
		},
	},
	{
		name: "release", checkType: types.CheckTypeRelease, extend: nil,
		fields: map[string]any{
			"purl":      "",
			"packageId": "",
		},
	},
	{
		name: "runtimetrace", checkType: types.CheckTypeRuntimeTrace, extend: nil,
		fields: map[string]any{
			"monitorType":     "",
			"processCount":    int64(0),
			"networkCount":    int64(0),
			"fileAccessCount": int64(0),
			"fileNames":       "",
		},
	},
	{
		name: "scorecard", checkType: types.CheckTypeScorecard, extend: nil,
		fields: map[string]any{
			"repo":    "",
			"version": "",
			"score":   float64(0),
			"checks":  map[string]int64{},
		},
	},
}

// AttestationVariables maps each attestation check type to the name of its
// CEL variable.
func AttestationVariables() map[types.CheckType]string {
	variables := make(map[types.CheckType]string, len(attestationVariables))
	for idx := range attestationVariables {
		variables[attestationVariables[idx].checkType] = attestationVariables[idx].name
	}

	return variables
}

// MetadataFields returns the metadata fields of a check type exposed to CEL,
// mapped to their default values, or nil for a check type without a CEL
// variable. Check result metadata must use these keys and value types for
// the values to reach CEL expressions.
func MetadataFields(checkType types.CheckType) map[string]any {
	for idx := range attestationVariables {
		if attestationVariables[idx].checkType == checkType {
			return cloneFields(attestationVariables[idx].fields)
		}
	}

	return nil
}

// build renders a check result into the variable map. A nil result yields
// every field with its default value.
func (v *attestationVariable) build(result *types.CheckResult) map[string]any {
	vars := cloneFields(v.fields)
	vars[varVerified] = false

	if result == nil {
		return vars
	}

	vars[varVerified] = result.Passed
	copyFields(result.Metadata, vars, v.fields)

	if v.extend != nil {
		v.extend(result, vars)
	}

	return vars
}

// cloneFields copies the default values, including nested field maps, so a
// variable map never aliases the registry.
func cloneFields(fields map[string]any) map[string]any {
	cloned := maps.Clone(fields)

	for key, value := range cloned {
		if nested, isMap := value.(map[string]any); isMap {
			cloned[key] = cloneFields(nested)
		}
	}

	return cloned
}

// copyFields copies the metadata values whose type matches the default of
// their field into vars.
func copyFields(meta, vars, fields map[string]any) {
	for key, def := range fields {
		value, found := meta[key]
		if !found {
			continue
		}

		if nested, isMap := def.(map[string]any); isMap {
			src, srcIsMap := value.(map[string]any)
			if !srcIsMap {
				continue
			}

			nestedVars := cloneFields(nested)
			copyFields(src, nestedVars, nested)
			vars[key] = nestedVars

			continue
		}

		if reflect.TypeOf(value) == reflect.TypeOf(def) {
			vars[key] = value
		}
	}
}

// extendSourceVars exposes at least the first location when the result has
// no location list, so a rule over all locations does not pass vacuously
// when the result names a source. A result without metadata (an attestation
// that did not verify) leaves the list empty, so locations.all(...) is true;
// policies combine it with source.verified or size(source.locations) > 0.
func extendSourceVars(result *types.CheckResult, vars map[string]any) {
	if _, ok := result.Metadata["locations"].([]map[string]string); ok {
		return
	}

	if source, _ := vars[fieldSource].(string); source != "" {
		branch, _ := vars["branch"].(string)
		vars["locations"] = []map[string]string{{"uri": source, "branch": branch}}
	}
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
		vars[variable.name] = buildAttestationVars(results[variable.checkType], variable)
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

func buildAttestationVars(result *types.CheckResult, variable *attestationVariable) map[string]any {
	if result == nil || result.Missing {
		return map[string]any{
			varVerified: false,
			varPresent:  false,
		}
	}

	vars := variable.build(result)
	vars[varPresent] = true

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

	copyMeta[bool](result.Metadata, vars, guac.MetaKeyAvailable)

	if available, _ := result.Metadata[guac.MetaKeyVulnerabilitiesAvailable].(bool); available {
		vars[guac.MetaKeyVulnerabilitiesAvailable] = true

		copyMeta[[]any](result.Metadata, vars,
			guac.MetaKeyVulnerabilities, guac.MetaKeyTransitiveVulns)
	}

	if available, _ := result.Metadata[guac.MetaKeyScorecardAvailable].(bool); available {
		vars[guac.MetaKeyScorecardAvailable] = true

		copyMeta[map[string]any](result.Metadata, vars, guac.MetaKeyScorecard)
	}

	if available, _ := result.Metadata[guac.MetaKeyDependenciesAvailable].(bool); available {
		vars[guac.MetaKeyDependenciesAvailable] = true

		copyMeta[[]any](result.Metadata, vars, guac.MetaKeyDependencies)
		copyMeta[int64](result.Metadata, vars, guac.MetaKeyDependencyCount)
	}

	return vars
}

// copyMeta copies metadata values of type T into vars.
func copyMeta[T any](meta, vars map[string]any, keys ...string) {
	for _, key := range keys {
		if value, ok := meta[key].(T); ok {
			vars[key] = value
		}
	}
}

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

package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	sectionCEL          = "cel"
	fieldMissingPolicy  = "MissingPolicy"
	fieldMaxAge         = "MaxAge"
	fieldMaxAgeDuration = "MaxAgeDuration"
	jsonMaxAge          = "maxAge"
)

// sectionSpec describes one policy section, i.e. one pointer field of
// Sections. The registry drives the generic parts of validation (the
// missingPolicy action and a positive maxAge duration), missing policy
// lookups, and derived value resolution. Cloning and merging are reflection
// based and need no per-section code.
type sectionSpec struct {
	// name is the JSON field name of the section.
	name string
	// checkType is the attestation type whose missing attestation behavior
	// is controlled by the section's missingPolicy, or empty.
	checkType types.CheckType
	// errMaxAgeNotPositive is returned for a non-positive maxAge. It is nil
	// for sections without a maxAge field.
	errMaxAgeNotPositive error
	// validate runs section specific checks. It is only called when the
	// section is set.
	validate func(s *Sections) error
}

//nolint:gochecknoglobals // immutable registry of policy sections
var sectionRegistry = []sectionSpec{
	{name: "trust", validate: (*Sections).validateTrust},
	{
		name: "slsa", checkType: types.CheckTypeSLSA,
		errMaxAgeNotPositive: ErrSLSAMaxAgeNotPositive, validate: (*Sections).validateSLSA,
	},
	{name: "vex", checkType: types.CheckTypeVEX, validate: (*Sections).validateVEX},
	{
		name: "vsa", checkType: types.CheckTypeVSA,
		errMaxAgeNotPositive: ErrVSAMaxAgeNotPositive, validate: (*Sections).validateVSA,
	},
	{name: "signatures"},
	{name: "notation", checkType: types.CheckTypeNotation, validate: (*Sections).validateNotation},
	{name: sectionCEL},
	{name: "sbom", checkType: types.CheckTypeSBOM, validate: (*Sections).validateSBOM},
	{name: "scai", checkType: types.CheckTypeSCAI, validate: (*Sections).validateSCAI},
	{
		name: "source", checkType: types.CheckTypeSource,
		errMaxAgeNotPositive: ErrSourceMaxAgeNotPositive, validate: (*Sections).validateSource,
	},
	{name: "buildEnv", checkType: types.CheckTypeBuildEnv, validate: (*Sections).validateBuildEnv},
	{
		name: "vulnScan", checkType: types.CheckTypeVulnScan,
		errMaxAgeNotPositive: ErrVulnScanMaxAgeNotPositive, validate: (*Sections).validateVulnScan,
	},
	{
		name:                 "testResult",
		checkType:            types.CheckTypeTestResult,
		errMaxAgeNotPositive: ErrTestResultMaxAgeNotPositive,
		validate:             (*Sections).validateTestResult,
	},
	{name: "release", checkType: types.CheckTypeRelease, validate: (*Sections).validateRelease},
	{
		name: "runtimeTrace", checkType: types.CheckTypeRuntimeTrace,
		errMaxAgeNotPositive: ErrRuntimeTraceMaxAgeNotPositive,
		validate:             (*Sections).validateRuntimeTrace,
	},
	{
		name:      "scorecard",
		checkType: types.CheckTypeScorecard,
		validate:  (*Sections).validateScorecard,
	},
}

var (
	sectionIndexOnce sync.Once      //nolint:gochecknoglobals // lazily built immutable index
	sectionIndex     map[string]int //nolint:gochecknoglobals // JSON name to Sections field index
)

// sectionFieldIndex maps section JSON names to their Sections field index.
func sectionFieldIndex() map[string]int {
	sectionIndexOnce.Do(func() {
		sectionType := reflect.TypeFor[Sections]()
		sectionIndex = make(map[string]int, sectionType.NumField())

		for idx := range sectionType.NumField() {
			field := sectionType.Field(idx)
			if field.IsExported() {
				sectionIndex[jsonFieldName(&field)] = idx
			}
		}
	})

	return sectionIndex
}

// section returns the section pointer value for the given JSON name.
func (s *Sections) section(name string) reflect.Value {
	return reflect.ValueOf(s).Elem().Field(sectionFieldIndex()[name])
}

func jsonFieldName(field *reflect.StructField) string {
	name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
	if name == "" {
		return field.Name
	}

	return name
}

// sectionForCheckType returns the registry entry for an attestation type.
func sectionForCheckType(checkType types.CheckType) *sectionSpec {
	for idx := range sectionRegistry {
		if sectionRegistry[idx].checkType == checkType {
			return &sectionRegistry[idx]
		}
	}

	return nil
}

// missingPolicy returns the configured missingPolicy of the section or an
// empty action when the section or the field is not set.
func (s *Sections) missingPolicy(spec *sectionSpec) types.Action {
	section := s.section(spec.name)
	if section.IsNil() {
		return ""
	}

	field := section.Elem().FieldByName(fieldMissingPolicy)
	if !field.IsValid() {
		return ""
	}

	return types.Action(field.String())
}

// validateSections validates every set section using the registry and
// resolves derived values such as parsed maxAge durations.
func (s *Sections) validateSections() []error {
	var errs []error

	for idx := range sectionRegistry {
		spec := &sectionRegistry[idx]

		section := s.section(spec.name)
		if section.IsNil() {
			continue
		}

		if action := s.missingPolicy(spec); action != "" {
			err := types.ValidateAction(spec.name+".missingPolicy", action)
			if err != nil {
				errs = append(errs, fmt.Errorf("validating %s policy: %w", spec.name, err))
			}
		}

		if spec.errMaxAgeNotPositive != nil {
			err := resolveMaxAge(section.Elem(), spec)
			if err != nil {
				errs = append(errs, err)
			}
		}

		if spec.validate != nil {
			err := spec.validate(s)
			if err != nil {
				errs = append(errs, err)
			}
		}
	}

	return errs
}

// resolveMaxAge parses the section's maxAge into MaxAgeDuration.
func resolveMaxAge(section reflect.Value, spec *sectionSpec) error {
	raw := section.FieldByName(fieldMaxAge).String()
	if raw == "" {
		return nil
	}

	maxAge, err := time.ParseDuration(raw)
	if err != nil {
		return fmt.Errorf("invalid %s.maxAge %q: %w", spec.name, raw, err)
	}

	if maxAge <= 0 {
		return fmt.Errorf("%w, got %q", spec.errMaxAgeNotPositive, raw)
	}

	section.FieldByName(fieldMaxAgeDuration).SetInt(int64(maxAge))

	return nil
}

// cloneSections returns a deep copy of all sections.
func cloneSections(src *Sections) Sections {
	var dst Sections

	srcValue := reflect.ValueOf(src).Elem()
	dstValue := reflect.ValueOf(&dst).Elem()

	for _, idx := range sectionFieldIndex() {
		dstValue.Field(idx).Set(deepCopy(srcValue.Field(idx)))
	}

	dst.explicit = src.explicit

	return dst
}

// mergeSections overlays src onto dst field by field. A field is taken from
// src when it is set there: non-nil pointers, slices and maps are always
// considered set, while scalars are set when they appear in the policy JSON
// (or, for policies built in code, when they are non-zero). Lists and maps
// replace the base value as a whole. The CEL section is replaced as a whole
// so that it always matches the compiled programs.
func mergeSections(dst, src *Sections) {
	srcValue := reflect.ValueOf(src).Elem()
	dstValue := reflect.ValueOf(dst).Elem()

	for name, idx := range sectionFieldIndex() {
		srcSection := srcValue.Field(idx)
		if srcSection.IsNil() {
			continue
		}

		dstSection := dstValue.Field(idx)
		if dstSection.IsNil() || name == sectionCEL {
			dstSection.Set(deepCopy(srcSection))

			continue
		}

		mergeStruct(dstSection.Elem(), srcSection.Elem(), name, src.explicit)
	}

	resolveMergedMaxAges(dst, src)
}

func mergeStruct(dst, src reflect.Value, path string, explicit map[string]bool) {
	structType := src.Type()

	for idx := range structType.NumField() {
		field := structType.Field(idx)
		if !field.IsExported() {
			continue
		}

		name := jsonFieldName(&field)
		srcField := src.Field(idx)
		dstField := dst.Field(idx)

		if name == "-" {
			// Derived values follow their source fields (see
			// resolveMergedMaxAges); only carry over non-zero values.
			if !srcField.IsZero() {
				dstField.Set(deepCopy(srcField))
			}

			continue
		}

		fieldPath := path + "." + name
		if !isFieldSet(srcField, fieldPath, explicit) {
			continue
		}

		if srcField.Kind() == reflect.Pointer && !dstField.IsNil() &&
			srcField.Elem().
				Kind() ==
				reflect.Struct && !hasUnexportedFields(srcField.Elem().Type()) {
			mergeStruct(dstField.Elem(), srcField.Elem(), fieldPath, explicit)

			continue
		}

		dstField.Set(deepCopy(srcField))
	}
}

//nolint:exhaustive // only reference kinds have nil semantics
func isFieldSet(value reflect.Value, path string, explicit map[string]bool) bool {
	switch value.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Map, reflect.Interface:
		// JSON null and omitted fields both decode to nil and mean "unset".
		return !value.IsNil()
	default:
		if explicit != nil {
			return explicit[path]
		}

		return !value.IsZero()
	}
}

// resolveMergedMaxAges recomputes MaxAgeDuration for sections whose maxAge
// was taken from src, including an explicit empty maxAge that clears it.
func resolveMergedMaxAges(dst, src *Sections) {
	for idx := range sectionRegistry {
		spec := &sectionRegistry[idx]
		if spec.errMaxAgeNotPositive == nil {
			continue
		}

		dstSection := dst.section(spec.name)
		if dstSection.IsNil() {
			continue
		}

		raw := dstSection.Elem().FieldByName(fieldMaxAge).String()
		duration := dstSection.Elem().FieldByName(fieldMaxAgeDuration)

		if raw == "" {
			if src.explicit[spec.name+"."+jsonMaxAge] {
				duration.SetInt(0)
			}

			continue
		}

		parsed, err := time.ParseDuration(raw)
		if err == nil && parsed > 0 {
			duration.SetInt(int64(parsed))
		}
	}
}

// deepCopy returns a deep copy of pointers, slices, maps and structs made of
// exported fields. Structs with unexported fields (e.g. time.Time) and all
// other kinds are copied by value.
//
//nolint:exhaustive // all other kinds are copied by value
func deepCopy(value reflect.Value) reflect.Value {
	switch value.Kind() {
	case reflect.Pointer:
		return copyPointer(value)
	case reflect.Slice:
		return copySlice(value)
	case reflect.Map:
		return copyMap(value)
	case reflect.Struct:
		return copyStruct(value)
	default:
		return value
	}
}

func copyPointer(value reflect.Value) reflect.Value {
	if value.IsNil() {
		return reflect.Zero(value.Type())
	}

	clone := reflect.New(value.Type().Elem())
	clone.Elem().Set(deepCopy(value.Elem()))

	return clone
}

func copySlice(value reflect.Value) reflect.Value {
	if value.IsNil() {
		return reflect.Zero(value.Type())
	}

	clone := reflect.MakeSlice(value.Type(), value.Len(), value.Len())
	for idx := range value.Len() {
		clone.Index(idx).Set(deepCopy(value.Index(idx)))
	}

	return clone
}

func copyMap(value reflect.Value) reflect.Value {
	if value.IsNil() {
		return reflect.Zero(value.Type())
	}

	clone := reflect.MakeMapWithSize(value.Type(), value.Len())

	iter := value.MapRange()
	for iter.Next() {
		clone.SetMapIndex(deepCopy(iter.Key()), deepCopy(iter.Value()))
	}

	return clone
}

func copyStruct(value reflect.Value) reflect.Value {
	if hasUnexportedFields(value.Type()) {
		return value
	}

	clone := reflect.New(value.Type()).Elem()
	for idx := range value.NumField() {
		clone.Field(idx).Set(deepCopy(value.Field(idx)))
	}

	return clone
}

func hasUnexportedFields(structType reflect.Type) bool {
	for field := range structType.Fields() {
		if !field.IsExported() {
			return true
		}
	}

	return false
}

// recordExplicitFields remembers which JSON fields were present in the policy
// document, so merges can tell an explicit zero value (e.g. false) apart
// from an omitted field. Paths are section relative ("slsa.maxAge").
func recordExplicitFields(pol *Policy, data []byte) error {
	var document struct {
		Rules []map[string]json.RawMessage `json:"rules"`
	}

	var raw map[string]json.RawMessage

	err := json.Unmarshal(data, &raw)
	if err != nil {
		return fmt.Errorf("recording policy fields: %w", err)
	}

	err = json.Unmarshal(data, &document)
	if err != nil {
		return fmt.Errorf("recording policy rule fields: %w", err)
	}

	pol.explicit = explicitPaths(raw, "")

	for idx := range document.Rules {
		if idx < len(pol.Rules) {
			pol.Rules[idx].explicit = explicitPaths(document.Rules[idx], "")
		}
	}

	return nil
}

func explicitPaths(object map[string]json.RawMessage, prefix string) map[string]bool {
	paths := make(map[string]bool, len(object))

	for key, value := range object {
		trimmed := bytes.TrimSpace(value)

		// A JSON null decodes to the zero value, so it is recorded as unset
		// and a merge keeps the base value, as for omitted fields.
		if bytes.Equal(trimmed, []byte("null")) {
			continue
		}

		path := prefix + key
		paths[path] = true

		if len(trimmed) == 0 || trimmed[0] != '{' {
			continue
		}

		var nested map[string]json.RawMessage
		if json.Unmarshal(trimmed, &nested) != nil {
			continue
		}

		for nestedPath := range explicitPaths(nested, path+".") {
			paths[nestedPath] = true
		}
	}

	return paths
}

// errSectionRegistryIncomplete indicates a Sections field has no registry
// entry (or the other way around).
var errSectionRegistryIncomplete = errors.New("policy section registry is incomplete")

// checkSectionRegistry verifies that every Sections field has exactly one
// registry entry. It is exercised by tests to keep the registry in sync.
func checkSectionRegistry() error {
	index := sectionFieldIndex()
	if len(index) != len(sectionRegistry) {
		return fmt.Errorf(
			"%w: %d sections, %d registry entries",
			errSectionRegistryIncomplete, len(index), len(sectionRegistry),
		)
	}

	for idx := range sectionRegistry {
		if _, ok := index[sectionRegistry[idx].name]; !ok {
			return fmt.Errorf(
				"%w: unknown section %q",
				errSectionRegistryIncomplete,
				sectionRegistry[idx].name,
			)
		}
	}

	return nil
}

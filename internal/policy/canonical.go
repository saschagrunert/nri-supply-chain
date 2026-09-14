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
	"fmt"
	"maps"
	"reflect"
	"strings"
)

// checkCanonicalFields rejects policy documents that spell a field name
// differently from its JSON tag. encoding/json matches field names
// case-insensitively, so "MissingPolicy" would decode into missingPolicy
// while the explicit field tracking used by merges (which works on the raw
// document) would not see it, silently dropping the override.
func checkCanonicalFields(data []byte) error {
	return checkCanonicalValue(data, reflect.TypeFor[Policy](), "")
}

//nolint:exhaustive // only composite kinds carry field names
func checkCanonicalValue(raw []byte, typ reflect.Type, path string) error {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}

	if implementsUnmarshaler(typ) {
		return nil
	}

	// Values of the wrong JSON type are skipped here, the decoder reports them.
	switch typ.Kind() {
	case reflect.Struct:
		if object, ok := rawObject(raw); ok {
			return checkCanonicalObject(object, typ, path)
		}
	case reflect.Slice, reflect.Array:
		if items, ok := rawList(raw); ok {
			return checkCanonicalList(items, typ.Elem(), path)
		}
	case reflect.Map:
		if object, ok := rawObject(raw); ok {
			return checkCanonicalMap(object, typ.Elem(), path)
		}
	}

	return nil
}

func checkCanonicalList(items []json.RawMessage, elem reflect.Type, path string) error {
	for idx, item := range items {
		err := checkCanonicalValue(item, elem, fmt.Sprintf("%s[%d]", path, idx))
		if err != nil {
			return err
		}
	}

	return nil
}

// checkCanonicalMap checks the values of a JSON object decoded into a Go map.
// Map keys are data (e.g. Scorecard check names), not field names.
func checkCanonicalMap(object map[string]json.RawMessage, elem reflect.Type, path string) error {
	for key, value := range object {
		err := checkCanonicalValue(value, elem, joinFieldPath(path, key))
		if err != nil {
			return err
		}
	}

	return nil
}

func checkCanonicalObject(object map[string]json.RawMessage, typ reflect.Type, path string) error {
	fields := jsonFields(typ)

	for key, value := range object {
		fieldType, known := fields[key]
		if !known {
			for name := range fields {
				if strings.EqualFold(name, key) {
					return fmt.Errorf(
						"%w: %q, use %q",
						ErrNonCanonicalField, joinFieldPath(path, key), joinFieldPath(path, name),
					)
				}
			}

			// Unknown fields are rejected by the decoder.
			continue
		}

		err := checkCanonicalValue(value, fieldType, joinFieldPath(path, key))
		if err != nil {
			return err
		}
	}

	return nil
}

// rawObject decodes raw as a JSON object. ok is false for any other value.
func rawObject(raw []byte) (object map[string]json.RawMessage, ok bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, false
	}

	return object, json.Unmarshal(trimmed, &object) == nil
}

// rawList decodes raw as a JSON array. ok is false for any other value.
func rawList(raw []byte) (items []json.RawMessage, ok bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return nil, false
	}

	return items, json.Unmarshal(trimmed, &items) == nil
}

// jsonFields returns the JSON field names of a struct type, including the
// fields promoted from embedded structs, mapped to their types.
func jsonFields(typ reflect.Type) map[string]reflect.Type {
	fields := make(map[string]reflect.Type, typ.NumField())

	for field := range typ.Fields() {
		tag := field.Tag.Get("json")
		if tag == "-" {
			continue
		}

		if field.Anonymous && tag == "" && field.Type.Kind() == reflect.Struct {
			maps.Copy(fields, jsonFields(field.Type))

			continue
		}

		if !field.IsExported() {
			continue
		}

		fields[jsonFieldName(&field)] = field.Type
	}

	return fields
}

func implementsUnmarshaler(typ reflect.Type) bool {
	unmarshaler := reflect.TypeFor[json.Unmarshaler]()

	return typ.Implements(unmarshaler) || reflect.PointerTo(typ).Implements(unmarshaler)
}

func joinFieldPath(path, key string) string {
	if path == "" {
		return key
	}

	return path + "." + key
}

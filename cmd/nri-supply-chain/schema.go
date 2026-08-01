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

package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"strings"

	"github.com/invopop/jsonschema"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
)

const (
	schemaPolicy = "policy"
	schemaResult = "result"
)

// PolicyJSONSchema generates the JSON Schema for policy configuration files.
func PolicyJSONSchema() ([]byte, error) {
	return generateSchema(
		&policy.Policy{},
		"nri-supply-chain Policy",
		"Defines the trust roots and "+
			"per-namespace verification settings for nri-supply-chain.",
	)
}

// VerifyResultJSONSchema generates the JSON Schema for verify output.
func VerifyResultJSONSchema() ([]byte, error) {
	return generateSchema(
		&verifyOutput{
			Image:        "",
			Digest:       "",
			Namespace:    "",
			PolicyFile:   "",
			Mode:         "",
			Allowed:      false,
			Reason:       "",
			CheckResults: nil,
		},
		"nri-supply-chain Verify Result",
		"JSON output of the verify command.",
	)
}

func generateSchema(
	target any, title, description string,
) ([]byte, error) {
	reflector := &jsonschema.Reflector{
		// Prefix types from the internal/cel package with "CEL" so that
		// cel.Policy becomes "CELPolicy" in $defs and does not collide
		// with the top-level policy.Policy definition.
		Namer: func(t reflect.Type) string {
			if strings.HasSuffix(t.PkgPath(), "/internal/cel") {
				return "CEL" + t.Name()
			}

			return ""
		},
	}

	schema := reflector.Reflect(target)
	schema.ID = ""
	schema.Title = title
	schema.Description = description

	data, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling schema: %w", err)
	}

	data = append(data, '\n')

	return data, nil
}

func printJSONSchema(schemaType string) int {
	var (
		data []byte
		err  error
	)

	switch schemaType {
	case schemaPolicy:
		data, err = PolicyJSONSchema()
	case schemaResult:
		data, err = VerifyResultJSONSchema()
	default:
		slog.Error(
			"Unknown schema type, use 'policy' or 'result'",
			"type", schemaType,
		)

		return exitError
	}

	if err != nil {
		slog.Error("Failed to generate JSON Schema", "error", err)

		return exitError
	}

	_, err = os.Stdout.Write(data)
	if err != nil {
		slog.Error("Failed to write JSON Schema", "error", err)

		return exitError
	}

	return exitSuccess
}

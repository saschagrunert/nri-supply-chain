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
	"github.com/spf13/cobra"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
)

const (
	schemaPolicy = "policy"
	schemaResult = "result"
	schemaConfig = "config"
)

func newJSONSchemaCmd() *cobra.Command {
	return &cobra.Command{
		Use:   cmdJSONSchema + " <type>",
		Short: "Print JSON Schema for a given type",
		Long: "Print the JSON Schema definition for a given type.\n\n" +
			"Available types:\n" +
			"  policy   Policy configuration file schema\n" +
			"  result   Verification result output schema\n" +
			"  config   TOML configuration file schema",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errMissingSchemaType
			}

			if len(args) > 1 {
				return fmt.Errorf("%w, received %d", errTooManyArgs, len(args))
			}

			return nil
		},
		ValidArgs: []string{schemaPolicy, schemaResult, schemaConfig},
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true

			code := printJSONSchema(args[0])
			if code != 0 {
				return errExitNonZero
			}

			return nil
		},
	}
}

func policyJSONSchema() ([]byte, error) {
	return generateSchema(
		&policy.Policy{},
		"nri-supply-chain Policy",
		"Defines the trust roots and "+
			"per-namespace verification settings for nri-supply-chain.",
	)
}

func configJSONSchema() ([]byte, error) {
	return generateSchema(
		(*config.Config)(nil),
		"nri-supply-chain Config",
		"TOML configuration file schema for nri-supply-chain.",
	)
}

func verifyResultJSONSchema() ([]byte, error) {
	return generateSchema(
		&verifyOutput{
			Image:         "",
			Digest:        "",
			Namespace:     "",
			PolicyFile:    "",
			Mode:          "",
			PreviewPolicy: "",
			Allowed:       false,
			Reason:        "",
			CheckResults:  nil,
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
		data, err = policyJSONSchema()
	case schemaResult:
		data, err = verifyResultJSONSchema()
	case schemaConfig:
		data, err = configJSONSchema()
	default:
		slog.Error(
			"Unknown schema type, use 'policy', 'result', or 'config'",
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

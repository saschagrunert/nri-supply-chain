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
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

// TestKnownPredicateTypesCoverAttestationPredicates checks that inspect
// shortens every predicate type the attestation package declares, so a new
// attestation type cannot be added without a short name.
func TestKnownPredicateTypesCoverAttestationPredicates(t *testing.T) {
	t.Parallel()

	file, err := parser.ParseFile(
		token.NewFileSet(),
		"../../internal/attestation/attestation.go",
		nil,
		parser.SkipObjectResolution,
	)
	if err != nil {
		t.Fatalf("parsing attestation.go: %v", err)
	}

	found := 0

	ast.Inspect(file, func(node ast.Node) bool {
		spec, isValue := node.(*ast.ValueSpec)
		if !isValue {
			return true
		}

		for idx, ident := range spec.Names {
			if !ident.IsExported() || !strings.HasPrefix(ident.Name, "Predicate") ||
				idx >= len(spec.Values) {
				continue
			}

			literal, isLiteral := spec.Values[idx].(*ast.BasicLit)
			if !isLiteral || literal.Kind != token.STRING {
				continue
			}

			value, unquoteErr := strconv.Unquote(literal.Value)
			if unquoteErr != nil {
				t.Fatalf("unquoting %s: %v", ident.Name, unquoteErr)
			}

			found++

			if _, known := knownPredicateTypes[value]; !known {
				t.Errorf(
					"attestation.%s (%q) has no short name in knownPredicateTypes",
					ident.Name,
					value,
				)
			}
		}

		return true
	})

	if found == 0 {
		t.Fatal("found no predicate type constants in attestation.go")
	}
}

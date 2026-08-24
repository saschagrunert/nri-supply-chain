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

package testutil

import (
	"encoding/json"
	"testing"
)

const (
	// InTotoStatementType is the standard in-toto statement type used in tests.
	InTotoStatementType = "https://in-toto.io/Statement/v1"

	// TestSubjectName is the default subject name for test in-toto statements.
	TestSubjectName = "test-image"

	// TestDigestAlgo is the default digest algorithm for test in-toto statements.
	TestDigestAlgo = "sha256"
)

// InTotoWrapper is the top-level in-toto statement envelope used in tests.
type InTotoWrapper struct {
	Type          string          `json:"_type"` //nolint:tagliatelle // In-toto spec field name.
	Subject       []InTotoSubj    `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

// InTotoSubj represents a single subject in an in-toto statement.
type InTotoSubj struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// WrapInToto wraps a predicate document in an in-toto statement envelope.
func WrapInToto(t *testing.T, doc any, digest, predicateType string) []byte {
	t.Helper()

	predBytes := MustMarshal(t, doc)

	wrapper := InTotoWrapper{
		Type: InTotoStatementType,
		Subject: []InTotoSubj{
			{
				Name:   TestSubjectName,
				Digest: map[string]string{TestDigestAlgo: digest[len(TestDigestAlgo)+1:]},
			},
		},
		PredicateType: predicateType,
		Predicate:     predBytes,
	}

	return MustMarshal(t, wrapper)
}

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
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

const (
	policyDocPath      = "../../docs/policy.md"
	jsonSchemaStartTag = "<!-- jsonschema-start -->"
	jsonSchemaEndTag   = "<!-- jsonschema-end -->"
)

func TestPolicyJSONSchemaMatchesDocs(t *testing.T) {
	t.Parallel()

	schemaBytes, err := policyJSONSchema()
	if err != nil {
		t.Fatalf("generating schema: %v", err)
	}

	var generatedObj any

	unmarshalErr := json.Unmarshal(schemaBytes, &generatedObj)
	if unmarshalErr != nil {
		t.Fatalf("unmarshaling generated schema: %v", unmarshalErr)
	}

	docBytes, err := os.ReadFile(policyDocPath)
	if err != nil {
		t.Fatalf("reading policy doc: %v", err)
	}

	doc := string(docBytes)

	startIdx := strings.Index(doc, jsonSchemaStartTag)
	if startIdx == -1 {
		t.Fatalf("missing %s in %s", jsonSchemaStartTag, policyDocPath)
	}

	endIdx := strings.Index(doc, jsonSchemaEndTag)
	if endIdx == -1 {
		t.Fatalf("missing %s in %s", jsonSchemaEndTag, policyDocPath)
	}

	if endIdx <= startIdx {
		t.Fatalf("end marker before start marker in %s", policyDocPath)
	}

	section := doc[startIdx+len(jsonSchemaStartTag) : endIdx]

	codeStart := strings.Index(section, "```json\n")
	if codeStart == -1 {
		t.Fatalf("missing json code block in schema section of %s", policyDocPath)
	}

	codeEnd := strings.Index(section[codeStart+len("```json\n"):], "\n```")
	if codeEnd == -1 {
		t.Fatalf("missing closing code fence in schema section of %s", policyDocPath)
	}

	embedded := strings.TrimSpace(
		section[codeStart+len("```json\n") : codeStart+len("```json\n")+codeEnd],
	)

	var embeddedObj any

	unmarshalErr = json.Unmarshal([]byte(embedded), &embeddedObj)
	if unmarshalErr != nil {
		t.Fatalf("unmarshaling embedded schema: %v", unmarshalErr)
	}

	generatedNorm, marshalErr := json.Marshal(generatedObj)
	if marshalErr != nil {
		t.Fatalf("re-marshaling generated schema: %v", marshalErr)
	}

	embeddedNorm, marshalErr := json.Marshal(embeddedObj)
	if marshalErr != nil {
		t.Fatalf("re-marshaling embedded schema: %v", marshalErr)
	}

	if !bytes.Equal(generatedNorm, embeddedNorm) {
		t.Errorf(
			"JSON Schema in %s is out of date.\n"+
				"Run 'nri-supply-chain json-schema policy' and update the "+
				"section between %s and %s",
			policyDocPath, jsonSchemaStartTag, jsonSchemaEndTag,
		)
	}
}

func TestVerifyResultJSONSchemaMatchesDocs(t *testing.T) {
	t.Parallel()

	schemaBytes, err := verifyResultJSONSchema()
	if err != nil {
		t.Fatalf("generating schema: %v", err)
	}

	var generatedObj any

	unmarshalErr := json.Unmarshal(schemaBytes, &generatedObj)
	if unmarshalErr != nil {
		t.Fatalf("unmarshaling generated schema: %v", unmarshalErr)
	}

	const configDocPath = "../../docs/config.md"

	docBytes, err := os.ReadFile(configDocPath)
	if err != nil {
		t.Fatalf("reading config doc: %v", err)
	}

	doc := string(docBytes)

	const (
		startTag = "<!-- verify-jsonschema-start -->"
		endTag   = "<!-- verify-jsonschema-end -->"
	)

	startIdx := strings.Index(doc, startTag)
	if startIdx == -1 {
		t.Fatalf("missing %s in %s", startTag, configDocPath)
	}

	endIdx := strings.Index(doc, endTag)
	if endIdx == -1 {
		t.Fatalf("missing %s in %s", endTag, configDocPath)
	}

	if endIdx <= startIdx {
		t.Fatalf("end marker before start marker in %s", configDocPath)
	}

	section := doc[startIdx+len(startTag) : endIdx]

	codeStart := strings.Index(section, "```json\n")
	if codeStart == -1 {
		t.Fatalf("missing json code block in schema section of %s", configDocPath)
	}

	codeEnd := strings.Index(section[codeStart+len("```json\n"):], "\n```")
	if codeEnd == -1 {
		t.Fatalf("missing closing code fence in schema section of %s", configDocPath)
	}

	embedded := strings.TrimSpace(
		section[codeStart+len("```json\n") : codeStart+len("```json\n")+codeEnd],
	)

	var embeddedObj any

	unmarshalErr = json.Unmarshal([]byte(embedded), &embeddedObj)
	if unmarshalErr != nil {
		t.Fatalf("unmarshaling embedded schema: %v", unmarshalErr)
	}

	generatedNorm, marshalErr := json.Marshal(generatedObj)
	if marshalErr != nil {
		t.Fatalf("re-marshaling generated schema: %v", marshalErr)
	}

	embeddedNorm, marshalErr := json.Marshal(embeddedObj)
	if marshalErr != nil {
		t.Fatalf("re-marshaling embedded schema: %v", marshalErr)
	}

	if !bytes.Equal(generatedNorm, embeddedNorm) {
		t.Errorf(
			"JSON Schema in %s is out of date.\n"+
				"Run 'nri-supply-chain json-schema result' and update the "+
				"section between %s and %s",
			configDocPath, startTag, endTag,
		)
	}
}

func TestPrintJSONSchemaPolicy(t *testing.T) {
	t.Parallel()

	exitCode := printJSONSchema("policy")
	if exitCode != exitSuccess {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
}

func TestPrintJSONSchemaVerifyResult(t *testing.T) {
	t.Parallel()

	exitCode := printJSONSchema("result")
	if exitCode != exitSuccess {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
}

func TestPrintJSONSchemaConfig(t *testing.T) {
	t.Parallel()

	exitCode := printJSONSchema("config")
	if exitCode != exitSuccess {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
}

func TestConfigJSONSchema(t *testing.T) {
	t.Parallel()

	data, err := configJSONSchema()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(data) == 0 {
		t.Fatal("expected non-empty schema")
	}
}

func TestPrintJSONSchemaUnknown(t *testing.T) {
	t.Parallel()

	exitCode := printJSONSchema("bogus")
	if exitCode != exitError {
		t.Errorf("expected exit code %d, got %d", exitError, exitCode)
	}
}

func TestVerifyResultJSONSchema(t *testing.T) {
	t.Parallel()

	data, err := verifyResultJSONSchema()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(data) == 0 {
		t.Fatal("expected non-empty schema")
	}
}

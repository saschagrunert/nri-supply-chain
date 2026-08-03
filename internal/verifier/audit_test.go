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

package verifier_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

func attrMap(attrs []any) map[string]any {
	m := make(map[string]any, len(attrs)/2)
	for i := 0; i < len(attrs)-1; i += 2 {
		if k, ok := attrs[i].(string); ok {
			m[k] = attrs[i+1]
		}
	}

	return m
}

func TestAuditEventLogAttrs(t *testing.T) {
	t.Parallel()

	t.Run("check event includes check fields", func(t *testing.T) {
		t.Parallel()

		event := verifier.ExportNewAuditEvent(
			"docker.io/library/nginx:latest", "sha256:abc123", "default",
			true, "slsa", "pass", "SLSA verification passed", "", "",
			nil,
		)

		attrs := attrMap(verifier.ExportAuditEventLogAttrs(event))
		testutil.AssertEqual(t, "docker.io/library/nginx:latest", attrs["image"])
		testutil.AssertEqual(t, "sha256:abc123", attrs["digest"])
		testutil.AssertEqual(t, "default", attrs["namespace"])
		testutil.AssertEqual(t, true, attrs["allowed"])
		testutil.AssertEqual(t, "slsa", attrs["check"])
	})

	t.Run("decision event includes decision fields", func(t *testing.T) {
		t.Parallel()

		event := verifier.ExportNewAuditEvent(
			"docker.io/library/nginx:latest", "sha256:abc123", "default",
			true, "", "", "", "allowed", "image is excluded",
			nil,
		)

		attrs := attrMap(verifier.ExportAuditEventLogAttrs(event))
		testutil.AssertEqual(t, "allowed", attrs["decision"])
		testutil.AssertEqual(t, "image is excluded", attrs["reason"])
		testutil.AssertEqual(t, true, attrs["allowed"])
	})
}

func TestAuditEventLogAttrsEnrichmentFields(t *testing.T) {
	t.Parallel()

	event := verifier.ExportNewAuditEvent(
		"docker.io/library/nginx:latest", "sha256:abc123", "default",
		true, "", "", "", "allowed", "test",
		verifier.NewExportAuditInfo("sha256:policy1", "node-1", "my-service-account", "enforce"),
	)

	attrs := attrMap(verifier.ExportAuditEventLogAttrs(event))
	testutil.AssertEqual(t, "sha256:policy1", attrs["policyHash"])
	testutil.AssertEqual(t, "node-1", attrs["nodeName"])
	testutil.AssertEqual(t, "my-service-account", attrs["podServiceAccount"])
	testutil.AssertEqual(t, "enforce", attrs["verificationMode"])
}

func TestAuditEventLogAttrsOmitsEmptyEnrichmentFields(t *testing.T) {
	t.Parallel()

	event := verifier.ExportNewAuditEvent(
		"docker.io/library/nginx:latest", "sha256:abc123", "default",
		true, "", "", "", "allowed", "test",
		nil,
	)

	attrs := attrMap(verifier.ExportAuditEventLogAttrs(event))

	if _, ok := attrs["policyHash"]; ok {
		t.Error("expected policyHash to be omitted when empty")
	}

	if _, ok := attrs["nodeName"]; ok {
		t.Error("expected nodeName to be omitted when empty")
	}

	if _, ok := attrs["podServiceAccount"]; ok {
		t.Error("expected podServiceAccount to be omitted when empty")
	}

	if _, ok := attrs["verificationMode"]; ok {
		t.Error("expected verificationMode to be omitted when empty")
	}
}

func TestLogAuditDecisionWithAuditInfo(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	info := verifier.NewExportAuditInfo("sha256:pol", "node-2", "sa-1", "warn")

	verifier.ExportLogAuditDecision(
		context.Background(), logger,
		"docker.io/library/nginx:latest", "sha256:abc123",
		"default", "allowed", "test reason", info,
	)

	output := buf.String()

	var parsed map[string]any

	testutil.AssertNoError(t, json.Unmarshal([]byte(output), &parsed))

	testutil.AssertEqual(t, "sha256:pol", parsed["policyHash"])
	testutil.AssertEqual(t, "node-2", parsed["nodeName"])
	testutil.AssertEqual(t, "sa-1", parsed["podServiceAccount"])
	testutil.AssertEqual(t, "warn", parsed["verificationMode"])
}

func TestLogResultSerializesControlCharacters(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	result := &types.Result{
		Allowed: true,
		Reason:  "",
		CheckResults: []types.CheckResult{
			{
				Type:     types.CheckTypeSLSA,
				Status:   types.StatusPass,
				Passed:   true,
				Detail:   "image with\nnewline\tand\ttabs",
				Err:      nil,
				Metadata: nil,
			},
		},
	}

	verifier.ExportLogResult(
		context.Background(), logger,
		"evil\nimage\r\nref", "sha256:abc", "ns\x00null",
		result, nil,
	)

	output := buf.String()
	if output == "" {
		t.Fatal("expected log output")
	}

	var parsed map[string]any

	testutil.AssertNoError(t, json.Unmarshal([]byte(output), &parsed))

	image, ok := parsed["image"].(string)
	if !ok {
		t.Fatal("expected image field in log output")
	}

	if !strings.Contains(image, "evil") {
		t.Error("expected image to contain 'evil'")
	}

	detail, ok := parsed["detail"].(string)
	if !ok {
		t.Fatal("expected detail field in log output")
	}

	if !strings.Contains(detail, "newline") {
		t.Error("expected detail to contain 'newline'")
	}
}

func TestLogAuditDecision(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	verifier.ExportLogAuditDecision(
		context.Background(), logger,
		"docker.io/library/nginx:latest", "sha256:abc123",
		"default", "allowed", "image is excluded", nil,
	)

	output := buf.String()

	var parsed map[string]any

	testutil.AssertNoError(t, json.Unmarshal([]byte(output), &parsed))

	testutil.AssertEqual(t, "allowed", parsed["decision"])
	testutil.AssertEqual(t, "image is excluded", parsed["reason"])
	testutil.AssertEqual(t, true, parsed["allowed"])
}

func TestAllowResultSetsAllowed(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	result := verifier.ExportAllowResult(
		context.Background(), logger,
		"docker.io/library/nginx:latest", "sha256:abc123",
		"default", "test reason", nil,
	)

	testutil.AssertEqual(t, true, result.Allowed)
	testutil.AssertEqual(t, "test reason", result.Reason)
}

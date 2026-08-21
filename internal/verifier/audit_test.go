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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
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

	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

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

	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) == 0 {
		t.Fatal("expected at least one log line")
	}

	var parsed map[string]any

	testutil.AssertNoError(t, json.Unmarshal([]byte(lines[0]), &parsed))

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

func TestOpenAuditLoggerEmptyPath(t *testing.T) {
	t.Parallel()

	logger, file, err := verifier.ExportOpenAuditLogger("")
	testutil.AssertNoError(t, err)

	if logger == nil {
		t.Fatal("expected non-nil logger")
	}

	if file != nil {
		t.Error("expected nil file for empty path")
	}
}

func TestOpenAuditLoggerCreatesFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "audit.log")

	logger, file, err := verifier.ExportOpenAuditLogger(path)
	testutil.AssertNoError(t, err)

	if logger == nil {
		t.Fatal("expected non-nil logger")
	}

	if file == nil {
		t.Fatal("expected non-nil file")
	}

	defer func() { _ = file.Close() }()

	logger.Info("test message", "key", "value")

	info, statErr := os.Stat(path)
	testutil.AssertNoError(t, statErr)

	if info.Size() == 0 {
		t.Error("expected non-empty audit log file after writing")
	}
}

func TestOpenAuditLoggerInvalidPath(t *testing.T) {
	t.Parallel()

	_, _, err := verifier.ExportOpenAuditLogger("/nonexistent/dir/audit.log")
	if err == nil {
		t.Fatal("expected error for invalid path")
	}

	if !strings.Contains(err.Error(), "opening audit log") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestCloseAuditLogFileNil(t *testing.T) {
	t.Parallel()

	verifier.ExportCloseAuditLogFile(nil)
}

func TestCloseAuditLogFileValid(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "audit.log")

	_, file, err := verifier.ExportOpenAuditLogger(path)
	testutil.AssertNoError(t, err)

	verifier.ExportCloseAuditLogFile(file)
}

func TestLogResultMultipleChecks(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	result := &types.Result{
		Allowed: false,
		Reason:  "verification failed",
		CheckResults: []types.CheckResult{
			{
				Type:     types.CheckTypeSLSA,
				Status:   types.StatusFail,
				Passed:   false,
				Detail:   "no SLSA provenance found",
				Err:      nil,
				Metadata: nil,
			},
			{
				Type:     types.CheckTypeSBOM,
				Status:   types.StatusPass,
				Passed:   true,
				Detail:   "SBOM verified",
				Err:      nil,
				Metadata: nil,
			},
		},
	}

	verifier.ExportLogResult(
		context.Background(), logger,
		"docker.io/library/nginx:latest", "sha256:abc", "default",
		result, nil,
	)

	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")

	if len(lines) < 3 {
		t.Fatalf("expected at least 3 log lines (2 checks + 1 decision), got %d", len(lines))
	}

	var lastLine map[string]any
	testutil.AssertNoError(t, json.Unmarshal([]byte(lines[len(lines)-1]), &lastLine))
	testutil.AssertEqual(t, "denied", lastLine["decision"])
}

func TestReloadAuditLoggerSamePath(t *testing.T) {
	t.Parallel()

	prevCfg := config.DefaultConfig()
	prevCfg.AuditLog = "/var/log/audit.log"

	nextCfg := config.DefaultConfig()
	nextCfg.AuditLog = "/var/log/audit.log"

	prevLogger := slog.Default()
	prev := verifier.ExportNewSnapshot(prevCfg, prevLogger, nil)

	logger, file := verifier.ExportReloadAuditLogger(context.Background(), prev, nextCfg)
	if logger != prevLogger {
		t.Error("expected same logger when audit log path unchanged")
	}

	if file != nil {
		t.Error("expected nil file when audit log path unchanged")
	}
}

func TestReloadAuditLoggerDifferentPath(t *testing.T) {
	t.Parallel()

	prevCfg := config.DefaultConfig()
	prevCfg.AuditLog = ""

	nextCfg := config.DefaultConfig()
	nextCfg.AuditLog = filepath.Join(t.TempDir(), "new-audit.log")

	prev := verifier.ExportNewSnapshot(prevCfg, slog.Default(), nil)

	logger, file := verifier.ExportReloadAuditLogger(context.Background(), prev, nextCfg)
	if logger == nil {
		t.Fatal("expected non-nil logger for new audit log path")
	}

	if file == nil {
		t.Fatal("expected non-nil file for new audit log path")
	}

	t.Cleanup(func() { verifier.ExportCloseAuditLogFile(file) })
}

func TestReloadAuditLoggerInvalidPathFallsBack(t *testing.T) {
	t.Parallel()

	prevCfg := config.DefaultConfig()
	prevCfg.AuditLog = ""

	nextCfg := config.DefaultConfig()
	nextCfg.AuditLog = "/nonexistent/dir/audit.log"

	prev := verifier.ExportNewSnapshot(prevCfg, slog.Default(), nil)

	logger, file := verifier.ExportReloadAuditLogger(context.Background(), prev, nextCfg)
	if logger == nil {
		t.Fatal("expected non-nil fallback logger")
	}

	if file != nil {
		t.Error("expected nil file on fallback")
	}
}

func TestReloadAuditLoggerClosesPreviousFile(t *testing.T) {
	t.Parallel()

	prevPath := filepath.Join(t.TempDir(), "prev-audit.log")

	_, prevFile, err := verifier.ExportOpenAuditLogger(prevPath)
	testutil.AssertNoError(t, err)

	prevCfg := config.DefaultConfig()
	prevCfg.AuditLog = prevPath
	prevCfg.VerificationTimeout = config.Duration{Duration: 1}

	nextCfg := config.DefaultConfig()
	nextCfg.AuditLog = filepath.Join(t.TempDir(), "next-audit.log")

	prev := verifier.ExportNewSnapshot(prevCfg, slog.Default(), prevFile)

	_, newFile := verifier.ExportReloadAuditLogger(context.Background(), prev, nextCfg)
	if newFile != nil {
		t.Cleanup(func() { verifier.ExportCloseAuditLogFile(newFile) })
	}
}

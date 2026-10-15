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
	"path/filepath"
	"strings"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

func newTestResult(allowed, verified bool, checks ...*types.CheckResult) types.Result {
	result := types.Result{
		Allowed:      allowed,
		Verified:     verified,
		Mode:         string(config.ModeWarn),
		Reason:       "",
		CheckResults: nil,
	}

	for _, check := range checks {
		result.CheckResults = append(result.CheckResults, *check)
	}

	return result
}

func TestVerificationPassed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		result types.Result
		want   bool
	}{
		{
			name:   "verified",
			result: newTestResult(true, true, types.PassResult(types.CheckTypeSLSA, "ok")),
			want:   true,
		},
		{
			name:   "denied",
			result: newTestResult(false, false, types.FailResult(types.CheckTypeSLSA, "x", nil)),
			want:   false,
		},
		{
			name:   "failed check admitted in warn mode",
			result: newTestResult(true, false, types.FailResult(types.CheckTypeSLSA, "x", nil)),
			want:   false,
		},
		{
			name:   "denial without a check admitted in warn mode",
			result: newTestResult(true, false),
			want:   false,
		},
		{
			name: "verification error admitted in warn mode",
			result: newTestResult(true, false, &types.CheckResult{
				Type:     types.CheckTypeInternal,
				Passed:   true,
				Status:   types.StatusWarn,
				Detail:   "verification error (allowed in warn mode)",
				Err:      nil,
				Metadata: nil,
				Missing:  false,
			}),
			want: false,
		},
		{
			name: "fetch failure admitted by fetch_failure_policy",
			result: newTestResult(
				true, false, types.WarnResult(types.CheckTypeFetch, "fetch failed"),
			),
			want: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := verificationPassed(&test.result); got != test.want {
				t.Errorf("verificationPassed() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestRunPreviewWarnModeCountsFailuresAsDenied(t *testing.T) {
	t.Parallel()

	policyDir := t.TempDir()
	writeValidationPolicy(t, policyDir, "default.json",
		`{"slsa": {"missingPolicy": "deny"}}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = policyDir

	var buf bytes.Buffer

	code := runPreview(&buf, []string{pushTestImage(t, "preview-warn")},
		testNamespaceDefault, outputFormatJSON, "", cfg)
	if code != exitDenied {
		t.Fatalf("exit code = %d, want %d\noutput: %s", code, exitDenied, buf.String())
	}

	var out previewOutput

	err := json.Unmarshal(buf.Bytes(), &out)
	if err != nil {
		t.Fatalf("invalid JSON: %v\nraw: %s", err, buf.String())
	}

	if out.Summary.Allowed != 0 || out.Summary.Denied != 1 {
		t.Errorf("Summary = %+v, want allowed 0, denied 1", out.Summary)
	}

	if len(out.Images) != 1 {
		t.Fatalf("got %d images, want 1", len(out.Images))
	}

	img := out.Images[0]
	if !img.Allowed || img.Passed || img.Mode != string(config.ModeWarn) {
		t.Errorf("image = allowed %v, passed %v, mode %q; want allowed, not passed, warn mode",
			img.Allowed, img.Passed, img.Mode)
	}

	for _, suggestion := range out.Suggestions {
		if strings.Contains(suggestion, "safe to promote") {
			t.Errorf("unexpected suggestion for failing images: %q", suggestion)
		}
	}
}

func TestCLIVerifyDoesNotWriteAuditLog(t *testing.T) {
	t.Parallel()

	policyDir := t.TempDir()
	writeValidationPolicy(t, policyDir, "default.json",
		`{"slsa": {"missingPolicy": "warn"}}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = policyDir
	cfg.AuditLog = filepath.Join(t.TempDir(), "audit.json")

	var buf bytes.Buffer

	code := runVerifyTo(&buf, pushTestImage(t, "verify-audit"),
		testNamespaceDefault, outputFormatJSON, cfg, "")
	if code != exitSuccess {
		t.Fatalf("exit code = %d, want %d\noutput: %s", code, exitSuccess, buf.String())
	}

	_, err := os.Stat(cfg.AuditLog)
	if !os.IsNotExist(err) {
		t.Errorf("CLI verification wrote the audit log %s (stat error %v)", cfg.AuditLog, err)
	}
}

func TestDescribePolicyOCISource(t *testing.T) {
	t.Parallel()

	ref := pushPolicyArtifact(t)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.Policy.Source = config.PolicySourceOCI
	cfg.Policy.OCIRef = ref

	verif, err := newVerifier(t.Context(), cfg, nil)
	if err != nil {
		t.Fatalf("creating verifier: %v", err)
	}

	t.Cleanup(verif.Stop)

	got := describePolicy(cfg, verif, "production")
	if want := ref + " (default.json)"; got != want {
		t.Errorf("describePolicy() = %q, want %q", got, want)
	}
}

func TestBundleRejectsUnknownSubcommand(t *testing.T) {
	t.Parallel()

	cmd := newRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{cmdBundle, "crate"})

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), `unknown command "crate"`) {
		t.Fatalf("expected an unknown command error, got %v", err)
	}

	if code := exitCodeFor(err); code != exitError {
		t.Errorf("exit code = %d, want %d", code, exitError)
	}
}

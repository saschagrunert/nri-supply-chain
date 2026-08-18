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
	"path/filepath"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	internaltypes "github.com/saschagrunert/nri-supply-chain/internal/types"
)

func TestRunEffectivePolicyDefault(t *testing.T) {
	t.Parallel()

	policyDir := t.TempDir()
	writeValidationPolicy(t, policyDir, "default.json",
		`{"slsa": {"missingPolicy": "deny"}}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = policyDir

	var buf bytes.Buffer

	code := runEffectivePolicy(&buf, policy.DefaultPolicyLabel, "", cfg)
	if code != exitSuccess {
		t.Fatalf("expected exit code %d, got %d", exitSuccess, code)
	}

	var out effectivePolicyOutput

	err := json.Unmarshal(buf.Bytes(), &out)
	if err != nil {
		t.Fatalf("invalid JSON: %v\nraw: %s", err, buf.String())
	}

	if out.Namespace != policy.DefaultPolicyLabel {
		t.Errorf("Namespace = %q, want %q", out.Namespace, policy.DefaultPolicyLabel)
	}

	if out.Mode != string(config.ModeWarn) {
		t.Errorf("Mode = %q, want %q", out.Mode, config.ModeWarn)
	}

	if out.Source != policySourceDefault {
		t.Errorf("Source = %q, want %q", out.Source, policySourceDefault)
	}

	if out.RuleIndex != -1 {
		t.Errorf("RuleIndex = %d, want -1", out.RuleIndex)
	}

	if out.Policy == nil {
		t.Fatal("expected non-nil Policy")
	}
}

func TestRunEffectivePolicyNamespace(t *testing.T) {
	t.Parallel()

	policyDir := t.TempDir()
	writeValidationPolicy(t, policyDir, "default.json",
		`{"slsa": {"missingPolicy": "warn"}}`)
	writeValidationPolicy(t, policyDir, "production.json",
		`{"inherits": true, "slsa": {"missingPolicy": "deny"}}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.PolicyDir = policyDir

	var buf bytes.Buffer

	code := runEffectivePolicy(&buf, testNamespaceProduction, "", cfg)
	if code != exitSuccess {
		t.Fatalf("expected exit code %d, got %d", exitSuccess, code)
	}

	var out effectivePolicyOutput

	err := json.Unmarshal(buf.Bytes(), &out)
	if err != nil {
		t.Fatalf("invalid JSON: %v\nraw: %s", err, buf.String())
	}

	if out.Namespace != testNamespaceProduction {
		t.Errorf("Namespace = %q, want %q", out.Namespace, testNamespaceProduction)
	}

	if out.Source != policySourceNamespace {
		t.Errorf("Source = %q, want %q", out.Source, policySourceNamespace)
	}

	if out.Policy == nil {
		t.Fatal("expected non-nil Policy")
	}

	if out.Policy.SLSA == nil {
		t.Fatal("expected non-nil SLSA policy after inheritance merge")
	}
}

func TestRunEffectivePolicyWithImageRule(t *testing.T) {
	t.Parallel()

	policyDir := t.TempDir()
	writeValidationPolicy(t, policyDir, "default.json",
		`{
			"slsa": {"missingPolicy": "warn"},
			"rules": [
				{
					"images": ["ghcr.io/org/*"],
					"slsa": {"missingPolicy": "deny"}
				}
			]
		}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = policyDir

	var buf bytes.Buffer

	code := runEffectivePolicy(&buf, policy.DefaultPolicyLabel, "ghcr.io/org/app:latest", cfg)
	if code != exitSuccess {
		t.Fatalf("expected exit code %d, got %d", exitSuccess, code)
	}

	var out effectivePolicyOutput

	err := json.Unmarshal(buf.Bytes(), &out)
	if err != nil {
		t.Fatalf("invalid JSON: %v\nraw: %s", err, buf.String())
	}

	if out.RuleIndex != 0 {
		t.Errorf("RuleIndex = %d, want 0", out.RuleIndex)
	}

	if len(out.RulePatterns) != 1 || out.RulePatterns[0] != "ghcr.io/org/*" {
		t.Errorf("RulePatterns = %v, want [ghcr.io/org/*]", out.RulePatterns)
	}

	if out.Policy.SLSAMissingPolicy() != internaltypes.ActionDeny {
		t.Errorf("resolved SLSA MissingPolicy = %q, want %q",
			out.Policy.SLSAMissingPolicy(), internaltypes.ActionDeny)
	}
}

func TestRunEffectivePolicyNoImageRuleMatch(t *testing.T) {
	t.Parallel()

	policyDir := t.TempDir()
	writeValidationPolicy(t, policyDir, "default.json",
		`{
			"slsa": {"missingPolicy": "warn"},
			"rules": [
				{
					"images": ["ghcr.io/org/*"],
					"slsa": {"missingPolicy": "deny"}
				}
			]
		}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = policyDir

	var buf bytes.Buffer

	code := runEffectivePolicy(
		&buf, policy.DefaultPolicyLabel, "docker.io/library/nginx:latest", cfg,
	)
	if code != exitSuccess {
		t.Fatalf("expected exit code %d, got %d", exitSuccess, code)
	}

	var out effectivePolicyOutput

	err := json.Unmarshal(buf.Bytes(), &out)
	if err != nil {
		t.Fatalf("invalid JSON: %v\nraw: %s", err, buf.String())
	}

	if out.RuleIndex != -1 {
		t.Errorf("RuleIndex = %d, want -1", out.RuleIndex)
	}
}

func TestRunEffectivePolicyNamespaceFlag(t *testing.T) {
	t.Parallel()

	policyDir := t.TempDir()
	writeValidationPolicy(t, policyDir, "default.json",
		`{"slsa": {"missingPolicy": "warn"}}`)
	writeValidationPolicy(t, policyDir, "custom-ns.json",
		`{"inherits": true, "slsa": {"missingPolicy": "deny"}}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = policyDir

	var buf bytes.Buffer

	code := runEffectivePolicy(&buf, "custom-ns", "", cfg)
	if code != exitSuccess {
		t.Fatalf("expected exit code %d, got %d", exitSuccess, code)
	}

	var out effectivePolicyOutput

	err := json.Unmarshal(buf.Bytes(), &out)
	if err != nil {
		t.Fatalf("invalid JSON: %v\nraw: %s", err, buf.String())
	}

	if out.Namespace != "custom-ns" {
		t.Errorf("Namespace = %q, want %q", out.Namespace, "custom-ns")
	}

	if out.Source != policySourceNamespace {
		t.Errorf("Source = %q, want %q", out.Source, policySourceNamespace)
	}
}

func TestNewEffectivePolicyCmdViaRoot(t *testing.T) {
	t.Parallel()

	policyDir := t.TempDir()
	writeValidationPolicy(t, policyDir, "default.json",
		`{"slsa": {"missingPolicy": "warn"}}`)

	configPath := filepath.Join(t.TempDir(), "config.toml")
	writeTestConfig(t, configPath, policyDir, "warn")

	cmd := newRootCmd()
	cmd.SetArgs([]string{
		testFlagConfig, configPath,
		cmdEffectivePolicy, "-n", "test-ns",
	})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunEffectivePolicyMissingNamespace(t *testing.T) {
	t.Parallel()

	policyDir := t.TempDir()

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = policyDir

	var buf bytes.Buffer

	code := runEffectivePolicy(&buf, "nonexistent", "", cfg)
	if code != exitError {
		t.Errorf("expected exit code %d, got %d", exitError, code)
	}
}

func TestRunEffectivePolicyFallsBackToDefault(t *testing.T) {
	t.Parallel()

	policyDir := t.TempDir()
	writeValidationPolicy(t, policyDir, "default.json",
		`{"slsa": {"missingPolicy": "warn"}}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = policyDir

	var buf bytes.Buffer

	code := runEffectivePolicy(&buf, "nonexistent-ns", "", cfg)
	if code != exitSuccess {
		t.Fatalf("expected exit code %d, got %d", exitSuccess, code)
	}

	var out effectivePolicyOutput

	err := json.Unmarshal(buf.Bytes(), &out)
	if err != nil {
		t.Fatalf("invalid JSON: %v\nraw: %s", err, buf.String())
	}

	if out.Source != policySourceDefault {
		t.Errorf("Source = %q, want %q", out.Source, policySourceDefault)
	}

	if out.Policy == nil {
		t.Fatal("expected non-nil Policy when falling back to default")
	}
}

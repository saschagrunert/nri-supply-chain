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

package policy_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	testProductionJSON  = "production.json"
	testDevJSON         = "dev.json"
	testStagingJSONFile = "staging.json"
	testInheritsJSON    = `{"inherits": true}`
	// testInheritsKeylessVerifierJSON adds a keyless verifier without issuers.
	testInheritsKeylessVerifierJSON = `{
		"inherits": true,
		"trust": {"verifiers": [{"id": "https://example.com/v"}]}
	}`
)

func TestLoad(t *testing.T) {
	t.Parallel()

	//nolint:exhaustruct_v5 // table cases only set the fields they assert
	tests := []struct {
		name string
		// content is written to the policy file; empty loads a missing file.
		content string
		wantErr error
		check   func(t *testing.T, pol *policy.Policy)
	}{
		{
			name: "valid policy",
			content: `{
				"trust": {"builders": [{"id": "https://example.com/builder", "maxLevel": 2}]},
				"slsa": {"missingPolicy": "warn"}
			}`,
			check: func(t *testing.T, pol *policy.Policy) {
				t.Helper()

				if len(pol.Builders()) != 1 {
					t.Fatalf("expected 1 builder, got %d", len(pol.Builders()))
				}

				testutil.AssertEqual(t, "https://example.com/builder", pol.Builders()[0].ID)
				testutil.AssertEqual(t, types.ActionWarn, pol.SLSAMissingPolicy())
			},
		},
		{
			name: "mode is loaded",
			content: `{
				"mode": "enforce",
				"slsa": {"missingPolicy": "deny"}
			}`,
			check: func(t *testing.T, pol *policy.Policy) {
				t.Helper()

				testutil.AssertEqual(t, config.ModeEnforce, pol.Mode)
			},
		},
		{
			name: "rules merge section fields and CEL",
			content: `{
				"slsa": {"missingPolicy": "deny"},
				"cel": {"rules": [{"require": "slsa.verified == true"}]},
				"rules": [
					{"images": ["ghcr.io/org/fast/**"], "slsa": {"maxAge": "1h"}},
					{"images": ["ghcr.io/org/nocel/**"], "cel": {"rules": []}}
				]
			}`,
			check: func(t *testing.T, pol *policy.Policy) {
				t.Helper()

				resolved := policy.ApplyRule(pol, &pol.Rules[0])
				testutil.AssertEqual(t, types.ActionDeny, resolved.SLSAMissingPolicy())
				testutil.AssertEqual(t, time.Hour, resolved.SLSA.MaxAgeDuration)

				if resolved.CompiledCEL == nil {
					t.Error("expected base CEL to be kept when the rule does not set cel")
				}

				noCEL := policy.ApplyRule(pol, &pol.Rules[1])
				if noCEL.CompiledCEL != nil {
					t.Error("expected an empty rule CEL section to clear the base CEL programs")
				}

				if noCEL.CEL == nil || len(noCEL.CEL.Rules) != 0 {
					t.Errorf("expected empty CEL rules, got %+v", noCEL.CEL)
				}
			},
		},
		{name: "unknown fields rejected", content: `{"unknownField": true}`, wantErr: errAnyError},
		{
			name:    "non-canonical section field spelling rejected",
			content: `{"slsa": {"MissingPolicy": "deny"}}`,
			wantErr: policy.ErrNonCanonicalField,
		},
		{
			name:    "non-canonical top-level field spelling rejected",
			content: `{"Mode": "enforce"}`,
			wantErr: policy.ErrNonCanonicalField,
		},
		{
			name: "non-canonical rule field spelling rejected",
			content: `{"rules": [
				{"images": ["ghcr.io/org/**"], "trust": {"SANPatterns": ["https://github.com/org/**"]}}
			]}`,
			wantErr: policy.ErrNonCanonicalField,
		},
		{
			name:    "non-canonical nested list item field spelling rejected",
			content: `{"trust": {"builders": [{"ID": "https://example.com/builder"}]}}`,
			wantErr: policy.ErrNonCanonicalField,
		},
		{
			name:    "map keys are not field names",
			content: `{"scorecard": {"checks": {"Code-Review": 5, "code-review": 6}}}`,
		},
		{name: "trailing content rejected", content: `{}{}`, wantErr: policy.ErrTrailingContent},
		{name: "missing file", wantErr: errAnyError},
		{
			name:    "validation error",
			content: `{"trust":{"builders":[{"id":"","maxLevel":0}]}}`,
			wantErr: policy.ErrBuilderIDRequired,
		},
		{
			name:    "invalid mode",
			content: `{"mode": "invalid"}`,
			wantErr: policy.ErrInvalidPolicyMode,
		},
	}

	for idx := range tests {
		test := &tests[idx]

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			policyPath := filepath.Join(t.TempDir(), "test.json")
			if test.content != "" {
				writeFile(t, policyPath, test.content)
			}

			pol, err := policy.Load(policyPath)
			assertErr(t, err, test.wantErr)

			if err == nil && test.check != nil {
				test.check(t, pol)
			}
		})
	}
}

func TestLoadAll(t *testing.T) {
	t.Parallel()

	//nolint:exhaustruct_v5 // table cases only set the fields they assert
	tests := []struct {
		name  string
		files map[string]string
		// setup prepares additional directory content.
		setup func(t *testing.T, dir string)
		// dir overrides the policy directory instead of a temporary one.
		dir          *string
		wantErr      error
		wantContains []string
		check        func(t *testing.T, dir string, policies map[string]*policy.Policy)
	}{
		{
			name: "namespaces",
			files: map[string]string{
				testDefaultJSON:    `{"slsa":{"missingPolicy":"allow"}}`,
				testProductionJSON: testDenyPolicyJSON,
			},
			check: func(t *testing.T, _ string, policies map[string]*policy.Policy) {
				t.Helper()

				testutil.AssertEqual(t, 2, len(policies))
				assertNamespaceSLSA(t, policies, "", types.ActionAllow)
				assertNamespaceSLSA(t, policies, "production", types.ActionDeny)
			},
		},
		{
			name:  "empty directory",
			files: nil,
			check: expectPolicyCount(0),
		},
		{name: "nonexistent directory", dir: new("/nonexistent/dir"), check: expectPolicyCount(0)},
		{name: "empty directory path", dir: new(""), check: expectPolicyCount(0)},
		{
			name:  "skips non-JSON files and directories",
			files: map[string]string{testDefaultJSON: `{}`, "readme.txt": `not a policy`},
			setup: func(t *testing.T, dir string) {
				t.Helper()

				testutil.AssertNoError(t, os.MkdirAll(filepath.Join(dir, "subdir"), 0o750))
			},
			check: expectPolicyCount(1),
		},
		{
			name:    "invalid JSON",
			files:   map[string]string{"bad.json": `{invalid json}`},
			wantErr: errAnyError,
		},
		{
			name: "collects errors from every file",
			files: map[string]string{
				"a.json": `{"trust":{"builders":[{"id":""}]}}`,
				"b.json": `{"trust":{"builders":[{"id":""}]}}`,
			},
			wantErr:      errAnyError,
			wantContains: []string{"a.json", "b.json"},
		},
		{
			name: "rejects invalid filename",
			files: map[string]string{
				testDefaultJSON:   `{}`,
				"Production.json": `{"mode": "enforce"}`,
			},
			wantErr: policy.ErrInvalidPolicyFilename,
		},
		{
			name:    "default cannot inherit",
			files:   map[string]string{testDefaultJSON: testInheritsJSON},
			wantErr: policy.ErrDefaultCannotInherit,
		},
		{
			name: "inherited keyless verifier uses default issuers",
			files: map[string]string{
				testDefaultJSON:     `{"trust": {"issuers": ["https://issuer.example.com"]}}`,
				testStagingJSONFile: testInheritsKeylessVerifierJSON,
			},
			check: func(t *testing.T, _ string, policies map[string]*policy.Policy) {
				t.Helper()

				staging := policies["staging"]
				testutil.AssertEqual(t, "https://issuer.example.com", joined(staging.Trust.Issuers))
				testutil.AssertEqual(t, 1, len(staging.Trust.Verifiers))
			},
		},
		{
			name: "inherited keyless verifier without default issuers",
			files: map[string]string{
				testDefaultJSON:     `{"slsa": {"missingPolicy": "deny"}}`,
				testStagingJSONFile: testInheritsKeylessVerifierJSON,
			},
			wantErr: policy.ErrKeylessVerifierRequiresIssuers,
		},
		{
			name:    "inherited keyless verifier without default policy",
			files:   map[string]string{testStagingJSONFile: testInheritsKeylessVerifierJSON},
			wantErr: policy.ErrKeylessVerifierRequiresIssuers,
		},
		{
			name: "inheriting policy clears issuers of default keyless verifier",
			files: map[string]string{
				testDefaultJSON: `{"trust": {
					"issuers": ["https://issuer.example.com"],
					"verifiers": [{"id": "https://example.com/v"}]
				}}`,
				testStagingJSONFile: `{"inherits": true, "trust": {"issuers": []}}`,
			},
			wantErr: policy.ErrKeylessVerifierRequiresIssuers,
		},
		{
			name: "rules with unknown field",
			files: map[string]string{
				testDefaultJSON: `{"rules": [{"images": ["ghcr.io/**"], "mode": "enforce"}]}`,
			},
			wantErr: errAnyError,
		},
		{
			name: "inherits merges with default",
			files: map[string]string{
				testDefaultJSON: `{
					"slsa": {"missingPolicy": "deny"},
					"include": ["docker.io/myorg/**"],
					"exclude": ["default-exclude/*"]
				}`,
				testStagingJSONFile: `{"inherits": true, "slsa": {"missingPolicy": "allow"}}`,
			},
			check: func(t *testing.T, _ string, policies map[string]*policy.Policy) {
				t.Helper()

				staging := policies["staging"]
				testutil.AssertEqual(t, types.ActionAllow, staging.SLSAMissingPolicy())
				testutil.AssertEqual(t, "default-exclude/*", joined(staging.Exclude))
				testutil.AssertEqual(t, testIncludePattern, joined(staging.Include))
			},
		},
		{
			name: "inherits merges section fields",
			files: map[string]string{
				testDefaultJSON: `{
					"slsa": {"missingPolicy": "deny", "maxAge": "720h"},
					"signatures": {"requireTransparencyLog": true}
				}`,
				testStagingJSONFile: `{
					"inherits": true,
					"slsa": {"maxAge": "24h"},
					"signatures": {"requireTransparencyLog": false}
				}`,
			},
			check: func(t *testing.T, _ string, policies map[string]*policy.Policy) {
				t.Helper()

				staging := policies["staging"]
				testutil.AssertEqual(t, types.ActionDeny, staging.SLSAMissingPolicy())
				testutil.AssertEqual(t, testMaxAge, staging.SLSA.MaxAge)
				testutil.AssertEqual(t, 24*time.Hour, staging.SLSA.MaxAgeDuration)
				testutil.AssertEqual(t, false, staging.Signatures.RequireTransparencyLog)
			},
		},
		{
			name: "inherits with explicit empty maxAge clears duration",
			files: map[string]string{
				testDefaultJSON: `{"vsa": {"maxAge": "24h"}}`,
				testDevJSON:     `{"inherits": true, "vsa": {"maxAge": ""}}`,
			},
			check: func(t *testing.T, _ string, policies map[string]*policy.Policy) {
				t.Helper()

				testutil.AssertEqual(t, time.Duration(0), policies["dev"].VSA.MaxAgeDuration)
				testutil.AssertEqual(t, 24*time.Hour, policies[""].VSA.MaxAgeDuration)
			},
		},
		{
			name: "inherits with null fields keeps default values",
			files: map[string]string{
				testDefaultJSON: `{
					"slsa": {"missingPolicy": "deny", "maxAge": "720h"},
					"signatures": {"requireTransparencyLog": true},
					"trust": {"sanPatterns": ["https://github.com/org/**"]},
					"scorecard": {"minScore": 7, "checks": {"Code-Review": 5}}
				}`,
				testDevJSON: `{
					"inherits": true,
					"slsa": {"missingPolicy": null, "maxAge": null},
					"signatures": {"requireTransparencyLog": null},
					"trust": {"sanPatterns": null},
					"scorecard": {"minScore": null, "checks": null}
				}`,
			},
			check: func(t *testing.T, _ string, policies map[string]*policy.Policy) {
				t.Helper()

				dev := policies["dev"]
				testutil.AssertEqual(t, types.ActionDeny, dev.SLSAMissingPolicy())
				testutil.AssertEqual(t, "720h", dev.SLSA.MaxAge)
				testutil.AssertEqual(t, 720*time.Hour, dev.SLSA.MaxAgeDuration)
				testutil.AssertEqual(t, true, dev.Signatures.RequireTransparencyLog)
				testutil.AssertEqual(t, "https://github.com/org/**", joined(dev.Trust.SANPatterns))

				if dev.Scorecard.MinScore == nil || *dev.Scorecard.MinScore != 7 {
					t.Errorf(
						"expected inherited scorecard.minScore 7, got %v",
						dev.Scorecard.MinScore,
					)
				}

				testutil.AssertEqual(t, 5, dev.Scorecard.Checks["Code-Review"])
			},
		},
		{
			name: "inherits false does not merge",
			files: map[string]string{
				testDefaultJSON:     `{"exclude": ["default-exclude/*"]}`,
				testStagingJSONFile: `{"inherits": false}`,
			},
			check: expectStagingExcludeNil,
		},
		{
			name: "unset inherits does not merge",
			files: map[string]string{
				testDefaultJSON:     `{"exclude": ["default-exclude/*"]}`,
				testStagingJSONFile: `{}`,
			},
			check: expectStagingExcludeNil,
		},
		{
			name: "namespace mode is kept",
			files: map[string]string{
				testDefaultJSON:    `{"slsa": {"missingPolicy": "allow"}}`,
				testProductionJSON: `{"mode": "enforce", "slsa": {"missingPolicy": "deny"}}`,
			},
			check: func(t *testing.T, _ string, policies map[string]*policy.Policy) {
				t.Helper()

				testutil.AssertEqual(t, 2, len(policies))
				testutil.AssertEqual(t, config.ModeEnforce, policies["production"].Mode)
			},
		},
		{
			name: "inherits keeps namespace mode",
			files: map[string]string{
				testDefaultJSON:     `{"slsa": {"missingPolicy": "allow"}}`,
				testStagingJSONFile: `{"inherits": true, "mode": "enforce"}`,
			},
			check: func(t *testing.T, _ string, policies map[string]*policy.Policy) {
				t.Helper()

				testutil.AssertEqual(t, config.ModeEnforce, policies["staging"].Mode)
				testutil.AssertEqual(t, types.ActionAllow, policies["staging"].SLSAMissingPolicy())
			},
		},
		{
			name: "namespace without inherits uses default mode",
			files: map[string]string{
				testDefaultJSON: `{"mode": "enforce"}`,
				"team.json":     `{"slsa": {"missingPolicy": "warn"}}`,
				testDevJSON:     `{"mode": "warn"}`,
			},
			check: func(t *testing.T, _ string, policies map[string]*policy.Policy) {
				t.Helper()

				testutil.AssertEqual(t, config.ModeEnforce, policies["team"].Mode)
				testutil.AssertEqual(t, config.ModeWarn, policies["dev"].Mode)
			},
		},
		{
			name: "rules are loaded",
			files: map[string]string{testDefaultJSON: `{
				"slsa": {"missingPolicy": "warn"},
				"rules": [
					{
						"images": ["ghcr.io/myorg/critical-*"],
						"slsa": {"missingPolicy": "deny"},
						"vex": {"missingPolicy": "deny"}
					},
					{"images": ["ghcr.io/myorg/experimental-*"], "slsa": {"missingPolicy": "allow"}}
				]
			}`},
			check: func(t *testing.T, _ string, policies map[string]*policy.Policy) {
				t.Helper()

				pol := policies[""]
				if len(pol.Rules) != 2 {
					t.Fatalf("expected 2 rules, got %d", len(pol.Rules))
				}

				testutil.AssertEqual(t, "ghcr.io/myorg/critical-*", pol.Rules[0].Images[0])
				testutil.AssertEqual(t, types.ActionDeny, pol.Rules[0].SLSA.MissingPolicy)
				testutil.AssertEqual(t, types.ActionAllow, pol.Rules[1].SLSA.MissingPolicy)
			},
		},
		{
			name: "loaded rules are isolated between loads",
			files: map[string]string{testDefaultJSON: `{
				"rules": [{"images": ["ghcr.io/**"], "slsa": {"missingPolicy": "deny"}}]
			}`},
			check: func(t *testing.T, dir string, policies map[string]*policy.Policy) {
				t.Helper()

				original := policies[""]
				if len(original.Rules) != 1 {
					t.Fatalf("expected 1 rule, got %d", len(original.Rules))
				}

				original.Rules[0].Images[0] = testMutatedValue

				reloaded, err := policy.LoadAll(dir)
				testutil.AssertNoError(t, err)

				if reloaded[""].Rules[0].Images[0] == testMutatedValue {
					t.Error("clone did not isolate rules")
				}
			},
		},
		{
			name: "inherits rules",
			files: map[string]string{
				testDefaultJSON: `{
					"slsa": {"missingPolicy": "warn"},
					"rules": [{"images": ["ghcr.io/myorg/**"], "slsa": {"missingPolicy": "deny"}}]
				}`,
				testStagingJSONFile: testInheritsJSON,
			},
			check: func(t *testing.T, _ string, policies map[string]*policy.Policy) {
				t.Helper()

				staging := policies["staging"]
				if len(staging.Rules) != 1 {
					t.Fatalf("expected 1 inherited rule, got %d", len(staging.Rules))
				}

				testutil.AssertEqual(t, types.ActionDeny, staging.Rules[0].SLSA.MissingPolicy)
			},
		},
		{
			name: "CEL is compiled",
			files: map[string]string{testDefaultJSON: `{
				"cel": {"rules": [{
					"match": "image.registry == 'ghcr.io'",
					"require": "slsa.verified == true",
					"message": "GHCR images must have SLSA provenance"
				}]}
			}`},
			check: func(t *testing.T, _ string, policies map[string]*policy.Policy) {
				t.Helper()

				pol := policies[""]
				if pol.CEL == nil || len(pol.CEL.Rules) != 1 {
					t.Fatalf("expected 1 CEL rule, got %+v", pol.CEL)
				}

				testutil.AssertEqual(t, true, pol.CompiledCEL != nil)
			},
		},
		{
			name: "inherits CEL",
			files: map[string]string{
				testDefaultJSON: `{
					"cel": {"rules": [{"require": "slsa.verified == true", "message": "default CEL rule"}]}
				}`,
				testStagingJSONFile: testInheritsJSON,
			},
			check: func(t *testing.T, _ string, policies map[string]*policy.Policy) {
				t.Helper()

				staging := policies["staging"]
				if staging.CEL == nil {
					t.Fatal("expected CEL to be inherited")
				}

				testutil.AssertEqual(t, "default CEL rule", staging.CEL.Rules[0].Message)
				testutil.AssertEqual(t, true, staging.CompiledCEL != nil)
			},
		},
		{
			name: "namespace CEL overrides inherited CEL",
			files: map[string]string{
				testDefaultJSON: `{"cel": {"rules": [{"require": "true", "message": "default"}]}}`,
				testProductionJSON: `{
					"inherits": true,
					"cel": {"rules": [{
						"require": "slsa.verified == true && vex.verified == true",
						"message": "production requires all checks"
					}]}
				}`,
			},
			check: func(t *testing.T, _ string, policies map[string]*policy.Policy) {
				t.Helper()

				prod := policies["production"]
				if prod.CEL == nil || len(prod.CEL.Rules) != 1 {
					t.Fatalf("expected 1 CEL rule, got %+v", prod.CEL)
				}

				testutil.AssertEqual(t, "production requires all checks", prod.CEL.Rules[0].Message)
				testutil.AssertEqual(t, true, prod.CompiledCEL != nil)
			},
		},
		{
			name: "inherited rules keep compiled CEL",
			files: map[string]string{
				testDefaultJSON: `{
					"rules": [{
						"images": ["ghcr.io/**"],
						"cel": {"rules": [{"require": "slsa.verified == true", "message": "inherited rule CEL"}]}
					}]
				}`,
				testStagingJSONFile: testInheritsJSON,
			},
			check: func(t *testing.T, _ string, policies map[string]*policy.Policy) {
				t.Helper()

				staging := policies["staging"]
				if len(staging.Rules) != 1 {
					t.Fatalf("expected 1 inherited rule, got %d", len(staging.Rules))
				}

				testutil.AssertEqual(t, true, staging.Rules[0].CompiledCEL != nil)
			},
		},
		{
			name: "follows ConfigMap symlinks",
			// Mimic the layout of a Kubernetes ConfigMap volume:
			// default.json -> ..data/default.json, ..data -> ..2026_01_01
			setup: func(t *testing.T, dir string) {
				t.Helper()

				dataDir := filepath.Join(dir, "..2026_01_01")
				testutil.AssertNoError(t, os.Mkdir(dataDir, 0o700))
				writeFile(
					t,
					filepath.Join(dataDir, testDefaultJSON),
					`{"slsa": {"missingPolicy": "deny"}}`,
				)
				testutil.AssertNoError(t, os.Symlink("..2026_01_01", filepath.Join(dir, "..data")))
				testutil.AssertNoError(t, os.Symlink(
					filepath.Join("..data", testDefaultJSON), filepath.Join(dir, testDefaultJSON),
				))
			},
			check: func(t *testing.T, _ string, policies map[string]*policy.Policy) {
				t.Helper()

				assertNamespaceSLSA(t, policies, "", types.ActionDeny)
			},
		},
		{
			name: "rejects symlink outside the directory",
			setup: func(t *testing.T, dir string) {
				t.Helper()

				outside := filepath.Join(t.TempDir(), "evil.json")
				writeFile(t, outside, `{}`)
				testutil.AssertNoError(t, os.Symlink(outside, filepath.Join(dir, testDefaultJSON)))
			},
			wantErr: policy.ErrPolicySymlinkOutsideDir,
		},
		{
			name: "skips hidden files and dangling editor lock symlinks",
			files: map[string]string{
				testDefaultJSON: `{"slsa": {"missingPolicy": "deny"}}`,
				".default.json": `backup {`,
				".json":         `{}`,
			},
			setup: func(t *testing.T, dir string) {
				t.Helper()

				testutil.AssertNoError(t, os.Symlink(
					"user@host.12345:1700000000", filepath.Join(dir, ".#default.json"),
				))
			},
			check: func(t *testing.T, _ string, policies map[string]*policy.Policy) {
				t.Helper()

				testutil.AssertEqual(t, 1, len(policies))
				assertNamespaceSLSA(t, policies, "", types.ActionDeny)
			},
		},
		{
			name:    "invalid visible policy file still fails the load",
			files:   map[string]string{testDefaultJSON: `{}`, testProductionJSON: `{"mode":`},
			wantErr: errAnyError,
		},
	}

	for idx := range tests {
		test := &tests[idx]

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			dir := preparePolicyDir(t, test.dir, test.files, test.setup)

			policies, err := policy.LoadAll(dir)
			assertErr(t, err, test.wantErr)
			assertErrContains(t, err, test.wantContains)

			if err == nil && test.check != nil {
				test.check(t, dir, policies)
			}
		})
	}
}

// preparePolicyDir returns dirOverride when set, otherwise a temporary
// directory populated with files and prepared by setup.
func preparePolicyDir(
	t *testing.T, dirOverride *string, files map[string]string, setup func(*testing.T, string),
) string {
	t.Helper()

	if dirOverride != nil {
		return *dirOverride
	}

	dir := t.TempDir()

	for name, content := range files {
		writeFile(t, filepath.Join(dir, name), content)
	}

	if setup != nil {
		setup(t, dir)
	}

	return dir
}

func expectPolicyCount(want int) func(*testing.T, string, map[string]*policy.Policy) {
	return func(t *testing.T, _ string, policies map[string]*policy.Policy) {
		t.Helper()

		testutil.AssertEqual(t, want, len(policies))
	}
}

func expectStagingExcludeNil(t *testing.T, _ string, policies map[string]*policy.Policy) {
	t.Helper()

	if policies["staging"].Exclude != nil {
		t.Errorf("expected nil Exclude without inheritance, got %v", policies["staging"].Exclude)
	}
}

func assertNamespaceSLSA(
	t *testing.T, policies map[string]*policy.Policy, namespace string, want types.Action,
) {
	t.Helper()

	pol, found := policies[namespace]
	if !found {
		t.Fatalf("expected policy for namespace %q", namespace)
	}

	testutil.AssertEqual(t, want, pol.SLSAMissingPolicy())
}

func TestLoadAllTooManyPolicyFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	for i := range 1001 {
		testutil.WritePolicy(t, dir, fmt.Sprintf("policy-%04d.json", i), "{}")
	}

	_, err := policy.LoadAll(dir)
	testutil.AssertErrorIs(t, err, policy.ErrTooManyPolicyFiles)
}

func TestNamespaceFromFilename(t *testing.T) {
	t.Parallel()

	tests := []struct {
		filename  string
		namespace string
		wantErr   bool
	}{
		{filename: testDefaultJSON, namespace: "", wantErr: false},
		{filename: testProductionJSON, namespace: "production", wantErr: false},
		{filename: "kube-system.json", namespace: "kube-system", wantErr: false},
		{filename: "policies/prod.json", namespace: "prod", wantErr: false},
		{filename: ".json", namespace: "", wantErr: true},
		{filename: "Prod.json", namespace: "", wantErr: true},
		{filename: "-prod.json", namespace: "", wantErr: true},
		{filename: "prod_env.json", namespace: "", wantErr: true},
		{filename: "prod.yaml", namespace: "", wantErr: true},
		{filename: "a.b.json", namespace: "", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.filename, func(t *testing.T) {
			t.Parallel()

			namespace, err := policy.NamespaceFromFilename(test.filename)
			if test.wantErr {
				testutil.AssertErrorIs(t, err, policy.ErrInvalidPolicyFilename)

				return
			}

			testutil.AssertNoError(t, err)
			testutil.AssertEqual(t, test.namespace, namespace)
		})
	}
}

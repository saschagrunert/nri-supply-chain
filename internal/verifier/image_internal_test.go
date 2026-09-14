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

package verifier

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
)

const (
	testPinnedDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testAppTagGlob   = "ghcr.io/org/app:*"
	testAppV1        = "ghcr.io/org/app:v1"
)

func TestIsIncludedNormalizesReferences(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		patterns []string
		imageRef string
		want     bool
	}{
		{
			name:     "tag pattern covers digest pinned reference",
			patterns: []string{testAppTagGlob},
			imageRef: "ghcr.io/org/app@" + testPinnedDigest,
			want:     true,
		},
		{
			name:     "tag pattern does not cover other repository",
			patterns: []string{testAppTagGlob},
			imageRef: "ghcr.io/org/other@" + testPinnedDigest,
			want:     false,
		},
		{
			name:     "short name matches docker hub pattern",
			patterns: []string{testNginxTagGlob},
			imageRef: "nginx:1.27",
			want:     true,
		},
		{
			name:     "index docker io spelling matches docker io pattern",
			patterns: []string{"docker.io/myorg/**"},
			imageRef: "index.docker.io/myorg/app:v1",
			want:     true,
		},
		{
			name:     "user shorthand matches docker hub pattern",
			patterns: []string{"docker.io/myorg/*"},
			imageRef: "myorg/app:v1",
			want:     true,
		},
		{
			name:     "tag and digest reference matches tag pattern",
			patterns: []string{testAppV1},
			imageRef: testAppV1 + "@" + testPinnedDigest,
			want:     true,
		},
		{
			name:     "unrelated image",
			patterns: []string{"ghcr.io/org/**"},
			imageRef: "quay.io/other/app:v1",
			want:     false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := isIncluded(t.Context(), test.patterns, test.imageRef); got != test.want {
				t.Errorf(
					"isIncluded(%v, %q) = %v, want %v",
					test.patterns,
					test.imageRef,
					got,
					test.want,
				)
			}
		})
	}
}

func TestIsExcludedIsConservative(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		patterns []string
		imageRef string
		want     bool
	}{
		{
			name:     "raw reference",
			patterns: []string{"registry.k8s.io/**"},
			imageRef: "registry.k8s.io/pause:3.10",
			want:     true,
		},
		{
			name:     "qualified docker hub spelling is normalized",
			patterns: []string{"docker.io/library/busybox:*"},
			imageRef: "index.docker.io/library/busybox:1.36",
			want:     true,
		},
		{
			name:     "short name is not normalized",
			patterns: []string{"docker.io/library/busybox:*"},
			imageRef: "busybox:1.36",
			want:     false,
		},
		{
			name:     "tag pattern does not cover digest pinned reference",
			patterns: []string{testAppTagGlob},
			imageRef: "ghcr.io/org/app@" + testPinnedDigest,
			want:     false,
		},
		{
			name:     "repository pattern does not cover tags",
			patterns: []string{"ghcr.io/org/app"},
			imageRef: testAppV1,
			want:     false,
		},
		{
			name:     "exact tag does not cover a digest behind that tag",
			patterns: []string{testAppV1},
			imageRef: testAppV1 + "@" + testPinnedDigest,
			want:     false,
		},
		{
			name:     "normalized tag does not cover a digest behind that tag",
			patterns: []string{"docker.io/library/busybox:1.36"},
			imageRef: "index.docker.io/library/busybox:1.36@" + testPinnedDigest,
			want:     false,
		},
		{
			name:     "digest pattern covers tagged digest reference",
			patterns: []string{"ghcr.io/org/app@" + testPinnedDigest},
			imageRef: testAppV1 + "@" + testPinnedDigest,
			want:     true,
		},
		{
			name:     "partial tag wildcard does not cover a digest behind a matching tag",
			patterns: []string{"ghcr.io/org/app:v1*"},
			imageRef: "ghcr.io/org/app:v1.0@" + testPinnedDigest,
			want:     false,
		},
		{
			name:     "tag wildcard does not cover a digest behind a tag",
			patterns: []string{testAppTagGlob},
			imageRef: testAppV1 + "@" + testPinnedDigest,
			want:     false,
		},
		{
			name:     "short name partial tag wildcard does not cover a digest",
			patterns: []string{"app:dev-*"},
			imageRef: "app:dev-1@" + testPinnedDigest,
			want:     false,
		},
		{
			name:     "digest wildcard covers tagged digest reference",
			patterns: []string{"ghcr.io/org/app@sha256:*"},
			imageRef: testAppV1 + "@" + testPinnedDigest,
			want:     true,
		},
		{
			name:     "repository-wide wildcard covers tagged digest reference",
			patterns: []string{"ghcr.io/org/**"},
			imageRef: testAppV1 + "@" + testPinnedDigest,
			want:     true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := isExcluded(t.Context(), test.patterns, test.imageRef); got != test.want {
				t.Errorf(
					"isExcluded(%v, %q) = %v, want %v",
					test.patterns,
					test.imageRef,
					got,
					test.want,
				)
			}

			rulePolicy := &policy.Policy{Rules: []policy.ImageRule{{Images: test.patterns}}}

			_, ruleIdx := ResolveImagePolicy(t.Context(), rulePolicy, test.imageRef)
			if matched := ruleIdx == 0; matched != test.want {
				t.Errorf(
					"rule images %v matched %q = %v, want %v",
					test.patterns,
					test.imageRef,
					matched,
					test.want,
				)
			}
		})
	}
}

func TestValidatePoliciesAgainstConfig(t *testing.T) {
	t.Parallel()

	enforcing := map[string]*policy.Policy{
		"":     {Mode: ""},
		"prod": {Mode: config.ModeEnforce},
	}
	warning := map[string]*policy.Policy{"": {Mode: ""}}

	insecure := config.DefaultConfig()
	insecure.Verification = config.ModeWarn
	insecure.Registries = []config.Registry{
		{Prefix: "registry.local", Mirror: "", CACert: "", Insecure: true},
	}

	err := validatePoliciesAgainstConfig(insecure, enforcing)
	testutil.AssertErrorIs(t, err, config.ErrInsecureRegistryInEnforceMode)

	err = validatePoliciesAgainstConfig(insecure, warning)
	testutil.AssertNoError(t, err)

	unsigned := config.DefaultConfig()
	unsigned.Verification = config.ModeWarn
	unsigned.Policy.Source = config.PolicySourceOCI
	unsigned.Policy.OCIRef = "ghcr.io/org/policies:v1"

	err = validatePoliciesAgainstConfig(unsigned, enforcing)
	testutil.AssertErrorIs(t, err, config.ErrPolicyOCIUnsignedInEnforce)
}

func TestDisabledModeIgnoresPolicyModes(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{"mode": "enforce"}`)
	testutil.WritePolicy(t, dir, "prod.json", `{"mode": "enforce"}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeDisabled
	cfg.PolicyDir = dir

	// The global disabled mode is the emergency kill switch: policies that
	// set a mode must neither block startup nor a reload into disabled mode.
	verif, err := New(t.Context(), cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)

	defer verif.Stop()

	if verif.Enforcing() {
		t.Error("expected disabled verifier not to enforce")
	}

	enforce := config.DefaultConfig()
	enforce.Verification = config.ModeEnforce
	enforce.PolicyDir = dir

	err = verif.Reload(t.Context(), enforce)
	testutil.AssertNoError(t, err)

	err = verif.Reload(t.Context(), cfg)
	testutil.AssertNoError(t, err)

	if verif.Enforcing() {
		t.Error("expected reload into disabled mode to stop enforcing")
	}
}

func TestReloadRefusesEmptyPolicySet(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{"slsa": {"missingPolicy": "warn"}}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir

	verif, err := New(t.Context(), cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)

	defer verif.Stop()

	testutil.AssertNoError(t, os.Remove(filepath.Join(dir, "default.json")))

	err = verif.Reload(t.Context(), cfg)
	testutil.AssertErrorIs(t, err, ErrNoPolicies)

	if count := verif.Status().Policies.Count; count != 1 {
		t.Errorf("expected the previous policy to stay loaded, got %d policies", count)
	}
}

func TestPolicyUpdateRefusesEmptyPolicySet(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir

	verif, err := New(t.Context(), cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)

	defer verif.Stop()

	err = verif.onPolicyUpdate(t.Context(), map[string]*policy.Policy{})
	testutil.AssertErrorIs(t, err, ErrNoPolicies)
}

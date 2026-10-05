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
	"bytes"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
)

func TestTagScopedPatterns(t *testing.T) {
	t.Parallel()

	patterns := []string{
		"ghcr.io/org/app:prod-*", //nolint:goconst // test data
		"nginx:1.27",
		"localhost:5000/app",
		"localhost:5000/app:v1",
		"ghcr.io/org/**",
		"ghcr.io/org/app@sha256:*",
		"ghcr.io/org/app:v1@sha256:*",
	}

	got := policy.TagScopedPatternsForTest(patterns)
	want := []string{"ghcr.io/org/app:prod-*", "nginx:1.27", "localhost:5000/app:v1"}

	if !slices.Equal(got, want) {
		t.Errorf("tagScopedPatterns = %v, want %v", got, want)
	}
}

//nolint:paralleltest // replaces the default logger to capture the warning
func TestValidateWarnsAboutTagScopedRules(t *testing.T) {
	var logs bytes.Buffer

	previous := slog.Default()

	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))

	t.Cleanup(func() { slog.SetDefault(previous) })

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{
		"exclude": ["ghcr.io/org/debug:*"],
		"rules": [
			{"images": ["ghcr.io/org/app:prod-*"], "slsa": {"missingPolicy": "deny"}},
			{"images": ["ghcr.io/org/api:*", "ghcr.io/org/api@*"], "slsa": {"missingPolicy": "deny"}}
		]
	}`)

	_, err := policy.LoadAll(dir)
	testutil.AssertNoError(t, err)

	output := logs.String()

	for _, pattern := range []string{"ghcr.io/org/debug:*", "ghcr.io/org/app:prod-*"} {
		if !strings.Contains(output, pattern) {
			t.Errorf(
				"expected a message about the tag-scoped pattern %q, got logs:\n%s",
				pattern, output,
			)
		}
	}

	if strings.Contains(output, "ghcr.io/org/api:*") {
		t.Errorf(
			"expected no warning for a rule that also covers digest-pinned references, got logs:\n%s",
			output,
		)
	}
}

//nolint:paralleltest // replaces the default logger to capture the warning
func TestValidateWarnsAboutUppercasePatterns(t *testing.T) {
	var logs bytes.Buffer

	previous := slog.Default()

	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))

	t.Cleanup(func() { slog.SetDefault(previous) })

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{
		"include": ["ghcr.io/Org/**", "ghcr.io/org/app:Latest", "ghcr.io/org/api@sha256:ABC*"],
		"exclude": ["ghcr.io/Org/debug@*"],
		"rules": [{"images": ["ghcr.io/Org/critical@*"], "slsa": {"missingPolicy": "deny"}}]
	}`)

	_, err := policy.LoadAll(dir)
	testutil.AssertNoError(t, err)

	output := logs.String()

	// A rule or an exclude pattern that never matches is as easy to miss as
	// an include pattern.
	for _, pattern := range []string{
		"ghcr.io/Org/**", "ghcr.io/org/api@sha256:ABC*",
		"ghcr.io/Org/debug@*", "ghcr.io/Org/critical@*",
	} {
		if !strings.Contains(output, pattern) {
			t.Errorf("expected a warning about %q, got logs:\n%s", pattern, output)
		}
	}

	// Tags may contain uppercase characters.
	if strings.Contains(output, "ghcr.io/org/app:Latest") {
		t.Errorf("expected no warning for an uppercase tag, got logs:\n%s", output)
	}
}

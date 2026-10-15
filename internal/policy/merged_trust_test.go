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
	"strings"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
)

func TestLoadAllRejectsVerifierKeySharedWithInheritedBuilder(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{
		"trust": {"builders": [{"id": "https://builder.example.com", "keys": ["/k/b.pem"]}]}
	}`)
	testutil.WritePolicy(t, dir, "prod.json", `{
		"inherits": true,
		"trust": {"verifiers": [{"id": "https://verifier.example.com", "keys": ["/k/./b.pem"]}]}
	}`)

	_, err := policy.LoadAll(dir)
	testutil.AssertErrorIs(t, err, policy.ErrDuplicateKeyAcrossVerifiers)
	testutil.AssertContains(t, err.Error(), `namespace "prod"`)
}

func TestLoadAllRejectsRuleVerifierKeySharedWithBaseBuilder(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{
		"trust": {"builders": [{"id": "https://builder.example.com", "keys": ["/k/b.pem"]}]},
		"rules": [{
			"images": ["ghcr.io/org/app@*"],
			"trust": {"verifiers": [{"id": "https://verifier.example.com", "keys": ["/k/b.pem"]}]}
		}]
	}`)

	_, err := policy.LoadAll(dir)
	testutil.AssertErrorIs(t, err, policy.ErrDuplicateKeyAcrossVerifiers)
	testutil.AssertContains(t, err.Error(), "rules[0]")
}

//nolint:paralleltest // replaces the default logger to capture the warning
func TestTrustWarningsRunOnMergedPolicies(t *testing.T) {
	var logs bytes.Buffer

	previous := slog.Default()

	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))

	t.Cleanup(func() { slog.SetDefault(previous) })

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{
		"trust": {
			"issuers": ["https://token.actions.githubusercontent.com"],
			"sanPatterns": ["https://github.com/org/**"]
		},
		"rules": [{"images": ["ghcr.io/org/app@*"], "trust": {"sources": ["https://github.com/org/*"]}}]
	}`)
	testutil.WritePolicy(t, dir, "prod.json", `{
		"inherits": true,
		"trust": {"sources": ["https://github.com/org/*"]}
	}`)

	_, err := policy.LoadAll(dir)
	testutil.AssertNoError(t, err)

	if strings.Contains(logs.String(), "trust section is configured but has no builders") {
		t.Errorf(
			"expected no empty trust warning for partial trust sections, got logs:\n%s",
			logs.String(),
		)
	}

	logs.Reset()

	testutil.WritePolicy(
		t,
		dir,
		"default.json",
		`{"trust": {"sources": ["https://github.com/org/*"]}}`,
	)

	_, err = policy.LoadAll(dir)
	testutil.AssertNoError(t, err)

	if !strings.Contains(logs.String(), "trust section is configured but has no builders") {
		t.Errorf(
			"expected an empty trust warning for a complete policy, got logs:\n%s",
			logs.String(),
		)
	}
}

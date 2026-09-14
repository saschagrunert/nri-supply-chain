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

package slsa_test

import (
	"context"
	"errors"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/slsa"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	testGitCommit   = "7d5b4f8a0f0e2c1b9a8d7c6b5a4f3e2d1c0b9a8f"
	testWorkflowRef = "refs/heads/main"

	testKeyRepository = "repository"
	testKeyRef        = "ref"
)

var errNotAuthorized = errors.New("signer not authorized")

func rawStatement(
	buildType string, params map[string]any, deps []map[string]any,
) map[string]any {
	buildDefinition := map[string]any{
		"buildType":          buildType,
		"externalParameters": params,
	}

	if deps != nil {
		buildDefinition["resolvedDependencies"] = deps
	}

	return map[string]any{
		"_type": testutil.InTotoStatementType,
		"subject": []map[string]any{
			{
				"name":        testSubjectName,
				testKeyDigest: map[string]string{testDigestAlgo: testDigestHash},
			},
		},
		"predicateType": attestation.PredicateSLSAProvenanceV1,
		"predicate": map[string]any{
			"buildDefinition": buildDefinition,
			"runDetails": map[string]any{
				"builder": map[string]any{"id": testBuilderID},
			},
		},
	}
}

func workflowParams(repository, ref string) map[string]any {
	return map[string]any{
		"workflow": map[string]any{
			testKeyRepository: repository,
			testKeyRef:        ref,
			"path":            testWorkflow,
		},
	}
}

func sourcePolicy() *policy.Policy {
	return &policy.Policy{
		Trust: &policy.TrustPolicy{
			Sources: []string{testSourceGlob},
		},
	}
}

func TestVerifySourceByBuildType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		stmt       map[string]any
		wantPass   bool
		wantSource string
		wantRef    string
	}{
		{
			name: "GitHub artifact attestation workflow layout",
			stmt: rawStatement(slsa.BuildTypeGitHubActionsWorkflow,
				workflowParams(testSource, testWorkflowRef), nil),
			wantPass:   true,
			wantSource: testSource,
			wantRef:    testWorkflowRef,
		},
		{
			name: "slsa-github-generator workflow layout",
			stmt: rawStatement(slsa.BuildTypeSLSAGitHubWorkflow,
				workflowParams(testSource, testWorkflowRef), nil),
			wantPass:   true,
			wantSource: testSource,
			wantRef:    testWorkflowRef,
		},
		{
			name: "Cloud Build sourceToBuild layout",
			stmt: rawStatement(slsa.BuildTypeGCBTriggered, map[string]any{
				testKeySourceToBuild: map[string]any{
					testKeyRepository: "git+" + testSource,
					testKeyRef:        testWorkflowRef,
				},
			}, nil),
			wantPass:   true,
			wantSource: testSource,
			wantRef:    testWorkflowRef,
		},
		{
			name: "untrusted workflow repository",
			stmt: rawStatement(slsa.BuildTypeGitHubActionsWorkflow,
				workflowParams("https://github.com/evil/repo", testWorkflowRef), nil),
			wantPass:   false,
			wantSource: "",
			wantRef:    "",
		},
		{
			name: "generic source with git ref suffix",
			stmt: rawStatement("https://builder.example.com/v1", map[string]any{
				testKeySource: "git+" + testSource + "@" + testWorkflowRef,
			}, nil),
			wantPass:   true,
			wantSource: testSource,
			wantRef:    testWorkflowRef,
		},
		{
			name: "ssh authority is not treated as a ref",
			stmt: rawStatement("https://builder.example.com/v1", map[string]any{
				testKeySource: "git+ssh://git@github.com/example/repo@" + testWorkflowRef,
			}, nil),
			wantPass:   false,
			wantSource: "",
			wantRef:    "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			result, err := slsa.Verify(context.Background(),
				testutil.MustMarshal(t, tc.stmt), sourcePolicy(), testDigest)
			testutil.AssertNoError(t, err)
			testutil.AssertEqual(t, tc.wantPass, result.Passed)

			if !tc.wantPass {
				return
			}

			testutil.AssertEqual[any](t, tc.wantSource, result.Metadata[testKeySource])
			testutil.AssertEqual[any](t, tc.wantRef, result.Metadata["sourceRef"])
		})
	}
}

func TestVerifyResolvedDependencies(t *testing.T) {
	t.Parallel()

	dependency := func(uri string, digest map[string]string) map[string]any {
		return map[string]any{testKeyURI: uri, testKeyDigest: digest}
	}

	tests := []struct {
		name       string
		deps       []map[string]any
		wantPass   bool
		wantDigest string
	}{
		{
			name: "matching ref and digest",
			deps: []map[string]any{
				dependency(
					"git+"+testSource+"@"+testWorkflowRef,
					map[string]string{testKeyGitCommit: testGitCommit},
				),
			},
			wantPass:   true,
			wantDigest: "gitCommit:" + testGitCommit,
		},
		{
			name: "different ref",
			deps: []map[string]any{
				dependency(
					"git+"+testSource+"@refs/heads/feature",
					map[string]string{testKeyGitCommit: testGitCommit},
				),
			},
			wantPass:   false,
			wantDigest: "",
		},
		{
			name: "missing digest",
			deps: []map[string]any{
				dependency("git+"+testSource+"@"+testWorkflowRef, nil),
			},
			wantPass:   false,
			wantDigest: "",
		},
		{
			name: "unrelated dependencies are ignored",
			deps: []map[string]any{
				dependency("https://github.com/actions/checkout@v4", nil),
			},
			wantPass:   true,
			wantDigest: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			stmt := rawStatement(slsa.BuildTypeGitHubActionsWorkflow,
				workflowParams(testSource, testWorkflowRef), tc.deps)

			result, err := slsa.Verify(context.Background(),
				testutil.MustMarshal(t, stmt), sourcePolicy(), testDigest)
			testutil.AssertNoError(t, err)
			testutil.AssertEqual(t, tc.wantPass, result.Passed)

			if tc.wantPass {
				testutil.AssertEqual[any](t, tc.wantDigest, result.Metadata["sourceDigest"])
			} else {
				testutil.AssertContains(t, result.Detail, "resolved dependencies")
			}
		})
	}
}

func TestVerifyEmptyTrustWarns(t *testing.T) {
	t.Parallel()

	result, err := slsa.Verify(context.Background(),
		testutil.MustMarshal(t, validStatement()), &policy.Policy{}, testDigest)
	testutil.AssertNoError(t, err)
	testutil.AssertTrue(t, result.Passed)
	testutil.AssertEqual(t, types.StatusWarn, result.Status)
	testutil.AssertContains(t, result.Detail, "no trusted builders")
	testutil.AssertEqual[any](t, false, result.Metadata["trustConfigured"])
}

func TestVerifyMultipleBindBuilder(t *testing.T) {
	t.Parallel()

	pol := &policy.Policy{
		Trust: &policy.TrustPolicy{
			Builders: []policy.TrustedBuilder{
				{ID: testBuilderID, MaxLevel: 0},
				{ID: "https://other.example.com", MaxLevel: 0},
			},
		},
	}

	atts := []attestation.VerifiedAttestation{
		{
			Payload: testutil.MustMarshal(t, validStatement()),
		},
	}

	t.Run("hook receives matched builders and can accept", func(t *testing.T) {
		t.Parallel()

		var matchedIDs []string

		result, err := slsa.VerifyMultipleWithOptions(context.Background(), atts, pol, testDigest,
			&slsa.VerifyOptions{
				BindBuilder: func(_ *attestation.VerifiedAttestation, matched []policy.TrustedBuilder) error {
					for idx := range matched {
						matchedIDs = append(matchedIDs, matched[idx].ID)
					}

					return nil
				},
			})
		testutil.AssertNoError(t, err)
		testutil.AssertTrue(t, result.Passed)
		testutil.AssertEqual(t, 1, len(matchedIDs))
		testutil.AssertEqual(t, testBuilderID, matchedIDs[0])
	})

	t.Run("hook rejection fails the attestation", func(t *testing.T) {
		t.Parallel()

		result, err := slsa.VerifyMultipleWithOptions(context.Background(), atts, pol, testDigest,
			&slsa.VerifyOptions{
				BindBuilder: func(_ *attestation.VerifiedAttestation, _ []policy.TrustedBuilder) error {
					return errNotAuthorized
				},
			})
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, false, result.Passed)
		testutil.AssertContains(t, result.Detail, "signer not authorized")
	})
}

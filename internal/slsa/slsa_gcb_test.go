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
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/slsa"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
)

const (
	testGCBRepository = "https://github.com/GoogleCloudPlatform/cloud-build-samples"
	testGCBCommit     = "bb0fe8075f92bb82b679afe400a47b106f0cec4b"
	testTagRef        = "refs/tags/v1"
	testMetaSourceRef = "sourceRef"
	testMetaDigest    = "sourceDigest"
	testDigestSHA1    = "sha1:"

	testKeyURI           = "uri"
	testKeyDigest        = "digest"
	testKeyConfigSource  = "configSource"
	testKeySourceToBuild = "sourceToBuild"
	testKeyGitCommit     = "gitCommit"
)

// gcbSpecExample is the triggered-build v1 example from
// https://github.com/slsa-framework/gcb-buildtypes (triggered-build/v1),
// with the subject digest replaced by the test digest.
//
//nolint:lll // verbatim specification example
const gcbSpecExample = `{
  "_type": "https://in-toto.io/Statement/v1",
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://slsa-framework.github.io/gcb-buildtypes/triggered-build/v1",
      "externalParameters": {
        "configSource": {
          "ref": "refs/heads/main",
          "repository": "https://github.com/GoogleCloudPlatform/cloud-build-samples",
          "path": "basic-config/cloudbuild.yaml"
        },
        "sourceToBuild": {
          "dir": "basic-config"
        },
        "substitutions": {
          "count": "3",
          "mass": "1.3kg",
          "name": "wrench"
        }
      },
      "resolvedDependencies": [
        {
          "uri": "git+https://github.com/GoogleCloudPlatform/cloud-build-samples@refs/heads/main",
          "digest": { "sha1": "bb0fe8075f92bb82b679afe400a47b106f0cec4b" }
        }
      ]
    },
    "runDetails": {
      "metadata": {
        "invocationId": "https://cloudbuild.googleapis.com/v1/projects/cloud-build-samples-project/locations/us-west1/builds/03eb98be-0390-4b05-b861-ef52ed4d2a34",
        "startedOn": "2023-01-01T12:34:56Z"
      }
    }
  },
  "subject": [
    {
      "name": "_",
      "digest": { "sha256": "%DIGEST%" }
    }
  ]
}`

func gcbPolicy(sources ...string) *policy.Policy {
	return &policy.Policy{Trust: &policy.TrustPolicy{Sources: sources}}
}

func TestVerifyGCBSpecExample(t *testing.T) {
	t.Parallel()

	att := []byte(strings.Replace(gcbSpecExample, "%DIGEST%", testDigestHash, 1))

	result, err := slsa.Verify(context.Background(), att,
		gcbPolicy("https://github.com/GoogleCloudPlatform/*"), testDigest)
	testutil.AssertNoError(t, err)
	testutil.AssertTrue(t, result.Passed)
	testutil.AssertEqual[any](t, testGCBRepository, result.Metadata[testKeySource])
	testutil.AssertEqual[any](t, testWorkflowRef, result.Metadata[testMetaSourceRef])
	testutil.AssertEqual[any](t, testDigestSHA1+testGCBCommit, result.Metadata[testMetaDigest])
}

func TestVerifyGCBSourceLayouts(t *testing.T) {
	t.Parallel()

	gitDep := func(ref, commit string) []map[string]any {
		return []map[string]any{{
			testKeyURI:    "git+" + testSource + "@" + ref,
			testKeyDigest: map[string]string{"sha1": commit},
		}}
	}

	tests := []struct {
		name       string
		params     map[string]any
		deps       []map[string]any
		wantPass   bool
		wantRef    string
		wantDigest string
		wantDetail string
	}{
		{
			name: "sourceToBuild repository overrides configSource",
			params: map[string]any{
				testKeyConfigSource: map[string]any{
					testKeyRepository: "https://github.com/example/config",
					testKeyRef:        testWorkflowRef,
				},
				testKeySourceToBuild: map[string]any{
					testKeyRepository: testSource, testKeyRef: testTagRef,
				},
			},
			deps:       nil,
			wantPass:   true,
			wantRef:    testTagRef,
			wantDigest: "",
			wantDetail: "",
		},
		{
			name: "configSource used when sourceToBuild has no repository",
			params: map[string]any{
				testKeyConfigSource: map[string]any{
					testKeyRepository: testSource, testKeyRef: testWorkflowRef,
				},
				testKeySourceToBuild: map[string]any{"dir": "app"},
			},
			deps:       nil,
			wantPass:   true,
			wantRef:    testWorkflowRef,
			wantDigest: "",
			wantDetail: "",
		},
		{
			name: "commit SHA ref skips ref comparison with branch dependency",
			params: map[string]any{
				testKeyConfigSource: map[string]any{
					testKeyRepository: testSource, testKeyRef: testGCBCommit,
				},
			},
			deps:       gitDep(testWorkflowRef, testGCBCommit),
			wantPass:   true,
			wantRef:    testGCBCommit,
			wantDigest: testDigestSHA1 + testGCBCommit,
			wantDetail: "",
		},
		{
			name: "commit SHA ref must match dependency digest",
			params: map[string]any{
				testKeyConfigSource: map[string]any{
					testKeyRepository: testSource, testKeyRef: testGCBCommit,
				},
			},
			deps:       gitDep(testWorkflowRef, testGitCommit),
			wantPass:   false,
			wantRef:    "",
			wantDigest: "",
			wantDetail: "resolved commit",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			stmt := rawStatement(slsa.BuildTypeGCBTriggered, tc.params, tc.deps)

			result, err := slsa.Verify(context.Background(),
				testutil.MustMarshal(t, stmt), sourcePolicy(), testDigest)
			testutil.AssertNoError(t, err)
			testutil.AssertEqual(t, tc.wantPass, result.Passed)

			if !tc.wantPass {
				testutil.AssertContains(t, result.Detail, tc.wantDetail)

				return
			}

			testutil.AssertEqual[any](t, testSource, result.Metadata[testKeySource])
			testutil.AssertEqual[any](t, tc.wantRef, result.Metadata[testMetaSourceRef])
			testutil.AssertEqual[any](t, tc.wantDigest, result.Metadata[testMetaDigest])
		})
	}
}

func TestVerifyGCBConfigSourceAtAnotherRef(t *testing.T) {
	t.Parallel()

	stmt := rawStatement(slsa.BuildTypeGCBTriggered, map[string]any{
		testKeyConfigSource: map[string]any{
			testKeyRepository: testSource, testKeyRef: "refs/heads/evil",
		},
		testKeySourceToBuild: map[string]any{
			testKeyRepository: testSource, testKeyRef: testTagRef,
		},
	}, nil)

	result, err := slsa.Verify(context.Background(),
		testutil.MustMarshal(t, stmt), gcbPolicy("git+"+testSource+"@refs/tags/*"), testDigest)
	testutil.AssertNoError(t, err)

	if result.Passed {
		t.Error(
			"expected a build configuration from an untrusted ref of the same repository to fail",
		)
	}
}

func TestVerifySCPStyleGitSources(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		params   map[string]any
		pattern  string
		wantPass bool
	}{
		{
			name:     "scp-style source matches its repository pattern",
			params:   map[string]any{testKeySource: "git@github.com:example/repo"},
			pattern:  "git@github.com:example/*",
			wantPass: true,
		},
		{
			name:     "scp-style source with ref matches a ref-pinned pattern",
			params:   map[string]any{testKeySource: "git@github.com:example/repo@" + testTagRef},
			pattern:  "git@github.com:example/repo@refs/tags/*",
			wantPass: true,
		},
		{
			name: "ref text naming the trusted repository does not match another repository",
			params: map[string]any{
				testKeySource: "git@evil.example:attacker/repo",
				testKeyRef:    "github.com:example/repo@refs/tags/v1",
			},
			pattern:  "git@github.com:example/repo@refs/tags/*",
			wantPass: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			stmt := rawStatement("https://example.com/custom-build/v1", tc.params, nil)

			result, err := slsa.Verify(context.Background(),
				testutil.MustMarshal(t, stmt), gcbPolicy(tc.pattern), testDigest)
			testutil.AssertNoError(t, err)
			testutil.AssertEqual(t, tc.wantPass, result.Passed)
		})
	}
}

func TestVerifyObjectShapedSourceParameter(t *testing.T) {
	t.Parallel()

	stmt := rawStatement(
		"https://slsa-framework.github.io/container-based-build/v0.1",
		map[string]any{
			testKeySource: map[string]any{
				testKeyURI:    "git+" + testSource + "@" + testWorkflowRef,
				testKeyDigest: map[string]string{"sha1": testGCBCommit},
			},
		},
		nil,
	)

	result, err := slsa.Verify(context.Background(),
		testutil.MustMarshal(t, stmt), sourcePolicy(), testDigest)
	testutil.AssertNoError(t, err)
	testutil.AssertTrue(t, result.Passed)
	testutil.AssertEqual[any](t, testSource, result.Metadata[testKeySource])
	testutil.AssertEqual[any](t, testWorkflowRef, result.Metadata[testMetaSourceRef])
	testutil.AssertEqual[any](t, testDigestSHA1+testGCBCommit, result.Metadata[testMetaDigest])
}

func TestVerifyRefPinnedSourcePatterns(t *testing.T) {
	t.Parallel()

	tagPattern := "git+" + testSource + "@refs/tags/*"

	tests := []struct {
		name     string
		params   map[string]any
		wantPass bool
	}{
		{
			name:     "raw source URI with tag matches ref-pinned pattern",
			params:   map[string]any{testKeySource: "git+" + testSource + "@" + testTagRef},
			wantPass: true,
		},
		{
			name:     "raw source URI with branch does not match tag pattern",
			params:   map[string]any{testKeySource: "git+" + testSource + "@" + testWorkflowRef},
			wantPass: false,
		},
		{
			name:     "workflow layout with tag ref matches ref-pinned pattern",
			params:   workflowParams(testSource, testTagRef),
			wantPass: true,
		},
		{
			name:     "workflow layout with branch ref does not match tag pattern",
			params:   workflowParams(testSource, testWorkflowRef),
			wantPass: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			stmt := rawStatement(slsa.BuildTypeGitHubActionsWorkflow, tc.params, nil)

			result, err := slsa.Verify(context.Background(),
				testutil.MustMarshal(t, stmt), gcbPolicy(tagPattern), testDigest)
			testutil.AssertNoError(t, err)
			testutil.AssertEqual(t, tc.wantPass, result.Passed)
		})
	}
}

func TestVerifyResolvedDependencyRefKinds(t *testing.T) {
	t.Parallel()

	dep := func(ref string) []map[string]any {
		return []map[string]any{{
			testKeyURI:    "git+" + testSource + "@" + ref,
			testKeyDigest: map[string]string{testKeyGitCommit: testGitCommit},
		}}
	}

	tests := []struct {
		name      string
		sourceRef string
		depRef    string
		wantPass  bool
	}{
		{
			name:      "tag and branch with same name differ",
			sourceRef: testTagRef,
			depRef:    "refs/heads/v1",
			wantPass:  false,
		},
		{
			name:      "short name matches qualified tag",
			sourceRef: "v1",
			depRef:    testTagRef,
			wantPass:  true,
		},
		{
			name:      "qualified tag matches short name",
			sourceRef: testTagRef,
			depRef:    "v1",
			wantPass:  true,
		},
		{name: "identical refs", sourceRef: testTagRef, depRef: testTagRef, wantPass: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			stmt := rawStatement(slsa.BuildTypeGitHubActionsWorkflow,
				workflowParams(testSource, tc.sourceRef), dep(tc.depRef))

			result, err := slsa.Verify(context.Background(),
				testutil.MustMarshal(t, stmt), sourcePolicy(), testDigest)
			testutil.AssertNoError(t, err)
			testutil.AssertEqual(t, tc.wantPass, result.Passed)
		})
	}
}

func TestVerifyZeroStartedOnTreatedAsAbsent(t *testing.T) {
	t.Parallel()

	stmt := validStatement()
	zero := time.Time{}
	stmt.Predicate.RunDetails.Metadata.StartedOn = &zero

	payload, err := json.Marshal(stmt)
	testutil.AssertNoError(t, err)

	t.Run("without maxAge passes", func(t *testing.T) {
		t.Parallel()

		pol := &policy.Policy{
			Trust: &policy.TrustPolicy{Builders: []policy.TrustedBuilder{{ID: testBuilderID}}},
		}

		result, verifyErr := slsa.Verify(context.Background(), payload, pol, testDigest)
		testutil.AssertNoError(t, verifyErr)
		testutil.AssertTrue(t, result.Passed)
	})

	t.Run("with maxAge is missing", func(t *testing.T) {
		t.Parallel()

		pol := &policy.Policy{
			Trust: &policy.TrustPolicy{Builders: []policy.TrustedBuilder{{ID: testBuilderID}}},
			SLSA:  &policy.SLSAPolicy{MaxAge: testMaxAge, MaxAgeDuration: 24 * time.Hour},
		}

		result, verifyErr := slsa.Verify(context.Background(), payload, pol, testDigest)
		testutil.AssertNoError(t, verifyErr)
		testutil.AssertEqual(t, false, result.Passed)
		testutil.AssertContains(t, result.Detail, "no build timestamp")
	})
}

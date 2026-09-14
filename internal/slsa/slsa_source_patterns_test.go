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
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/slsa"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
)

const (
	testCommitSHA256 = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"
	testEvilRef      = "refs/heads/evil"
	testKeySHA256    = "sha256"
	testKeySHA1      = "sha1"
	testCustomBuild  = "https://example.com/custom-build/v1"
	testTagPattern   = "@refs/tags/*"
)

func TestVerifySourcePatternMatching(t *testing.T) {
	t.Parallel()

	mainPinned := "git+" + testSource + "@" + testWorkflowRef

	tests := []struct {
		name      string
		buildType string
		pattern   string
		params    map[string]any
		wantPass  bool
	}{
		{
			name:      "explicit ref overrides a ref embedded in the source URI",
			buildType: testCustomBuild,
			pattern:   mainPinned,
			params: map[string]any{
				testKeySource: mainPinned,
				testKeyRef:    testEvilRef,
			},
			wantPass: false,
		},
		{
			name:      "explicit workflow ref overrides a ref embedded in the repository",
			buildType: slsa.BuildTypeGitHubActionsWorkflow,
			pattern:   mainPinned,
			params:    workflowParams(mainPinned, testEvilRef),
			wantPass:  false,
		},
		{
			name:      "ref text cannot satisfy a repository wildcard",
			buildType: testCustomBuild,
			pattern:   "https://github.com/example/*-prod",
			params:    map[string]any{testKeySource: "https://github.com/example/evil@x-prod"},
			wantPass:  false,
		},
		{
			name:      "ref text cannot satisfy a host wildcard",
			buildType: testCustomBuild,
			pattern:   "https://**/example/repo",
			params:    map[string]any{testKeySource: "https://evil.example/x@/example/repo"},
			wantPass:  false,
		},
		{
			name:      "ref-pinned pattern requires a ref",
			buildType: testCustomBuild,
			pattern:   "git+" + testSource + testTagPattern,
			params:    map[string]any{testKeySource: testSource},
			wantPass:  false,
		},
		{
			name:      "ref-pinned pattern matches the resolved ref",
			buildType: testCustomBuild,
			pattern:   "git+" + testSource + testTagPattern,
			params:    map[string]any{testKeySource: testSource, testKeyRef: testTagRef},
			wantPass:  true,
		},
		{
			name:      "ref-pinned pattern without git+ prefix",
			buildType: testCustomBuild,
			pattern:   testSource + testTagPattern,
			params:    map[string]any{testKeySource: "git+" + testSource + "@" + testTagRef},
			wantPass:  true,
		},
		{
			name:      "git+ prefixed pattern without ref matches the repository",
			buildType: testCustomBuild,
			pattern:   "git+https://github.com/example/*",
			params:    map[string]any{testKeySource: mainPinned},
			wantPass:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			stmt := rawStatement(tc.buildType, tc.params, nil)

			result, err := slsa.Verify(context.Background(),
				testutil.MustMarshal(t, stmt), gcbPolicy(tc.pattern), testDigest)
			testutil.AssertNoError(t, err)
			testutil.AssertEqual(t, tc.wantPass, result.Passed)
		})
	}
}

func TestVerifyGCBConfigAndSourceRepositories(t *testing.T) {
	t.Parallel()

	gitDep := func(repository, ref, commit string) map[string]any {
		return map[string]any{
			testKeyURI:    "git+" + repository + "@" + ref,
			testKeyDigest: map[string]string{testKeySHA1: commit},
		}
	}

	tests := []struct {
		name     string
		config   map[string]any
		built    map[string]any
		deps     []map[string]any
		wantPass bool
	}{
		{
			name: "untrusted configSource repository fails",
			config: map[string]any{
				testKeyRepository: "https://github.com/evil/config", testKeyRef: testWorkflowRef,
			},
			built:    map[string]any{testKeyRepository: testSource, testKeyRef: testTagRef},
			deps:     nil,
			wantPass: false,
		},
		{
			name: "trusted configSource and sourceToBuild repositories pass",
			config: map[string]any{
				testKeyRepository: "https://github.com/example/config", testKeyRef: testWorkflowRef,
			},
			built:    map[string]any{testKeyRepository: testSource, testKeyRef: testTagRef},
			deps:     nil,
			wantPass: true,
		},
		{
			name:   "same repository at different refs checks each dependency against its ref",
			config: map[string]any{testKeyRepository: testSource, testKeyRef: testWorkflowRef},
			built:  map[string]any{testKeyRepository: testSource, testKeyRef: testTagRef},
			deps: []map[string]any{
				gitDep(testSource, testWorkflowRef, testGCBCommit),
				gitDep(testSource, testTagRef, testGitCommit),
			},
			wantPass: true,
		},
		{
			name:   "same repository dependency at another ref still fails",
			config: map[string]any{testKeyRepository: testSource, testKeyRef: testWorkflowRef},
			built:  map[string]any{testKeyRepository: testSource, testKeyRef: testTagRef},
			deps: []map[string]any{
				gitDep(testSource, testEvilRef, testGCBCommit),
			},
			wantPass: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			stmt := rawStatement(slsa.BuildTypeGCBTriggered, map[string]any{
				testKeyConfigSource:  tc.config,
				testKeySourceToBuild: tc.built,
			}, tc.deps)

			result, err := slsa.Verify(context.Background(),
				testutil.MustMarshal(t, stmt), sourcePolicy(), testDigest)
			testutil.AssertNoError(t, err)
			testutil.AssertEqual(t, tc.wantPass, result.Passed)
		})
	}
}

func TestVerifyCommitDigestMatchesRefLength(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		ref      string
		digest   map[string]string
		wantPass bool
	}{
		{
			name: "sha256 commit ref compares the sha256 digest",
			ref:  testCommitSHA256,
			digest: map[string]string{
				testKeySHA1:   testGCBCommit,
				testKeySHA256: testCommitSHA256,
			},
			wantPass: true,
		},
		{
			name:     "sha256 commit ref with mismatching sha256 digest fails",
			ref:      testCommitSHA256,
			digest:   map[string]string{testKeySHA1: testGCBCommit, testKeySHA256: testDigestHash},
			wantPass: false,
		},
		{
			name:     "sha1 commit ref ignores a sha256 content digest",
			ref:      testGCBCommit,
			digest:   map[string]string{testKeySHA256: testDigestHash},
			wantPass: true,
		},
		{
			name:     "sha1 commit ref compares the sha1 digest",
			ref:      testGCBCommit,
			digest:   map[string]string{testKeySHA1: testGitCommit, testKeySHA256: testDigestHash},
			wantPass: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			stmt := rawStatement(slsa.BuildTypeGCBTriggered, map[string]any{
				testKeyConfigSource: map[string]any{
					testKeyRepository: testSource,
					testKeyRef:        tc.ref,
				},
			}, []map[string]any{{
				testKeyURI:    "git+" + testSource + "@" + testWorkflowRef,
				testKeyDigest: tc.digest,
			}})

			result, err := slsa.Verify(context.Background(),
				testutil.MustMarshal(t, stmt), sourcePolicy(), testDigest)
			testutil.AssertNoError(t, err)
			testutil.AssertEqual(t, tc.wantPass, result.Passed)
		})
	}
}

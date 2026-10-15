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

package buildenv_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/buildenv"
	"github.com/saschagrunert/nri-supply-chain/internal/checker/checkertest"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	testDigest        = "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	testPredicateType = "https://in-toto.io/attestation/build-env/v1"
	testPropOS        = "linux"
	testPropArch      = "amd64"
	testPropCompiler  = "gcc-12"
	testPropDebug     = "DEBUG_MODE"
)

type buildEnvDoc struct {
	Environment []envProperty `json:"environment"`
}

type envProperty struct {
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
}

func validDoc() buildEnvDoc {
	return buildEnvDoc{
		Environment: []envProperty{
			{Name: testPropOS, Value: "ubuntu-22.04"},
			{Name: testPropArch, Value: "x86_64"},
			{Name: testPropCompiler, Value: "12.3.0"},
		},
	}
}

func TestVerify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		doc        buildEnvDoc
		pol        *policy.Policy
		wantPassed bool
		wantStatus types.CheckStatus
	}{
		{
			name:       "valid doc with no policy passes",
			doc:        validDoc(),
			pol:        &policy.Policy{},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name: "required property present passes",
			doc:  validDoc(),
			pol: &policy.Policy{
				BuildEnv: &policy.BuildEnvPolicy{
					RequiredProperties: []string{testPropOS},
				},
			},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name: "required property missing fails",
			doc:  validDoc(),
			pol: &policy.Policy{
				BuildEnv: &policy.BuildEnvPolicy{
					RequiredProperties: []string{testPropDebug},
				},
			},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name: "forbidden property absent passes",
			doc:  validDoc(),
			pol: &policy.Policy{
				BuildEnv: &policy.BuildEnvPolicy{
					ForbiddenProperties: []string{testPropDebug},
				},
			},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name: "forbidden property present fails",
			doc:  validDoc(),
			pol: &policy.Policy{
				BuildEnv: &policy.BuildEnvPolicy{
					ForbiddenProperties: []string{testPropOS},
				},
			},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name: "forbidden property padded with whitespace fails",
			doc: buildEnvDoc{
				Environment: []envProperty{{Name: " " + testPropOS + "\t", Value: "debug"}},
			},
			pol: &policy.Policy{
				BuildEnv: &policy.BuildEnvPolicy{
					ForbiddenProperties: []string{testPropOS + " "},
				},
			},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name: "property matching is case-insensitive",
			doc:  validDoc(),
			pol: &policy.Policy{
				BuildEnv: &policy.BuildEnvPolicy{
					RequiredProperties: []string{"LINUX"},
				},
			},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			att := testutil.WrapInToto(t, test.doc, testDigest, testPredicateType)

			result, err := buildenv.VerifyMultiple(
				context.Background(),
				[][]byte{att},
				test.pol,
				testDigest,
			)
			testutil.AssertNoError(t, err)

			testutil.AssertEqual(t, test.wantPassed, result.Passed)
			testutil.AssertEqual(t, test.wantStatus, result.Status)
		})
	}
}

func TestVerifyMetadata(t *testing.T) {
	t.Parallel()

	att := testutil.WrapInToto(t, validDoc(), testDigest, testPredicateType)

	result, err := buildenv.VerifyMultiple(
		context.Background(),
		[][]byte{att},
		&policy.Policy{},
		testDigest,
	)
	testutil.AssertNoError(t, err)

	if result.Metadata == nil {
		t.Fatal("expected metadata on build environment result")
	}

	propCount, ok := result.Metadata["propertyCount"].(int64)
	if !ok || propCount != 3 {
		t.Errorf("propertyCount = %v, want 3", result.Metadata["propertyCount"])
	}

	props, ok := result.Metadata["properties"].(string)
	if !ok {
		t.Fatal("expected properties to be a string")
	}

	if !strings.Contains(props, testPropOS) {
		t.Errorf("properties = %q, want to contain %s", props, testPropOS)
	}
}

func TestVerifyForbiddenDetailMessage(t *testing.T) {
	t.Parallel()

	att := testutil.WrapInToto(t, validDoc(), testDigest, testPredicateType)

	result, err := buildenv.VerifyMultiple(context.Background(), [][]byte{att}, &policy.Policy{
		BuildEnv: &policy.BuildEnvPolicy{
			ForbiddenProperties: []string{testPropOS},
		},
	}, testDigest)
	testutil.AssertNoError(t, err)

	if result.Passed {
		t.Fatal("expected fail")
	}

	if !strings.Contains(result.Detail, "forbidden") {
		t.Errorf("expected detail to mention forbidden, got %q", result.Detail)
	}

	if !strings.Contains(result.Detail, testPropOS) {
		t.Errorf("expected detail to contain property name, got %q", result.Detail)
	}
}

func TestVerifyRequiredDetailMessage(t *testing.T) {
	t.Parallel()

	att := testutil.WrapInToto(t, validDoc(), testDigest, testPredicateType)

	result, err := buildenv.VerifyMultiple(context.Background(), [][]byte{att}, &policy.Policy{
		BuildEnv: &policy.BuildEnvPolicy{
			RequiredProperties: []string{testPropDebug},
		},
	}, testDigest)
	testutil.AssertNoError(t, err)

	if result.Passed {
		t.Fatal("expected fail")
	}

	if !strings.Contains(result.Detail, "required") {
		t.Errorf("expected detail to mention required, got %q", result.Detail)
	}

	if !strings.Contains(result.Detail, testPropDebug) {
		t.Errorf("expected detail to contain property name, got %q", result.Detail)
	}
}

func TestVerifyEmptyEnvironment(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		predicate json.RawMessage
	}{
		{name: "empty environment", predicate: json.RawMessage(`{"environment":[]}`)},
		{name: "empty property name", predicate: json.RawMessage(`{"environment":[{"name":""}]}`)},
		{name: "empty object", predicate: json.RawMessage(`{}`)},
		{name: "null predicate", predicate: json.RawMessage(`null`)},
	}

	for _, tc := range tests {
		t.Run(tc.name+" is rejected without policy", func(t *testing.T) {
			t.Parallel()

			att := testutil.WrapInToto(t, tc.predicate, testDigest, testPredicateType)

			result, err := buildenv.VerifyMultiple(
				context.Background(),
				[][]byte{att},
				&policy.Policy{},
				testDigest,
			)
			checkertest.AssertFailed(t, result, err, buildenv.ErrInvalidBuildEnv)
		})
	}
}

func TestVerifyMultiple(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		docs       []buildEnvDoc
		pol        *policy.Policy
		wantPassed bool
		wantStatus types.CheckStatus
	}{
		{
			name:       "all pass",
			docs:       []buildEnvDoc{validDoc()},
			pol:        &policy.Policy{},
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name: "any forbidden property fails",
			docs: []buildEnvDoc{validDoc()},
			pol: &policy.Policy{
				BuildEnv: &policy.BuildEnvPolicy{
					ForbiddenProperties: []string{testPropOS},
				},
			},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name:       "empty attestation list fails",
			docs:       []buildEnvDoc{},
			pol:        &policy.Policy{},
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			attestations := make([][]byte, len(test.docs))
			for idx := range test.docs {
				attestations[idx] = testutil.WrapInToto(
					t, test.docs[idx], testDigest, testPredicateType,
				)
			}

			result, err := buildenv.VerifyMultiple(
				context.Background(),
				attestations,
				test.pol,
				testDigest,
			)
			testutil.AssertNoError(t, err)

			testutil.AssertEqual(t, test.wantPassed, result.Passed)
			testutil.AssertEqual(t, test.wantStatus, result.Status)
		})
	}
}

func TestVerifyMultipleMergesMetadata(t *testing.T) {
	t.Parallel()

	doc1 := buildEnvDoc{
		Environment: []envProperty{
			{Name: testPropOS, Value: "ubuntu-22.04"},
		},
	}
	doc2 := buildEnvDoc{
		Environment: []envProperty{
			{Name: testPropArch, Value: "x86_64"},
			{Name: testPropCompiler, Value: "12.3.0"},
		},
	}

	attestations := [][]byte{
		testutil.WrapInToto(t, doc1, testDigest, testPredicateType),
		testutil.WrapInToto(t, doc2, testDigest, testPredicateType),
	}

	result, err := buildenv.VerifyMultiple(
		context.Background(), attestations, &policy.Policy{}, testDigest,
	)
	testutil.AssertNoError(t, err)

	if !result.Passed {
		t.Fatalf("expected pass, got: %s", result.Detail)
	}

	if result.Metadata == nil {
		t.Fatal("expected metadata on merged result")
	}

	propCount, ok := result.Metadata["propertyCount"].(int64)
	if !ok || propCount != 3 {
		t.Errorf("propertyCount = %v, want 3", result.Metadata["propertyCount"])
	}

	props, ok := result.Metadata["properties"].(string)
	if !ok {
		t.Fatal("expected properties to be a string")
	}

	if !strings.Contains(props, testPropOS) {
		t.Errorf("properties = %q, want to contain %s", props, testPropOS)
	}

	if !strings.Contains(props, testPropArch) {
		t.Errorf("properties = %q, want to contain %s", props, testPropArch)
	}

	if !strings.Contains(props, testPropCompiler) {
		t.Errorf("properties = %q, want to contain %s", props, testPropCompiler)
	}
}

func TestVerifyMultipleEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("nil attestation slice", func(t *testing.T) {
		t.Parallel()

		result, err := buildenv.VerifyMultiple(
			context.Background(),
			nil,
			&policy.Policy{},
			testDigest,
		)
		testutil.AssertNoError(t, err)

		if result.Passed {
			t.Error("expected failure for nil attestation slice")
		}
	})

	t.Run("all invalid returns fail with parse errors", func(t *testing.T) {
		t.Parallel()

		attestations := [][]byte{
			[]byte("bad json 1"),
			[]byte("bad json 2"),
		}

		result, err := buildenv.VerifyMultiple(
			context.Background(),
			attestations,
			&policy.Policy{},
			testDigest,
		)
		testutil.AssertNoError(t, err)

		if result.Passed {
			t.Error("expected fail when all documents are invalid")
		}

		testutil.AssertEqual(t, types.StatusFail, result.Status)
	})

	t.Run("mix of valid and invalid fails", func(t *testing.T) {
		t.Parallel()

		attestations := [][]byte{
			[]byte("invalid json"),
			testutil.WrapInToto(t, validDoc(), testDigest, testPredicateType),
		}

		result, err := buildenv.VerifyMultiple(
			context.Background(),
			attestations,
			&policy.Policy{},
			testDigest,
		)
		testutil.AssertNoError(t, err)

		if result.Passed {
			t.Error("expected fail when any document is invalid")
		}
	})
}

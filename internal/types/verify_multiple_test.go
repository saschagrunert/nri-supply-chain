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

package types_test

import (
	"errors"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

var errVerify = errors.New("verification failed")

const (
	testLabel      = "test"
	testPassDetail = "test passed"
)

func noopMerge(_, _ map[string]any) {}

func sumMerge(dst, src map[string]any) {
	for key, val := range src {
		if existing, ok := dst[key]; ok {
			if dstCount, ok := existing.(int64); ok {
				if srcCount, ok := val.(int64); ok {
					dst[key] = dstCount + srcCount

					continue
				}
			}
		}

		dst[key] = val
	}
}

func TestVerifyMultipleWithMergeAllPass(t *testing.T) {
	t.Parallel()

	attestations := [][]byte{[]byte("a1"), []byte("a2")}

	result, err := types.VerifyMultipleWithMerge(
		types.CheckTypeSLSA, testLabel, testPassDetail,
		attestations,
		func(_ []byte) (*types.CheckResult, error) {
			res := types.PassResult(types.CheckTypeSLSA, testPassDetail)
			res.Metadata = map[string]any{"count": int64(1)}

			return res, nil
		},
		sumMerge,
	)

	testutil.AssertNoError(t, err)
	testutil.AssertTrue(t, result.Passed)
	testutil.AssertEqual(t, types.StatusPass, result.Status)
	//nolint:forcetypeassert // test
	testutil.AssertEqual(t, int64(2), result.Metadata["count"].(int64))
}

func TestVerifyMultipleWithMergeOneFails(t *testing.T) {
	t.Parallel()

	attestations := [][]byte{[]byte("good"), []byte("bad")}
	callCount := 0

	result, err := types.VerifyMultipleWithMerge(
		types.CheckTypeSLSA, testLabel, testPassDetail,
		attestations,
		func(att []byte) (*types.CheckResult, error) {
			callCount++

			if string(att) == "bad" {
				return types.FailResult(types.CheckTypeSLSA, "bad attestation", nil), nil
			}

			return types.PassResult(types.CheckTypeSLSA, testPassDetail), nil
		},
		noopMerge,
	)

	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, false, result.Passed)
	testutil.AssertEqual(t, types.StatusFail, result.Status)
	testutil.AssertContains(t, result.Detail, "bad attestation")
}

func TestVerifyMultipleWithMergeAllErrors(t *testing.T) {
	t.Parallel()

	attestations := [][]byte{[]byte("e1"), []byte("e2")}

	result, err := types.VerifyMultipleWithMerge(
		types.CheckTypeSCAI, testLabel, testPassDetail,
		attestations,
		func(_ []byte) (*types.CheckResult, error) {
			return nil, errVerify
		},
		noopMerge,
	)

	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, false, result.Passed)
	testutil.AssertContains(t, result.Detail, "all test documents failed verification")
}

func TestVerifyMultipleWithMergeEmpty(t *testing.T) {
	t.Parallel()

	result, err := types.VerifyMultipleWithMerge(
		types.CheckTypeSLSA, testLabel, testPassDetail,
		nil,
		func(_ []byte) (*types.CheckResult, error) {
			return types.PassResult(types.CheckTypeSLSA, testPassDetail), nil
		},
		noopMerge,
	)

	testutil.AssertNoError(t, err)
	testutil.AssertTrue(t, result.Passed)
	testutil.AssertEqual(t, testPassDetail, result.Detail)
}

func TestVerifyMultipleWithMergeErrorAndPass(t *testing.T) {
	t.Parallel()

	attestations := [][]byte{[]byte("err"), []byte("ok")}

	result, err := types.VerifyMultipleWithMerge(
		types.CheckTypeVulnScan, testLabel, testPassDetail,
		attestations,
		func(att []byte) (*types.CheckResult, error) {
			if string(att) == "err" {
				return nil, errVerify
			}

			return types.PassResult(types.CheckTypeVulnScan, testPassDetail), nil
		},
		noopMerge,
	)

	testutil.AssertNoError(t, err)
	testutil.AssertTrue(t, result.Passed)
}

func TestVerifyMultipleWithMergeMetadataMerged(t *testing.T) {
	t.Parallel()

	attestations := [][]byte{[]byte("a"), []byte("b"), []byte("c")}

	result, err := types.VerifyMultipleWithMerge(
		types.CheckTypeBuildEnv, testLabel, testPassDetail,
		attestations,
		func(_ []byte) (*types.CheckResult, error) {
			res := types.PassResult(types.CheckTypeBuildEnv, testPassDetail)
			res.Metadata = map[string]any{"count": int64(5)}

			return res, nil
		},
		sumMerge,
	)

	testutil.AssertNoError(t, err)
	testutil.AssertTrue(t, result.Passed)
	//nolint:forcetypeassert // test
	testutil.AssertEqual(t, int64(15), result.Metadata["count"].(int64))
}

func TestVerifyMultipleWithMergeFailedMetadataNotMerged(t *testing.T) {
	t.Parallel()

	attestations := [][]byte{[]byte("a")}

	result, err := types.VerifyMultipleWithMerge(
		types.CheckTypeSLSA, testLabel, testPassDetail,
		attestations,
		func(_ []byte) (*types.CheckResult, error) {
			res := types.FailResult(types.CheckTypeSLSA, "denied", nil)
			res.Metadata = map[string]any{"key": "val"}

			return res, nil
		},
		sumMerge,
	)

	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, false, result.Passed)

	if result.Metadata != nil {
		t.Error("expected nil metadata for failed result")
	}
}

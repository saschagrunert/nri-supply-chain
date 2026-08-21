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
	"context"
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

func TestVerifyMultipleFirstPassReturnsOnFirstPass(t *testing.T) {
	t.Parallel()

	attestations := [][]byte{[]byte("fail"), []byte("pass"), []byte("unreachable")}
	callCount := 0

	result, err := types.VerifyMultipleFirstPass(context.Background(),
		types.CheckTypeSLSA, testLabel, attestations,
		func(att []byte) (*types.CheckResult, error) {
			callCount++

			if string(att) == "pass" {
				return types.PassResult(types.CheckTypeSLSA, testPassDetail), nil
			}

			return types.FailResult(types.CheckTypeSLSA, "failed", nil), nil
		},
	)

	testutil.AssertNoError(t, err)
	testutil.AssertTrue(t, result.Passed)
	testutil.AssertEqual(t, 2, callCount)
}

func TestVerifyMultipleFirstPassAllFail(t *testing.T) {
	t.Parallel()

	attestations := [][]byte{[]byte("a"), []byte("b")}

	result, err := types.VerifyMultipleFirstPass(context.Background(),
		types.CheckTypeSLSA, testLabel, attestations,
		func(_ []byte) (*types.CheckResult, error) {
			return types.FailResult(types.CheckTypeSLSA, "denied", nil), nil
		},
	)

	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, false, result.Passed)
	testutil.AssertContains(t, result.Detail, "denied")
}

func TestVerifyMultipleFirstPassParseErrorsOnly(t *testing.T) {
	t.Parallel()

	attestations := [][]byte{[]byte("bad")}

	result, err := types.VerifyMultipleFirstPass(context.Background(),
		types.CheckTypeSLSA, testLabel, attestations,
		func(_ []byte) (*types.CheckResult, error) {
			return nil, errVerify
		},
	)

	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, false, result.Passed)
	testutil.AssertContains(t, result.Detail, "no valid test attestation")
}

func TestVerifyMultipleFirstPassEmpty(t *testing.T) {
	t.Parallel()

	result, err := types.VerifyMultipleFirstPass(context.Background(),
		types.CheckTypeSLSA, testLabel, nil,
		func(_ []byte) (*types.CheckResult, error) {
			return types.PassResult(types.CheckTypeSLSA, testPassDetail), nil
		},
	)

	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, false, result.Passed)
	testutil.AssertContains(t, result.Detail, "no valid test attestation found")
}

func TestVerifyMultipleFirstPassCancelledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	attestations := [][]byte{[]byte("a")}

	_, err := types.VerifyMultipleFirstPass(ctx,
		types.CheckTypeSLSA, testLabel, attestations,
		func(_ []byte) (*types.CheckResult, error) {
			t.Fatal("verifyOne should not be called with cancelled context")

			return nil, nil
		},
	)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}

	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

func TestVerifyMultipleFirstPassMixedErrorsAndFailures(t *testing.T) {
	t.Parallel()

	attestations := [][]byte{[]byte("err"), []byte("fail")}

	result, err := types.VerifyMultipleFirstPass(context.Background(),
		types.CheckTypeSLSA, testLabel, attestations,
		func(att []byte) (*types.CheckResult, error) {
			if string(att) == "err" {
				return nil, errVerify
			}

			return types.FailResult(types.CheckTypeSLSA, "denied", nil), nil
		},
	)

	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, false, result.Passed)
	testutil.AssertContains(t, result.Detail, "denied")
	testutil.AssertContains(t, result.Detail, "also failed to parse")
}

func TestVerifyMultipleWithMergeCancelledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	attestations := [][]byte{[]byte("a1")}

	_, err := types.VerifyMultipleWithMerge(ctx,
		types.CheckTypeSLSA, testLabel, testPassDetail,
		attestations,
		func(_ []byte) (*types.CheckResult, error) {
			t.Fatal("verifyOne should not be called with cancelled context")

			return nil, nil
		},
		noopMerge,
	)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}

	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

func TestVerifyMultipleWithMergeAllPass(t *testing.T) {
	t.Parallel()

	attestations := [][]byte{[]byte("a1"), []byte("a2")}

	result, err := types.VerifyMultipleWithMerge(context.Background(),
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

	result, err := types.VerifyMultipleWithMerge(context.Background(),
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

	result, err := types.VerifyMultipleWithMerge(context.Background(),
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

	result, err := types.VerifyMultipleWithMerge(context.Background(),
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

	result, err := types.VerifyMultipleWithMerge(context.Background(),
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

	result, err := types.VerifyMultipleWithMerge(context.Background(),
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

	result, err := types.VerifyMultipleWithMerge(context.Background(),
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

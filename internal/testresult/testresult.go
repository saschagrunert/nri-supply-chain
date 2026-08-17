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

// Package testresult provides test result attestation verification for supply chain checks.
package testresult

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/intoto"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const checkType = types.CheckTypeTestResult

var (
	// ErrInvalidTestResult indicates the test result document could not be parsed.
	ErrInvalidTestResult = errors.New("invalid test result document")

	// ErrTestsFailed indicates one or more test suites failed.
	ErrTestsFailed = errors.New("tests failed")

	// ErrRequiredSuiteMissing indicates a required test suite was not found in the results.
	ErrRequiredSuiteMissing = errors.New("required test suite missing")

	// ErrStaleTestResult indicates the test result is older than the maximum allowed age.
	ErrStaleTestResult = errors.New("test result is stale")

	// ErrFutureTimestamp indicates the test result timestamp is in the future.
	ErrFutureTimestamp = errors.New("test result timestamp is in the future")
)

// testResultPredicate represents the in-toto test result predicate.
type testResultPredicate struct {
	Result   string      `json:"result"`
	Suites   []testSuite `json:"suites,omitempty"`
	Metadata *testMeta   `json:"metadata,omitempty"`
}

type testSuite struct {
	Name   string `json:"name"`
	Result string `json:"result"`
	Count  *int   `json:"count,omitempty"`
	Passed *int   `json:"passed,omitempty"`
	Failed *int   `json:"failed,omitempty"`
}

type testMeta struct {
	FinishedOn *time.Time `json:"finishedOn,omitempty"`
}

// Verify checks a single test result attestation against the given policy.
func Verify( //nolint:revive // ctx reserved for future context-aware logging
	ctx context.Context,
	att []byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	predicate, err := intoto.VerifySubjectAndExtractPredicate(att, imageDigest)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidTestResult, err)
	}

	return verifyTestResultPredicate(predicate, pol)
}

// VerifyMultiple checks multiple test result attestations. All must pass
// (any failure causes denial).
func VerifyMultiple(
	ctx context.Context,
	attestations [][]byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	//nolint:wrapcheck // VerifyMultipleWithMerge returns domain errors
	return types.VerifyMultipleWithMerge(
		checkType, "test result", "test result verification passed",
		attestations,
		func(att []byte) (*types.CheckResult, error) {
			return Verify(ctx, att, pol, imageDigest)
		},
		mergeSuiteMeta,
	)
}

//nolint:cyclop,funlen // sequential verification steps
func verifyTestResultPredicate(
	predicate []byte, pol *policy.Policy,
) (*types.CheckResult, error) {
	var pred testResultPredicate

	err := json.Unmarshal(predicate, &pred)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidTestResult, err)
	}

	suiteNames := make([]string, 0, len(pred.Suites))
	totalPassed := int64(0)
	totalFailed := int64(0)

	for idx := range pred.Suites {
		suiteNames = append(suiteNames, pred.Suites[idx].Name)

		if pred.Suites[idx].Passed != nil {
			totalPassed += int64(*pred.Suites[idx].Passed)
		}

		if pred.Suites[idx].Failed != nil {
			totalFailed += int64(*pred.Suites[idx].Failed)
		}
	}

	meta := map[string]any{
		"result":     pred.Result,
		"suiteCount": int64(len(pred.Suites)),
		"suites":     strings.Join(suiteNames, ","),
		"passed":     totalPassed, //nolint:goconst // metadata key, not worth a constant
		"failed":     totalFailed, //nolint:goconst // metadata key, not worth a constant
	}

	overallPassed := strings.EqualFold(pred.Result, "pass") ||
		strings.EqualFold(pred.Result, "passed")

	if !overallPassed {
		failedSuites := collectFailedSuites(pred.Suites)
		detail := fmt.Sprintf("%s: overall result %q", ErrTestsFailed, pred.Result)

		if len(failedSuites) > 0 {
			detail += " (failed suites: " + strings.Join(failedSuites, ", ") + ")"
		}

		result := check.Fail(detail)
		result.Metadata = meta

		return result, nil
	}

	if pol.TestResult != nil {
		var finishedOn *time.Time
		if pred.Metadata != nil {
			finishedOn = pred.Metadata.FinishedOn
		}

		err = verifyFreshness(finishedOn, pol)
		if err != nil {
			result := check.Fail(err.Error())
			result.Metadata = meta

			return result, nil
		}

		missing := checkRequiredSuites(pred.Suites, pol.TestResult.RequiredSuites)
		if missing != "" {
			result := check.Fail(missing)
			result.Metadata = meta

			return result, nil
		}
	}

	result := check.Pass()
	result.Metadata = meta

	return result, nil
}

func collectFailedSuites(suites []testSuite) []string {
	var failed []string

	for idx := range suites {
		result := strings.ToLower(suites[idx].Result)
		if result == "fail" || result == "failed" || result == "error" {
			failed = append(failed, suites[idx].Name)
		}
	}

	return failed
}

func checkRequiredSuites(suites []testSuite, required []string) string {
	if len(required) == 0 {
		return ""
	}

	suiteMap := make(map[string]*testSuite, len(suites))
	for idx := range suites {
		suiteMap[strings.ToLower(suites[idx].Name)] = &suites[idx]
	}

	for _, name := range required {
		suite, found := suiteMap[strings.ToLower(name)]
		if !found {
			return fmt.Sprintf("%s: %q", ErrRequiredSuiteMissing, name)
		}

		result := strings.ToLower(suite.Result)
		if result != "pass" && result != "passed" {
			return fmt.Sprintf("%s: suite %q has result %q", ErrTestsFailed, name, suite.Result)
		}
	}

	return ""
}

func verifyFreshness(finishedOn *time.Time, pol *policy.Policy) error {
	maxAgeConfigured := pol.TestResult != nil && pol.TestResult.MaxAge != ""

	if finishedOn == nil {
		if maxAgeConfigured {
			return fmt.Errorf("%w: no finished timestamp in attestation", ErrStaleTestResult)
		}

		return nil
	}

	if !maxAgeConfigured {
		return nil
	}

	maxAge := &pol.TestResult.MaxAgeDuration

	//nolint:wrapcheck // VerifyFreshness wraps the caller's sentinel errors
	return types.VerifyFreshness(
		*finishedOn,
		maxAge,
		"finished",
		ErrFutureTimestamp,
		ErrStaleTestResult,
		ErrStaleTestResult,
	)
}

func mergeSuiteMeta(dst, src map[string]any) {
	for key, val := range src {
		existing, hasPrev := dst[key]
		if !hasPrev {
			dst[key] = val

			continue
		}

		switch key {
		case "suiteCount", "passed", "failed":
			if srcCount, ok := val.(int64); ok {
				if dstCount, ok := existing.(int64); ok {
					dst[key] = dstCount + srcCount
				}
			}
		case "suites":
			if dstSuites, ok := existing.(string); ok {
				if srcSuites, ok := val.(string); ok {
					dst[key] = types.MergeCommaSeparated(dstSuites, srcSuites)
				}
			}
		default:
		}
	}
}

var check = types.Checker{ //nolint:gochecknoglobals // package-scoped helper
	Type:    checkType,
	PassMsg: "test result verification passed",
}

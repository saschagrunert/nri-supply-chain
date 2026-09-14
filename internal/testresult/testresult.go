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
//
// Both the in-toto test result v0.1 fields (result, passedTests, warnedTests,
// failedTests) and the suite-based extension (suites, metadata.finishedOn)
// are understood.
package testresult

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/checker"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

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

	errMissingResult = errors.New("result is required")
)

const (
	metaPassed = "passed"
	metaFailed = "failed"
	metaWarned = "warned"
)

// testResultPredicate represents the in-toto test result predicate.
type testResultPredicate struct {
	Result      string      `json:"result"`
	PassedTests []string    `json:"passedTests,omitempty"`
	WarnedTests []string    `json:"warnedTests,omitempty"`
	FailedTests []string    `json:"failedTests,omitempty"`
	Suites      []testSuite `json:"suites,omitempty"`
	Metadata    *testMeta   `json:"metadata,omitempty"`
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

//nolint:gochecknoglobals // immutable check declaration
var spec = &checker.Spec[testResultPredicate]{
	Info: checker.Info{
		Type:  types.CheckTypeTestResult,
		Label: "test result",
	},
	Aggregation: checker.AllMustPass,
	ErrInvalid:  ErrInvalidTestResult,
	Validate:    validatePredicate,
	Meta:        predicateMeta,
	Freshness: &checker.Freshness[testResultPredicate]{
		Timestamp: func(pred *testResultPredicate) *time.Time {
			if pred.Metadata == nil {
				return nil
			}

			return pred.Metadata.FinishedOn
		},
		MaxAge: func(pol *policy.Policy) *time.Duration {
			if pol.TestResult == nil || pol.TestResult.MaxAge == "" {
				return nil
			}

			return &pol.TestResult.MaxAgeDuration
		},
		Label:     "finished",
		ErrStale:  ErrStaleTestResult,
		ErrFuture: ErrFutureTimestamp,
	},
	Rules: []checker.Rule[testResultPredicate]{
		checkOverallResult,
		checkConsistency,
		checkRequiredSuites,
	},
	Merge: map[string]checker.MergeFunc{
		"suiteCount": checker.Sum(),
		metaPassed:   checker.Sum(),
		metaFailed:   checker.Sum(),
		metaWarned:   checker.Sum(),
		"suites":     checker.CSV(),
	},
}

// Info returns the check type and label of the test result check.
func Info() checker.Info {
	return spec.Info
}

// Verify checks a single test result attestation against the given policy.
func Verify(
	ctx context.Context,
	att []byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	//nolint:wrapcheck // the generic checker returns domain errors
	return spec.Verify(ctx, att, pol, imageDigest)
}

// VerifyMultiple checks multiple test result attestations. All must pass
// (any failure or invalid document causes denial).
func VerifyMultiple(
	ctx context.Context,
	attestations [][]byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	//nolint:wrapcheck // the generic checker returns domain errors
	return spec.VerifyMultiple(ctx, attestations, pol, imageDigest)
}

func validatePredicate(pred *testResultPredicate) error {
	if strings.TrimSpace(pred.Result) == "" {
		return errMissingResult
	}

	return nil
}

func predicateMeta(pred *testResultPredicate) map[string]any {
	suiteNames := make([]string, 0, len(pred.Suites))
	totalPassed := int64(len(pred.PassedTests))
	totalFailed := int64(len(pred.FailedTests))

	for idx := range pred.Suites {
		suiteNames = append(suiteNames, pred.Suites[idx].Name)

		if pred.Suites[idx].Passed != nil {
			totalPassed += int64(*pred.Suites[idx].Passed)
		}

		if pred.Suites[idx].Failed != nil {
			totalFailed += int64(*pred.Suites[idx].Failed)
		}
	}

	return map[string]any{
		"result":     pred.Result,
		"suiteCount": int64(len(pred.Suites)),
		"suites":     strings.Join(suiteNames, ","),
		metaPassed:   totalPassed,
		metaFailed:   totalFailed,
		metaWarned:   int64(len(pred.WarnedTests)),
	}
}

// isPassed reports whether a result counts as passing. The test result
// specification defines WARNED as a run that passed with warnings.
func isPassed(result string) bool {
	switch strings.ToLower(result) {
	case "pass", metaPassed, "warn", metaWarned:
		return true
	default:
		return false
	}
}

func isFailed(result string) bool {
	switch strings.ToLower(result) {
	case "fail", metaFailed, "error":
		return true
	default:
		return false
	}
}

func checkOverallResult(pred *testResultPredicate, _ *policy.Policy) string {
	if isPassed(pred.Result) {
		return ""
	}

	detail := fmt.Sprintf("%s: overall result %q", ErrTestsFailed, pred.Result)

	if failed := collectFailedSuites(pred); len(failed) > 0 {
		detail += " (failed suites: " + strings.Join(failed, ", ") + ")"
	}

	return detail
}

// checkConsistency rejects documents whose overall result claims success
// while individual tests or suites report failures.
func checkConsistency(pred *testResultPredicate, _ *policy.Policy) string {
	if len(pred.FailedTests) > 0 {
		return fmt.Sprintf(
			"%s: overall result %q but failed tests reported: %s",
			ErrTestsFailed, pred.Result, strings.Join(pred.FailedTests, ", "),
		)
	}

	if failed := collectFailedSuites(pred); len(failed) > 0 {
		return fmt.Sprintf(
			"%s: overall result %q but failed suites reported: %s",
			ErrTestsFailed, pred.Result, strings.Join(failed, ", "),
		)
	}

	return ""
}

func collectFailedSuites(pred *testResultPredicate) []string {
	var failed []string

	for idx := range pred.Suites {
		suite := &pred.Suites[idx]
		if isFailed(suite.Result) || (suite.Failed != nil && *suite.Failed > 0) {
			failed = append(failed, suite.Name)
		}
	}

	return failed
}

func checkRequiredSuites(pred *testResultPredicate, pol *policy.Policy) string {
	if pol.TestResult == nil || len(pol.TestResult.RequiredSuites) == 0 {
		return ""
	}

	suiteMap := make(map[string]*testSuite, len(pred.Suites))
	for idx := range pred.Suites {
		suiteMap[strings.ToLower(pred.Suites[idx].Name)] = &pred.Suites[idx]
	}

	for _, name := range pol.TestResult.RequiredSuites {
		suite, found := suiteMap[strings.ToLower(name)]
		if found {
			if !isPassed(suite.Result) {
				return fmt.Sprintf("%s: suite %q has result %q", ErrTestsFailed, name, suite.Result)
			}

			continue
		}

		if !containsFold(pred.PassedTests, name) && !containsFold(pred.WarnedTests, name) {
			return fmt.Sprintf("%s: %q", ErrRequiredSuiteMissing, name)
		}
	}

	return ""
}

func containsFold(values []string, name string) bool {
	return slices.ContainsFunc(values, func(value string) bool {
		return strings.EqualFold(value, name)
	})
}

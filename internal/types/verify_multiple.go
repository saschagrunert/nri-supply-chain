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

package types

import (
	"context"
	"fmt"
	"strings"
)

// VerifyMultipleFirstPass verifies multiple attestations, returning
// immediately on the first passing result. Parse errors and verification
// failures are accumulated and reported only when no attestation passes.
func VerifyMultipleFirstPass(
	ctx context.Context,
	checkType CheckType,
	label string,
	attestations [][]byte,
	verifyOne func(att []byte) (*CheckResult, error),
) (*CheckResult, error) {
	return VerifyMultipleFirstPassOf(
		ctx, checkType, label, attestations,
		func(att *[]byte) (*CheckResult, error) {
			return verifyOne(*att)
		},
	)
}

// VerifyMultipleFirstPassOf is the generic form of VerifyMultipleFirstPass
// for callers that need more than the raw payload of each item (for example
// the signer identity of a verified attestation).
func VerifyMultipleFirstPassOf[T any](
	ctx context.Context,
	checkType CheckType,
	label string,
	items []T,
	verifyOne func(item *T) (*CheckResult, error),
) (*CheckResult, error) {
	var (
		failReasons []string
		parseErrors []string
	)

	for idx := range items {
		ctxErr := ctx.Err()
		if ctxErr != nil {
			return nil, fmt.Errorf("verification cancelled: %w", ctxErr)
		}

		result, err := verifyOne(&items[idx])
		if err != nil {
			parseErrors = append(parseErrors, err.Error())

			continue
		}

		if result.Passed {
			return result, nil
		}

		failReasons = append(failReasons, result.Detail)
	}

	if len(failReasons) > 0 {
		detail := strings.Join(failReasons, "; ")
		if len(parseErrors) > 0 {
			detail += " (also failed to parse: " + strings.Join(parseErrors, "; ") + ")"
		}

		return FailResult(checkType, detail, nil), nil
	}

	if len(parseErrors) > 0 {
		return FailResult(
			checkType,
			"no valid "+label+" attestation: "+strings.Join(parseErrors, "; "),
			nil,
		), nil
	}

	return FailResult(checkType, "no valid "+label+" attestation found", nil), nil
}

// VerifyMultipleWithMerge verifies multiple attestations that must all pass,
// merging metadata from the passing results. A document that cannot be
// parsed or validated fails the aggregate: dropping it would let a newer
// report that happens to be malformed be masked by an older valid one.
// Inconclusive results (Passed=false, Status=warn) yield an inconclusive
// aggregate unless a hard failure is also present.
func VerifyMultipleWithMerge(
	ctx context.Context,
	checkType CheckType,
	label string,
	passDetail string,
	attestations [][]byte,
	verifyOne func(att []byte) (*CheckResult, error),
	mergeMeta func(dst, src map[string]any),
) (*CheckResult, error) {
	agg := mergeAggregate{mergeMeta: mergeMeta} //nolint:exhaustruct_v5 // accumulators start empty

	for _, att := range attestations {
		ctxErr := ctx.Err()
		if ctxErr != nil {
			return nil, fmt.Errorf("verification cancelled: %w", ctxErr)
		}

		agg.add(verifyOne(att))
	}

	if len(agg.verifyErrors) > 0 {
		agg.failDetails = append(agg.failDetails, invalidDocumentsDetail(
			label, len(agg.verifyErrors), len(attestations), agg.verifyErrors,
		))
	}

	if len(agg.failDetails) > 0 {
		return FailResult(checkType, strings.Join(agg.failDetails, "; "), nil), nil
	}

	if len(agg.softDetails) > 0 {
		return SoftFailResult(checkType, strings.Join(agg.softDetails, "; "), nil), nil
	}

	result := PassResult(checkType, passDetail)
	result.Metadata = agg.mergedMeta

	return result, nil
}

// mergeAggregate accumulates per-document outcomes for VerifyMultipleWithMerge.
type mergeAggregate struct {
	failDetails  []string
	softDetails  []string
	verifyErrors []string
	mergedMeta   map[string]any
	mergeMeta    func(dst, src map[string]any)
}

func (a *mergeAggregate) add(result *CheckResult, err error) {
	switch {
	case err != nil:
		a.verifyErrors = append(a.verifyErrors, err.Error())
	case result.Passed:
		if result.Metadata == nil {
			return
		}

		if a.mergedMeta == nil {
			a.mergedMeta = make(map[string]any)
		}

		a.mergeMeta(a.mergedMeta, result.Metadata)
	case result.Status == StatusFail:
		a.failDetails = append(a.failDetails, result.Detail)
	default:
		a.softDetails = append(a.softDetails, result.Detail)
	}
}

func invalidDocumentsDetail(label string, invalid, total int, errs []string) string {
	if invalid == total {
		return "all " + label + " documents failed verification: " + strings.Join(errs, "; ")
	}

	return fmt.Sprintf(
		"%d of %d %s documents failed verification: %s",
		invalid, total, label, strings.Join(errs, "; "),
	)
}

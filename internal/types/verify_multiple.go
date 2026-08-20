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

// VerifyMultipleWithMerge verifies multiple attestations, collecting failures
// and merging metadata from passing results. This is the common pattern used
// by scai, buildenv, vulnscan, and testresult packages.
func VerifyMultipleWithMerge( //nolint:cyclop // shared helper consolidating 4 duplicated implementations
	ctx context.Context,
	checkType CheckType,
	label string,
	passDetail string,
	attestations [][]byte,
	verifyOne func(att []byte) (*CheckResult, error),
	mergeMeta func(dst, src map[string]any),
) (*CheckResult, error) {
	var (
		failDetails  []string
		verifyErrors []string
		anyValid     bool
		mergedMeta   map[string]any
	)

	for _, att := range attestations {
		ctxErr := ctx.Err()
		if ctxErr != nil {
			return nil, fmt.Errorf("verification cancelled: %w", ctxErr)
		}

		result, err := verifyOne(att)
		if err != nil {
			verifyErrors = append(verifyErrors, err.Error())

			continue
		}

		anyValid = true

		if !result.Passed && result.Status == StatusFail {
			failDetails = append(failDetails, result.Detail)
		}

		if result.Passed && result.Metadata != nil {
			if mergedMeta == nil {
				mergedMeta = make(map[string]any)
			}

			mergeMeta(mergedMeta, result.Metadata)
		}
	}

	if len(failDetails) > 0 {
		return FailResult(checkType, strings.Join(failDetails, "; "), nil), nil
	}

	if len(attestations) > 0 && !anyValid {
		return FailResult(
			checkType,
			"all "+label+" documents failed verification: "+strings.Join(verifyErrors, "; "),
			nil,
		), nil
	}

	result := PassResult(checkType, passDetail)
	result.Metadata = mergedMeta

	return result, nil
}

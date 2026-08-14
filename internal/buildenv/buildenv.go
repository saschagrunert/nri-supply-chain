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

// Package buildenv provides build environment attestation verification for supply chain checks.
package buildenv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/saschagrunert/nri-supply-chain/internal/intoto"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const checkType = types.CheckTypeBuildEnv

var (
	// ErrInvalidBuildEnv indicates the build environment document could not be parsed.
	ErrInvalidBuildEnv = errors.New("invalid build environment document")

	errMissingProperty   = errors.New("required property missing")
	errForbiddenProperty = errors.New("forbidden property present")
)

// buildEnvPredicate represents the build environment attestation predicate.
type buildEnvPredicate struct {
	Environment []envProperty `json:"environment"`
}

type envProperty struct {
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
}

// Verify checks a single build environment attestation against the given policy.
func Verify( //nolint:revive // ctx reserved for future context-aware logging
	ctx context.Context,
	att []byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	predicate, err := intoto.VerifySubjectAndExtractPredicate(att, imageDigest)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidBuildEnv, err)
	}

	return verifyBuildEnvPredicate(predicate, pol)
}

// VerifyMultiple checks multiple build environment attestations. Any policy
// violation in any document causes failure.
func VerifyMultiple(
	ctx context.Context,
	attestations [][]byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	//nolint:wrapcheck // VerifyMultipleWithMerge returns domain errors
	return types.VerifyMultipleWithMerge(
		checkType, "build environment", "build environment verification passed",
		attestations,
		func(att []byte) (*types.CheckResult, error) {
			return Verify(ctx, att, pol, imageDigest)
		},
		mergePropertyMeta,
	)
}

func verifyBuildEnvPredicate(
	predicate []byte, pol *policy.Policy,
) (*types.CheckResult, error) {
	var pred buildEnvPredicate

	err := json.Unmarshal(predicate, &pred)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidBuildEnv, err)
	}

	propNames := make([]string, 0, len(pred.Environment))
	for idx := range pred.Environment {
		propNames = append(propNames, pred.Environment[idx].Name)
	}

	meta := map[string]any{
		"propertyCount": int64(len(pred.Environment)),
		"properties":    strings.Join(propNames, ","),
	}

	if pol.BuildEnv == nil {
		result := passResult()
		result.Metadata = meta

		return result, nil
	}

	violation := checkPropertyPolicy(pred.Environment, pol.BuildEnv)
	if violation != "" {
		result := failResult(violation)
		result.Metadata = meta

		return result, nil
	}

	result := passResult()
	result.Metadata = meta

	return result, nil
}

func checkPropertyPolicy(props []envProperty, pol *policy.BuildEnvPolicy) string {
	for _, required := range pol.RequiredProperties {
		if !containsProperty(props, required) {
			return fmt.Sprintf("%s: %q", errMissingProperty, required)
		}
	}

	for _, forbidden := range pol.ForbiddenProperties {
		if containsProperty(props, forbidden) {
			return fmt.Sprintf("%s: %q", errForbiddenProperty, forbidden)
		}
	}

	return ""
}

func containsProperty(props []envProperty, name string) bool {
	for idx := range props {
		if strings.EqualFold(props[idx].Name, name) {
			return true
		}
	}

	return false
}

func mergePropertyMeta(dst, src map[string]any) {
	for key, val := range src {
		existing, hasPrev := dst[key]
		if !hasPrev {
			dst[key] = val

			continue
		}

		switch key {
		case "propertyCount":
			if dstCount, ok := existing.(int64); ok {
				if srcCount, ok := val.(int64); ok {
					dst[key] = dstCount + srcCount
				}
			}
		case "properties":
			if dstProps, ok := existing.(string); ok {
				if srcProps, ok := val.(string); ok {
					dst[key] = types.MergeCommaSeparated(dstProps, srcProps)
				}
			}
		default:
		}
	}
}

func passResult() *types.CheckResult {
	return types.PassResult(checkType, "build environment verification passed")
}

func failResult(detail string) *types.CheckResult {
	return types.FailResult(checkType, detail, nil)
}

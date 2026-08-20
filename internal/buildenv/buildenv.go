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
func Verify(
	ctx context.Context,
	att []byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	ctxErr := ctx.Err()
	if ctxErr != nil {
		return nil, fmt.Errorf("verification cancelled: %w", ctxErr)
	}

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
		ctx, checkType, "build environment", "build environment verification passed",
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
	propValues := make(map[string]string, len(pred.Environment))

	for idx := range pred.Environment {
		propNames = append(propNames, pred.Environment[idx].Name)
		propValues[pred.Environment[idx].Name] = pred.Environment[idx].Value
	}

	meta := map[string]any{
		"propertyCount":  int64(len(pred.Environment)),
		"properties":     strings.Join(propNames, ","),
		"propertyValues": propValues,
	}

	if pol.BuildEnv == nil {
		result := check.Pass()
		result.Metadata = meta

		return result, nil
	}

	violation := checkPropertyPolicy(pred.Environment, pol.BuildEnv)
	if violation != "" {
		result := check.Fail(violation)
		result.Metadata = meta

		return result, nil
	}

	result := check.Pass()
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
			mergeInt64(dst, key, existing, val)
		case "properties":
			mergeString(dst, key, existing, val)
		case "propertyValues":
			mergeStringMap(existing, val)
		default:
		}
	}
}

func mergeInt64(dst map[string]any, key string, existing, val any) {
	dstCount, dstOK := existing.(int64)
	srcCount, srcOK := val.(int64)

	if dstOK && srcOK {
		dst[key] = dstCount + srcCount
	}
}

func mergeString(dst map[string]any, key string, existing, val any) {
	dstProps, dstOK := existing.(string)
	srcProps, srcOK := val.(string)

	if dstOK && srcOK {
		dst[key] = types.MergeCommaSeparated(dstProps, srcProps)
	}
}

func mergeStringMap(dst, src any) {
	dstMap, dstOK := dst.(map[string]string)
	if !dstOK {
		return
	}

	srcMap, srcOK := src.(map[string]string)
	if !srcOK {
		return
	}

	for key, val := range srcMap {
		if _, exists := dstMap[key]; !exists {
			dstMap[key] = val
		}
	}
}

var check = types.Checker{ //nolint:gochecknoglobals,gosec // package-scoped helper
	Type:    checkType,
	PassMsg: "build environment verification passed",
}

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
//
// The policy model only constrains property names (required and forbidden).
// Property values are exposed to CEL as buildenv.propertyValues so that value
// constraints can be expressed as CEL rules. A property whose value differs
// between attestations is dropped from buildenv.propertyValues and listed in
// buildenv.conflicts, so rules reading it fail closed.
package buildenv

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/saschagrunert/nri-supply-chain/internal/checker"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

var (
	// ErrInvalidBuildEnv indicates the build environment document could not be parsed.
	ErrInvalidBuildEnv = errors.New("invalid build environment document")

	errNoProperties        = errors.New("environment must contain at least one property")
	errEmptyPropertyName   = errors.New("environment property has an empty name")
	errConflictingProperty = errors.New(
		"environment property has conflicting values",
	)
	errMissingProperty   = errors.New("required property missing")
	errForbiddenProperty = errors.New("forbidden property present")
)

const (
	metaPropertyValues = "propertyValues"
	metaConflicts      = "conflicts"
)

// buildEnvPredicate represents the build environment attestation predicate.
type buildEnvPredicate struct {
	Environment []envProperty `json:"environment"`
}

type envProperty struct {
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
}

//nolint:gochecknoglobals // immutable check declaration
var spec = &checker.Spec[buildEnvPredicate]{
	Info: checker.Info{
		Type:  types.CheckTypeBuildEnv,
		Label: "build environment",
	},
	Aggregation: checker.AllMustPass,
	ErrInvalid:  ErrInvalidBuildEnv,
	Validate:    validatePredicate,
	Meta:        predicateMeta,
	Freshness:   nil,
	Rules:       []checker.Rule[buildEnvPredicate]{checkPropertyPolicy},
	Merge: map[string]checker.MergeFunc{
		"propertyCount":    checker.Sum(),
		"properties":       checker.CSV(),
		metaPropertyValues: checker.UnionMapDropConflicts(),
	},
}

// Info returns the check type and label of the build environment check.
func Info() checker.Info {
	return spec.Info
}

// Verify checks a single build environment attestation against the given policy.
func Verify(
	ctx context.Context,
	att []byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	result, err := spec.Verify(ctx, att, pol, imageDigest)
	if err != nil {
		//nolint:wrapcheck // the generic checker returns domain errors
		return nil, err
	}

	checker.ResolveConflictingMap(result.Metadata, metaPropertyValues, metaConflicts)

	return result, nil
}

// VerifyMultiple checks multiple build environment attestations. Any policy
// violation or invalid document causes failure. Properties whose values
// differ between attestations are dropped from the merged property values
// and listed as conflicting properties.
func VerifyMultiple(
	ctx context.Context,
	attestations [][]byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	result, err := spec.VerifyMultiple(ctx, attestations, pol, imageDigest)
	if err != nil {
		//nolint:wrapcheck // the generic checker returns domain errors
		return nil, err
	}

	checker.ResolveConflictingMap(result.Metadata, metaPropertyValues, metaConflicts)

	return result, nil
}

func validatePredicate(pred *buildEnvPredicate) error {
	if len(pred.Environment) == 0 {
		return errNoProperties
	}

	values := make(map[string]string, len(pred.Environment))

	for idx := range pred.Environment {
		prop := &pred.Environment[idx]
		if strings.TrimSpace(prop.Name) == "" {
			return fmt.Errorf("%w: environment[%d]", errEmptyPropertyName, idx)
		}

		// Property names are matched case-insensitively by the policy, so a
		// repeated name with a different value is ambiguous.
		folded := strings.ToLower(prop.Name)
		if previous, seen := values[folded]; seen && previous != prop.Value {
			return fmt.Errorf(
				"%w: %q is both %q and %q", errConflictingProperty, prop.Name, previous, prop.Value,
			)
		}

		values[folded] = prop.Value
	}

	return nil
}

func predicateMeta(pred *buildEnvPredicate) map[string]any {
	propNames := make([]string, 0, len(pred.Environment))
	propValues := make(map[string]string, len(pred.Environment))

	for idx := range pred.Environment {
		propNames = append(propNames, pred.Environment[idx].Name)
		propValues[pred.Environment[idx].Name] = pred.Environment[idx].Value
	}

	return map[string]any{
		"propertyCount":    int64(len(pred.Environment)),
		"properties":       strings.Join(propNames, ","),
		metaPropertyValues: propValues,
	}
}

func checkPropertyPolicy(pred *buildEnvPredicate, pol *policy.Policy) string {
	if pol.BuildEnv == nil {
		return ""
	}

	for _, required := range pol.BuildEnv.RequiredProperties {
		if !containsProperty(pred.Environment, required) {
			return fmt.Sprintf("%s: %q", errMissingProperty, required)
		}
	}

	for _, forbidden := range pol.BuildEnv.ForbiddenProperties {
		if containsProperty(pred.Environment, forbidden) {
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

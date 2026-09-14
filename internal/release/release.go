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

// Package release provides release attestation verification for supply chain checks.
package release

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/saschagrunert/nri-supply-chain/internal/checker"
	"github.com/saschagrunert/nri-supply-chain/internal/glob"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

var (
	// ErrInvalidRelease indicates the release attestation could not be parsed.
	ErrInvalidRelease = errors.New("invalid release attestation")

	// ErrUntrustedRegistry indicates the release purl does not match trusted registries.
	ErrUntrustedRegistry = errors.New("release purl does not match trusted registries")

	// ErrMissingPackageID indicates the release attestation is missing the required packageId.
	ErrMissingPackageID = errors.New("release attestation missing required packageId")

	errMissingPURL = errors.New("purl is required")
)

type releasePredicate struct {
	PURL      string `json:"purl"`
	PackageID string `json:"packageId,omitempty"` //nolint:tagliatelle // matches in-toto release spec field name
}

//nolint:gochecknoglobals // immutable check declaration
var spec = &checker.Spec[releasePredicate]{
	Info: checker.Info{
		Type:  types.CheckTypeRelease,
		Label: "release",
	},
	Aggregation: checker.FirstPass,
	ErrInvalid:  ErrInvalidRelease,
	Validate:    validatePredicate,
	Meta: func(pred *releasePredicate) map[string]any {
		return map[string]any{
			"purl":      pred.PURL,
			"packageId": pred.PackageID,
		}
	},
	Freshness: nil,
	Rules: []checker.Rule[releasePredicate]{
		checkTrustedRegistry,
		checkPackageID,
	},
	Merge: nil,
}

// Info returns the check type and label of the release check.
func Info() checker.Info {
	return spec.Info
}

// Verify checks a single release attestation against the given policy.
func Verify(
	ctx context.Context,
	att []byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	//nolint:wrapcheck // the generic checker returns domain errors
	return spec.Verify(ctx, att, pol, imageDigest)
}

// VerifyMultiple checks multiple release attestations, accepting if any valid one passes.
func VerifyMultiple(
	ctx context.Context,
	attestations [][]byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	//nolint:wrapcheck // the generic checker returns domain errors
	return spec.VerifyMultiple(ctx, attestations, pol, imageDigest)
}

func validatePredicate(pred *releasePredicate) error {
	if strings.TrimSpace(pred.PURL) == "" {
		return errMissingPURL
	}

	return nil
}

func checkTrustedRegistry(pred *releasePredicate, pol *policy.Policy) string {
	if pol.Release == nil || len(pol.Release.TrustedRegistries) == 0 {
		return ""
	}

	for _, pattern := range pol.Release.TrustedRegistries {
		matched, err := glob.Match(pattern, pred.PURL)
		if err != nil {
			return fmt.Sprintf("invalid registry pattern %q: %s", pattern, err)
		}

		if matched {
			return ""
		}
	}

	return fmt.Sprintf("%s: %q", ErrUntrustedRegistry, pred.PURL)
}

func checkPackageID(pred *releasePredicate, pol *policy.Policy) string {
	if pol.Release != nil && pol.Release.RequirePackageID && pred.PackageID == "" {
		return ErrMissingPackageID.Error()
	}

	return ""
}

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
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/saschagrunert/nri-supply-chain/internal/glob"
	"github.com/saschagrunert/nri-supply-chain/internal/intoto"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const checkType = types.CheckTypeRelease

var (
	// ErrInvalidRelease indicates the release attestation could not be parsed.
	ErrInvalidRelease = errors.New("invalid release attestation")

	// ErrUntrustedRegistry indicates the release purl does not match trusted registries.
	ErrUntrustedRegistry = errors.New("release purl does not match trusted registries")

	// ErrMissingPackageID indicates the release attestation is missing the required packageId.
	ErrMissingPackageID = errors.New("release attestation missing required packageId")
)

type releasePredicate struct {
	PURL      string `json:"purl"`
	PackageID string `json:"packageId,omitempty"` //nolint:tagliatelle // matches in-toto release spec field name
}

// Verify checks a single release attestation against the given policy.
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
		return nil, fmt.Errorf("%w: %w", ErrInvalidRelease, err)
	}

	return verifyReleasePredicate(predicate, pol)
}

// VerifyMultiple checks multiple release attestations, accepting if any valid one passes.
func VerifyMultiple(
	ctx context.Context,
	attestations [][]byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	var (
		failReasons []string
		parseErrors []string
	)

	for _, att := range attestations {
		ctxErr := ctx.Err()
		if ctxErr != nil {
			return nil, fmt.Errorf("verification cancelled: %w", ctxErr)
		}

		result, err := Verify(ctx, att, pol, imageDigest)
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

		return check.Fail(detail), nil
	}

	if len(parseErrors) > 0 {
		return check.Fail(
			"no valid release attestation: " + strings.Join(parseErrors, "; "),
		), nil
	}

	return check.Fail("no valid release attestation found"), nil
}

func verifyReleasePredicate(
	predicate []byte, pol *policy.Policy,
) (*types.CheckResult, error) {
	var pred releasePredicate

	err := json.Unmarshal(predicate, &pred)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidRelease, err)
	}

	meta := map[string]any{
		"purl":      pred.PURL,
		"packageId": pred.PackageID,
	}

	if pol.Release != nil && len(pol.Release.TrustedRegistries) > 0 {
		err = verifyTrustedRegistry(pred.PURL, pol.Release.TrustedRegistries)
		if err != nil {
			result := check.Fail(err.Error())
			result.Metadata = meta

			return result, nil
		}
	}

	if pol.Release != nil && pol.Release.RequirePackageID && pred.PackageID == "" {
		result := check.Fail(ErrMissingPackageID.Error())
		result.Metadata = meta

		return result, nil
	}

	result := check.Pass()
	result.Metadata = meta

	return result, nil
}

func verifyTrustedRegistry(purl string, trustedRegistries []string) error {
	if purl == "" {
		return fmt.Errorf("%w: purl not found in attestation", ErrUntrustedRegistry)
	}

	for _, pattern := range trustedRegistries {
		matched, err := glob.Match(pattern, purl)
		if err != nil {
			return fmt.Errorf("invalid registry pattern %q: %w", pattern, err)
		}

		if matched {
			return nil
		}
	}

	return fmt.Errorf("%w: %q", ErrUntrustedRegistry, purl)
}

var check = types.Checker{ //nolint:gochecknoglobals // package-scoped helper
	Type:    checkType,
	PassMsg: "release verification passed",
}

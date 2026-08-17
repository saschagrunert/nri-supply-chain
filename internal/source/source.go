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

// Package source provides SLSA source track verification for supply chain checks.
package source

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/glob"
	"github.com/saschagrunert/nri-supply-chain/internal/intoto"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const checkType = types.CheckTypeSource

var (
	// ErrInvalidSource indicates the source attestation could not be parsed.
	ErrInvalidSource = errors.New("invalid source attestation")

	// ErrUntrustedSourceRepo indicates the source repository is not trusted.
	ErrUntrustedSourceRepo = errors.New("untrusted source repository")

	// ErrSourceLevelInsufficient indicates the source level is below the minimum.
	ErrSourceLevelInsufficient = errors.New("source level below minimum")

	// ErrStaleSource indicates the source attestation is older than the maximum allowed age.
	ErrStaleSource = errors.New("source attestation is stale")

	// ErrFutureTimestamp indicates the source attestation timestamp is in the future.
	ErrFutureTimestamp = errors.New("source attestation timestamp is in the future")
)

// sourcePredicate represents the SLSA source track v1 predicate.
type sourcePredicate struct {
	SourceLocations []sourceLocation `json:"sourceLocations"`
	SourceMetadata  *sourceMetadata  `json:"sourceMetadata,omitempty"`
}

type sourceLocation struct {
	URI    string            `json:"uri"`
	Digest map[string]string `json:"digest,omitempty"`
	Branch string            `json:"branch,omitempty"`
}

type sourceMetadata struct {
	SourceLevel int        `json:"sourceLevel,omitempty"`
	VerifiedOn  *time.Time `json:"verifiedOn,omitempty"`
}

// Verify checks a single source attestation against the given policy.
func Verify( //nolint:revive // ctx reserved for future context-aware logging
	ctx context.Context,
	att []byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	predicate, err := intoto.VerifySubjectAndExtractPredicate(att, imageDigest)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSource, err)
	}

	return verifySourcePredicate(predicate, pol)
}

// VerifyMultiple checks multiple source attestations, accepting if any valid one passes.
func VerifyMultiple(
	ctx context.Context,
	attestations [][]byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	var (
		failReasons []string
		parseErrors []string
	)

	for _, att := range attestations {
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
			"no valid source attestation: " + strings.Join(parseErrors, "; "),
		), nil
	}

	return check.Fail("no valid source attestation found"), nil
}

//nolint:cyclop,funlen // sequential verification steps
func verifySourcePredicate(
	predicate []byte, pol *policy.Policy,
) (*types.CheckResult, error) {
	var pred sourcePredicate

	err := json.Unmarshal(predicate, &pred)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSource, err)
	}

	sourceURI := ""
	branch := ""

	if len(pred.SourceLocations) > 0 {
		sourceURI = pred.SourceLocations[0].URI
		branch = pred.SourceLocations[0].Branch
	}

	sourceLevel := 0
	if pred.SourceMetadata != nil {
		sourceLevel = pred.SourceMetadata.SourceLevel
	}

	meta := map[string]any{
		"source": sourceURI,
		"branch": branch,
		"level":  int64(sourceLevel),
	}

	if pol.Trust != nil && len(pol.Trust.Sources) > 0 {
		err = verifySourceRepo(sourceURI, pol.Trust.Sources)
		if err != nil {
			result := check.Fail(err.Error())
			result.Metadata = meta

			return result, nil
		}
	}

	if pol.Source != nil {
		if sourceLevel < pol.Source.MinimumLevel {
			result := check.Fail(fmt.Sprintf(
				"%s: got %d, minimum %d",
				ErrSourceLevelInsufficient, sourceLevel, pol.Source.MinimumLevel,
			))
			result.Metadata = meta

			return result, nil
		}

		var verifiedOn *time.Time
		if pred.SourceMetadata != nil {
			verifiedOn = pred.SourceMetadata.VerifiedOn
		}

		err = verifyFreshness(verifiedOn, pol)
		if err != nil {
			result := check.Fail(err.Error())
			result.Metadata = meta

			return result, nil
		}
	}

	result := check.Pass()
	result.Metadata = meta

	return result, nil
}

func verifySourceRepo(sourceURI string, trustedSources []string) error {
	if sourceURI == "" {
		return fmt.Errorf("%w: source URI not found in attestation", ErrUntrustedSourceRepo)
	}

	for _, pattern := range trustedSources {
		matched, err := glob.Match(pattern, sourceURI)
		if err != nil {
			return fmt.Errorf("invalid source pattern %q: %w", pattern, err)
		}

		if matched {
			return nil
		}
	}

	return fmt.Errorf("%w: %q", ErrUntrustedSourceRepo, sourceURI)
}

func verifyFreshness(verifiedOn *time.Time, pol *policy.Policy) error {
	maxAgeConfigured := pol.Source != nil && pol.Source.MaxAge != ""

	if verifiedOn == nil {
		if maxAgeConfigured {
			return fmt.Errorf("%w: no verified timestamp in attestation", ErrStaleSource)
		}

		return nil
	}

	if !maxAgeConfigured {
		return nil
	}

	maxAge := &pol.Source.MaxAgeDuration

	//nolint:wrapcheck // VerifyFreshness wraps the caller's sentinel errors
	return types.VerifyFreshness(
		*verifiedOn,
		maxAge,
		"verified",
		ErrFutureTimestamp,
		ErrStaleSource,
		ErrStaleSource,
	)
}

var check = types.Checker{ //nolint:gochecknoglobals // package-scoped helper
	Type:    checkType,
	PassMsg: "source verification passed",
}

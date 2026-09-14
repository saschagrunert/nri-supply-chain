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
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/checker"
	"github.com/saschagrunert/nri-supply-chain/internal/glob"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

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

	errNoSourceLocation = errors.New("sourceLocations with a non-empty uri is required")
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

//nolint:gochecknoglobals // immutable check declaration
var spec = &checker.Spec[sourcePredicate]{
	Info: checker.Info{
		Type:  types.CheckTypeSource,
		Label: "source",
	},
	Aggregation: checker.FirstPass,
	ErrInvalid:  ErrInvalidSource,
	Validate:    validatePredicate,
	Meta:        predicateMeta,
	Freshness: &checker.Freshness[sourcePredicate]{
		Timestamp: func(pred *sourcePredicate) *time.Time {
			if pred.SourceMetadata == nil {
				return nil
			}

			return pred.SourceMetadata.VerifiedOn
		},
		MaxAge: func(pol *policy.Policy) *time.Duration {
			if pol.Source == nil || pol.Source.MaxAge == "" {
				return nil
			}

			return &pol.Source.MaxAgeDuration
		},
		Label:     "verified",
		ErrStale:  ErrStaleSource,
		ErrFuture: ErrFutureTimestamp,
	},
	Rules: []checker.Rule[sourcePredicate]{
		checkTrustedSource,
		checkSourceLevel,
	},
	Merge: nil,
}

// Info returns the check type and label of the source check.
func Info() checker.Info {
	return spec.Info
}

// Verify checks a single source attestation against the given policy.
func Verify(
	ctx context.Context,
	att []byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	//nolint:wrapcheck // the generic checker returns domain errors
	return spec.Verify(ctx, att, pol, imageDigest)
}

// VerifyMultiple checks multiple source attestations, accepting if any valid one passes.
func VerifyMultiple(
	ctx context.Context,
	attestations [][]byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	//nolint:wrapcheck // the generic checker returns domain errors
	return spec.VerifyMultiple(ctx, attestations, pol, imageDigest)
}

func validatePredicate(pred *sourcePredicate) error {
	if len(pred.SourceLocations) == 0 || strings.TrimSpace(pred.SourceLocations[0].URI) == "" {
		return errNoSourceLocation
	}

	return nil
}

func predicateMeta(pred *sourcePredicate) map[string]any {
	return map[string]any{
		"source": pred.SourceLocations[0].URI,
		"branch": pred.SourceLocations[0].Branch,
		"level":  int64(sourceLevel(pred)),
	}
}

func sourceLevel(pred *sourcePredicate) int {
	if pred.SourceMetadata == nil {
		return 0
	}

	return pred.SourceMetadata.SourceLevel
}

func checkTrustedSource(pred *sourcePredicate, pol *policy.Policy) string {
	if pol.Trust == nil || len(pol.Trust.Sources) == 0 {
		return ""
	}

	err := verifySourceRepo(&pred.SourceLocations[0], pol.Trust.Sources)
	if err != nil {
		return err.Error()
	}

	return ""
}

func checkSourceLevel(pred *sourcePredicate, pol *policy.Policy) string {
	if pol.Source == nil {
		return ""
	}

	level := sourceLevel(pred)
	if level < pol.Source.MinimumLevel {
		return fmt.Sprintf(
			"%s: got %d, minimum %d",
			ErrSourceLevelInsufficient, level, pol.Source.MinimumLevel,
		)
	}

	return ""
}

// verifySourceRepo matches the source location against trust.sources the
// same way as SLSA provenance sources (see glob.MatchSource). The branch
// takes precedence over a ref embedded in the URI, and a short branch name
// also matches as "refs/heads/<branch>".
func verifySourceRepo(location *sourceLocation, trustedSources []string) error {
	repository, ref, _ := glob.SplitGitRef(location.URI)
	if location.Branch != "" {
		ref = location.Branch
	}

	refs := []string{ref}
	if ref != "" && !strings.HasPrefix(ref, "refs/") {
		refs = append(refs, "refs/heads/"+ref)
	}

	for _, pattern := range trustedSources {
		for _, candidate := range refs {
			matched, err := glob.MatchSource(pattern, repository, candidate)
			if err != nil {
				return fmt.Errorf("invalid source pattern %q: %w", pattern, err)
			}

			if matched {
				return nil
			}
		}
	}

	return fmt.Errorf("%w: %q", ErrUntrustedSourceRepo, location.URI)
}

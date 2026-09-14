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

// Package scorecard provides OpenSSF Scorecard attestation verification.
package scorecard

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/checker"
	"github.com/saschagrunert/nri-supply-chain/internal/glob"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	inconclusiveScore = -1
	maxScore          = 10
	scorecardDate     = "2006-01-02"
	httpsScheme       = "https://"

	// dateOnlyTolerance is the timezone allowance for date-only values.
	dateOnlyTolerance = 24 * time.Hour
)

var (
	// ErrInvalidScorecard indicates the Scorecard result could not be parsed or validated.
	ErrInvalidScorecard = errors.New("invalid OpenSSF Scorecard result")

	// ErrScoreBelowMinimum indicates the aggregate score is below the configured minimum.
	ErrScoreBelowMinimum = errors.New("scorecard aggregate score is below minimum")

	// ErrCheckMissing indicates a check required by policy is absent from the result.
	ErrCheckMissing = errors.New("required Scorecard check is missing")

	// ErrCheckBelowMinimum indicates a per-check score is below the configured minimum.
	ErrCheckBelowMinimum = errors.New("scorecard check score is below minimum")

	// ErrUntrustedRepository indicates the scored repository does not match trust.sources.
	ErrUntrustedRepository = errors.New("scorecard repository does not match trusted sources")

	// ErrFutureTimestamp indicates the Scorecard date is in the future.
	ErrFutureTimestamp = errors.New("scorecard date is in the future")

	errMissingRepo      = errors.New("repository name is required")
	errMissingVersion   = errors.New("scorecard version is required")
	errScoreRange       = errors.New("score is outside the valid range")
	errNoChecks         = errors.New("at least one check is required")
	errMissingCheckName = errors.New("check name is required")
)

// scorecardPredicate represents the OpenSSF Scorecard JSON v2 result carried
// as an in-toto predicate.
type scorecardPredicate struct {
	Date      string        `json:"date,omitempty"`
	Repo      repoInfo      `json:"repo"`
	Scorecard scorecardInfo `json:"scorecard"`
	Score     float64       `json:"score"`
	Checks    []checkResult `json:"checks"`

	// parsedDate is the parsed Date, set during validation.
	parsedDate *time.Time
}

type repoInfo struct {
	Name   string `json:"name"`
	Commit string `json:"commit,omitempty"`
}

type scorecardInfo struct {
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
}

type checkResult struct {
	Name  string `json:"name"`
	Score int    `json:"score"`
}

//nolint:gochecknoglobals // immutable check declaration
var spec = &checker.Spec[scorecardPredicate]{
	Info: checker.Info{
		Type:  types.CheckTypeScorecard,
		Label: "OpenSSF Scorecard",
	},
	Aggregation: checker.AllMustPass,
	ErrInvalid:  ErrInvalidScorecard,
	Validate:    validatePredicate,
	Meta: func(pred *scorecardPredicate) map[string]any {
		return map[string]any{
			"repo":    pred.Repo.Name,
			"version": pred.Scorecard.Version,
			"score":   pred.Score,
			"checks":  collectCheckScores(pred.Checks),
		}
	},
	// The policy has no maxAge for Scorecard results, so only future and
	// implausibly old dates are rejected.
	Freshness: &checker.Freshness[scorecardPredicate]{
		Timestamp: func(pred *scorecardPredicate) *time.Time { return pred.parsedDate },
		MaxAge:    nil,
		Label:     "scored",
		ErrStale:  ErrInvalidScorecard,
		ErrFuture: ErrFutureTimestamp,
	},
	Rules: []checker.Rule[scorecardPredicate]{
		checkTrustedRepository,
		checkPolicy,
	},
	Merge: map[string]checker.MergeFunc{
		"repo":    checker.CSV(),
		"version": checker.CSV(),
		"score":   checker.Min(),
		"checks":  checker.MinMap(),
	},
}

// Info returns the check type and label of the OpenSSF Scorecard check.
func Info() checker.Info {
	return spec.Info
}

// Verify checks a single OpenSSF Scorecard attestation against the given policy.
func Verify(
	ctx context.Context,
	att []byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	//nolint:wrapcheck // the generic checker returns domain errors
	return spec.Verify(ctx, att, pol, imageDigest)
}

// VerifyMultiple checks multiple OpenSSF Scorecard attestations. Any policy
// violation or invalid document causes failure.
func VerifyMultiple(
	ctx context.Context,
	attestations [][]byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	//nolint:wrapcheck // the generic checker returns domain errors
	return spec.VerifyMultiple(ctx, attestations, pol, imageDigest)
}

//nolint:cyclop // sequential field validation
func validatePredicate(pred *scorecardPredicate) error {
	if pred.Repo.Name == "" {
		return errMissingRepo
	}

	if pred.Scorecard.Version == "" {
		return errMissingVersion
	}

	if pred.Score < inconclusiveScore || pred.Score > maxScore {
		return fmt.Errorf(
			"%w: aggregate score %.1f, expected -1.0 to 10.0",
			errScoreRange,
			pred.Score,
		)
	}

	if len(pred.Checks) == 0 {
		return errNoChecks
	}

	for idx := range pred.Checks {
		if pred.Checks[idx].Name == "" {
			return fmt.Errorf("%w: checks[%d]", errMissingCheckName, idx)
		}

		if pred.Checks[idx].Score < inconclusiveScore || pred.Checks[idx].Score > maxScore {
			return fmt.Errorf(
				"%w: check %q score %d, expected -1 to 10",
				errScoreRange, pred.Checks[idx].Name, pred.Checks[idx].Score,
			)
		}
	}

	if pred.Date != "" {
		parsed, err := parseDate(pred.Date)
		if err != nil {
			return err
		}

		pred.parsedDate = &parsed
	}

	return nil
}

// parseDate parses an RFC 3339 timestamp or a date-only value. Scorecard
// JSON v1 writes the scanner's local date, which can be up to a day ahead of
// the UTC date, so a date-only value is moved back by dateOnlyTolerance to
// avoid rejecting it as a future timestamp.
func parseDate(date string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, strings.ToUpper(date))
	if err == nil {
		return parsed, nil
	}

	parsed, err = time.Parse(scorecardDate, date)
	if err != nil {
		return time.Time{}, fmt.Errorf("parsing date %q: %w", date, err)
	}

	return parsed.Add(-dateOnlyTolerance), nil
}

func collectCheckScores(checks []checkResult) map[string]int64 {
	scores := make(map[string]int64, len(checks))

	for idx := range checks {
		score := int64(checks[idx].Score)

		existing, found := scores[checks[idx].Name]
		if !found || score < existing {
			scores[checks[idx].Name] = score
		}
	}

	return scores
}

// checkTrustedRepository binds the scored repository to trust.sources when
// sources are configured, with the pattern semantics of SLSA source
// verification (see glob.MatchSource). Scorecard reports repository names
// without a scheme (github.com/org/repo), so an https:// form is also
// matched. Scorecard results carry no ref, so a ref-pinned pattern is matched
// against the scored commit and never matches a result without one.
func checkTrustedRepository(pred *scorecardPredicate, pol *policy.Policy) string {
	if pol.Trust == nil || len(pol.Trust.Sources) == 0 {
		return ""
	}

	candidates := []string{pred.Repo.Name}
	if !strings.Contains(pred.Repo.Name, "://") {
		candidates = append(candidates, httpsScheme+pred.Repo.Name)
	}

	for _, pattern := range pol.Trust.Sources {
		for _, candidate := range candidates {
			matched, err := glob.MatchSource(pattern, candidate, pred.Repo.Commit)
			if err != nil {
				return fmt.Sprintf("invalid source pattern %q: %s", pattern, err)
			}

			if matched {
				return ""
			}
		}
	}

	return fmt.Sprintf("%s: %q", ErrUntrustedRepository, pred.Repo.Name)
}

func checkPolicy(pred *scorecardPredicate, pol *policy.Policy) string {
	if pol.Scorecard == nil {
		return ""
	}

	if pol.Scorecard.MinScore != nil && pred.Score < *pol.Scorecard.MinScore {
		return fmt.Sprintf(
			"%s: got %.1f, require at least %.1f",
			ErrScoreBelowMinimum, pred.Score, *pol.Scorecard.MinScore,
		)
	}

	checks := collectCheckScores(pred.Checks)

	names := make([]string, 0, len(pol.Scorecard.Checks))
	for name := range pol.Scorecard.Checks {
		names = append(names, name)
	}

	sort.Strings(names)

	for _, name := range names {
		checkScore, found := checks[name]
		if !found {
			return fmt.Sprintf("%s: %q", ErrCheckMissing, name)
		}

		minimum := int64(pol.Scorecard.Checks[name])
		if checkScore < minimum {
			return fmt.Sprintf(
				"%s: %q got %d, require at least %d",
				ErrCheckBelowMinimum, name, checkScore, minimum,
			)
		}
	}

	return ""
}

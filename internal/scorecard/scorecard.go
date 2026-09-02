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
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/saschagrunert/nri-supply-chain/internal/intoto"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	checkType         = types.CheckTypeScorecard
	inconclusiveScore = -1
	maxScore          = 10
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
)

// scorecardPredicate represents the OpenSSF Scorecard JSON v2 result carried
// as an in-toto predicate.
type scorecardPredicate struct {
	Date      string        `json:"date,omitempty"`
	Repo      repoInfo      `json:"repo"`
	Scorecard scorecardInfo `json:"scorecard"`
	Score     float64       `json:"score"`
	Checks    []checkResult `json:"checks"`
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

// Verify checks a single OpenSSF Scorecard attestation against the given policy.
func Verify( //nolint:revive // ctx reserved for future context-aware logging
	ctx context.Context,
	att []byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	predicate, err := intoto.VerifySubjectAndExtractPredicate(att, imageDigest)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidScorecard, err)
	}

	return verifyScorecardPredicate(predicate, pol)
}

// VerifyMultiple checks multiple OpenSSF Scorecard attestations. Any policy
// violation in any document causes failure.
func VerifyMultiple(
	ctx context.Context,
	attestations [][]byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	//nolint:wrapcheck // VerifyMultipleWithMerge returns domain errors
	return types.VerifyMultipleWithMerge(
		ctx, checkType, "OpenSSF Scorecard", "OpenSSF Scorecard verification passed",
		attestations,
		func(att []byte) (*types.CheckResult, error) {
			return Verify(ctx, att, pol, imageDigest)
		},
		mergeScorecardMeta,
	)
}

func verifyScorecardPredicate(
	predicate []byte, pol *policy.Policy,
) (*types.CheckResult, error) {
	var pred scorecardPredicate

	err := json.Unmarshal(predicate, &pred)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidScorecard, err)
	}

	validateErr := validatePredicate(&pred)
	if validateErr != nil {
		return nil, validateErr
	}

	checkScores := collectCheckScores(pred.Checks)
	meta := map[string]any{
		"repo":    pred.Repo.Name,
		"version": pred.Scorecard.Version,
		"score":   pred.Score,
		"checks":  checkScores,
	}

	if pol.Scorecard != nil {
		violation := checkPolicy(pred.Score, checkScores, pol.Scorecard)
		if violation != "" {
			result := check.Fail(violation)
			result.Metadata = meta

			return result, nil
		}
	}

	result := check.Pass()
	result.Metadata = meta

	return result, nil
}

func validatePredicate(pred *scorecardPredicate) error {
	if pred.Repo.Name == "" {
		return fmt.Errorf("%w: repository name is required", ErrInvalidScorecard)
	}

	if pred.Scorecard.Version == "" {
		return fmt.Errorf("%w: Scorecard version is required", ErrInvalidScorecard)
	}

	if pred.Score < inconclusiveScore || pred.Score > maxScore {
		return fmt.Errorf(
			"%w: aggregate score %.1f is outside the range -1.0 to 10.0",
			ErrInvalidScorecard, pred.Score,
		)
	}

	if len(pred.Checks) == 0 {
		return fmt.Errorf("%w: at least one check is required", ErrInvalidScorecard)
	}

	for idx := range pred.Checks {
		if pred.Checks[idx].Name == "" {
			return fmt.Errorf("%w: checks[%d].name is required", ErrInvalidScorecard, idx)
		}

		if pred.Checks[idx].Score < inconclusiveScore || pred.Checks[idx].Score > maxScore {
			return fmt.Errorf(
				"%w: check %q score %d is outside the range -1 to 10",
				ErrInvalidScorecard, pred.Checks[idx].Name, pred.Checks[idx].Score,
			)
		}
	}

	return nil
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

func checkPolicy(score float64, checks map[string]int64, pol *policy.ScorecardPolicy) string {
	if pol.MinScore != nil && score < *pol.MinScore {
		return fmt.Sprintf(
			"%s: got %.1f, require at least %.1f",
			ErrScoreBelowMinimum, score, *pol.MinScore,
		)
	}

	names := make([]string, 0, len(pol.Checks))
	for name := range pol.Checks {
		names = append(names, name)
	}

	sort.Strings(names)

	for _, name := range names {
		checkScore, found := checks[name]
		if !found {
			return fmt.Sprintf("%s: %q", ErrCheckMissing, name)
		}

		minimum := int64(pol.Checks[name])
		if checkScore < minimum {
			return fmt.Sprintf(
				"%s: %q got %d, require at least %d",
				ErrCheckBelowMinimum, name, checkScore, minimum,
			)
		}
	}

	return ""
}

func mergeScorecardMeta(dst, src map[string]any) {
	for key, val := range src {
		existing, found := dst[key]
		if !found {
			dst[key] = val

			continue
		}

		switch key {
		case "repo", "version":
			mergeStringMeta(dst, key, existing, val)
		case "score":
			mergeScoreMeta(dst, key, existing, val)
		case "checks":
			mergeCheckScores(existing, val)
		default:
		}
	}
}

func mergeStringMeta(dst map[string]any, key string, existing, incoming any) {
	dstValue, dstOK := existing.(string)
	srcValue, srcOK := incoming.(string)

	if dstOK && srcOK {
		dst[key] = types.MergeCommaSeparated(dstValue, srcValue)
	}
}

func mergeScoreMeta(dst map[string]any, key string, existing, incoming any) {
	dstScore, dstOK := existing.(float64)
	srcScore, srcOK := incoming.(float64)

	if dstOK && srcOK && srcScore < dstScore {
		dst[key] = srcScore
	}
}

func mergeCheckScores(existing, incoming any) {
	dstChecks, dstOK := existing.(map[string]int64)
	srcChecks, srcOK := incoming.(map[string]int64)

	if !dstOK || !srcOK {
		return
	}

	for name, score := range srcChecks {
		existingScore, found := dstChecks[name]
		if !found || score < existingScore {
			dstChecks[name] = score
		}
	}
}

var check = types.Checker{ //nolint:gochecknoglobals,gosec // package-scoped helper
	Type:    checkType,
	PassMsg: "OpenSSF Scorecard verification passed",
}

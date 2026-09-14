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

// Package checker provides a generic verifier for in-toto predicate
// attestations. Attestation type packages declare how to parse, validate,
// describe, and evaluate their predicate in a Spec; subject binding,
// predicate decoding, freshness, aggregation across documents, and result
// construction are implemented once here.
package checker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/intoto"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

var (
	// ErrNotObject indicates the predicate is not a JSON object.
	ErrNotObject = errors.New("predicate must be a JSON object")

	// ErrNoValidator indicates a Spec was declared without a Validate function.
	ErrNoValidator = errors.New("predicate validator not configured")
)

// Aggregation selects how results from multiple attestations of the same
// type are combined.
type Aggregation int

const (
	// FirstPass accepts when any attestation parses and passes.
	FirstPass Aggregation = iota
	// AllMustPass requires every attestation to parse and pass. Metadata
	// from all documents is merged using Spec.Merge.
	AllMustPass
)

// Info identifies an attestation check type and its human-readable label.
type Info struct {
	// Type is the check type recorded in results.
	Type types.CheckType
	// Label is a human-readable name used in messages, for example
	// "build environment".
	Label string
}

// PassMessage returns the detail used for passing results.
func (i Info) PassMessage() string {
	return i.Label + " verification passed"
}

// Rule evaluates a policy constraint against a parsed predicate. It returns
// a non-empty violation detail when the constraint is not satisfied.
type Rule[P any] func(pred *P, pol *policy.Policy) string

// Freshness declares how the timestamp of a predicate is checked.
type Freshness[P any] struct {
	// Timestamp returns the predicate timestamp, or nil when absent.
	Timestamp func(pred *P) *time.Time
	// MaxAge returns the configured maximum age, or nil when unset.
	MaxAge func(pol *policy.Policy) *time.Duration
	// Label describes the timestamp in stale messages, for example "scanned".
	Label string
	// ErrStale is returned for stale or missing timestamps when a maximum
	// age is configured.
	ErrStale error
	// ErrFuture is returned for timestamps beyond the clock skew tolerance.
	ErrFuture error
}

// Spec declares how to verify one predicate type. P is the predicate
// document type decoded from JSON.
type Spec[P any] struct {
	// Info identifies the check type and label.
	Info Info

	// Aggregation selects how multiple attestations are combined.
	Aggregation Aggregation
	// ErrInvalid wraps parse and validation errors.
	ErrInvalid error
	// Validate checks that the predicate carries the fields its
	// specification requires. It is mandatory: a Spec without it rejects
	// every document.
	Validate func(pred *P) error
	// Meta returns metadata exposed to CEL expressions and audit logs.
	Meta func(pred *P) map[string]any
	// Freshness, when set, is evaluated after all rules. A timestamp in the
	// future is always rejected; staleness is only checked when a maximum
	// age is configured.
	Freshness *Freshness[P]
	// Rules are evaluated in order; the first violation fails the check.
	Rules []Rule[P]
	// Merge combines metadata values by key for AllMustPass aggregation.
	// Keys without a merge function keep the first value.
	Merge map[string]MergeFunc
}

// Verify checks a single in-toto statement against the policy.
func (s *Spec[P]) Verify(
	ctx context.Context, att []byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	ctxErr := ctx.Err()
	if ctxErr != nil {
		return nil, fmt.Errorf("verification cancelled: %w", ctxErr)
	}

	predicate, err := intoto.VerifySubjectAndExtractPredicate(att, imageDigest)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", s.ErrInvalid, err)
	}

	pred, err := s.Parse(predicate)
	if err != nil {
		return nil, err
	}

	return s.Evaluate(pred, pol), nil
}

// VerifyMultiple checks all attestations using the Spec's aggregation.
func (s *Spec[P]) VerifyMultiple(
	ctx context.Context, attestations [][]byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	verifyOne := func(att []byte) (*types.CheckResult, error) {
		return s.Verify(ctx, att, pol, imageDigest)
	}

	if s.Aggregation == FirstPass {
		//nolint:wrapcheck // shared helper returns domain errors
		return types.VerifyMultipleFirstPass(
			ctx,
			s.Info.Type,
			s.Info.Label,
			attestations,
			verifyOne,
		)
	}

	//nolint:wrapcheck // shared helper returns domain errors
	return types.VerifyMultipleWithMerge(
		ctx, s.Info.Type, s.Info.Label, s.Info.PassMessage(), attestations, verifyOne, s.mergeMeta,
	)
}

// Parse decodes and validates a raw predicate. Empty, null, and non-object
// predicates are rejected.
func (s *Spec[P]) Parse(predicate []byte) (*P, error) {
	trimmed := bytes.TrimSpace(predicate)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, fmt.Errorf("%w: %w", s.ErrInvalid, ErrNotObject)
	}

	var pred P

	err := json.Unmarshal(trimmed, &pred)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", s.ErrInvalid, err)
	}

	if s.Validate == nil {
		return nil, fmt.Errorf("%w: %w", s.ErrInvalid, ErrNoValidator)
	}

	err = s.Validate(&pred)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", s.ErrInvalid, err)
	}

	return &pred, nil
}

// Evaluate applies rules and freshness to a parsed predicate.
func (s *Spec[P]) Evaluate(pred *P, pol *policy.Policy) *types.CheckResult {
	var meta map[string]any
	if s.Meta != nil {
		meta = s.Meta(pred)
	}

	for _, rule := range s.Rules {
		violation := rule(pred, pol)
		if violation != "" {
			return withMeta(types.FailResult(s.Info.Type, violation, nil), meta)
		}
	}

	if s.Freshness != nil {
		err := s.Freshness.check(pred, pol)
		if err != nil {
			return withMeta(types.FailResult(s.Info.Type, err.Error(), nil), meta)
		}
	}

	return withMeta(types.PassResult(s.Info.Type, s.Info.PassMessage()), meta)
}

// mergeMeta merges src into dst using the Spec's merge functions.
func (s *Spec[P]) mergeMeta(dst, src map[string]any) {
	for key, val := range src {
		existing, found := dst[key]
		if !found {
			dst[key] = val

			continue
		}

		merge, ok := s.Merge[key]
		if !ok {
			continue
		}

		if merged, mergedOK := merge(existing, val); mergedOK {
			dst[key] = merged
		}
	}
}

func (f *Freshness[P]) check(pred *P, pol *policy.Policy) error {
	var maxAge *time.Duration
	if f.MaxAge != nil {
		maxAge = f.MaxAge(pol)
	}

	// A zero time (for example "0001-01-01T00:00:00Z", which Go emits for an
	// unset time.Time) carries no information and is treated as absent.
	timestamp := f.Timestamp(pred)
	if timestamp == nil || timestamp.IsZero() {
		if maxAge != nil {
			return fmt.Errorf("%w: no %s timestamp in attestation", f.ErrStale, f.Label)
		}

		return nil
	}

	//nolint:wrapcheck // VerifyFreshness wraps the caller's sentinel errors
	return types.VerifyFreshness(
		*timestamp, maxAge, f.Label, f.ErrFuture, f.ErrStale, f.ErrStale,
	)
}

func withMeta(result *types.CheckResult, meta map[string]any) *types.CheckResult {
	result.Metadata = meta

	return result
}

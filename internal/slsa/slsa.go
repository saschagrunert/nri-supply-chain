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

// Package slsa provides SLSA provenance verification for supply chain attestations.
package slsa

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/glob"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	checkType = types.CheckTypeSLSA

	metaBuilderID = "builderID"
	metaBuildType = "buildType"
	metaSource    = "source"

	clockSkewTolerance = 60 * time.Second

	// maxReasonableAge caps the computed age to prevent time.Duration overflow
	// on crafted timestamps (e.g., year 0001). time.Duration is int64
	// nanoseconds, overflowing at ~292 years.
	maxReasonableAge = 200 * 365 * 24 * time.Hour
)

var (
	// ErrSubjectDigestMismatch indicates the provenance subject does not match the image digest.
	ErrSubjectDigestMismatch = errors.New("subject digest mismatch")

	// ErrUntrustedBuilder indicates the builder is not in the trusted builders list.
	ErrUntrustedBuilder = errors.New("untrusted builder")

	// ErrUntrustedBuildType indicates the build type is not in the allowed list.
	ErrUntrustedBuildType = errors.New("untrusted build type")

	// ErrUntrustedSource indicates the source repository is not in the allowed list.
	ErrUntrustedSource = errors.New("untrusted source repository")

	// ErrUnknownParameters indicates unrecognized external parameters were found.
	ErrUnknownParameters = errors.New("unrecognized external parameters")

	// ErrInvalidProvenance indicates the provenance attestation could not be parsed.
	ErrInvalidProvenance = errors.New("invalid provenance attestation")

	// ErrStaleProvenance indicates the provenance is older than the maximum allowed age.
	ErrStaleProvenance = errors.New("provenance is stale")

	// ErrFutureTimestamp indicates the provenance build timestamp is in the future.
	ErrFutureTimestamp = errors.New("provenance build timestamp is in the future")

	warnedMaxLevel   sync.Map //nolint:gochecknoglobals // dedup per builder ID
	warnedEmptyTrust sync.Map //nolint:gochecknoglobals // one-time empty trust warning
)

// Statement represents an in-toto statement wrapping a SLSA provenance predicate.
type Statement struct {
	Type          string              `json:"_type"` //nolint:tagliatelle // In-toto spec field name.
	Subject       []Subject           `json:"subject"`
	PredicateType string              `json:"predicateType"`
	Predicate     ProvenancePredicate `json:"predicate"`
}

// Subject represents an in-toto subject with name and digests.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// ProvenancePredicate represents the SLSA provenance v1 predicate.
type ProvenancePredicate struct {
	BuildDefinition BuildDefinition `json:"buildDefinition"`
	RunDetails      RunDetails      `json:"runDetails"`
}

// BuildDefinition describes what was built and how.
type BuildDefinition struct {
	BuildType          string         `json:"buildType"`
	ExternalParameters map[string]any `json:"externalParameters"`
	InternalParameters map[string]any `json:"internalParameters"`
}

// RunDetails describes the build execution.
type RunDetails struct {
	Builder  Builder  `json:"builder"`
	Metadata Metadata `json:"metadata"`
}

// Builder identifies the build system.
type Builder struct {
	ID string `json:"id"`
}

// Metadata holds build metadata.
type Metadata struct {
	InvocationID string     `json:"invocationId"` //nolint:tagliatelle // SLSA spec field name.
	StartedOn    *time.Time `json:"startedOn,omitempty"`
}

// Verify checks a SLSA provenance attestation against the given policy.
func Verify(
	ctx context.Context, att []byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	var header struct {
		PredicateType string `json:"predicateType"`
	}

	err := json.Unmarshal(att, &header)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidProvenance, err)
	}

	if header.PredicateType == attestation.PredicateSLSAProvenanceV02 {
		return verifyV02(ctx, att, pol, imageDigest)
	}

	return verifyV1(ctx, att, pol, imageDigest)
}

func verifyV1(
	ctx context.Context, att []byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	var stmt Statement

	err := json.Unmarshal(att, &stmt)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidProvenance, err)
	}

	if stmt.PredicateType != attestation.PredicateSLSAProvenanceV1 {
		return nil, fmt.Errorf(
			"%w: unexpected predicate type %q", ErrInvalidProvenance, stmt.PredicateType,
		)
	}

	warnEmptyTrust(ctx, pol)

	err = verifySubjectDigest(stmt.Subject, imageDigest)
	if err != nil {
		return failResult(err.Error()), nil
	}

	err = verifyBuilder(ctx, stmt.Predicate.RunDetails.Builder, pol)
	if err != nil {
		return failResult(err.Error()), nil
	}

	err = verifyBuildType(stmt.Predicate.BuildDefinition.BuildType, pol)
	if err != nil {
		return failResult(err.Error()), nil
	}

	err = verifySources(stmt.Predicate.BuildDefinition.ExternalParameters, pol)
	if err != nil {
		return failResult(err.Error()), nil
	}

	err = verifyParameters(stmt.Predicate.BuildDefinition.ExternalParameters, pol)
	if err != nil {
		return failResult(err.Error()), nil
	}

	err = verifyFreshness(stmt.Predicate.RunDetails.Metadata.StartedOn, pol)
	if err != nil {
		return failResult(err.Error()), nil
	}

	result := passResult()
	result.Metadata = map[string]any{
		metaBuilderID: stmt.Predicate.RunDetails.Builder.ID,
		metaBuildType: stmt.Predicate.BuildDefinition.BuildType,
		metaSource:    extractSource(stmt.Predicate.BuildDefinition.ExternalParameters),
	}

	return result, nil
}

// StatementV02 represents an in-toto v0.1 statement wrapping a SLSA provenance v0.2 predicate.
type StatementV02 struct {
	Type          string                 `json:"_type"` //nolint:tagliatelle // In-toto spec field name.
	Subject       []Subject              `json:"subject"`
	PredicateType string                 `json:"predicateType"`
	Predicate     ProvenancePredicateV02 `json:"predicate"`
}

// ProvenancePredicateV02 represents the SLSA provenance v0.2 predicate.
type ProvenancePredicateV02 struct {
	Builder    Builder       `json:"builder"`
	BuildType  string        `json:"buildType"`
	Invocation InvocationV02 `json:"invocation"`
	Materials  []MaterialV02 `json:"materials"`
	Metadata   MetadataV02   `json:"metadata"`
}

// MetadataV02 holds build metadata for v0.2 provenance.
type MetadataV02 struct {
	BuildStartedOn *time.Time `json:"buildStartedOn,omitempty"`
}

// InvocationV02 holds v0.2 invocation metadata.
type InvocationV02 struct {
	ConfigSource ConfigSourceV02 `json:"configSource"`
}

// ConfigSourceV02 identifies the source of a v0.2 build invocation.
type ConfigSourceV02 struct {
	URI string `json:"uri"`
}

// MaterialV02 represents a v0.2 build material.
type MaterialV02 struct {
	URI string `json:"uri"`
}

func verifyV02(
	ctx context.Context, att []byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	var stmt StatementV02

	err := json.Unmarshal(att, &stmt)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidProvenance, err)
	}

	warnEmptyTrust(ctx, pol)

	err = verifySubjectDigest(stmt.Subject, imageDigest)
	if err != nil {
		return failResult(err.Error()), nil
	}

	err = verifyBuilder(ctx, stmt.Predicate.Builder, pol)
	if err != nil {
		return failResult(err.Error()), nil
	}

	err = verifyBuildType(stmt.Predicate.BuildType, pol)
	if err != nil {
		return failResult(err.Error()), nil
	}

	err = verifySourceV02(&stmt.Predicate, pol)
	if err != nil {
		return failResult(err.Error()), nil
	}

	// v0.2 has no externalParameters, so rejectUnknownParameters does not
	// apply. Parameter validation is only meaningful for v1 provenance.

	err = verifyFreshness(stmt.Predicate.Metadata.BuildStartedOn, pol)
	if err != nil {
		return failResult(err.Error()), nil
	}

	result := passResult()
	result.Metadata = map[string]any{
		metaBuilderID: stmt.Predicate.Builder.ID,
		metaBuildType: stmt.Predicate.BuildType,
		metaSource:    normalizeSourceV02(sourceV02(&stmt.Predicate)),
	}

	return result, nil
}

func verifySourceV02(pred *ProvenancePredicateV02, pol *policy.Policy) error {
	if pol.Trust == nil || len(pol.Trust.Sources) == 0 {
		return nil
	}

	source := normalizeSourceV02(sourceV02(pred))
	if source == "" {
		return fmt.Errorf("%w: source not found in v0.2 provenance", ErrUntrustedSource)
	}

	for _, pattern := range pol.Trust.Sources {
		matched, err := glob.Match(pattern, source)
		if err != nil {
			return fmt.Errorf("invalid source pattern %q: %w", pattern, err)
		}

		if matched {
			return nil
		}
	}

	return fmt.Errorf("%w: %q", ErrUntrustedSource, source)
}

// sourceV02 returns the raw source URI from a v0.2 provenance predicate.
// Falls back to the first material URI; this relies on the SLSA GitHub
// generator always listing the source repo as the first material.
func sourceV02(pred *ProvenancePredicateV02) string {
	if pred.Invocation.ConfigSource.URI != "" {
		return pred.Invocation.ConfigSource.URI
	}

	if len(pred.Materials) > 0 {
		return pred.Materials[0].URI
	}

	return ""
}

// normalizeSourceV02 converts v0.2 git URIs like
// "git+https://github.com/org/repo@refs/heads/main" into bare paths
// like "github.com/org/repo" so they match the same trust policy
// source patterns used for v1 provenance.
func normalizeSourceV02(uri string) string {
	normalized := uri
	normalized = strings.TrimPrefix(normalized, "git+https://")
	normalized = strings.TrimPrefix(normalized, "git+http://")
	normalized = strings.TrimPrefix(normalized, "https://")
	normalized = strings.TrimPrefix(normalized, "http://")

	if idx := strings.IndexByte(normalized, '@'); idx > 0 {
		normalized = normalized[:idx]
	}

	return normalized
}

// VerifyMultiple checks multiple provenance attestations, accepting if any valid one passes.
func VerifyMultiple(
	ctx context.Context,
	attestations []attestation.VerifiedAttestation, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	var (
		failReasons []string
		parseErrors []string
	)

	for idx := range attestations {
		result, err := Verify(ctx, attestations[idx].Payload, pol, imageDigest)
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

		return failResult(detail), nil
	}

	if len(parseErrors) > 0 {
		return failResult(
			"no valid provenance: " + strings.Join(parseErrors, "; "),
		), nil
	}

	return failResult("no valid provenance attestation found"), nil
}

func verifySubjectDigest(subjects []Subject, imageDigest string) error {
	for _, subject := range subjects {
		if types.MatchDigestInMap(imageDigest, subject.Digest) {
			return nil
		}
	}

	return fmt.Errorf("%w: none of the subjects match %q", ErrSubjectDigestMismatch, imageDigest)
}

// verifyBuilder checks whether the builder is in the trusted builders list.
// When a matched builder has a MaxLevel configured, a warning is logged because
// SLSA provenance does not declare a build level, so MaxLevel can only be
// enforced via VSA verification (vsa.minimumLevel).
func verifyBuilder(ctx context.Context, builder Builder, pol *policy.Policy) error {
	builders := pol.Builders()
	if len(builders) == 0 {
		return nil
	}

	for _, trusted := range builders {
		if trusted.ID == builder.ID {
			if trusted.MaxLevel > 0 {
				if _, loaded := warnedMaxLevel.LoadOrStore(builder.ID, struct{}{}); !loaded {
					slog.WarnContext(ctx,
						"Builder has maxLevel configured but SLSA provenance does not "+
							"declare build levels; use VSA verification to enforce levels",
						"builder", builder.ID,
						"maxLevel", trusted.MaxLevel,
					)
				}
			}

			return nil
		}
	}

	return fmt.Errorf("%w: %q", ErrUntrustedBuilder, builder.ID)
}

func verifyBuildType(buildType string, pol *policy.Policy) error {
	if pol.Trust == nil || len(pol.Trust.BuildTypes) == 0 {
		return nil
	}

	if slices.Contains(pol.Trust.BuildTypes, buildType) {
		return nil
	}

	return fmt.Errorf("%w: %q", ErrUntrustedBuildType, buildType)
}

// verifySources checks whether the provenance source matches any trusted
// source pattern. '*' matches non-'/' characters, '**' matches any
// characters including '/'.
func verifySources(params map[string]any, pol *policy.Policy) error {
	if pol.Trust == nil || len(pol.Trust.Sources) == 0 {
		return nil
	}

	sourceVal, exists := params[metaSource]
	if !exists {
		return fmt.Errorf("%w: source parameter missing", ErrUntrustedSource)
	}

	source, isString := sourceVal.(string)
	if !isString {
		return fmt.Errorf("%w: source parameter is not a string", ErrUntrustedSource)
	}

	for _, pattern := range pol.Trust.Sources {
		matched, err := glob.Match(pattern, source)
		if err != nil {
			return fmt.Errorf("invalid source pattern %q: %w", pattern, err)
		}

		if matched {
			return nil
		}
	}

	return fmt.Errorf("%w: %q", ErrUntrustedSource, source)
}

func extractSource(params map[string]any) string {
	if s, ok := params[metaSource].(string); ok {
		return s
	}

	return ""
}

// verifyParameters rejects provenance with unrecognized externalParameters
// when rejectUnknownParameters is enabled. Uses the policy's KnownParameters
// list if configured, otherwise falls back to the GitHub Actions parameter set.
func verifyParameters(params map[string]any, pol *policy.Policy) error {
	if pol.SLSA == nil || !pol.SLSA.RejectUnknownParameters {
		return nil
	}

	known := pol.SLSA.KnownParameters
	if len(known) == 0 {
		known = defaultKnownParameters()
	}

	for paramKey := range params {
		if !slices.Contains(known, paramKey) {
			return fmt.Errorf("%w: %q", ErrUnknownParameters, paramKey)
		}
	}

	return nil
}

func defaultKnownParameters() []string {
	return []string{metaSource, "repository", "ref", "workflow", metaBuildType}
}

func passResult() *types.CheckResult {
	return types.PassResult(checkType, "SLSA provenance verified")
}

// ResetWarnings clears the deduplication state so that maxLevel
// and empty-trust warnings are re-emitted on the next verification cycle.
// Call this after a config reload to ensure warnings reflect the new policy state.
func ResetWarnings() {
	warnedMaxLevel.Clear()
	warnedEmptyTrust.Clear()
}

func warnEmptyTrust(ctx context.Context, pol *policy.Policy) {
	if len(pol.Builders()) > 0 {
		return
	}

	if pol.Trust != nil && (len(pol.Trust.Sources) > 0 || len(pol.Trust.BuildTypes) > 0) {
		return
	}

	if _, loaded := warnedEmptyTrust.LoadOrStore("empty", struct{}{}); loaded {
		return
	}

	slog.WarnContext(ctx,
		"SLSA verification has no trusted builders, sources, or build types configured; "+
			"any provenance will pass builder and source checks")
}

func verifyFreshness(buildStarted *time.Time, pol *policy.Policy) error {
	maxAgeConfigured := pol.SLSA != nil && pol.SLSA.MaxAge != ""

	if buildStarted == nil {
		if maxAgeConfigured {
			return fmt.Errorf("%w: no build timestamp in provenance", ErrStaleProvenance)
		}

		return nil
	}

	age := time.Since(*buildStarted)

	if age < -clockSkewTolerance {
		return fmt.Errorf("%w: %s", ErrFutureTimestamp, buildStarted.Format(time.RFC3339Nano))
	}

	if age < 0 {
		age = 0
	}

	if age > maxReasonableAge {
		return fmt.Errorf(
			"%w: timestamp %s is unreasonably old",
			ErrStaleProvenance,
			buildStarted.Format(time.RFC3339Nano),
		)
	}

	if maxAgeConfigured && age > pol.SLSA.MaxAgeDuration {
		return fmt.Errorf(
			"%w: built %s ago, max %s",
			ErrStaleProvenance,
			age.Truncate(time.Second),
			pol.SLSA.MaxAgeDuration,
		)
	}

	return nil
}

func failResult(detail string) *types.CheckResult {
	return types.FailResult(checkType, detail, nil)
}

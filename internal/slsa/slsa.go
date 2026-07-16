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
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
	"github.com/saschagrunert/nri-supply-chain/policy"
)

const (
	checkType       = "slsa_provenance"
	digestPartCount = 2
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
	InvocationID string `json:"invocationId"` //nolint:tagliatelle // SLSA spec field name.
}

// Verify checks a SLSA provenance attestation against the given policy.
func Verify(att []byte, pol *policy.Policy, imageDigest string) (*types.CheckResult, error) {
	var stmt Statement

	err := json.Unmarshal(att, &stmt)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidProvenance, err)
	}

	if !isSLSAPredicate(stmt.PredicateType) {
		return nil, fmt.Errorf(
			"%w: unexpected predicate type %q", ErrInvalidProvenance, stmt.PredicateType,
		)
	}

	err = verifySubjectDigest(stmt.Subject, imageDigest)
	if err != nil {
		return failResult(err.Error()), nil
	}

	err = verifyBuilder(stmt.Predicate.RunDetails.Builder, pol)
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

	return passResult(), nil
}

// VerifyMultiple checks multiple provenance attestations, accepting if any valid one passes.
func VerifyMultiple(
	attestations []attestation.VerifiedAttestation, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error) {
	var (
		failReasons []string
		parseErrors []string
	)

	for idx := range attestations {
		result, err := Verify(attestations[idx].Payload, pol, imageDigest)
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
		return failResult(strings.Join(failReasons, "; ")), nil
	}

	if len(parseErrors) > 0 {
		return failResult(
			"no valid provenance: " + strings.Join(parseErrors, "; "),
		), nil
	}

	return failResult("no valid provenance attestation found"), nil
}

func isSLSAPredicate(predicateType string) bool {
	return predicateType == attestation.PredicateSLSAProvenanceV1
}

func verifySubjectDigest(subjects []Subject, imageDigest string) error {
	digestParts := strings.SplitN(imageDigest, ":", digestPartCount)
	if len(digestParts) != digestPartCount {
		return fmt.Errorf("%w: invalid digest format %q", ErrSubjectDigestMismatch, imageDigest)
	}

	algo := digestParts[0]
	hash := digestParts[1]

	for _, subject := range subjects {
		if subject.Digest[algo] == hash {
			return nil
		}
	}

	return fmt.Errorf("%w: none of the subjects match %q", ErrSubjectDigestMismatch, imageDigest)
}

// verifyBuilder checks whether the builder is in the trusted builders list.
// MaxLevel is not checked here because SLSA provenance does not declare a build
// level; levels are a property of the builder's infrastructure. The VSA verifier
// checks verifiedLevels against the policy's minimumLevel.
func verifyBuilder(builder Builder, pol *policy.Policy) error {
	builders := pol.Builders()
	if len(builders) == 0 {
		return nil
	}

	for _, trusted := range builders {
		if trusted.ID == builder.ID {
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

func verifySources(params map[string]any, pol *policy.Policy) error {
	if pol.Trust == nil || len(pol.Trust.Sources) == 0 {
		return nil
	}

	sourceVal, exists := params["source"]
	if !exists {
		return fmt.Errorf("%w: source parameter missing", ErrUntrustedSource)
	}

	source, isString := sourceVal.(string)
	if !isString {
		return fmt.Errorf("%w: source parameter is not a string", ErrUntrustedSource)
	}

	for _, pattern := range pol.Trust.Sources {
		matched, err := path.Match(pattern, source)
		if err != nil {
			return fmt.Errorf("invalid source pattern %q: %w", pattern, err)
		}

		if matched {
			return nil
		}
	}

	return fmt.Errorf("%w: %q", ErrUntrustedSource, source)
}

// verifyParameters rejects provenance with unrecognized externalParameters
// when rejectUnknownParameters is enabled. The known keys list covers GitHub
// Actions SLSA provenance. Other build systems (Cloud Build, Tekton, etc.)
// use different parameter names and will be rejected. Disable
// rejectUnknownParameters in the policy for non-GitHub-Actions builders.
func verifyParameters(params map[string]any, pol *policy.Policy) error {
	if pol.Provenance == nil || !pol.Provenance.RejectUnknownParameters {
		return nil
	}

	knownKeys := map[string]bool{
		"source":     true,
		"repository": true,
		"ref":        true,
		"workflow":   true,
		"buildType":  true,
	}

	for key := range params {
		if !knownKeys[key] {
			return fmt.Errorf("%w: %q", ErrUnknownParameters, key)
		}
	}

	return nil
}

func passResult() *types.CheckResult {
	return types.PassResult(checkType, "SLSA provenance verified")
}

func failResult(detail string) *types.CheckResult {
	return types.FailResult(checkType, detail)
}

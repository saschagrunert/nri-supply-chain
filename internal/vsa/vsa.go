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

// Package vsa provides Verification Summary Attestation (VSA) verification.
package vsa

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	checkType = types.CheckTypeVSA

	// ResultPassed indicates the VSA verification passed.
	ResultPassed = "PASSED"

	// ResultFailed indicates the VSA verification failed.
	ResultFailed = "FAILED"

	minSLSAVersion = "1.0"

	clockSkewTolerance = 60 * time.Second

	// maxReasonableAge caps the computed age to prevent time.Duration overflow
	// on crafted timestamps (e.g., year 0001). time.Duration is int64
	// nanoseconds, overflowing at ~292 years.
	maxReasonableAge = 200 * 365 * 24 * time.Hour
)

var (
	// ErrInvalidVSA indicates the VSA attestation could not be parsed.
	ErrInvalidVSA = errors.New("invalid VSA attestation")

	// ErrUntrustedVerifier indicates the verifier is not in the trusted list.
	ErrUntrustedVerifier = errors.New("untrusted VSA verifier")

	// ErrVerificationFailed indicates the VSA reports a FAILED verification result.
	ErrVerificationFailed = errors.New("VSA verification result is FAILED")

	// ErrInsufficientLevel indicates the verified SLSA levels are below the minimum.
	ErrInsufficientLevel = errors.New("insufficient SLSA verification level")

	// ErrResourceMismatch indicates the VSA resource URI does not match the image.
	ErrResourceMismatch = errors.New("VSA resource URI mismatch")

	// ErrSLSAVersionTooOld indicates the SLSA version is below the minimum.
	ErrSLSAVersionTooOld = errors.New("SLSA version below minimum")

	// ErrPolicyMismatch indicates the VSA policy URI does not match the expected policy.
	ErrPolicyMismatch = errors.New("VSA policy URI mismatch")

	// ErrStaleVSA indicates the VSA is older than the maximum allowed age.
	ErrStaleVSA = errors.New("VSA is stale")

	// ErrFutureTimestamp indicates the VSA's timeVerified is in the future.
	ErrFutureTimestamp = errors.New("VSA timeVerified is in the future")
)

// Statement represents an in-toto statement wrapping a VSA predicate.
type Statement struct {
	Type          string    `json:"_type"` //nolint:tagliatelle // In-toto spec field name.
	PredicateType string    `json:"predicateType"`
	Predicate     Predicate `json:"predicate"`
}

// Predicate represents the VSA predicate fields.
type Predicate struct {
	Verifier           Verifier `json:"verifier"`
	TimeVerified       string   `json:"timeVerified"`
	ResourceURI        string   `json:"resourceUri"` //nolint:tagliatelle // SLSA VSA spec field name.
	Policy             Policy   `json:"policy"`
	VerificationResult string   `json:"verificationResult"`
	VerifiedLevels     []string `json:"verifiedLevels"`
	SLSAVersion        string   `json:"slsaVersion"`
}

// Verifier identifies who performed the verification.
type Verifier struct {
	ID string `json:"id"`
}

// Policy represents the policy used during verification.
type Policy struct {
	URI string `json:"uri"`
}

// VerifyResult contains the VSA verification outcome and whether fallback is allowed.
type VerifyResult struct {
	Check      *types.CheckResult
	HardReject bool
}

// Verify checks a VSA attestation against the given policy.
// HardReject is true when a trusted verifier reports FAILED, preventing fallback to direct verification.
// When parsedImageRef is non-nil it is used instead of re-parsing imageRef.
func Verify(
	att []byte,
	pol *policy.Policy,
	imageRef string,
	parsedImageRef name.Reference,
) (*VerifyResult, error) {
	var stmt Statement

	err := json.Unmarshal(att, &stmt)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidVSA, err)
	}

	meta := predicateMetadata(&stmt.Predicate)

	err = verifyTrustedVerifier(stmt.Predicate.Verifier, pol)
	if err != nil {
		return withMetadata(untrustedResult(err.Error()), meta), nil
	}

	if stmt.Predicate.VerificationResult == ResultFailed {
		return withMetadata(hardRejectResult(), meta), nil
	}

	if stmt.Predicate.VerificationResult != ResultPassed {
		return withMetadata(untrustedResult(
			fmt.Sprintf("unexpected verification result: %q", stmt.Predicate.VerificationResult),
		), meta), nil
	}

	err = verifyLevels(stmt.Predicate.VerifiedLevels, pol)
	if err != nil {
		return withMetadata(failResult(err.Error()), meta), nil
	}

	err = verifyResourceURI(stmt.Predicate.ResourceURI, imageRef, parsedImageRef)
	if err != nil {
		return withMetadata(failResult(err.Error()), meta), nil
	}

	err = verifySLSAVersion(stmt.Predicate.SLSAVersion)
	if err != nil {
		return withMetadata(failResult(err.Error()), meta), nil
	}

	err = verifyPolicyURI(stmt.Predicate.Policy, pol)
	if err != nil {
		return withMetadata(failResult(err.Error()), meta), nil
	}

	err = verifyFreshness(stmt.Predicate.TimeVerified, pol)
	if err != nil {
		return withMetadata(staleResult(err.Error()), meta), nil
	}

	return withMetadata(passResult(), meta), nil
}

func verifyTrustedVerifier(ver Verifier, pol *policy.Policy) error {
	if pol.Trust == nil || len(pol.Trust.Verifiers) == 0 {
		return fmt.Errorf("%w: no verifiers configured", ErrUntrustedVerifier)
	}

	for _, trusted := range pol.Trust.Verifiers {
		if trusted.ID == ver.ID {
			return nil
		}
	}

	return fmt.Errorf("%w: %q", ErrUntrustedVerifier, ver.ID)
}

func verifyLevels(levels []string, pol *policy.Policy) error {
	if pol.VSA == nil || pol.VSA.MinimumLevel == 0 {
		return nil
	}

	required := fmt.Sprintf("SLSA_BUILD_LEVEL_%d", pol.VSA.MinimumLevel)

	for _, level := range levels {
		if meetsMinimumLevel(level, required) {
			return nil
		}
	}

	return fmt.Errorf("%w: required %s, got %v", ErrInsufficientLevel, required, levels)
}

func meetsMinimumLevel(level, required string) bool {
	levelNum := extractLevelNumber(level)
	requiredNum := extractLevelNumber(required)

	return levelNum >= requiredNum
}

const slsaBuildLevelPrefix = "SLSA_BUILD_LEVEL_"

func extractLevelNumber(level string) int {
	if !strings.HasPrefix(level, slsaBuildLevelPrefix) {
		return 0
	}

	num, err := strconv.Atoi(level[len(slsaBuildLevelPrefix):])
	if err != nil {
		return 0
	}

	return num
}

func verifyResourceURI(resourceURI, imageRef string, parsedImageRef name.Reference) error {
	if resourceURI == "" {
		return fmt.Errorf("%w: empty resource URI", ErrResourceMismatch)
	}

	if resourceURI == imageRef {
		return nil
	}

	if !strings.Contains(resourceURI, "@") {
		return fmt.Errorf(
			"%w: resource URI %q is tag-based (not digest-pinned)",
			ErrResourceMismatch, resourceURI,
		)
	}

	normalizedResource, err := normalizeRef(resourceURI)
	if err != nil {
		return fmt.Errorf("%w: invalid resource URI %q: %w", ErrResourceMismatch, resourceURI, err)
	}

	normalizedImage, err := normalizeImageRef(imageRef, parsedImageRef)
	if err != nil {
		return fmt.Errorf("%w: invalid image ref %q: %w", ErrResourceMismatch, imageRef, err)
	}

	if normalizedResource != normalizedImage {
		return fmt.Errorf("%w: expected %q, got %q", ErrResourceMismatch, imageRef, resourceURI)
	}

	return nil
}

func normalizeImageRef(imageRef string, parsed name.Reference) (string, error) {
	if parsed == nil {
		return normalizeRef(imageRef)
	}

	if digest, ok := parsed.(name.Digest); ok {
		return digest.String(), nil
	}

	return parsed.Context().String(), nil
}

func normalizeRef(ref string) (string, error) {
	parsed, err := name.ParseReference(ref)
	if err != nil {
		return "", fmt.Errorf("parsing reference: %w", err)
	}

	if digest, ok := parsed.(name.Digest); ok {
		return digest.String(), nil
	}

	return parsed.Context().String(), nil
}

func verifySLSAVersion(ver string) error {
	if ver == "" {
		return fmt.Errorf("%w: empty version", ErrSLSAVersionTooOld)
	}

	if compareVersions(ver, minSLSAVersion) < 0 {
		return fmt.Errorf(
			"%w: got %q, minimum %q",
			ErrSLSAVersionTooOld, ver, minSLSAVersion,
		)
	}

	return nil
}

func compareVersions(a, b string) int {
	aMajor, aMinor := parseVersion(a)
	bMajor, bMinor := parseVersion(b)

	if aMajor != bMajor {
		return aMajor - bMajor
	}

	return aMinor - bMinor
}

func parseVersion(ver string) (major, minor int) {
	const versionParts = 2

	parts := strings.SplitN(ver, ".", versionParts)

	major, err := strconv.Atoi(strings.TrimPrefix(parts[0], "v"))
	if err != nil {
		return -1, 0
	}

	if len(parts) > 1 {
		minor, minorErr := strconv.Atoi(parts[1])
		if minorErr != nil {
			return major, 0
		}

		return major, minor
	}

	return major, 0
}

func verifyPolicyURI(vsaPolicy Policy, pol *policy.Policy) error {
	if pol.VSA == nil || pol.VSA.Policy == "" {
		return nil
	}

	if vsaPolicy.URI != pol.VSA.Policy {
		return fmt.Errorf(
			"%w: expected %q, got %q",
			ErrPolicyMismatch,
			pol.VSA.Policy,
			vsaPolicy.URI,
		)
	}

	return nil
}

func verifyFreshness(timeVerified string, pol *policy.Policy) error {
	verified, err := time.Parse(time.RFC3339Nano, timeVerified)
	if err != nil {
		return fmt.Errorf("parsing time_verified %q: %w", timeVerified, err)
	}

	age := time.Since(verified)

	if age < -clockSkewTolerance {
		return fmt.Errorf("%w: %s", ErrFutureTimestamp, timeVerified)
	}

	if age < 0 {
		age = 0
	}

	if age > maxReasonableAge {
		return fmt.Errorf("%w: timestamp %s is unreasonably old", ErrStaleVSA, timeVerified)
	}

	if pol.VSA == nil || pol.VSA.MaxAge == "" {
		return nil
	}

	if age > pol.VSA.MaxAgeDuration {
		return fmt.Errorf(
			"%w: verified %s ago, max %s",
			ErrStaleVSA,
			age.Truncate(time.Second),
			pol.VSA.MaxAgeDuration,
		)
	}

	return nil
}

func predicateMetadata(pred *Predicate) map[string]any {
	return map[string]any{
		"verifierID": pred.Verifier.ID,
		"result":     pred.VerificationResult,
		"level":      int64(maxVerifiedLevel(pred.VerifiedLevels)),
	}
}

func maxVerifiedLevel(levels []string) int {
	result := 0

	for _, level := range levels {
		if n := extractLevelNumber(level); n > result {
			result = n
		}
	}

	return result
}

func withMetadata(vr *VerifyResult, meta map[string]any) *VerifyResult {
	vr.Check.Metadata = meta

	return vr
}

func passResult() *VerifyResult {
	return &VerifyResult{
		Check:      types.PassResult(checkType, "VSA verification passed"),
		HardReject: false,
	}
}

func failResult(detail string) *VerifyResult {
	return &VerifyResult{
		Check:      types.FailResult(checkType, detail, nil),
		HardReject: false,
	}
}

func hardRejectResult() *VerifyResult {
	return &VerifyResult{
		Check: types.FailResult(
			checkType, "trusted verifier reported FAILED verification", nil,
		),
		HardReject: true,
	}
}

func untrustedResult(detail string) *VerifyResult {
	return &VerifyResult{
		Check:      types.SoftFailResult(checkType, detail, nil),
		HardReject: false,
	}
}

func staleResult(detail string) *VerifyResult {
	return &VerifyResult{
		Check:      types.SoftFailResult(checkType, detail, nil),
		HardReject: false,
	}
}

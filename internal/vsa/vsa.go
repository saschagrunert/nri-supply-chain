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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/saschagrunert/nri-supply-chain/internal/imageref"
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

	// ErrSubjectMismatch indicates no VSA subject digest matches the image digest.
	ErrSubjectMismatch = errors.New("VSA subject digest mismatch")

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
	Subject       []Subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     Predicate `json:"predicate"`
}

// Subject represents an in-toto subject with name and digests.
type Subject struct {
	Name   string            `json:"name,omitempty"`
	Digest map[string]string `json:"digest"`
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
	// MatchedVerifiers lists the trusted verifier entries whose ID equals the
	// verifier.id claimed by the VSA. The claim is only a string inside the
	// signed payload; callers must confirm that the attestation signer is one
	// of these verifiers before honoring a PASSED or FAILED result.
	MatchedVerifiers []policy.TrustedVerifier
}

// Verify checks a VSA attestation against the given policy.
//
// The VSA is first bound to the image: the resource URI must name the same
// repository and digest as imageRef, and a statement subject must carry the
// image digest. Only a bound VSA from a trusted verifier can report FAILED,
// which sets HardReject and prevents fallback to direct verification.
// When parsedImageRef is non-nil it is used instead of re-parsing imageRef.
func Verify( //nolint:cyclop,funlen // sequential verification steps
	ctx context.Context,
	att []byte,
	pol *policy.Policy,
	imageRef string,
	parsedImageRef name.Reference,
) (*VerifyResult, error) {
	ctxErr := ctx.Err()
	if ctxErr != nil {
		return nil, fmt.Errorf("verification cancelled: %w", ctxErr)
	}

	var stmt Statement

	err := json.Unmarshal(att, &stmt)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidVSA, err)
	}

	meta := predicateMetadata(&stmt.Predicate)

	matched, err := verifyTrustedVerifier(stmt.Predicate.Verifier, pol)
	if err != nil {
		return withMetadata(untrustedResult(err.Error()), meta, nil), nil
	}

	err = verifyBinding(&stmt, imageRef, parsedImageRef)
	if err != nil {
		return withMetadata(failResult(err.Error()), meta, matched), nil
	}

	if stmt.Predicate.VerificationResult == ResultFailed {
		return withMetadata(hardRejectResult(), meta, matched), nil
	}

	if stmt.Predicate.VerificationResult != ResultPassed {
		return withMetadata(untrustedResult(
			fmt.Sprintf("unexpected verification result: %q", stmt.Predicate.VerificationResult),
		), meta, matched), nil
	}

	err = verifyLevels(stmt.Predicate.VerifiedLevels, pol)
	if err != nil {
		return withMetadata(failResult(err.Error()), meta, matched), nil
	}

	err = verifySLSAVersion(stmt.Predicate.SLSAVersion)
	if err != nil {
		return withMetadata(failResult(err.Error()), meta, matched), nil
	}

	err = verifyPolicyURI(stmt.Predicate.Policy, pol)
	if err != nil {
		return withMetadata(failResult(err.Error()), meta, matched), nil
	}

	err = verifyFreshness(stmt.Predicate.TimeVerified, pol)
	if err != nil {
		return withMetadata(staleResult(err.Error()), meta, matched), nil
	}

	return withMetadata(passResult(), meta, matched), nil
}

func verifyTrustedVerifier(ver Verifier, pol *policy.Policy) ([]policy.TrustedVerifier, error) {
	if pol.Trust == nil || len(pol.Trust.Verifiers) == 0 {
		return nil, fmt.Errorf("%w: no verifiers configured", ErrUntrustedVerifier)
	}

	var matched []policy.TrustedVerifier

	for idx := range pol.Trust.Verifiers {
		if pol.Trust.Verifiers[idx].ID == ver.ID {
			matched = append(matched, pol.Trust.Verifiers[idx])
		}
	}

	if len(matched) == 0 {
		return nil, fmt.Errorf("%w: %q", ErrUntrustedVerifier, ver.ID)
	}

	return matched, nil
}

// verifyBinding ties the VSA to the image through both the resource URI and
// the statement subject.
func verifyBinding(stmt *Statement, imageRef string, parsedImageRef name.Reference) error {
	imageDigest, err := verifyResourceURI(stmt.Predicate.ResourceURI, imageRef, parsedImageRef)
	if err != nil {
		return err
	}

	for idx := range stmt.Subject {
		if types.MatchDigestInMap(imageDigest.DigestStr(), stmt.Subject[idx].Digest) {
			return nil
		}
	}

	return fmt.Errorf(
		"%w: no subject matches %q", ErrSubjectMismatch, imageDigest.DigestStr(),
	)
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

// verifyResourceURI requires the VSA resource URI and the image reference to
// be digest-pinned references to the same repository and digest. Repository
// names are normalized with imageref.NormalizeRepository, so every Docker Hub
// alias (docker.io, index.docker.io, registry-1.docker.io,
// registry.hub.docker.com) compares equal. It returns the image digest.
func verifyResourceURI(
	resourceURI, imageRef string, parsedImageRef name.Reference,
) (name.Digest, error) {
	if resourceURI == "" {
		return name.Digest{}, fmt.Errorf("%w: empty resource URI", ErrResourceMismatch)
	}

	if !strings.Contains(resourceURI, "@") {
		return name.Digest{}, fmt.Errorf(
			"%w: resource URI %q is tag-based (not digest-pinned)",
			ErrResourceMismatch, resourceURI,
		)
	}

	resource, err := parseDigestRef(resourceURI, nil)
	if err != nil {
		return name.Digest{}, fmt.Errorf(
			"%w: invalid resource URI %q: %w", ErrResourceMismatch, resourceURI, err,
		)
	}

	image, err := parseDigestRef(imageRef, parsedImageRef)
	if err != nil {
		return name.Digest{}, fmt.Errorf(
			"%w: image reference %q: %w", ErrResourceMismatch, imageRef, err,
		)
	}

	if imageref.NormalizeRepository(resource.Context().Name()) !=
		imageref.NormalizeRepository(image.Context().Name()) ||
		resource.DigestStr() != image.DigestStr() {
		return name.Digest{}, fmt.Errorf(
			"%w: expected %q, got %q", ErrResourceMismatch, imageRef, resourceURI,
		)
	}

	return image, nil
}

var errNotDigestPinned = errors.New("reference is not digest-pinned")

func parseDigestRef(ref string, parsed name.Reference) (name.Digest, error) {
	if parsed == nil {
		var err error

		parsed, err = name.ParseReference(ref)
		if err != nil {
			return name.Digest{}, fmt.Errorf("parsing reference: %w", err)
		}
	}

	digest, ok := parsed.(name.Digest)
	if !ok {
		return name.Digest{}, errNotDigestPinned
	}

	return digest, nil
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

// verifyFreshness parses timeVerified as RFC 3339, which permits lowercase
// "t" and "z" separators that Go's layout parser does not accept.
func verifyFreshness(timeVerified string, pol *policy.Policy) error {
	verified, err := time.Parse(time.RFC3339Nano, strings.ToUpper(timeVerified))
	if err != nil {
		return fmt.Errorf("parsing time_verified %q: %w", timeVerified, err)
	}

	var maxAge *time.Duration
	if pol.VSA != nil && pol.VSA.MaxAge != "" {
		maxAge = &pol.VSA.MaxAgeDuration
	}

	//nolint:wrapcheck // VerifyFreshness wraps the caller's sentinel errors
	return types.VerifyFreshness(
		verified, maxAge, "verified",
		ErrFutureTimestamp, ErrStaleVSA, ErrStaleVSA,
	)
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

func withMetadata(
	vr *VerifyResult, meta map[string]any, matched []policy.TrustedVerifier,
) *VerifyResult {
	vr.Check.Metadata = meta
	vr.MatchedVerifiers = matched

	return vr
}

func passResult() *VerifyResult {
	return &VerifyResult{
		Check:            types.PassResult(checkType, "VSA verification passed"),
		HardReject:       false,
		MatchedVerifiers: nil,
	}
}

func failResult(detail string) *VerifyResult {
	return &VerifyResult{
		Check:            types.FailResult(checkType, detail, nil),
		HardReject:       false,
		MatchedVerifiers: nil,
	}
}

func hardRejectResult() *VerifyResult {
	return &VerifyResult{
		Check: types.FailResult(
			checkType, "trusted verifier reported FAILED verification", nil,
		),
		HardReject:       true,
		MatchedVerifiers: nil,
	}
}

func untrustedResult(detail string) *VerifyResult {
	return &VerifyResult{
		Check:            types.SoftFailResult(checkType, detail, nil),
		HardReject:       false,
		MatchedVerifiers: nil,
	}
}

func staleResult(detail string) *VerifyResult {
	return &VerifyResult{
		Check:            types.SoftFailResult(checkType, detail, nil),
		HardReject:       false,
		MatchedVerifiers: nil,
	}
}

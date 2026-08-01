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

// Package notation provides Notation/Notary v2 signature verification for container images.
package notation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/notaryproject/notation-go/verifier"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	checkType = types.CheckTypeNotation

	// defaultVerificationLevel is the verification level used when none is configured.
	defaultVerificationLevel = "strict"

	// trustPolicyDocVersion is the trust policy document version.
	trustPolicyDocVersion = "1.0"
)

var (
	// ErrNoTrustStores indicates no Notation trust stores are configured.
	ErrNoTrustStores = errors.New("no notation trust stores configured")

	// ErrNoTrustPolicy indicates no Notation trust policy rules are configured.
	ErrNoTrustPolicy = errors.New("no notation trust policy rules configured")

	// ErrNotationNotConfigured indicates the Notation policy section is not configured.
	ErrNotationNotConfigured = errors.New("notation policy section is not configured")

	// ErrBuildTrustPolicy indicates the trust policy document could not be built.
	ErrBuildTrustPolicy = errors.New("building notation trust policy document")

	// ErrBuildVerifier indicates the notation verifier could not be created.
	ErrBuildVerifier = errors.New("creating notation verifier")

	// ErrNoApplicableTrustPolicy indicates no trust policy rule matches the image.
	ErrNoApplicableTrustPolicy = errors.New("no applicable notation trust policy")
)

// Verify checks a single Notation signature against the given policy.
func Verify(
	ctx context.Context,
	signatureRef string,
	imageRef, digest string,
	pol *policy.Policy,
) (*types.CheckResult, error) {
	notationPolicy := pol.Notation
	if notationPolicy == nil {
		return nil, ErrNotationNotConfigured
	}

	err := checkPolicyRequirements(notationPolicy)
	if err != nil {
		return nil, err
	}

	err = validatePolicyForImage(notationPolicy, imageRef)
	if err != nil {
		return nil, err
	}

	slog.DebugContext(ctx, "Notation signature verified via trust policy",
		"image", imageRef,
		"digest", digest,
		"signatureRef", signatureRef,
	)

	return passResult(), nil
}

// VerifyMultiple checks multiple Notation signatures, accepting if any valid one passes.
func VerifyMultiple(
	ctx context.Context,
	signatures []attestation.VerifiedAttestation,
	imageRef, digest string,
	pol *policy.Policy,
) (*types.CheckResult, error) {
	notationPolicy := pol.Notation
	if notationPolicy == nil {
		return nil, ErrNotationNotConfigured
	}

	err := checkPolicyRequirements(notationPolicy)
	if err != nil {
		return nil, err
	}

	err = validatePolicyForImage(notationPolicy, imageRef)
	if err != nil {
		return nil, err
	}

	return verifySignatures(ctx, signatures, imageRef, digest)
}

func checkPolicyRequirements(notationPolicy *policy.NotationPolicy) error {
	if len(notationPolicy.TrustStores) == 0 {
		return ErrNoTrustStores
	}

	if len(notationPolicy.TrustPolicy) == 0 {
		return ErrNoTrustPolicy
	}

	return nil
}

func verifySignatures(
	ctx context.Context,
	signatures []attestation.VerifiedAttestation,
	imageRef, digest string,
) (*types.CheckResult, error) {
	var failReasons []string

	for idx := range signatures {
		signatureRef := string(signatures[idx].Payload)

		result := verifySignatureEntry(ctx, signatureRef, imageRef, digest)
		if result.Passed {
			return result, nil
		}

		failReasons = append(failReasons, result.Detail)
	}

	return buildMultipleResult(failReasons), nil
}

func buildMultipleResult(failReasons []string) *types.CheckResult {
	if len(failReasons) > 0 {
		return failResult(strings.Join(failReasons, "; "))
	}

	return failResult("no notation signatures found")
}

// validatePolicyForImage builds the trust policy document and verifier,
// validates the policy, and checks that an applicable trust policy rule
// exists for the given image reference.
func validatePolicyForImage(notationPolicy *policy.NotationPolicy, imageRef string) error {
	policyDoc := buildTrustPolicyDocument(notationPolicy)

	err := policyDoc.Validate()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrBuildTrustPolicy, err)
	}

	trustStore, err := newTrustStore(notationPolicy.TrustStores)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrBuildVerifier, err)
	}

	_, err = verifier.New(policyDoc, trustStore, nil)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrBuildVerifier, err)
	}

	// Verify that a trust policy rule applies to this image reference.
	_, err = policyDoc.GetApplicableTrustPolicy(imageRef)
	if err != nil {
		return fmt.Errorf("%w for %q: %w", ErrNoApplicableTrustPolicy, imageRef, err)
	}

	return nil
}

// BuildTrustPolicyDocument constructs a Notation trust policy document from
// the policy configuration. Exported for testing.
func BuildTrustPolicyDocument(notationPolicy *policy.NotationPolicy) *trustpolicy.Document {
	return buildTrustPolicyDocument(notationPolicy)
}

func buildTrustPolicyDocument(notationPolicy *policy.NotationPolicy) *trustpolicy.Document {
	level := defaultVerificationLevel
	if notationPolicy.VerificationLevel != "" {
		level = notationPolicy.VerificationLevel
	}

	policies := make([]trustpolicy.TrustPolicy, 0, len(notationPolicy.TrustPolicy))

	for _, rule := range notationPolicy.TrustPolicy {
		policies = append(policies, trustpolicy.TrustPolicy{
			Name:           rule.Name,
			RegistryScopes: rule.RegistryScopes,
			SignatureVerification: trustpolicy.SignatureVerification{
				VerificationLevel: level,
			},
			TrustStores:       rule.TrustStores,
			TrustedIdentities: rule.TrustedIdentities,
		})
	}

	return &trustpolicy.Document{
		Version:       trustPolicyDocVersion,
		TrustPolicies: policies,
	}
}

// verifySignatureEntry verifies a single Notation signature against the
// trust policy. Verification currently passes based on trust policy
// validation alone (performed by the caller). Full cryptographic signature
// verification requires notation-go's repository interface to pull and
// verify the signature envelope against the trust store certificate chain.
func verifySignatureEntry(
	ctx context.Context,
	signatureRef, imageRef, digest string,
) *types.CheckResult {
	slog.DebugContext(ctx,
		"Notation signature accepted via trust policy"+
			" (cryptographic verification not yet implemented)",
		"image", imageRef,
		"digest", digest,
		"signatureRef", signatureRef,
	)

	return passResult()
}

func passResult() *types.CheckResult {
	return types.PassResult(
		checkType,
		"Notation trust policy matched (cryptographic verification not yet implemented)",
	)
}

func failResult(detail string) *types.CheckResult {
	return types.FailResult(checkType, detail, nil)
}

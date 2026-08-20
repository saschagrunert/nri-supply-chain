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

	notationlib "github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/verifier"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	godigest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	checkType = types.CheckTypeNotation

	// defaultVerificationLevel is the verification level used when none is configured.
	defaultVerificationLevel = "strict"

	// revocationModeStrict enforces OCSP/CRL revocation checking.
	revocationModeStrict = "strict"

	// revocationModeSoft logs revocation check failures without enforcing.
	revocationModeSoft = "soft"

	// revocationModeSkip explicitly disables revocation checking by
	// setting ActionSkip. When revocationMode is omitted, no override
	// is set and the base verification level controls revocation behavior.
	revocationModeSkip = "skip"

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
	sig *attestation.VerifiedAttestation,
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

	notationVerifier, trustPolicyName, err := buildVerifierForImage(notationPolicy, imageRef)
	if err != nil {
		return nil, err
	}

	return verifySignatureEntry(ctx, notationVerifier, sig, imageRef, digest, trustPolicyName), nil
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

	notationVerifier, trustPolicyName, err := buildVerifierForImage(notationPolicy, imageRef)
	if err != nil {
		return nil, err
	}

	return verifySignatures(ctx, notationVerifier, signatures, imageRef, digest, trustPolicyName)
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
	notationVerifier notationlib.Verifier,
	signatures []attestation.VerifiedAttestation,
	imageRef, digest, trustPolicyName string,
) (*types.CheckResult, error) {
	var failReasons []string

	for idx := range signatures {
		ctxErr := ctx.Err()
		if ctxErr != nil {
			return nil, fmt.Errorf("verification cancelled: %w", ctxErr)
		}

		result := verifySignatureEntry(
			ctx,
			notationVerifier,
			&signatures[idx],
			imageRef,
			digest,
			trustPolicyName,
		)
		if result.Passed {
			return result, nil
		}

		failReasons = append(failReasons, result.Detail)
	}

	return buildMultipleResult(failReasons), nil
}

func buildMultipleResult(failReasons []string) *types.CheckResult {
	if len(failReasons) > 0 {
		return check.Fail(strings.Join(failReasons, "; "))
	}

	return check.Fail("no notation signatures found")
}

//nolint:ireturn // notation.Verifier is the API type returned by notation-go.
func buildVerifierForImage(
	notationPolicy *policy.NotationPolicy, imageRef string,
) (notationlib.Verifier, string, error) {
	policyDoc := buildTrustPolicyDocument(notationPolicy)

	err := policyDoc.Validate()
	if err != nil {
		return nil, "", fmt.Errorf("%w: %w", ErrBuildTrustPolicy, err)
	}

	trustStore, err := newTrustStore(notationPolicy.TrustStores)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %w", ErrBuildVerifier, err)
	}

	notationVerifier, err := verifier.New(policyDoc, trustStore, nil)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %w", ErrBuildVerifier, err)
	}

	tp, err := policyDoc.GetApplicableTrustPolicy(imageRef)
	if err != nil {
		return nil, "", fmt.Errorf("%w for %q: %w", ErrNoApplicableTrustPolicy, imageRef, err)
	}

	return notationVerifier, tp.Name, nil
}

func buildTrustPolicyDocument(notationPolicy *policy.NotationPolicy) *trustpolicy.Document {
	level := defaultVerificationLevel
	if notationPolicy.VerificationLevel != "" {
		level = notationPolicy.VerificationLevel
	}

	override := revocationOverride(notationPolicy.RevocationMode)

	policies := make([]trustpolicy.TrustPolicy, 0, len(notationPolicy.TrustPolicy))

	for _, rule := range notationPolicy.TrustPolicy {
		sigVerification := trustpolicy.SignatureVerification{
			VerificationLevel: level,
		}

		// Only set Override when non-nil to avoid rejection by notation-go
		// for verificationLevel "skip" which disallows any overrides.
		if override != nil {
			sigVerification.Override = override
		}

		policies = append(policies, trustpolicy.TrustPolicy{
			Name:                  rule.Name,
			RegistryScopes:        rule.RegistryScopes,
			SignatureVerification: sigVerification,
			TrustStores:           rule.TrustStores,
			TrustedIdentities:     rule.TrustedIdentities,
		})
	}

	return &trustpolicy.Document{
		Version:       trustPolicyDocVersion,
		TrustPolicies: policies,
	}
}

// revocationOverride returns the Override map for the given revocation mode.
// An empty mode returns nil so that notation-go's default behavior applies.
// "skip" returns ActionSkip to explicitly disable revocation checking.
func revocationOverride(mode string) map[trustpolicy.ValidationType]trustpolicy.ValidationAction {
	switch mode {
	case revocationModeStrict:
		return map[trustpolicy.ValidationType]trustpolicy.ValidationAction{
			trustpolicy.TypeRevocation: trustpolicy.ActionEnforce,
		}
	case revocationModeSoft:
		return map[trustpolicy.ValidationType]trustpolicy.ValidationAction{
			trustpolicy.TypeRevocation: trustpolicy.ActionLog,
		}
	case revocationModeSkip:
		return map[trustpolicy.ValidationType]trustpolicy.ValidationAction{
			trustpolicy.TypeRevocation: trustpolicy.ActionSkip,
		}
	default:
		return nil
	}
}

//nolint:funlen // sequential verification steps
func verifySignatureEntry(
	ctx context.Context,
	notationVerifier notationlib.Verifier,
	sig *attestation.VerifiedAttestation,
	imageRef, digest, trustPolicyName string,
) *types.CheckResult {
	desc := ocispec.Descriptor{
		MediaType: sig.NotationSubjectMediaType,
		Size:      sig.NotationSubjectSize,
	}

	if sig.NotationSubjectDigest != "" {
		parsed, err := godigest.Parse(sig.NotationSubjectDigest)
		if err != nil {
			return check.Fail(fmt.Sprintf("invalid subject digest: %s", err))
		}

		desc.Digest = parsed
	}

	if sig.NotationSubjectDigest == "" {
		return check.Fail("signature has no subject binding")
	}

	if sig.NotationSubjectDigest != digest {
		return check.Fail(fmt.Sprintf(
			"subject digest %s does not match image digest %s",
			sig.NotationSubjectDigest, digest,
		))
	}

	opts := notationlib.VerifierVerifyOptions{
		ArtifactReference:  imageRef,
		SignatureMediaType: sig.NotationMediaType,
	}

	outcome, err := notationVerifier.Verify(ctx, desc, sig.Payload, opts)
	if err != nil {
		slog.DebugContext(ctx, "Notation signature verification failed",
			"image", imageRef,
			"digest", digest,
			"error", err,
		)

		return check.Fail(fmt.Sprintf("Notation signature verification failed: %s", err))
	}

	logAttrs := []any{
		"image", imageRef,
		"digest", digest,
	}

	if outcome.EnvelopeContent != nil {
		logAttrs = append(logAttrs,
			"signedAttributes", outcome.EnvelopeContent.SignerInfo.SignedAttributes,
		)
	}

	slog.DebugContext(ctx, "Notation signature cryptographically verified", logAttrs...)

	meta := map[string]any{
		"signerDN":    extractSignerDN(outcome),
		"trustPolicy": trustPolicyName,
	}

	result := check.Pass()
	result.Metadata = meta

	return result
}

func extractSignerDN(outcome *notationlib.VerificationOutcome) string {
	if outcome == nil || outcome.EnvelopeContent == nil {
		return ""
	}

	chain := outcome.EnvelopeContent.SignerInfo.CertificateChain
	if len(chain) == 0 {
		return ""
	}

	return chain[0].Subject.String()
}

var check = types.Checker{ //nolint:gochecknoglobals // package-scoped helper
	Type:    checkType,
	PassMsg: "Notation signature cryptographically verified",
}

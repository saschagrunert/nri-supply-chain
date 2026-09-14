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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"

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

	// maxCachedVerifiers bounds the verifier cache; it is cleared when full.
	maxCachedVerifiers = 64
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

// cachedVerifier is a Notation verifier built for one policy and trust store
// state, reused across verifications.
type cachedVerifier struct {
	verifier  notationlib.Verifier
	policyDoc *trustpolicy.Document
}

var (
	verifierCacheMu sync.Mutex                     //nolint:gochecknoglobals // process-wide cache
	verifierCache   = map[string]*cachedVerifier{} //nolint:gochecknoglobals // process-wide cache
)

// ResetVerifierCache clears cached Notation verifiers. Cached entries are keyed
// by policy content and certificate file metadata, so rotated certificates are
// picked up automatically; this is only needed to release memory.
func ResetVerifierCache() {
	verifierCacheMu.Lock()
	defer verifierCacheMu.Unlock()

	clear(verifierCache)
}

//nolint:ireturn // notation.Verifier is the API type returned by notation-go.
func buildVerifierForImage(
	notationPolicy *policy.NotationPolicy, imageRef string,
) (notationlib.Verifier, string, error) {
	cached, err := verifierForPolicy(notationPolicy)
	if err != nil {
		return nil, "", err
	}

	tp, err := cached.policyDoc.GetApplicableTrustPolicy(imageRef)
	if err != nil {
		return nil, "", fmt.Errorf("%w for %q: %w", ErrNoApplicableTrustPolicy, imageRef, err)
	}

	return cached.verifier, tp.Name, nil
}

// verifierForPolicy returns a cached verifier for the policy, building one
// when the policy or any referenced certificate file changed.
func verifierForPolicy(notationPolicy *policy.NotationPolicy) (*cachedVerifier, error) {
	key := verifierCacheKey(notationPolicy)

	verifierCacheMu.Lock()
	defer verifierCacheMu.Unlock()

	if cached, ok := verifierCache[key]; ok {
		return cached, nil
	}

	policyDoc := buildTrustPolicyDocument(notationPolicy)

	err := policyDoc.Validate()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBuildTrustPolicy, err)
	}

	trustStore, err := newTrustStore(notationPolicy.TrustStores)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBuildVerifier, err)
	}

	notationVerifier, err := verifier.New(policyDoc, trustStore, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBuildVerifier, err)
	}

	if len(verifierCache) >= maxCachedVerifiers {
		clear(verifierCache)
	}

	cached := &cachedVerifier{verifier: notationVerifier, policyDoc: policyDoc}
	verifierCache[key] = cached

	return cached, nil
}

// verifierCacheKey derives a cache key from the policy content and the size
// and modification time of every referenced certificate file.
func verifierCacheKey(notationPolicy *policy.NotationPolicy) string {
	hasher := sha256.New()

	policyJSON, err := json.Marshal(notationPolicy)
	if err != nil {
		// Unreachable for plain policy structs; fall back to a unique key so
		// nothing stale is ever reused.
		policyJSON = []byte(err.Error())
	}

	_, _ = hasher.Write(policyJSON)

	for _, store := range notationPolicy.TrustStores {
		for _, certPath := range store.Certificates {
			_, _ = hasher.Write([]byte("\x00" + certPath))

			info, statErr := os.Stat(certPath)
			if statErr != nil {
				_, _ = hasher.Write([]byte("\x00missing"))

				continue
			}

			_, _ = hasher.Write([]byte(
				"\x00" + strconv.FormatInt(info.Size(), 10) +
					"\x00" + strconv.FormatInt(info.ModTime().UnixNano(), 10),
			))
		}
	}

	return hex.EncodeToString(hasher.Sum(nil))
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

	result := resultFromOutcome(ctx, outcome, imageRef)
	result.Metadata = meta

	return result
}

// resultFromOutcome inspects validations that notation-go only logged. A nil
// error from Verify does not mean the signature is trusted: at the "audit"
// level authenticity failures are logged, and at "skip" nothing is verified.
// Integrity and authenticity failures fail the check; logged expiry,
// revocation, and timestamp failures pass with a warning.
func resultFromOutcome(
	ctx context.Context, outcome *notationlib.VerificationOutcome, imageRef string,
) *types.CheckResult {
	if outcome == nil {
		return check.Fail("Notation verification returned no outcome")
	}

	if outcome.VerificationLevel != nil &&
		outcome.VerificationLevel.Name == trustpolicy.LevelSkip.Name {
		return check.Fail("Notation signature verification skipped by trust policy")
	}

	hardFailures, warnings := classifyLoggedFailures(outcome.VerificationResults)

	if len(hardFailures) > 0 {
		slog.WarnContext(ctx, "Notation signature failed logged validations",
			"image", imageRef,
			"failures", hardFailures,
		)

		return check.Fail("Notation signature not trusted: " + strings.Join(hardFailures, "; "))
	}

	if len(warnings) > 0 {
		return types.WarnResult(
			checkType,
			"Notation signature verified with logged failures: "+strings.Join(warnings, "; "),
		)
	}

	return check.Pass()
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

// classifyLoggedFailures splits failed validations into failures that break
// trust (integrity, authenticity, unknown types) and warnings.
func classifyLoggedFailures(
	results []*notationlib.ValidationResult,
) (hardFailures, warnings []string) {
	for _, validation := range results {
		if validation == nil || validation.Error == nil {
			continue
		}

		detail := fmt.Sprintf("%s: %s", validation.Type, validation.Error)

		switch validation.Type {
		case trustpolicy.TypeAuthenticTimestamp, trustpolicy.TypeExpiry, trustpolicy.TypeRevocation:
			warnings = append(warnings, detail)
		case trustpolicy.TypeIntegrity, trustpolicy.TypeAuthenticity:
			hardFailures = append(hardFailures, detail)
		default:
			hardFailures = append(hardFailures, detail)
		}
	}

	return hardFailures, warnings
}

var check = types.Checker{ //nolint:gochecknoglobals // package-scoped helper
	Type:    checkType,
	PassMsg: "Notation signature cryptographically verified",
}

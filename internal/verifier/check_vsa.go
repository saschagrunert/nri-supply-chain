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

package verifier

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
	"github.com/saschagrunert/nri-supply-chain/internal/vsa"
)

// scopeBuilderKeys drops attestations signed with a key that is only trusted
// as a builder key, unless they are SLSA provenance. Builder keys join the
// trusted key set so provenance can be verified, but a provenance signing key
// must not be able to vouch for VEX, SBOM or any other attestation type.
// Verifier keys keep their scope.
func scopeBuilderKeys(
	ctx context.Context, attestations []attestation.VerifiedAttestation,
	pol *policy.Policy, imageRef string,
) []attestation.VerifiedAttestation {
	builderOnly := builderOnlyKeys(pol.Trust)
	if len(builderOnly) == 0 {
		return attestations
	}

	scoped := make([]attestation.VerifiedAttestation, 0, len(attestations))

	for idx := range attestations {
		att := &attestations[idx]

		if signedOnlyWithBuilderKeys(&att.Signer, builderOnly) &&
			!isProvenancePredicate(att.PredicateType) {
			slog.WarnContext(ctx, "Ignoring attestation signed with a builder key",
				"image", imageRef,
				"predicateType", att.PredicateType,
				"signer_key", att.Signer.KeyPath,
			)

			continue
		}

		scoped = append(scoped, *att)
	}

	return scoped
}

// signedOnlyWithBuilderKeys reports whether every configured key path that
// verified the signature is a builder-only key. The same key material may be
// configured at several paths, so a signature also verified by a verifier
// key path keeps the verifier scope.
func signedOnlyWithBuilderKeys(
	signer *attestation.SignerIdentity, builderOnly map[string]struct{},
) bool {
	paths := signer.KeyPaths
	if len(paths) == 0 {
		if signer.KeyPath == "" {
			return false
		}

		paths = []string{signer.KeyPath}
	}

	for _, keyPath := range paths {
		if _, builderKey := builderOnly[keyPath]; !builderKey {
			return false
		}
	}

	return true
}

// builderOnlyKeys returns the key paths trusted for builders but not for
// any verifier.
func builderOnlyKeys(trust *policy.TrustPolicy) map[string]struct{} {
	if trust == nil {
		return nil
	}

	// Verifier key paths are compared cleaned, like trustedKeyRefs does, so
	// a differently spelled builder entry of a verifier key keeps the
	// verifier scope.
	verifierKeys := make(map[string]struct{})

	for idx := range trust.Verifiers {
		for _, keyPath := range trust.Verifiers[idx].Keys {
			verifierKeys[filepath.Clean(keyPath)] = struct{}{}
		}
	}

	keys := make(map[string]struct{})

	for idx := range trust.Builders {
		for _, keyPath := range trust.Builders[idx].Keys {
			if _, verifierKey := verifierKeys[filepath.Clean(keyPath)]; !verifierKey {
				keys[keyPath] = struct{}{}
			}
		}
	}

	return keys
}

func isProvenancePredicate(predicateType string) bool {
	return predicateType == attestation.PredicateSLSAProvenanceV1 ||
		predicateType == attestation.PredicateSLSAProvenanceV02
}

// vsaOutcome is the combined result of all VSA attestations of an image.
type vsaOutcome struct {
	// passed is the first PASSED VSA signed by its claimed verifier.
	passed *types.CheckResult
	// rejected is set when a VSA signed by its claimed verifier reports
	// FAILED for this image.
	rejected *types.Result
	// failures describes VSAs that were present but not trusted.
	failures []string
}

func (o *vsaOutcome) missingDetail(imageRef string) string {
	if len(o.failures) == 0 {
		return "no VSA attestation found for image " + imageRef
	}

	return fmt.Sprintf(
		"no trusted VSA passed for image %s: %s", imageRef, strings.Join(o.failures, "; "),
	)
}

// checkVSA evaluates the VSA attestations of an image. A VSA only counts when
// the attestation signer is bound to the verifier named in the VSA
// (trust.verifiers[].keys or identities): the verifier ID is just a claim in
// the signed payload, and any trusted signer could otherwise issue a VSA in
// the name of a trusted verifier and skip all other checks.
func checkVSA(
	ctx context.Context, vsaAttestations []attestation.VerifiedAttestation,
	pol *policy.Policy, imageRef, digest string, met *metrics.Metrics,
	parsedRef name.Reference,
) *vsaOutcome {
	outcome := &vsaOutcome{passed: nil, rejected: nil, failures: nil}

	if len(vsaAttestations) == 0 {
		return outcome
	}

	start := time.Now()

	defer func() {
		met.VerificationDuration.WithLabelValues(string(types.CheckTypeVSA)).
			Observe(time.Since(start).Seconds())
	}()

	digestRef := digestRefFromParsed(parsedRef, imageRef, digest)

	for idx := range vsaAttestations {
		if outcome.add(ctx, &vsaAttestations[idx], pol, imageRef, digestRef) {
			break
		}
	}

	return outcome
}

// add evaluates one VSA attestation and reports whether it rejected the
// image, which ends the evaluation.
func (o *vsaOutcome) add(
	ctx context.Context, att *attestation.VerifiedAttestation,
	pol *policy.Policy, imageRef, digestRef string,
) bool {
	vsaResult, err := vsa.Verify(ctx, att.Payload, pol, digestRef, nil)
	if err != nil {
		slog.WarnContext(ctx, "VSA verification error", "error", err)
		o.failures = append(o.failures, err.Error())

		return false
	}

	conclusive := vsaResult.HardReject ||
		(vsaResult.Check.Passed && vsaResult.Check.Status == types.StatusPass)
	if !conclusive {
		o.failures = append(o.failures, vsaResult.Check.Detail)

		return false
	}

	if !signerBoundToVerifiers(&att.Signer, vsaResult.MatchedVerifiers) {
		slog.WarnContext(ctx, "Ignoring VSA not signed by its claimed verifier",
			"image", imageRef,
			"verifier", vsaResult.Check.Metadata["verifierID"],
			"signer_key", att.Signer.KeyPath,
			"signer_issuer", att.Signer.Issuer,
			"signer_san", att.Signer.SAN,
		)

		o.failures = append(
			o.failures,
			"VSA is not signed by a key or identity bound to its verifier",
		)

		return false
	}

	if vsaResult.HardReject {
		o.rejected = resultFromCheck(vsaResult.Check)

		return true
	}

	if o.passed == nil {
		o.passed = vsaResult.Check
	}

	return false
}

func signerBoundToVerifiers(
	signer *attestation.SignerIdentity, verifiers []policy.TrustedVerifier,
) bool {
	for idx := range verifiers {
		if signer.MatchesAny(verifiers[idx].MatchesSigner) {
			return true
		}
	}

	return false
}

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
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/buildenv"
	celengine "github.com/saschagrunert/nri-supply-chain/internal/cel"
	"github.com/saschagrunert/nri-supply-chain/internal/checker"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/notation"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/release"
	"github.com/saschagrunert/nri-supply-chain/internal/runtimetrace"
	"github.com/saschagrunert/nri-supply-chain/internal/sbom"
	"github.com/saschagrunert/nri-supply-chain/internal/scai"
	"github.com/saschagrunert/nri-supply-chain/internal/scorecard"
	"github.com/saschagrunert/nri-supply-chain/internal/slsa"
	"github.com/saschagrunert/nri-supply-chain/internal/source"
	"github.com/saschagrunert/nri-supply-chain/internal/testresult"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
	"github.com/saschagrunert/nri-supply-chain/internal/vex"
	"github.com/saschagrunert/nri-supply-chain/internal/vulnscan"
)

const (
	reasonMissingAttestation = "missing_attestation"
	reasonMissingSignature   = "missing_signature"

	checkTypeBaselineSBOM types.CheckType = "baseline-sbom"
)

// ErrBuilderSignerMismatch indicates provenance that claims a trusted builder
// bound to keys or identities, signed by a different signer.
var ErrBuilderSignerMismatch = errors.New(
	"provenance is not signed by a key or identity bound to its builder",
)

// checkInput carries the per-verification data shared by all checks.
type checkInput struct {
	bins     attestationBins
	pol      *policy.Policy
	imageRef string
	digest   string
	// relatedDigests are other digests of the same image (index or platform
	// manifest digest) that attestation contents may name.
	relatedDigests []string
	parsedRef      name.Reference
}

func (input *checkInput) payloads(checkType types.CheckType) [][]byte {
	return extractPayloads(input.bins[checkType])
}

// checkSpec describes one attestation check. It is the single place to
// register a check type: the predicate types binned to it, how missing
// attestations are reported, and how present ones are verified.
type checkSpec struct {
	checkType types.CheckType
	label     string
	// missingNoun names what is missing, e.g. "provenance attestation".
	missingNoun   string
	missingReason string
	// predicates are the in-toto predicate types verified by this check.
	// Notation signatures are binned by signature type instead.
	predicates []string
	verify     func(ctx context.Context, input *checkInput) (*types.CheckResult, error)
}

// checkSpecs lists the attestation checks in result order.
//
//nolint:gochecknoglobals // immutable registry of check types
var checkSpecs = []checkSpec{
	{
		checkType:     types.CheckTypeSLSA,
		label:         "SLSA",
		missingNoun:   "provenance attestation",
		missingReason: reasonMissingAttestation,
		predicates: []string{
			attestation.PredicateSLSAProvenanceV1, attestation.PredicateSLSAProvenanceV02,
		},
		verify: func(ctx context.Context, input *checkInput) (*types.CheckResult, error) {
			return slsa.VerifyMultipleWithOptions(
				ctx, input.bins[types.CheckTypeSLSA], input.pol, input.digest,
				&slsa.VerifyOptions{BindBuilder: bindBuilderSigner(ctx, input.imageRef)},
			)
		},
	},
	{
		checkType:     types.CheckTypeVEX,
		label:         "VEX",
		missingNoun:   "VEX attestation",
		missingReason: reasonMissingAttestation,
		predicates:    []string{attestation.PredicateOpenVEX, attestation.PredicateCycloneDX},
		verify: func(ctx context.Context, input *checkInput) (*types.CheckResult, error) {
			return vex.VerifyMultiple(
				ctx,
				input.payloads(types.CheckTypeVEX),
				input.pol,
				input.imageRef,
				input.digest,
				input.parsedRef,
				input.relatedDigests...,
			)
		},
	},
	{
		checkType:     types.CheckTypeNotation,
		label:         "Notation",
		missingNoun:   "Notation signature",
		missingReason: reasonMissingSignature,
		predicates:    nil,
		verify: func(ctx context.Context, input *checkInput) (*types.CheckResult, error) {
			return notation.VerifyMultiple(
				ctx, input.bins[types.CheckTypeNotation], input.imageRef, input.digest, input.pol,
			)
		},
	},
	{
		checkType:     types.CheckTypeSBOM,
		label:         "SBOM",
		missingNoun:   "SBOM attestation",
		missingReason: reasonMissingAttestation,
		predicates:    []string{attestation.PredicateSPDX, attestation.PredicateCycloneDX},
		verify: func(ctx context.Context, input *checkInput) (*types.CheckResult, error) {
			return sbom.VerifyMultipleWithBaseline(
				ctx, input.payloads(types.CheckTypeSBOM), input.payloads(checkTypeBaselineSBOM),
				input.pol, input.digest,
			)
		},
	},
	payloadCheckSpec(scai.Info(), scai.VerifyMultiple, attestation.PredicateSCAI),
	payloadCheckSpec(source.Info(), source.VerifyMultiple, attestation.PredicateSLSASourceV1),
	payloadCheckSpec(buildenv.Info(), buildenv.VerifyMultiple, attestation.PredicateBuildEnv),
	payloadCheckSpec(
		vulnscan.Info(), vulnscan.VerifyMultiple,
		attestation.PredicateVulnScan, attestation.PredicateVulnScanV02,
	),
	payloadCheckSpec(testresult.Info(), testresult.VerifyMultiple, attestation.PredicateTestResult),
	payloadCheckSpec(release.Info(), release.VerifyMultiple, attestation.PredicateRelease),
	payloadCheckSpec(
		runtimetrace.Info(), runtimetrace.VerifyMultiple, attestation.PredicateRuntimeTrace,
	),
	payloadCheckSpec(scorecard.Info(), scorecard.VerifyMultiple, attestation.PredicateScorecard),
}

// payloadVerifyFunc is the shared signature of the generic predicate checks.
type payloadVerifyFunc func(
	ctx context.Context, payloads [][]byte,
	pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error)

func payloadCheckSpec(info checker.Info, verify payloadVerifyFunc, predicates ...string) checkSpec {
	return checkSpec{
		checkType:     info.Type,
		label:         info.Label,
		missingNoun:   info.Label + " attestation",
		missingReason: reasonMissingAttestation,
		predicates:    predicates,
		verify: func(ctx context.Context, input *checkInput) (*types.CheckResult, error) {
			return verify(ctx, input.payloads(info.Type), input.pol, input.digest)
		},
	}
}

// predicateCheckTypes maps predicate types to the checks (bins) that consume
// them, derived from checkSpecs plus the bin-only VSA and baseline SBOM
// predicates.
//
//nolint:gochecknoglobals // derived immutable lookup table
var predicateCheckTypes = buildPredicateCheckTypes()

func buildPredicateCheckTypes() map[string][]types.CheckType {
	lookup := map[string][]types.CheckType{
		attestation.PredicateVSA:          {types.CheckTypeVSA},
		attestation.PredicateBaselineSBOM: {checkTypeBaselineSBOM},
	}

	for idx := range checkSpecs {
		for _, predicate := range checkSpecs[idx].predicates {
			lookup[predicate] = append(lookup[predicate], checkSpecs[idx].checkType)
		}
	}

	return lookup
}

func runAttestationCheck(
	ctx context.Context, spec *checkSpec, input *checkInput, met *metrics.Metrics,
) *types.CheckResult {
	start := time.Now()

	defer func() {
		met.VerificationDuration.WithLabelValues(string(spec.checkType)).
			Observe(time.Since(start).Seconds())
	}()

	if len(input.bins[spec.checkType]) == 0 {
		return missingAttestationResult(ctx, spec, input)
	}

	result, err := spec.verify(ctx, input)
	if errors.Is(err, types.ErrNotApplicable) || errors.Is(err, notation.ErrNotationNotConfigured) {
		// The routed attestations carry nothing this check evaluates (for
		// example VEX-only CycloneDX documents routed to the SBOM check),
		// or a Notation signature was found but the policy has no Notation
		// section, so the signature is irrelevant.
		return missingAttestationResult(ctx, spec, input)
	}

	if err != nil {
		slog.ErrorContext(ctx,
			spec.label+" verification error",
			"error", err,
			"reason", "verification_error",
			"image", input.imageRef,
		)

		return types.FailResult(
			spec.checkType,
			fmt.Sprintf("%s verification error for %s: %s", spec.label, input.imageRef, err),
			err,
		)
	}

	return result
}

func missingAttestationResult(
	ctx context.Context, spec *checkSpec, input *checkInput,
) *types.CheckResult {
	logMissingAttestation(
		ctx,
		"No "+spec.missingNoun+" found",
		input.imageRef,
		spec.missingReason,
	)

	return handleMissingAttestation(
		input.pol.MissingPolicyFor(spec.checkType),
		spec.checkType,
		"no "+spec.missingNoun+" found for image "+input.imageRef,
	)
}

// warnedUnboundBuilders deduplicates warnings about provenance accepted for
// builders that are not bound to a signer. Reset on policy changes.
var warnedUnboundBuilders sync.Map //nolint:gochecknoglobals // dedup per builder ID

func resetBuilderBindingWarnings() {
	warnedUnboundBuilders.Clear()
}

// bindBuilderSigner returns the SLSA builder binding hook: provenance that
// claims a builder bound to keys or identities must be signed by one of
// them. When any matched entry for the builder ID is bound, an unbound entry
// with the same ID does not relax that requirement. Builders with only
// unbound entries keep accepting provenance from any trusted signer.
func bindBuilderSigner(
	ctx context.Context, imageRef string,
) func(att *attestation.VerifiedAttestation, matched []policy.TrustedBuilder) error {
	return func(att *attestation.VerifiedAttestation, matched []policy.TrustedBuilder) error {
		unbound := ""
		anyBound := false

		for idx := range matched {
			if !matched[idx].Bound() {
				unbound = matched[idx].ID

				continue
			}

			anyBound = true

			if att.Signer.MatchesAny(matched[idx].MatchesSigner) {
				return nil
			}
		}

		if unbound != "" && !anyBound {
			if _, warned := warnedUnboundBuilders.LoadOrStore(unbound, struct{}{}); !warned {
				slog.WarnContext(ctx,
					"Accepting provenance for a builder that is not bound to a signer; "+
						"set trust.builders[].keys or identities to bind it",
					"builder", unbound,
					"image", imageRef,
				)
			}

			return nil
		}

		return fmt.Errorf(
			"%w: key %q, issuer %q, SAN %q",
			ErrBuilderSignerMismatch, att.Signer.KeyPath, att.Signer.Issuer, att.Signer.SAN,
		)
	}
}

func runCELCheck(
	pol *policy.Policy, met *metrics.Metrics,
	imageRef, digest, namespace string,
	parsedRef name.Reference, result *types.Result,
) *types.CheckResult {
	if pol.CompiledCEL == nil {
		return nil
	}

	registry, repository := extractRegistryRepo(parsedRef, imageRef)

	checkResults := make(map[types.CheckType]*types.CheckResult, len(result.CheckResults))

	for idx := range result.CheckResults {
		checkResults[result.CheckResults[idx].Type] = &result.CheckResults[idx]
	}

	vars := celengine.BuildVars(
		imageRef, registry, repository, digest, namespace, checkResults,
	)

	timer := prometheus.NewTimer(met.CELEvaluationDuration)
	defer timer.ObserveDuration()

	return celengine.Evaluate(pol.CompiledCEL, vars)
}

func extractRegistryRepo(
	parsedRef name.Reference, imageRef string,
) (reg, repo string) {
	if parsedRef == nil {
		return imageRef, imageRef
	}

	ctx := parsedRef.Context()
	reg = ctx.RegistryStr()
	repo = ctx.RepositoryStr()

	return reg, repo
}

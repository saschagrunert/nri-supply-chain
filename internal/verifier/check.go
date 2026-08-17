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
	"runtime/debug"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/buildenv"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/notation"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/release"
	"github.com/saschagrunert/nri-supply-chain/internal/runtimetrace"
	"github.com/saschagrunert/nri-supply-chain/internal/sbom"
	"github.com/saschagrunert/nri-supply-chain/internal/scai"
	"github.com/saschagrunert/nri-supply-chain/internal/slsa"
	"github.com/saschagrunert/nri-supply-chain/internal/source"
	"github.com/saschagrunert/nri-supply-chain/internal/testresult"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
	"github.com/saschagrunert/nri-supply-chain/internal/vex"
	"github.com/saschagrunert/nri-supply-chain/internal/vsa"
	"github.com/saschagrunert/nri-supply-chain/internal/vulnscan"
)

func runChecks(
	ctx context.Context, state *snapshot,
	pol *policy.Policy, imageRef, digest, indexDigest, namespace string,
) *types.Result {
	if state.fetcher == nil {
		return runChecksWithoutFetcher(pol, state.metrics, imageRef)
	}

	parsedRef, parseErr := name.ParseReference(imageRef)
	host := registryHost(parsedRef, parseErr, imageRef)
	breaker := registryBreakerByHost(state.circuitBreakers, host)

	if breaker != nil && !breaker.Allow() {
		return handleFetchError(
			ctx, state.config, state.metrics,
			fmt.Errorf("%w: %s", ErrCircuitBreakerOpen, imageRef),
			imageRef, host,
		)
	}

	if state.fetchSem != nil {
		releaseSlots, semErr := acquireFetchSlots(ctx, state, host)
		if semErr != nil {
			recordBreakerFailure(ctx, breaker, state.metrics, host, state.config.FetchFailurePolicy)

			return handleFetchError(ctx, state.config, state.metrics, semErr, imageRef, host)
		}

		defer releaseSlots()
	}

	attestations, attestDigest, fetchErr := timedFetchAttestations(
		ctx, state, imageRef, digest, indexDigest, pol, host, parsedRef,
	)
	if fetchErr != nil {
		recordBreakerFailure(ctx, breaker, state.metrics, host, state.config.FetchFailurePolicy)

		return handleFetchError(ctx, state.config, state.metrics, fetchErr, imageRef, host)
	}

	if breaker != nil {
		breaker.RecordSuccess()
	}

	bins := binAttestations(ctx, attestations, imageRef)

	return runVSAAndParallelChecks(
		ctx, &bins, pol, state.metrics, imageRef, attestDigest, namespace, parsedRef,
	)
}

func runVSAAndParallelChecks(
	ctx context.Context, bins *attestationBins,
	pol *policy.Policy, met *metrics.Metrics,
	imageRef, digest, namespace string, parsedRef name.Reference,
) *types.Result {
	vsaResult := checkVSA(ctx, bins.vsa, pol, imageRef, digest, met, parsedRef)
	if vsaResult != nil {
		return vsaResult
	}

	if len(bins.vsa) == 0 {
		denied := checkVSAMissing(pol, imageRef, met)
		if denied != nil {
			return denied
		}
	}

	result := runParallelChecks(ctx, bins, pol, met, imageRef, digest, parsedRef)

	if len(bins.vsa) == 0 {
		prependVSAWarning(result, pol, "no VSA attestation found for image "+imageRef)
	}

	celCheck := runCELCheck(pol, met, imageRef, digest, namespace, parsedRef, result)
	if celCheck != nil {
		result.CheckResults = append(result.CheckResults, *celCheck)
		applyCheckResult(result, celCheck)
	}

	return result
}

func registryHost(parsed name.Reference, parseErr error, imageRef string) string {
	if parseErr != nil {
		return imageRef
	}

	return parsed.Context().RegistryStr()
}

type missingCheck struct {
	checkType     types.CheckType
	missingPolicy types.Action
}

func runChecksWithoutFetcher(
	pol *policy.Policy, met *metrics.Metrics, imageRef string,
) *types.Result {
	detail := "no attestation fetcher configured for image " + imageRef

	vsaMissing := pol.VSAMissingPolicy()

	met.VerificationDuration.WithLabelValues(string(types.CheckTypeVSA)).Observe(0)

	if vsaMissing != types.ActionAllow && vsaMissing != types.ActionWarn {
		check := handleMissingAttestation(vsaMissing, types.CheckTypeVSA, detail)

		return &types.Result{
			Allowed:      check.Passed,
			Reason:       check.Detail,
			CheckResults: []types.CheckResult{*check},
		}
	}

	missingChecks := make([]missingCheck, 0, len(types.AttestationCheckTypes))

	for _, checkType := range types.AttestationCheckTypes {
		if checkType == types.CheckTypeVSA {
			continue
		}

		if checkType == types.CheckTypeNotation && pol.Notation == nil {
			continue
		}

		missingChecks = append(missingChecks,
			missingCheck{checkType, pol.MissingPolicyFor(checkType)},
		)
	}

	results := make([]*types.CheckResult, 0, len(missingChecks))

	for _, mc := range missingChecks {
		checkResult := handleMissingAttestation(mc.missingPolicy, mc.checkType, detail)
		met.VerificationDuration.WithLabelValues(string(mc.checkType)).Observe(0)

		results = append(results, checkResult)
	}

	result := combineResults(results...)

	prependVSAWarning(result, pol, detail)

	return result
}

func timedFetchAttestations(
	ctx context.Context, state *snapshot,
	imageRef, digest, indexDigest string, pol *policy.Policy,
	host string, parsedRef name.Reference,
) ([]attestation.VerifiedAttestation, string, error) {
	start := time.Now()

	defer func() {
		state.metrics.FetchDuration.WithLabelValues(host).
			Observe(time.Since(start).Seconds())
	}()

	return fetchAttestations(ctx, state, imageRef, digest, indexDigest, pol, parsedRef)
}

func fetchAttestations(
	ctx context.Context, state *snapshot,
	imageRef, digest, indexDigest string, pol *policy.Policy,
	parsedRef name.Reference,
) ([]attestation.VerifiedAttestation, string, error) {
	opts := buildFetchOpts(pol, digest, state.config.FetchTimeout.Duration, parsedRef)

	var indexErr error

	// When the image resolved from a manifest list, try the index digest
	// first: cosign attaches attestations to the manifest list digest.
	if indexDigest != "" {
		indexOpts := buildFetchOpts(pol, indexDigest, state.config.FetchTimeout.Duration, parsedRef)

		atts, err := state.fetcher.Fetch(ctx, imageRef, indexOpts)
		if err == nil && len(atts) > 0 {
			return atts, indexDigest, nil
		}

		if err != nil {
			indexErr = err

			slog.DebugContext(ctx,
				"Index digest fetch failed, falling back to platform digest",
				"indexDigest", indexDigest,
				"platformDigest", digest,
				"error", err,
			)
		} else {
			slog.DebugContext(ctx,
				"No attestations on index digest, falling back to platform digest",
				"indexDigest", indexDigest,
				"platformDigest", digest,
			)
		}
	}

	attestations, err := state.fetcher.Fetch(ctx, imageRef, opts)
	if err != nil {
		platformErr := fmt.Errorf("fetching attestations: %w", err)
		if indexErr != nil {
			return nil, digest, errors.Join(
				platformErr,
				fmt.Errorf("index digest fetch also failed: %w", indexErr),
			)
		}

		return nil, digest, platformErr
	}

	return attestations, digest, nil
}

func buildFetchOpts(
	pol *policy.Policy, digest string, timeout time.Duration,
	parsedRef name.Reference,
) *attestation.FetchOptions {
	opts := &attestation.FetchOptions{
		RequireTransparencyLog: pol.Signatures != nil && pol.Signatures.RequireTransparencyLog,
		Timeout:                timeout,
		Digest:                 digest,
		ParsedRef:              parsedRef,
	}

	if pol.Trust != nil {
		opts.TrustedIssuers = pol.Trust.Issuers
		opts.SANPatterns = pol.Trust.SANPatterns

		totalKeys := 0
		for idx := range pol.Trust.Verifiers {
			totalKeys += len(pol.Trust.Verifiers[idx].Keys)
		}

		keys := make([]attestation.TrustedKeyRef, 0, totalKeys)

		for idx := range pol.Trust.Verifiers {
			for _, keyPath := range pol.Trust.Verifiers[idx].Keys {
				keys = append(keys, attestation.TrustedKeyRef{
					Path:      keyPath,
					NotBefore: pol.Trust.Verifiers[idx].NotBeforeTime,
					NotAfter:  pol.Trust.Verifiers[idx].NotAfterTime,
				})
			}
		}

		opts.TrustedKeys = keys
	}

	return opts
}

func checkVSA(
	ctx context.Context, vsaAttestations []attestation.VerifiedAttestation,
	pol *policy.Policy, imageRef, digest string, met *metrics.Metrics,
	parsedRef name.Reference,
) *types.Result {
	if len(vsaAttestations) == 0 {
		return nil
	}

	start := time.Now()

	defer func() {
		met.VerificationDuration.WithLabelValues(string(types.CheckTypeVSA)).
			Observe(time.Since(start).Seconds())
	}()

	digestRef := digestRefFromParsed(parsedRef, imageRef, digest)

	var passed *vsa.VerifyResult

	for idx := range vsaAttestations {
		vsaResult, err := vsa.Verify(ctx, vsaAttestations[idx].Payload, pol, digestRef, nil)
		if err != nil {
			slog.WarnContext(ctx, "VSA verification error", "error", err)

			continue
		}

		if vsaResult.HardReject {
			return &types.Result{
				Allowed:      false,
				Reason:       vsaResult.Check.Detail,
				CheckResults: []types.CheckResult{*vsaResult.Check},
			}
		}

		if passed == nil && vsaResult.Check.Passed && vsaResult.Check.Status == types.StatusPass {
			passed = vsaResult
		}
	}

	if passed != nil {
		return &types.Result{
			Allowed:      true,
			Reason:       "VSA verification passed, skipping direct verification",
			CheckResults: []types.CheckResult{*passed.Check},
		}
	}

	return nil
}

//nolint:funlen // table-driven dispatch over all check types
func runParallelChecks(
	ctx context.Context, bins *attestationBins,
	pol *policy.Policy, met *metrics.Metrics,
	imageRef, digest string,
	parsedRef name.Reference,
) *types.Result {
	checks := []struct {
		checkType types.CheckType
		fn        func() *types.CheckResult
	}{
		{types.CheckTypeSLSA, func() *types.CheckResult {
			return runAttestationCheck(
				ctx, types.CheckTypeSLSA, bins.slsa, pol, met, imageRef,
				func() (*types.CheckResult, error) {
					return slsa.VerifyMultiple(ctx, bins.slsa, pol, digest)
				})
		}},
		{types.CheckTypeVEX, func() *types.CheckResult {
			return runAttestationCheck(
				ctx, types.CheckTypeVEX, bins.vex, pol, met, imageRef,
				func() (*types.CheckResult, error) {
					return vex.VerifyMultiple(
						ctx, extractPayloads(bins.vex),
						pol, imageRef, digest, parsedRef,
					)
				})
		}},
		{types.CheckTypeNotation, func() *types.CheckResult {
			return runAttestationCheck(
				ctx, types.CheckTypeNotation, bins.notation, pol, met, imageRef,
				func() (*types.CheckResult, error) {
					return notation.VerifyMultiple(
						ctx, bins.notation, imageRef, digest, pol,
					)
				})
		}},
		{types.CheckTypeSBOM, func() *types.CheckResult {
			return runAttestationCheck(
				ctx, types.CheckTypeSBOM, bins.sbom, pol, met, imageRef,
				func() (*types.CheckResult, error) {
					return sbom.VerifyMultiple(
						ctx, extractPayloads(bins.sbom), pol, digest,
					)
				})
		}},
		{types.CheckTypeSCAI, func() *types.CheckResult {
			return runAttestationCheck(
				ctx, types.CheckTypeSCAI, bins.scai, pol, met, imageRef,
				func() (*types.CheckResult, error) {
					return scai.VerifyMultiple(
						ctx, extractPayloads(bins.scai), pol, digest,
					)
				})
		}},
		{types.CheckTypeSource, func() *types.CheckResult {
			return runAttestationCheck(
				ctx, types.CheckTypeSource, bins.source, pol, met, imageRef,
				func() (*types.CheckResult, error) {
					return source.VerifyMultiple(
						ctx, extractPayloads(bins.source), pol, digest,
					)
				})
		}},
		{types.CheckTypeBuildEnv, func() *types.CheckResult {
			return runAttestationCheck(
				ctx, types.CheckTypeBuildEnv, bins.buildenv, pol, met, imageRef,
				func() (*types.CheckResult, error) {
					return buildenv.VerifyMultiple(
						ctx, extractPayloads(bins.buildenv), pol, digest,
					)
				})
		}},
		{types.CheckTypeVulnScan, func() *types.CheckResult {
			return runAttestationCheck(
				ctx, types.CheckTypeVulnScan, bins.vulnscan, pol, met, imageRef,
				func() (*types.CheckResult, error) {
					return vulnscan.VerifyMultiple(
						ctx, extractPayloads(bins.vulnscan), pol, digest,
					)
				})
		}},
		{types.CheckTypeTestResult, func() *types.CheckResult {
			return runAttestationCheck(
				ctx, types.CheckTypeTestResult, bins.testresult, pol, met, imageRef,
				func() (*types.CheckResult, error) {
					return testresult.VerifyMultiple(
						ctx, extractPayloads(bins.testresult), pol, digest,
					)
				})
		}},
		{types.CheckTypeRelease, func() *types.CheckResult {
			return runAttestationCheck(
				ctx, types.CheckTypeRelease, bins.release, pol, met, imageRef,
				func() (*types.CheckResult, error) {
					return release.VerifyMultiple(
						ctx, extractPayloads(bins.release), pol, digest,
					)
				})
		}},
		{types.CheckTypeRuntimeTrace, func() *types.CheckResult {
			return runAttestationCheck(
				ctx, types.CheckTypeRuntimeTrace, bins.runtimetrace, pol, met, imageRef,
				func() (*types.CheckResult, error) {
					return runtimetrace.VerifyMultiple(
						ctx, extractPayloads(bins.runtimetrace), pol, digest,
					)
				})
		}},
	}

	results := make([]*types.CheckResult, len(checks))

	var waitGroup sync.WaitGroup

	for idx, chk := range checks {
		waitGroup.Add(1)

		go runParallelCheck(&waitGroup, &results[idx], chk.checkType, chk.fn)
	}

	waitGroup.Wait()

	return combineResults(results...)
}

func runParallelCheck(
	waitGroup *sync.WaitGroup,
	result **types.CheckResult,
	checkType types.CheckType,
	checkFunc func() *types.CheckResult,
) {
	defer waitGroup.Done()
	defer func() {
		if r := recover(); r != nil {
			slog.Error("Panic during check",
				"type", checkType,
				"panic", r, "stack", string(debug.Stack()))

			*result = types.FailResult(
				checkType,
				"internal error during "+string(checkType)+" check", nil,
			)
		}
	}()

	*result = checkFunc()
}

type attestationBins struct {
	vsa          []attestation.VerifiedAttestation
	slsa         []attestation.VerifiedAttestation
	vex          []attestation.VerifiedAttestation
	notation     []attestation.VerifiedAttestation
	sbom         []attestation.VerifiedAttestation
	scai         []attestation.VerifiedAttestation
	source       []attestation.VerifiedAttestation
	buildenv     []attestation.VerifiedAttestation
	vulnscan     []attestation.VerifiedAttestation
	testresult   []attestation.VerifiedAttestation
	release      []attestation.VerifiedAttestation
	runtimetrace []attestation.VerifiedAttestation
}

func binAttestations( //nolint:cyclop // additional predicate type adds a branch
	ctx context.Context, attestations []attestation.VerifiedAttestation, imageRef string,
) attestationBins {
	var bins attestationBins

	for idx := range attestations {
		// Route by signature type first: Notation signatures carry
		// signature manifests, not in-toto attestation payloads.
		if attestations[idx].SignatureType == attestation.SignatureTypeNotation {
			bins.notation = append(bins.notation, attestations[idx])

			continue
		}

		switch attestations[idx].PredicateType {
		case attestation.PredicateVSA:
			bins.vsa = append(bins.vsa, attestations[idx])
		case attestation.PredicateSLSAProvenanceV1, attestation.PredicateSLSAProvenanceV02:
			bins.slsa = append(bins.slsa, attestations[idx])
		case attestation.PredicateOpenVEX:
			bins.vex = append(bins.vex, attestations[idx])
		case attestation.PredicateCycloneDX:
			bins.vex = append(bins.vex, attestations[idx])
			bins.sbom = append(bins.sbom, attestations[idx])
		case attestation.PredicateSPDX:
			bins.sbom = append(bins.sbom, attestations[idx])
		case attestation.PredicateSCAI:
			bins.scai = append(bins.scai, attestations[idx])
		case attestation.PredicateSLSASourceV1:
			bins.source = append(bins.source, attestations[idx])
		case attestation.PredicateBuildEnv:
			bins.buildenv = append(bins.buildenv, attestations[idx])
		case attestation.PredicateVulnScan, attestation.PredicateVulnScanV02:
			bins.vulnscan = append(bins.vulnscan, attestations[idx])
		case attestation.PredicateTestResult:
			bins.testresult = append(bins.testresult, attestations[idx])
		case attestation.PredicateRelease:
			bins.release = append(bins.release, attestations[idx])
		case attestation.PredicateRuntimeTrace:
			bins.runtimetrace = append(bins.runtimetrace, attestations[idx])
		case attestation.PredicateCosignSignature:
			slog.DebugContext(ctx,
				"Skipping bare cosign signature attestation",
				"image", imageRef,
			)
		default:
			slog.WarnContext(ctx,
				"Skipping attestation with unrecognized predicate type",
				"predicateType", attestations[idx].PredicateType,
				"image", imageRef,
			)
		}
	}

	return bins
}

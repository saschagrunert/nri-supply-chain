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
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/buildenv"
	celengine "github.com/saschagrunert/nri-supply-chain/internal/cel"
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
	"github.com/saschagrunert/nri-supply-chain/internal/vulnscan"
)

const (
	reasonMissingAttestation = "missing_attestation"
	reasonMissingSignature   = "missing_signature"
)

type checkRunner struct {
	checkType     types.CheckType
	label         string
	missingPolicy types.Action
	missingLog    string
	missingReason string
	missingDetail string
}

func (cr *checkRunner) run(
	ctx context.Context,
	met *metrics.Metrics,
	imageRef string,
	hasAttestations bool,
	verify func() (*types.CheckResult, error),
) *types.CheckResult {
	start := time.Now()

	defer func() {
		met.VerificationDuration.WithLabelValues(
			string(cr.checkType),
		).Observe(time.Since(start).Seconds())
	}()

	if !hasAttestations {
		logMissingAttestation(
			ctx, cr.missingPolicy,
			cr.missingLog, imageRef, cr.missingReason,
		)

		return handleMissingAttestation(
			cr.missingPolicy,
			cr.checkType,
			cr.missingDetail+imageRef,
		)
	}

	result, err := verify()
	if err != nil {
		slog.ErrorContext(ctx,
			cr.label+" verification error",
			"error", err,
			"reason", "verification_error",
			"image", imageRef,
		)

		return types.FailResult(
			cr.checkType,
			fmt.Sprintf(
				"%s verification error for %s: %s",
				cr.label, imageRef, err,
			),
			err,
		)
	}

	return result
}

func runSBOMCheck(
	ctx context.Context,
	sbomAtts []attestation.VerifiedAttestation,
	pol *policy.Policy, met *metrics.Metrics,
	imageRef, digest string,
) *types.CheckResult {
	runner := &checkRunner{
		checkType:     types.CheckTypeSBOM,
		label:         "SBOM",
		missingPolicy: pol.SBOMMissingPolicy(),
		missingLog:    "No SBOM attestation found",
		missingReason: reasonMissingAttestation,
		missingDetail: "no SBOM attestation found for image ",
	}

	return runner.run(
		ctx, met, imageRef, len(sbomAtts) > 0,
		func() (*types.CheckResult, error) {
			return sbom.VerifyMultiple(ctx, extractPayloads(sbomAtts), pol, digest)
		},
	)
}

func runSCAICheck(
	ctx context.Context,
	scaiAtts []attestation.VerifiedAttestation,
	pol *policy.Policy, met *metrics.Metrics,
	imageRef, digest string,
) *types.CheckResult {
	runner := &checkRunner{
		checkType:     types.CheckTypeSCAI,
		label:         "SCAI",
		missingPolicy: pol.SCAIMissingPolicy(),
		missingLog:    "No SCAI attestation found",
		missingReason: reasonMissingAttestation,
		missingDetail: "no SCAI attestation found for image ",
	}

	return runner.run(
		ctx, met, imageRef, len(scaiAtts) > 0,
		func() (*types.CheckResult, error) {
			return scai.VerifyMultiple(ctx, extractPayloads(scaiAtts), pol, digest)
		},
	)
}

func runSLSACheck(
	ctx context.Context,
	slsaAtts []attestation.VerifiedAttestation,
	pol *policy.Policy, met *metrics.Metrics,
	imageRef, digest string,
) *types.CheckResult {
	runner := &checkRunner{
		checkType:     types.CheckTypeSLSA,
		label:         "SLSA",
		missingPolicy: pol.SLSAMissingPolicy(),
		missingLog:    "No provenance attestation found",
		missingReason: reasonMissingAttestation,
		missingDetail: "no provenance attestation found for image ",
	}

	return runner.run(
		ctx, met, imageRef, len(slsaAtts) > 0,
		func() (*types.CheckResult, error) {
			return slsa.VerifyMultiple(ctx, slsaAtts, pol, digest)
		},
	)
}

func runVEXCheck(
	ctx context.Context,
	vexAtts []attestation.VerifiedAttestation,
	pol *policy.Policy, met *metrics.Metrics,
	imageRef, digest string,
	parsedRef name.Reference,
) *types.CheckResult {
	runner := &checkRunner{
		checkType:     types.CheckTypeVEX,
		label:         "VEX",
		missingPolicy: pol.VEXMissingPolicy(),
		missingLog:    "No VEX attestation found",
		missingReason: reasonMissingAttestation,
		missingDetail: "no VEX attestation found for image ",
	}

	return runner.run(
		ctx, met, imageRef, len(vexAtts) > 0,
		func() (*types.CheckResult, error) {
			return vex.VerifyMultiple(
				ctx, extractPayloads(vexAtts), pol, imageRef, digest, parsedRef,
			)
		},
	)
}

func runNotationCheck(
	ctx context.Context,
	notationAtts []attestation.VerifiedAttestation,
	pol *policy.Policy, met *metrics.Metrics,
	imageRef, digest string,
) *types.CheckResult {
	runner := &checkRunner{
		checkType:     types.CheckTypeNotation,
		label:         "Notation",
		missingPolicy: pol.NotationMissingPolicy(),
		missingLog:    "No Notation signature found",
		missingReason: reasonMissingSignature,
		missingDetail: "no Notation signature found for image ",
	}

	return runner.run(
		ctx, met, imageRef, len(notationAtts) > 0,
		func() (*types.CheckResult, error) {
			return notation.VerifyMultiple(
				ctx, notationAtts, imageRef, digest, pol,
			)
		},
	)
}

func runSourceCheck(
	ctx context.Context,
	sourceAtts []attestation.VerifiedAttestation,
	pol *policy.Policy, met *metrics.Metrics,
	imageRef, digest string,
) *types.CheckResult {
	runner := &checkRunner{
		checkType:     types.CheckTypeSource,
		label:         "Source",
		missingPolicy: pol.SourceMissingPolicy(),
		missingLog:    "No source attestation found",
		missingReason: reasonMissingAttestation,
		missingDetail: "no source attestation found for image ",
	}

	return runner.run(
		ctx, met, imageRef, len(sourceAtts) > 0,
		func() (*types.CheckResult, error) {
			return source.VerifyMultiple(ctx, extractPayloads(sourceAtts), pol, digest)
		},
	)
}

func runBuildEnvCheck(
	ctx context.Context,
	buildenvAtts []attestation.VerifiedAttestation,
	pol *policy.Policy, met *metrics.Metrics,
	imageRef, digest string,
) *types.CheckResult {
	runner := &checkRunner{
		checkType:     types.CheckTypeBuildEnv,
		label:         "BuildEnv",
		missingPolicy: pol.BuildEnvMissingPolicy(),
		missingLog:    "No build environment attestation found",
		missingReason: reasonMissingAttestation,
		missingDetail: "no build environment attestation found for image ",
	}

	return runner.run(
		ctx, met, imageRef, len(buildenvAtts) > 0,
		func() (*types.CheckResult, error) {
			return buildenv.VerifyMultiple(ctx, extractPayloads(buildenvAtts), pol, digest)
		},
	)
}

func runVulnScanCheck(
	ctx context.Context,
	vulnscanAtts []attestation.VerifiedAttestation,
	pol *policy.Policy, met *metrics.Metrics,
	imageRef, digest string,
) *types.CheckResult {
	runner := &checkRunner{
		checkType:     types.CheckTypeVulnScan,
		label:         "VulnScan",
		missingPolicy: pol.VulnScanMissingPolicy(),
		missingLog:    "No vulnerability scan attestation found",
		missingReason: reasonMissingAttestation,
		missingDetail: "no vulnerability scan attestation found for image ",
	}

	return runner.run(
		ctx, met, imageRef, len(vulnscanAtts) > 0,
		func() (*types.CheckResult, error) {
			return vulnscan.VerifyMultiple(ctx, extractPayloads(vulnscanAtts), pol, digest)
		},
	)
}

func runTestResultCheck(
	ctx context.Context,
	testresultAtts []attestation.VerifiedAttestation,
	pol *policy.Policy, met *metrics.Metrics,
	imageRef, digest string,
) *types.CheckResult {
	runner := &checkRunner{
		checkType:     types.CheckTypeTestResult,
		label:         "TestResult",
		missingPolicy: pol.TestResultMissingPolicy(),
		missingLog:    "No test result attestation found",
		missingReason: reasonMissingAttestation,
		missingDetail: "no test result attestation found for image ",
	}

	return runner.run(
		ctx, met, imageRef, len(testresultAtts) > 0,
		func() (*types.CheckResult, error) {
			return testresult.VerifyMultiple(ctx, extractPayloads(testresultAtts), pol, digest)
		},
	)
}

func runReleaseCheck(
	ctx context.Context,
	releaseAtts []attestation.VerifiedAttestation,
	pol *policy.Policy, met *metrics.Metrics,
	imageRef, digest string,
) *types.CheckResult {
	runner := &checkRunner{
		checkType:     types.CheckTypeRelease,
		label:         "Release",
		missingPolicy: pol.ReleaseMissingPolicy(),
		missingLog:    "No release attestation found",
		missingReason: reasonMissingAttestation,
		missingDetail: "no release attestation found for image ",
	}

	return runner.run(
		ctx, met, imageRef, len(releaseAtts) > 0,
		func() (*types.CheckResult, error) {
			return release.VerifyMultiple(ctx, extractPayloads(releaseAtts), pol, digest)
		},
	)
}

func runRuntimeTraceCheck(
	ctx context.Context,
	runtimetraceAtts []attestation.VerifiedAttestation,
	pol *policy.Policy, met *metrics.Metrics,
	imageRef, digest string,
) *types.CheckResult {
	runner := &checkRunner{
		checkType:     types.CheckTypeRuntimeTrace,
		label:         "RuntimeTrace",
		missingPolicy: pol.RuntimeTraceMissingPolicy(),
		missingLog:    "No runtime trace attestation found",
		missingReason: reasonMissingAttestation,
		missingDetail: "no runtime trace attestation found for image ",
	}

	return runner.run(
		ctx, met, imageRef, len(runtimetraceAtts) > 0,
		func() (*types.CheckResult, error) {
			return runtimetrace.VerifyMultiple(ctx, extractPayloads(runtimetraceAtts), pol, digest)
		},
	)
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

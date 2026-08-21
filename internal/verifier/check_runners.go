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
	celengine "github.com/saschagrunert/nri-supply-chain/internal/cel"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
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
			ctx, cr.missingLog, imageRef, cr.missingReason,
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

type checkDef struct {
	label         string
	missingLog    string
	missingReason string
	missingDetail string
}

//nolint:gochecknoglobals // registry of static metadata per check type
var checkDefs = map[types.CheckType]checkDef{
	types.CheckTypeSBOM: {
		label:         "SBOM",
		missingLog:    "No SBOM attestation found",
		missingReason: reasonMissingAttestation,
		missingDetail: "no SBOM attestation found for image ",
	},
	types.CheckTypeSCAI: {
		label:         "SCAI",
		missingLog:    "No SCAI attestation found",
		missingReason: reasonMissingAttestation,
		missingDetail: "no SCAI attestation found for image ",
	},
	types.CheckTypeSLSA: {
		label:         "SLSA",
		missingLog:    "No provenance attestation found",
		missingReason: reasonMissingAttestation,
		missingDetail: "no provenance attestation found for image ",
	},
	types.CheckTypeVEX: {
		label:         "VEX",
		missingLog:    "No VEX attestation found",
		missingReason: reasonMissingAttestation,
		missingDetail: "no VEX attestation found for image ",
	},
	types.CheckTypeNotation: {
		label:         "Notation",
		missingLog:    "No Notation signature found",
		missingReason: reasonMissingSignature,
		missingDetail: "no Notation signature found for image ",
	},
	types.CheckTypeSource: {
		label:         "Source",
		missingLog:    "No source attestation found",
		missingReason: reasonMissingAttestation,
		missingDetail: "no source attestation found for image ",
	},
	types.CheckTypeBuildEnv: {
		label:         "BuildEnv",
		missingLog:    "No build environment attestation found",
		missingReason: reasonMissingAttestation,
		missingDetail: "no build environment attestation found for image ",
	},
	types.CheckTypeVulnScan: {
		label:         "VulnScan",
		missingLog:    "No vulnerability scan attestation found",
		missingReason: reasonMissingAttestation,
		missingDetail: "no vulnerability scan attestation found for image ",
	},
	types.CheckTypeTestResult: {
		label:         "TestResult",
		missingLog:    "No test result attestation found",
		missingReason: reasonMissingAttestation,
		missingDetail: "no test result attestation found for image ",
	},
	types.CheckTypeRelease: {
		label:         "Release",
		missingLog:    "No release attestation found",
		missingReason: reasonMissingAttestation,
		missingDetail: "no release attestation found for image ",
	},
	types.CheckTypeRuntimeTrace: {
		label:         "RuntimeTrace",
		missingLog:    "No runtime trace attestation found",
		missingReason: reasonMissingAttestation,
		missingDetail: "no runtime trace attestation found for image ",
	},
}

func runAttestationCheck(
	ctx context.Context,
	checkType types.CheckType,
	atts []attestation.VerifiedAttestation,
	pol *policy.Policy, met *metrics.Metrics,
	imageRef string,
	verify func() (*types.CheckResult, error),
) *types.CheckResult {
	def, ok := checkDefs[checkType]
	if !ok {
		return types.FailResult(checkType,
			fmt.Sprintf("unknown check type: %s", checkType), nil)
	}

	runner := &checkRunner{
		checkType:     checkType,
		label:         def.label,
		missingPolicy: pol.MissingPolicyFor(checkType),
		missingLog:    def.missingLog,
		missingReason: def.missingReason,
		missingDetail: def.missingDetail,
	}

	return runner.run(ctx, met, imageRef, len(atts) > 0, verify)
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

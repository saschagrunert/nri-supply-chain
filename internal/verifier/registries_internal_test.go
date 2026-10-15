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
	"bytes"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"testing"

	celengine "github.com/saschagrunert/nri-supply-chain/internal/cel"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

// TestAttestationRegistriesAgree checks that every per-type registry lists
// the same attestation check types, so a new type cannot be added to one and
// silently missed by another.
func TestAttestationRegistriesAgree(t *testing.T) {
	t.Parallel()

	want := slices.Sorted(slices.Values(types.AttestationCheckTypes))

	sections := make([]types.CheckType, 0, len(types.AttestationCheckTypes))
	for _, section := range policy.AttestationSections() {
		sections = append(sections, section.CheckType)
	}

	// VSAs are evaluated before the other checks (see check_vsa.go), so
	// they have no entry in checkSpecs.
	specs := make([]types.CheckType, 0, len(checkSpecs)+1)
	specs = append(specs, types.CheckTypeVSA)

	for idx := range checkSpecs {
		specs = append(specs, checkSpecs[idx].checkType)
	}

	registries := map[string][]types.CheckType{
		"policy section registry":   sections,
		"verifier checkSpecs":       specs,
		"CEL attestation variables": slices.Collect(maps.Keys(celengine.AttestationVariables())),
		"missing policy artifacts":  slices.Collect(maps.Keys(missingPolicyArtifacts)),
	}

	for name, registry := range registries {
		got := slices.Sorted(slices.Values(registry))
		if !slices.Equal(got, want) {
			t.Errorf("%s lists %v, want %v", name, got, want)
		}
	}
}

//nolint:paralleltest // replaces the default logger to capture the warnings
func TestWarnPermissiveMissingPoliciesCoversAllSections(t *testing.T) {
	var logs bytes.Buffer

	previous := slog.Default()

	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))

	t.Cleanup(func() { slog.SetDefault(previous) })

	pol := &policy.Policy{
		Scorecard:    &policy.ScorecardPolicy{},
		RuntimeTrace: &policy.RuntimeTracePolicy{},
	}

	warnPermissiveMissingPolicies(t.Context(), "default", pol)

	output := logs.String()

	for _, setting := range []string{
		"slsa.missingPolicy", "vex.missingPolicy", "scorecard.missingPolicy", "runtimeTrace.missingPolicy",
	} {
		if !strings.Contains(output, "setting="+setting) {
			t.Errorf("expected a warning for %s, got logs:\n%s", setting, output)
		}
	}

	for _, field := range []string{
		`check=slsa artifact="SLSA provenance attestations" setting=slsa.missingPolicy`,
		`check=scorecard artifact="OpenSSF Scorecard attestations" setting=scorecard.missingPolicy`,
	} {
		if !strings.Contains(output, field) {
			t.Errorf("expected the warning fields %s, got logs:\n%s", field, output)
		}
	}

	if strings.Contains(output, "setting=sbom.missingPolicy") {
		t.Errorf("expected no warning for an unset sbom section, got logs:\n%s", output)
	}
}

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

// Package types provides shared data types for supply chain verification results.
package types

import "maps"

// CheckStatus represents the outcome status of a verification check.
type CheckStatus string

const (
	// StatusPass indicates a check passed.
	StatusPass CheckStatus = "pass"
	// StatusWarn indicates a check passed with a warning.
	StatusWarn CheckStatus = "warn"
	// StatusFail indicates a check failed.
	StatusFail CheckStatus = "fail"
)

// CheckType identifies the kind of verification check performed.
type CheckType string

const (
	// CheckTypeSLSA is the SLSA provenance check type.
	CheckTypeSLSA CheckType = "slsa"
	// CheckTypeVEX is the VEX attestation check type.
	CheckTypeVEX CheckType = "vex"
	// CheckTypeVSA is the VSA attestation check type.
	CheckTypeVSA CheckType = "vsa"
	// CheckTypeFetch is the attestation fetch result type.
	CheckTypeFetch CheckType = "fetch"
	// CheckTypePolicy is the policy lookup result type.
	CheckTypePolicy CheckType = "policy"
	// CheckTypeNotation is the Notation/Notary v2 signature check type.
	CheckTypeNotation CheckType = "notation"
	// CheckTypeCEL is the CEL custom rule check type.
	CheckTypeCEL CheckType = "cel"
	// CheckTypeSBOM is the SBOM attestation check type.
	CheckTypeSBOM CheckType = "sbom"
)

// Result represents the outcome of a supply chain verification.
type Result struct {
	// Allowed indicates whether the image passed verification.
	Allowed bool `json:"allowed"`
	// Reason provides details about the verification decision.
	Reason string `json:"reason,omitempty"`
	// CheckResults contains per-check outcomes for audit logging.
	CheckResults []CheckResult `json:"checkResults,omitempty"`
}

// CheckResult represents the outcome of an individual verification check.
//
// Passed and Status encode related but distinct signals:
//   - PassResult:     Passed=true,  Status="pass" (check succeeded)
//   - WarnResult:     Passed=true,  Status="warn" (succeeded with warnings, allowed)
//   - FailResult:     Passed=false, Status="fail" (check failed, denied)
//   - SoftFailResult: Passed=false, Status="warn" (inconclusive, not counted as pass)
//
// Always use the constructor functions to keep Passed and Status consistent.
type CheckResult struct {
	// Type is the check type (e.g., CheckTypeSLSA, CheckTypeVEX, CheckTypeVSA).
	Type CheckType `json:"type"`
	// Passed indicates whether this check passed.
	Passed bool `json:"passed"`
	// Status is the check outcome: StatusPass, StatusWarn, or StatusFail.
	Status CheckStatus `json:"status"`
	// Detail provides additional information about the check result.
	Detail string `json:"detail,omitempty"`
	// Err is the underlying error that caused a failure, if any.
	// Excluded from JSON serialization because errors are not JSON-marshalable.
	Err error `json:"-"`
	// Metadata carries domain-specific data from the verifier (e.g., SLSA
	// builderID, VEX status) for use in CEL policy expressions.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// PassResult returns a passing CheckResult.
func PassResult(checkType CheckType, detail string) *CheckResult {
	return &CheckResult{
		Type:     checkType,
		Passed:   true,
		Status:   StatusPass,
		Detail:   detail,
		Err:      nil,
		Metadata: nil,
	}
}

// WarnResult returns a warning CheckResult that allows with a warning.
func WarnResult(checkType CheckType, detail string) *CheckResult {
	return &CheckResult{
		Type:     checkType,
		Passed:   true,
		Status:   StatusWarn,
		Detail:   detail,
		Err:      nil,
		Metadata: nil,
	}
}

// FailResult returns a failing CheckResult with an optional underlying error.
func FailResult(checkType CheckType, detail string, err error) *CheckResult {
	return &CheckResult{
		Type:     checkType,
		Passed:   false,
		Status:   StatusFail,
		Detail:   detail,
		Err:      err,
		Metadata: nil,
	}
}

// Clone returns a shallow copy of the Result with a cloned CheckResults slice.
func (r *Result) Clone() Result {
	clone := *r
	if len(r.CheckResults) > 0 {
		clone.CheckResults = make([]CheckResult, len(r.CheckResults))
		copy(clone.CheckResults, r.CheckResults)

		for idx := range clone.CheckResults {
			if clone.CheckResults[idx].Metadata != nil {
				m := make(map[string]any, len(clone.CheckResults[idx].Metadata))
				maps.Copy(m, clone.CheckResults[idx].Metadata)

				clone.CheckResults[idx].Metadata = m
			}
		}
	}

	return clone
}

// SoftFailResult returns a CheckResult that did not pass but is only a warning.
// Used for inconclusive checks (e.g., untrusted or stale VSA verifier results)
// that should not block container creation but are not counted as passing.
func SoftFailResult(checkType CheckType, detail string, err error) *CheckResult {
	return &CheckResult{
		Type:     checkType,
		Passed:   false,
		Status:   StatusWarn,
		Detail:   detail,
		Err:      err,
		Metadata: nil,
	}
}

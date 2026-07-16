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

const (
	// StatusPass indicates a check passed.
	StatusPass = "pass"
	// StatusWarn indicates a check passed with a warning.
	StatusWarn = "warn"
	// StatusFail indicates a check failed.
	StatusFail = "fail"
)

// Result represents the outcome of a supply chain verification.
type Result struct {
	// Allowed indicates whether the image passed verification.
	Allowed bool
	// Reason provides details about the verification decision.
	Reason string
	// CheckResults contains per-check outcomes for audit logging.
	CheckResults []CheckResult
}

// CheckResult represents the outcome of an individual verification check.
type CheckResult struct {
	// Type is the check type (e.g., "slsa_provenance", "vex", "vsa").
	Type string
	// Passed indicates whether this check passed.
	Passed bool
	// Status is the check outcome: "pass", "warn", or "fail".
	Status string
	// Detail provides additional information about the check result.
	Detail string
}

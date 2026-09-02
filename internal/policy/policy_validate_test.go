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

package policy_test

import (
	"errors"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
)

const testScorecardCodeReview = "Code-Review"

func TestValidateVulnScan(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pol     *policy.Policy
		wantErr error
	}{
		{
			name: "maxScore out of range",
			pol: &policy.Policy{
				VulnScan: &policy.VulnScanPolicy{
					MaxScore: new(11.0),
				},
			},
			wantErr: policy.ErrVulnScanMaxScoreRange,
		},
		{
			name: "invalid minSeverity",
			pol: &policy.Policy{
				VulnScan: &policy.VulnScanPolicy{
					MinSeverity: "moderate",
				},
			},
			wantErr: policy.ErrVulnScanMinSeverityInvalid,
		},
		{
			name: "maxAge not positive", //nolint:goconst // repeated test name
			pol: &policy.Policy{
				VulnScan: &policy.VulnScanPolicy{
					MaxAge: "-1h", //nolint:goconst // test input
				},
			},
			wantErr: policy.ErrVulnScanMaxAgeNotPositive,
		},
		{
			name:    "valid vulnScan passes",
			wantErr: nil,
			pol: &policy.Policy{
				VulnScan: &policy.VulnScanPolicy{
					MaxScore:    new(7.0),
					MinSeverity: "high",
					MaxAge:      "24h",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := test.pol.Validate()

			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) {
					t.Errorf("expected %v, got %v", test.wantErr, err)
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateScorecard(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pol     *policy.Policy
		wantErr error
	}{
		{
			name: "minScore below range",
			pol: &policy.Policy{
				Scorecard: &policy.ScorecardPolicy{MinScore: new(-0.1)},
			},
			wantErr: policy.ErrScorecardMinScoreRange,
		},
		{
			name: "minScore above range",
			pol: &policy.Policy{
				Scorecard: &policy.ScorecardPolicy{MinScore: new(10.1)},
			},
			wantErr: policy.ErrScorecardMinScoreRange,
		},
		{
			name: "check score below range",
			pol: &policy.Policy{
				Scorecard: &policy.ScorecardPolicy{
					Checks: map[string]int{testScorecardCodeReview: -1},
				},
			},
			wantErr: policy.ErrScorecardCheckScoreRange,
		},
		{
			name: "check score above range",
			pol: &policy.Policy{
				Scorecard: &policy.ScorecardPolicy{
					Checks: map[string]int{testScorecardCodeReview: 11},
				},
			},
			wantErr: policy.ErrScorecardCheckScoreRange,
		},
		{
			name: "empty check name",
			pol: &policy.Policy{
				Scorecard: &policy.ScorecardPolicy{Checks: map[string]int{"": 7}},
			},
			wantErr: policy.ErrEmptyValue,
		},
		{
			name: "valid scorecard policy",
			pol: &policy.Policy{
				Scorecard: &policy.ScorecardPolicy{
					MinScore: new(7.0),
					Checks:   map[string]int{testScorecardCodeReview: 8, "Branch-Protection": 9},
				},
			},
			wantErr: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := test.pol.Validate()
			if test.wantErr != nil && !errors.Is(err, test.wantErr) {
				t.Errorf("error = %v, want %v", err, test.wantErr)
			} else if test.wantErr == nil && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestMergeScorecardDeepCopy(t *testing.T) {
	t.Parallel()

	defaultPolicy := &policy.Policy{
		Scorecard: &policy.ScorecardPolicy{
			MinScore: new(7.0),
			Checks:   map[string]int{testScorecardCodeReview: 8},
		},
	}

	merged := policy.MergeWithDefault(&policy.Policy{}, defaultPolicy)
	*merged.Scorecard.MinScore = 9.0
	merged.Scorecard.Checks[testScorecardCodeReview] = 10

	if *defaultPolicy.Scorecard.MinScore != 7.0 {
		t.Error("merging mutated the default minScore")
	}

	if defaultPolicy.Scorecard.Checks[testScorecardCodeReview] != 8 {
		t.Error("merging mutated the default checks map")
	}
}

func TestValidateSource(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pol     *policy.Policy
		wantErr error
	}{
		{
			name: "invalid source level",
			pol: &policy.Policy{
				Source: &policy.SourcePolicy{
					MinimumLevel: 4,
				},
			},
			wantErr: policy.ErrInvalidSourceLevel,
		},
		{
			name: "maxAge not positive",
			pol: &policy.Policy{
				Source: &policy.SourcePolicy{
					MaxAge: "-1h",
				},
			},
			wantErr: policy.ErrSourceMaxAgeNotPositive,
		},
		{
			name:    "valid source passes",
			wantErr: nil,
			pol: &policy.Policy{
				Source: &policy.SourcePolicy{
					MinimumLevel: 2,
					MaxAge:       "12h",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := test.pol.Validate()

			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) {
					t.Errorf("expected %v, got %v", test.wantErr, err)
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateBuildEnv(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pol     *policy.Policy
		wantErr error
	}{
		{
			name: "overlapping required and forbidden properties",
			pol: &policy.Policy{
				BuildEnv: &policy.BuildEnvPolicy{
					RequiredProperties:  []string{"OS"},
					ForbiddenProperties: []string{"os"},
				},
			},
			wantErr: policy.ErrBuildEnvOverlappingProperties,
		},
		{
			name:    "valid buildEnv passes",
			wantErr: nil,
			pol: &policy.Policy{
				BuildEnv: &policy.BuildEnvPolicy{
					RequiredProperties:  []string{"OS", "ARCH"},
					ForbiddenProperties: []string{"DEBUG_MODE"},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := test.pol.Validate()

			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) {
					t.Errorf("expected %v, got %v", test.wantErr, err)
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateTestResult(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pol     *policy.Policy
		wantErr error
	}{
		{
			name: "maxAge not positive",
			pol: &policy.Policy{
				TestResult: &policy.TestResultPolicy{
					MaxAge: "-1h",
				},
			},
			wantErr: policy.ErrTestResultMaxAgeNotPositive,
		},
		{
			name:    "valid testResult passes",
			wantErr: nil,
			pol: &policy.Policy{
				TestResult: &policy.TestResultPolicy{
					RequiredSuites: []string{"unit", "integration"},
					MaxAge:         "6h",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := test.pol.Validate()

			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) {
					t.Errorf("expected %v, got %v", test.wantErr, err)
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

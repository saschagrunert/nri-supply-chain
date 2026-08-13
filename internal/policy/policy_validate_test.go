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
				Sections: policy.Sections{
					VulnScan: &policy.VulnScanPolicy{
						MaxScore: new(11.0),
					},
				},
			},
			wantErr: policy.ErrVulnScanMaxScoreRange,
		},
		{
			name: "invalid minSeverity",
			pol: &policy.Policy{
				Sections: policy.Sections{
					VulnScan: &policy.VulnScanPolicy{
						MinSeverity: "moderate",
					},
				},
			},
			wantErr: policy.ErrVulnScanMinSeverityInvalid,
		},
		{
			name: "maxAge not positive", //nolint:goconst // repeated test name
			pol: &policy.Policy{
				Sections: policy.Sections{
					VulnScan: &policy.VulnScanPolicy{
						MaxAge: "-1h", //nolint:goconst // test input
					},
				},
			},
			wantErr: policy.ErrVulnScanMaxAgeNotPositive,
		},
		{
			name:    "valid vulnScan passes",
			wantErr: nil,
			pol: &policy.Policy{
				Sections: policy.Sections{
					VulnScan: &policy.VulnScanPolicy{
						MaxScore:    new(7.0),
						MinSeverity: "high",
						MaxAge:      "24h",
					},
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
				Sections: policy.Sections{
					Source: &policy.SourcePolicy{
						MinimumLevel: 4,
					},
				},
			},
			wantErr: policy.ErrInvalidSourceLevel,
		},
		{
			name: "maxAge not positive",
			pol: &policy.Policy{
				Sections: policy.Sections{
					Source: &policy.SourcePolicy{
						MaxAge: "-1h",
					},
				},
			},
			wantErr: policy.ErrSourceMaxAgeNotPositive,
		},
		{
			name:    "valid source passes",
			wantErr: nil,
			pol: &policy.Policy{
				Sections: policy.Sections{
					Source: &policy.SourcePolicy{
						MinimumLevel: 2,
						MaxAge:       "12h",
					},
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
				Sections: policy.Sections{
					BuildEnv: &policy.BuildEnvPolicy{
						RequiredProperties:  []string{"OS"},
						ForbiddenProperties: []string{"os"},
					},
				},
			},
			wantErr: policy.ErrBuildEnvOverlappingProperties,
		},
		{
			name:    "valid buildEnv passes",
			wantErr: nil,
			pol: &policy.Policy{
				Sections: policy.Sections{
					BuildEnv: &policy.BuildEnvPolicy{
						RequiredProperties:  []string{"OS", "ARCH"},
						ForbiddenProperties: []string{"DEBUG_MODE"},
					},
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
				Sections: policy.Sections{
					TestResult: &policy.TestResultPolicy{
						MaxAge: "-1h",
					},
				},
			},
			wantErr: policy.ErrTestResultMaxAgeNotPositive,
		},
		{
			name:    "valid testResult passes",
			wantErr: nil,
			pol: &policy.Policy{
				Sections: policy.Sections{
					TestResult: &policy.TestResultPolicy{
						RequiredSuites: []string{"unit", "integration"},
						MaxAge:         "6h",
					},
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

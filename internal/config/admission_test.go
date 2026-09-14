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

package config_test

import (
	"errors"
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

func TestAdmissionTimeoutDefaultAndValidation(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	testutil.AssertEqual(t, 1500*time.Millisecond, cfg.AdmissionTimeout.Duration)

	tests := []struct {
		name    string
		timeout time.Duration
		wantErr error
	}{
		{"zero", 0, config.ErrAdmissionTimeoutNotPositive},
		{"negative", -time.Second, config.ErrAdmissionTimeoutNotPositive},
		{"too high", 2 * time.Minute, config.ErrAdmissionTimeoutTooHigh},
		{"valid", 900 * time.Millisecond, nil},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cfg := config.DefaultConfig()
			cfg.AdmissionTimeout = config.Duration{Duration: test.timeout}

			err := cfg.Validate()
			if test.wantErr == nil {
				testutil.AssertNoError(t, err)

				return
			}

			if !errors.Is(err, test.wantErr) {
				t.Errorf("expected %v, got %v", test.wantErr, err)
			}
		})
	}
}

func TestLoadAdmissionTimeout(t *testing.T) {
	t.Parallel()

	cfg, err := config.LoadFromString(`admission_timeout = "900ms"`)
	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, 900*time.Millisecond, cfg.AdmissionTimeout.Duration)
}

func TestOCIMaxStalenessValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		staleness time.Duration
		wantErr   bool
	}{
		{"unlimited", 0, false},
		{"negative", -time.Minute, true},
		{"below poll interval", time.Minute, true},
		{"at poll interval", 5 * time.Minute, false},
		{"above poll interval", time.Hour, false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cfg := config.DefaultConfig()
			cfg.Policy.Source = config.PolicySourceOCI
			cfg.Policy.OCIRef = "ghcr.io/myorg/policies:v1"
			cfg.Policy.PollInterval = config.Duration{Duration: 5 * time.Minute}
			cfg.Policy.OCIMaxStaleness = config.Duration{Duration: test.staleness}

			err := cfg.Validate()
			if got := errors.Is(err, config.ErrOCIMaxStalenessInvalid); got != test.wantErr {
				t.Errorf("expected ErrOCIMaxStalenessInvalid=%v, got %v", test.wantErr, err)
			}
		})
	}
}

func TestFetchFailurePolicyExplicitRecordedOnLoad(t *testing.T) {
	t.Parallel()

	implicit, err := config.LoadFromString(`verification = "warn"`)
	testutil.AssertNoError(t, err)

	if implicit.FetchFailurePolicyExplicit {
		t.Error("expected default fetch_failure_policy not to be explicit")
	}

	explicit, err := config.LoadFromString(
		"verification = \"warn\"\nfetch_failure_policy = \"warn\"",
	)
	testutil.AssertNoError(t, err)

	if !explicit.FetchFailurePolicyExplicit {
		t.Error("expected configured fetch_failure_policy to be explicit")
	}
}

func TestEffectiveFetchFailurePolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		global   config.VerificationMode
		policy   types.Action
		explicit bool
		mode     config.VerificationMode
		want     types.Action
	}{
		{
			"warn namespace keeps policy",
			config.ModeWarn,
			types.ActionAllow,
			true,
			config.ModeWarn,
			types.ActionAllow,
		},
		{
			"global enforce keeps policy",
			config.ModeEnforce,
			types.ActionWarn,
			true,
			config.ModeEnforce,
			types.ActionWarn,
		},
		{
			"enforce namespace denies default warn", config.ModeWarn, types.ActionWarn, false,
			config.ModeEnforce, types.ActionDeny,
		},
		{
			"enforce namespace honors explicit warn", config.ModeWarn, types.ActionWarn, true,
			config.ModeEnforce, types.ActionWarn,
		},
		{
			"enforce namespace never allows", config.ModeWarn, types.ActionAllow, true,
			config.ModeEnforce, types.ActionDeny,
		},
		{
			"enforce namespace keeps deny",
			config.ModeWarn,
			types.ActionDeny,
			true,
			config.ModeEnforce,
			types.ActionDeny,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cfg := config.DefaultConfig()
			cfg.Verification = test.global
			cfg.FetchFailurePolicy = test.policy
			cfg.FetchFailurePolicyExplicit = test.explicit

			if got := cfg.EffectiveFetchFailurePolicy(test.mode); got != test.want {
				t.Errorf("EffectiveFetchFailurePolicy = %q, want %q", got, test.want)
			}
		})
	}
}

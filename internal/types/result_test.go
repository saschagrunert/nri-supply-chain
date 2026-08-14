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

package types_test

import (
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

var errTest = types.ErrInvalidAction

const (
	testDetail = "verified"
	testAB     = "a,b"
)

func TestCloneDeepCopiesMetadata(t *testing.T) {
	t.Parallel()

	original := types.Result{
		Allowed: true,
		Reason:  "ok",
		CheckResults: []types.CheckResult{
			{
				Type:     types.CheckTypeSLSA,
				Passed:   true,
				Status:   types.StatusPass,
				Detail:   testDetail,
				Err:      nil,
				Metadata: map[string]any{"builderID": "original"},
			},
		},
	}

	cloned := original.Clone()

	cloned.CheckResults[0].Metadata["builderID"] = "modified"

	if original.CheckResults[0].Metadata["builderID"] != "original" {
		t.Error("Clone did not deep copy Metadata: original was mutated")
	}
}

func TestCloneNilMetadata(t *testing.T) {
	t.Parallel()

	original := types.Result{
		Allowed: true,
		Reason:  "",
		CheckResults: []types.CheckResult{
			{
				Type:     types.CheckTypeSLSA,
				Passed:   true,
				Status:   types.StatusPass,
				Detail:   testDetail,
				Err:      nil,
				Metadata: nil,
			},
		},
	}

	cloned := original.Clone()

	if cloned.CheckResults[0].Metadata != nil {
		t.Error("expected nil Metadata in clone")
	}
}

func TestCheckResultConstructors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		create     func() *types.CheckResult
		wantType   types.CheckType
		wantPassed bool
		wantStatus types.CheckStatus
		wantDetail string
		wantErr    bool
	}{
		{
			name:       "PassResult",
			create:     func() *types.CheckResult { return types.PassResult(types.CheckTypeSLSA, testDetail) },
			wantType:   types.CheckTypeSLSA,
			wantPassed: true,
			wantStatus: types.StatusPass,
			wantDetail: testDetail,
			wantErr:    false,
		},
		{
			name:       "WarnResult",
			create:     func() *types.CheckResult { return types.WarnResult(types.CheckTypeVEX, "under investigation") },
			wantType:   types.CheckTypeVEX,
			wantPassed: true,
			wantStatus: types.StatusWarn,
			wantDetail: "under investigation",
			wantErr:    false,
		},
		{
			name:       "FailResult",
			create:     func() *types.CheckResult { return types.FailResult(types.CheckTypeVSA, "untrusted verifier", nil) },
			wantType:   types.CheckTypeVSA,
			wantPassed: false,
			wantStatus: types.StatusFail,
			wantDetail: "untrusted verifier",
			wantErr:    false,
		},
		{
			name:       "FailResult with error",
			create:     func() *types.CheckResult { return types.FailResult(types.CheckTypeSLSA, "fetch failed", errTest) },
			wantType:   types.CheckTypeSLSA,
			wantPassed: false,
			wantStatus: types.StatusFail,
			wantDetail: "fetch failed",
			wantErr:    true,
		},
		{
			name:       "SoftFailResult",
			create:     func() *types.CheckResult { return types.SoftFailResult(types.CheckTypeVSA, "stale verifier", nil) },
			wantType:   types.CheckTypeVSA,
			wantPassed: false,
			wantStatus: types.StatusWarn,
			wantDetail: "stale verifier",
			wantErr:    false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			result := test.create()

			if result.Type != test.wantType {
				t.Errorf("expected type %q, got %q", test.wantType, result.Type)
			}

			if result.Passed != test.wantPassed {
				t.Errorf("expected Passed=%v, got Passed=%v", test.wantPassed, result.Passed)
			}

			if result.Status != test.wantStatus {
				t.Errorf("expected status %q, got %q", test.wantStatus, result.Status)
			}

			if result.Detail != test.wantDetail {
				t.Errorf("expected detail %q, got %q", test.wantDetail, result.Detail)
			}

			if test.wantErr && result.Err == nil {
				t.Error("expected non-nil Err")
			}

			if !test.wantErr && result.Err != nil {
				t.Errorf("expected nil Err, got %v", result.Err)
			}
		})
	}
}

func TestMergeCommaSeparated(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		existing string
		incoming string
		want     string
	}{
		{
			name:     "both empty",
			existing: "",
			incoming: "",
			want:     "",
		},
		{
			name:     "existing empty",
			existing: "",
			incoming: testAB,
			want:     testAB,
		},
		{
			name:     "incoming empty",
			existing: testAB,
			incoming: "",
			want:     testAB,
		},
		{
			name:     "no overlap",
			existing: testAB,
			incoming: "c,d",
			want:     "a,b,c,d",
		},
		{
			name:     "full overlap",
			existing: testAB,
			incoming: testAB,
			want:     testAB,
		},
		{
			name:     "partial overlap",
			existing: testAB,
			incoming: "b,c",
			want:     "a,b,c",
		},
		{
			name:     "case insensitive dedup",
			existing: "Foo,Bar",
			incoming: "foo,baz",
			want:     "Foo,Bar,baz",
		},
		{
			name:     "single items",
			existing: "x",
			incoming: "x",
			want:     "x",
		},
		{
			name:     "single items no overlap",
			existing: "x",
			incoming: "y",
			want:     "x,y",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := types.MergeCommaSeparated(test.existing, test.incoming)
			if got != test.want {
				t.Errorf("MergeCommaSeparated(%q, %q) = %q, want %q",
					test.existing, test.incoming, got, test.want)
			}
		})
	}
}

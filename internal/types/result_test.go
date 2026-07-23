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

func TestPassResult(t *testing.T) {
	t.Parallel()

	result := types.PassResult(types.CheckTypeSLSA, "verified")

	if result.Type != types.CheckTypeSLSA {
		t.Errorf("expected type slsa, got %q", result.Type)
	}

	if !result.Passed {
		t.Error("expected Passed to be true")
	}

	if result.Status != types.StatusPass {
		t.Errorf("expected status %q, got %q", types.StatusPass, result.Status)
	}

	if result.Detail != "verified" {
		t.Errorf("expected detail %q, got %q", "verified", result.Detail)
	}
}

func TestWarnResult(t *testing.T) {
	t.Parallel()

	result := types.WarnResult(types.CheckTypeVEX, "under investigation")

	if result.Type != types.CheckTypeVEX {
		t.Errorf("expected type vex, got %q", result.Type)
	}

	if !result.Passed {
		t.Error("expected Passed to be true for warn")
	}

	if result.Status != types.StatusWarn {
		t.Errorf("expected status %q, got %q", types.StatusWarn, result.Status)
	}

	if result.Detail != "under investigation" {
		t.Errorf("expected detail %q, got %q", "under investigation", result.Detail)
	}
}

func TestFailResult(t *testing.T) {
	t.Parallel()

	result := types.FailResult(types.CheckTypeVSA, "untrusted verifier")

	if result.Type != types.CheckTypeVSA {
		t.Errorf("expected type vsa, got %q", result.Type)
	}

	if result.Passed {
		t.Error("expected Passed to be false")
	}

	if result.Status != types.StatusFail {
		t.Errorf("expected status %q, got %q", types.StatusFail, result.Status)
	}

	if result.Detail != "untrusted verifier" {
		t.Errorf("expected detail %q, got %q", "untrusted verifier", result.Detail)
	}
}

func TestSoftFailResult(t *testing.T) {
	t.Parallel()

	result := types.SoftFailResult(types.CheckTypeVSA, "stale verifier")

	if result.Type != types.CheckTypeVSA {
		t.Errorf("expected type vsa, got %q", result.Type)
	}

	if result.Passed {
		t.Error("expected Passed to be false")
	}

	if result.Status != types.StatusWarn {
		t.Errorf("expected status %q, got %q", types.StatusWarn, result.Status)
	}

	if result.Detail != "stale verifier" {
		t.Errorf("expected detail %q, got %q", "stale verifier", result.Detail)
	}
}

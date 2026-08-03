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

package openvex_test

import (
	"context"
	"testing"

	openvexlib "github.com/openvex/go-vex/pkg/vex"

	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/vex/openvex"
)

const (
	testDigest     = "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	testVEXContext = "https://openvex.dev/ns/v0.2.0"
)

func validDoc(status openvexlib.Status) openvexlib.VEX {
	return openvexlib.VEX{
		Metadata: openvexlib.Metadata{
			Context: testVEXContext,
			ID:      "https://openvex.dev/docs/example/vex-1",
		},
		Statements: []openvexlib.Statement{
			{
				Vulnerability: openvexlib.Vulnerability{
					Name: "CVE-2024-1234",
				},
				Products: []openvexlib.Product{
					{Component: openvexlib.Component{ID: testDigest}},
				},
				Status: status,
			},
		},
	}
}

func TestVerifyNotAffected(t *testing.T) {
	t.Parallel()

	doc := validDoc(openvexlib.StatusNotAffected)
	data := testutil.MustMarshal(t, doc)

	result, err := openvex.Verify(context.Background(), data, testDigest, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.AffectedNames) > 0 {
		t.Errorf("expected no affected, got %v", result.AffectedNames)
	}
}

func TestVerifyAffected(t *testing.T) {
	t.Parallel()

	doc := validDoc(openvexlib.StatusAffected)
	data := testutil.MustMarshal(t, doc)

	result, err := openvex.Verify(context.Background(), data, testDigest, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.AffectedNames) == 0 {
		t.Error("expected affected vulnerabilities")
	}

	if result.AffectedNames[0] != "CVE-2024-1234" {
		t.Errorf("expected CVE-2024-1234, got %s", result.AffectedNames[0])
	}
}

func TestVerifyUnderInvestigation(t *testing.T) {
	t.Parallel()

	doc := validDoc(openvexlib.StatusUnderInvestigation)
	data := testutil.MustMarshal(t, doc)

	result, err := openvex.Verify(context.Background(), data, testDigest, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.HasUnderInvestigation {
		t.Error("expected HasUnderInvestigation to be true")
	}
}

func TestVerifyFixed(t *testing.T) {
	t.Parallel()

	doc := validDoc(openvexlib.StatusFixed)
	data := testutil.MustMarshal(t, doc)

	result, err := openvex.Verify(context.Background(), data, testDigest, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.AffectedNames) > 0 || result.HasUnderInvestigation {
		t.Error("expected clean result for fixed status")
	}
}

func TestVerifyInvalidJSON(t *testing.T) {
	t.Parallel()

	_, err := openvex.Verify(
		context.Background(), []byte("not json"),
		testDigest, "",
	)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

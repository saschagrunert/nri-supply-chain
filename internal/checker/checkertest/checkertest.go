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

// Package checkertest provides the contract tests shared by the predicate
// checker packages. It is only imported by tests.
package checkertest

import (
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	celengine "github.com/saschagrunert/nri-supply-chain/internal/cel"
	"github.com/saschagrunert/nri-supply-chain/internal/intoto"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

// otherDigest is a digest no test statement is bound to.
const otherDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

// VerifyFunc is the VerifyMultiple function of a predicate checker.
type VerifyFunc func(
	ctx context.Context, attestations [][]byte, pol *policy.Policy, imageDigest string,
) (*types.CheckResult, error)

// Contract describes a predicate checker for RunContract.
type Contract struct {
	// Verify verifies attestations like the verifier does.
	Verify VerifyFunc
	// CheckType is the check type of every result.
	CheckType types.CheckType
	// PredicateType is the in-toto predicate type of the attestations.
	PredicateType string
	// Digest is the image digest the attestations are bound to.
	Digest string
	// ErrInvalid is the error invalid documents are reported with.
	ErrInvalid error
	// Valid is a predicate that passes an empty policy.
	Valid any
	// OptionalMeta lists CEL fields the valid predicate does not produce.
	OptionalMeta []string
}

// RunContract runs the tests every predicate checker must pass: results
// carry the check type, invalid documents and documents bound to another or
// no digest fail closed with the reason, a missing attestation set fails,
// cancellation is reported, and the metadata of a passing result reaches CEL
// with the declared field types.
func RunContract(t *testing.T, contract *Contract) {
	t.Helper()

	t.Run("valid document passes", contract.testValid)
	t.Run("invalid documents fail closed", contract.testInvalid)
	t.Run("unbound documents fail closed", contract.testUnbound)
	t.Run("no attestations fail", contract.testNoAttestations)
	t.Run("cancelled context is reported", contract.testCancelled)
}

func (c *Contract) testValid(t *testing.T) {
	t.Parallel()

	result, err := c.Verify(t.Context(), [][]byte{c.wrap(t, c.Valid)}, &policy.Policy{}, c.Digest)
	testutil.AssertNoError(t, err)
	testutil.AssertTrue(t, result.Passed)
	testutil.AssertEqual(t, c.CheckType, result.Type)
	AssertCELMetadata(t, result, c.OptionalMeta...)
}

func (c *Contract) testInvalid(t *testing.T) {
	t.Parallel()

	for _, payload := range [][]byte{
		nil,
		{},
		[]byte(`{"subject":[`),
		c.wrap(t, json.RawMessage(`null`)),
		c.wrap(t, json.RawMessage(`[]`)),
		c.wrap(t, json.RawMessage(`"text"`)),
	} {
		result, err := c.Verify(t.Context(), [][]byte{payload}, &policy.Policy{}, c.Digest)
		AssertFailed(t, result, err, c.ErrInvalid)
		testutil.AssertEqual(t, c.CheckType, result.Type)
	}
}

func (c *Contract) testUnbound(t *testing.T) {
	t.Parallel()

	att := c.wrap(t, c.Valid)

	for digest, reason := range map[string]error{
		otherDigest: intoto.ErrSubjectMismatch,
		"":          intoto.ErrNoDigestBinding,
	} {
		result, err := c.Verify(t.Context(), [][]byte{att}, &policy.Policy{}, digest)
		AssertFailed(t, result, err, c.ErrInvalid)
		AssertFailed(t, result, err, reason)
		testutil.AssertEqual(t, c.CheckType, result.Type)
	}
}

func (c *Contract) testNoAttestations(t *testing.T) {
	t.Parallel()

	result, err := c.Verify(t.Context(), nil, &policy.Policy{}, c.Digest)
	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, false, result.Passed)
	testutil.AssertEqual(t, c.CheckType, result.Type)
}

func (c *Contract) testCancelled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := c.Verify(ctx, [][]byte{c.wrap(t, c.Valid)}, &policy.Policy{}, c.Digest)
	testutil.AssertErrorIs(t, err, context.Canceled)
}

func (c *Contract) wrap(t *testing.T, predicate any) []byte {
	t.Helper()

	return testutil.WrapInToto(t, predicate, c.Digest, c.PredicateType)
}

// AssertFailed asserts that verification returned a failed result whose
// detail names want.
func AssertFailed(t *testing.T, result *types.CheckResult, err, want error) {
	t.Helper()

	if err != nil {
		t.Fatalf("expected a failed result, got error %v", err)
	}

	if result == nil || result.Passed || result.Status != types.StatusFail {
		t.Fatalf("expected a failed result, got %+v", result)
	}

	if want != nil && !strings.Contains(result.Detail, want.Error()) {
		t.Fatalf("expected the detail to name %q, got %q", want, result.Detail)
	}
}

// AssertCELMetadata asserts that the metadata of a result provides every CEL
// field of its check type, except the optional ones, with the value type CEL
// expects. A metadata key renamed in a checker would otherwise silently leave
// the CEL field at its default value.
func AssertCELMetadata(t *testing.T, result *types.CheckResult, optional ...string) {
	t.Helper()

	fields := celengine.MetadataFields(result.Type)
	if fields == nil {
		t.Fatalf("check type %q has no CEL variable", result.Type)
	}

	assertFields(t, string(result.Type), result.Metadata, fields, optional)
}

func assertFields(t *testing.T, path string, meta, fields map[string]any, optional []string) {
	t.Helper()

	for key, def := range fields {
		value, found := meta[key]
		if !found {
			if !slices.Contains(optional, key) {
				t.Errorf("metadata has no %s.%s field", path, key)
			}

			continue
		}

		if nested, isMap := def.(map[string]any); isMap {
			src, srcIsMap := value.(map[string]any)
			if !srcIsMap {
				t.Errorf("metadata %s.%s is %T, want a map", path, key, value)

				continue
			}

			assertFields(t, path+"."+key, src, nested, optional)

			continue
		}

		if reflect.TypeOf(value) != reflect.TypeOf(def) {
			t.Errorf("metadata %s.%s is %T, CEL expects %T", path, key, value, def)
		}
	}
}

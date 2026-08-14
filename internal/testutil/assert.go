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

// Package testutil provides shared test assertion helpers.
package testutil

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// AssertEqual asserts that expected and actual are equal.
func AssertEqual[T comparable](t *testing.T, expected, actual T) {
	t.Helper()

	if expected != actual {
		t.Errorf("expected %v, got %v", expected, actual)
	}
}

// AssertNoError asserts that err is nil.
func AssertNoError(t *testing.T, err error) {
	t.Helper()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// AssertError asserts that err is not nil.
func AssertError(t *testing.T, err error) {
	t.Helper()

	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// AssertErrorIs asserts that err is non-nil and matches target via errors.Is.
func AssertErrorIs(t *testing.T, err, target error) {
	t.Helper()

	if err == nil {
		t.Fatalf("expected error wrapping %v, got nil", target)
	}

	if !errors.Is(err, target) {
		t.Errorf("expected error wrapping %v, got %v", target, err)
	}
}

// AssertTrue asserts that val is true.
func AssertTrue(t *testing.T, val bool) {
	t.Helper()

	if !val {
		t.Error("expected true, got false")
	}
}

// AssertContains asserts that s contains substr.
func AssertContains(t *testing.T, s, substr string) {
	t.Helper()

	if !strings.Contains(s, substr) {
		t.Errorf("expected %q to contain %q", s, substr)
	}
}

// MustMarshal marshals val to JSON, failing the test on error.
func MustMarshal(t *testing.T, val any) []byte {
	t.Helper()

	data, err := json.Marshal(val)
	if err != nil {
		t.Fatalf("failed to marshal JSON: %v", err)
	}

	return data
}

const policyFileMode = 0o600

// WritePolicy writes a policy file to dir for use in tests.
func WritePolicy(t *testing.T, dir, name, content string) {
	t.Helper()

	err := os.WriteFile(filepath.Join(dir, name), []byte(content), policyFileMode)
	if err != nil {
		t.Fatalf("writing policy: %v", err)
	}
}

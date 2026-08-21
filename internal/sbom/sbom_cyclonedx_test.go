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

package sbom //nolint:testpackage // needs access to unexported mergeCVSSMeta and toStringSlice

import (
	"slices"
	"testing"
)

const (
	testPURLGolangA = "pkg:golang/a@1.0"
	testPURLGolangB = "pkg:golang/b@2.0"
	testKeyPURLs    = "purls"
)

func TestToStringSliceFromStringSlice(t *testing.T) {
	t.Parallel()

	input := []string{"a", "b", "c"}

	result := toStringSlice(input)

	if !slices.Equal(result, input) {
		t.Errorf("expected %v, got %v", input, result)
	}
}

func TestToStringSliceFromAnySlice(t *testing.T) {
	t.Parallel()

	input := []any{"x", "y", "z"}

	result := toStringSlice(input)

	if !slices.Equal(result, []string{"x", "y", "z"}) {
		t.Errorf("expected [x y z], got %v", result)
	}
}

func TestToStringSliceFromMixedAnySlice(t *testing.T) {
	t.Parallel()

	input := []any{"a", 42, "b", true}

	result := toStringSlice(input)

	if !slices.Equal(result, []string{"a", "b"}) {
		t.Errorf("expected [a b], got %v", result)
	}
}

func TestToStringSliceNonSlice(t *testing.T) {
	t.Parallel()

	result := toStringSlice(42)

	if result != nil {
		t.Errorf("expected nil for non-slice input, got %v", result)
	}
}

func TestToStringSliceNil(t *testing.T) {
	t.Parallel()

	result := toStringSlice(nil)

	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}
}

func TestMergeCVSSMetaPURLs(t *testing.T) {
	t.Parallel()

	dst := map[string]any{
		testKeyPURLs: []string{testPURLGolangA, "pkg:golang/c@3.0"},
	}
	src := map[string]any{
		testKeyPURLs: []string{testPURLGolangB, testPURLGolangA},
	}

	mergeCVSSMeta(dst, src)

	result := toStringSlice(dst[testKeyPURLs])

	expected := []string{testPURLGolangA, testPURLGolangB, "pkg:golang/c@3.0"}
	if !slices.Equal(result, expected) {
		t.Errorf("expected %v, got %v", expected, result)
	}
}

func TestMergeCVSSMetaPURLsFromAnySlice(t *testing.T) {
	t.Parallel()

	dst := map[string]any{
		testKeyPURLs: []any{testPURLGolangA},
	}
	src := map[string]any{
		testKeyPURLs: []any{testPURLGolangB},
	}

	mergeCVSSMeta(dst, src)

	result := toStringSlice(dst[testKeyPURLs])

	expected := []string{testPURLGolangA, testPURLGolangB}
	if !slices.Equal(result, expected) {
		t.Errorf("expected %v, got %v", expected, result)
	}
}

func TestMergeCVSSMetaPURLsNewKey(t *testing.T) {
	t.Parallel()

	dst := map[string]any{}
	src := map[string]any{
		testKeyPURLs: []string{testPURLGolangA},
	}

	mergeCVSSMeta(dst, src)

	result := toStringSlice(dst[testKeyPURLs])

	if !slices.Equal(result, []string{testPURLGolangA}) {
		t.Errorf("expected [pkg:golang/a@1.0], got %v", result)
	}
}

func TestMergeCVSSMetaPURLsEmptySrc(t *testing.T) {
	t.Parallel()

	dst := map[string]any{
		testKeyPURLs: []string{testPURLGolangA},
	}
	src := map[string]any{
		testKeyPURLs: []string{},
	}

	mergeCVSSMeta(dst, src)

	result := toStringSlice(dst[testKeyPURLs])

	if !slices.Equal(result, []string{testPURLGolangA}) {
		t.Errorf("expected [pkg:golang/a@1.0], got %v", result)
	}
}

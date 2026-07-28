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

package testutil_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
)

var errTestSentinel = errors.New("test error")

func TestAssertEqual(t *testing.T) {
	t.Parallel()

	testutil.AssertEqual(t, 42, 42)
	testutil.AssertEqual(t, "hello", "hello")
	testutil.AssertEqual(t, true, true)
}

func TestAssertEqualFails(t *testing.T) {
	t.Parallel()

	ft := &testing.T{}

	testutil.AssertEqual(ft, 1, 2)

	if !ft.Failed() {
		t.Error("expected AssertEqual to mark test as failed for unequal values")
	}
}

func TestAssertNoError(t *testing.T) {
	t.Parallel()

	testutil.AssertNoError(t, nil)
}

func TestAssertError(t *testing.T) {
	t.Parallel()

	testutil.AssertError(t, errTestSentinel)
}

func TestMustMarshal(t *testing.T) {
	t.Parallel()

	data := testutil.MustMarshal(t, map[string]int{"a": 1})

	if len(data) == 0 {
		t.Error("expected non-empty JSON output")
	}
}

func TestWritePolicy(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	testutil.WritePolicy(t, dir, "test.json", `{"key": "value"}`)

	content, err := os.ReadFile(filepath.Join(dir, "test.json")) //nolint:gosec // test temp dir
	if err != nil {
		t.Fatalf("reading written policy: %v", err)
	}

	testutil.AssertEqual(t, `{"key": "value"}`, string(content))
}

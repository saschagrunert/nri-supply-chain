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

package feed_test

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/feed"
)

func TestParseFileSingleEntry(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "vuln.json")

	data := `{
		"id": "GHSA-1234",
		"affected": [
			{"package": {"purl": "pkg:golang/example.com/foo@v1.0.0"}},
			{"package": {"purl": "pkg:npm/bar@2.0.0"}}
		]
	}`

	err := os.WriteFile(path, []byte(data), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	purls, parseErr := feed.ParseFile(path)
	if parseErr != nil {
		t.Fatalf("unexpected error: %v", parseErr)
	}

	if len(purls) != 2 {
		t.Fatalf("expected 2 PURLs, got %d", len(purls))
	}

	if !slices.Contains(purls, "pkg:golang/example.com/foo@v1.0.0") {
		t.Error("missing golang PURL")
	}

	if !slices.Contains(purls, "pkg:npm/bar@2.0.0") {
		t.Error("missing npm PURL")
	}
}

func TestParseFileArray(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "vulns.json")

	data := `[
		{
			"id": "CVE-2024-001",
			"affected": [{"package": {"purl": "pkg:golang/a@1.0"}}]
		},
		{
			"id": "CVE-2024-002",
			"affected": [{"package": {"purl": "pkg:golang/b@2.0"}}]
		}
	]`

	err := os.WriteFile(path, []byte(data), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	purls, parseErr := feed.ParseFile(path)
	if parseErr != nil {
		t.Fatalf("unexpected error: %v", parseErr)
	}

	if len(purls) != 2 {
		t.Fatalf("expected 2 PURLs, got %d", len(purls))
	}
}

func TestParseFileDeduplicates(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "dup.json")

	data := `[
		{
			"id": "CVE-1",
			"affected": [{"package": {"purl": "pkg:golang/same@1.0"}}]
		},
		{
			"id": "CVE-2",
			"affected": [{"package": {"purl": "pkg:golang/same@1.0"}}]
		}
	]`

	err := os.WriteFile(path, []byte(data), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	purls, parseErr := feed.ParseFile(path)
	if parseErr != nil {
		t.Fatalf("unexpected error: %v", parseErr)
	}

	if len(purls) != 1 {
		t.Fatalf("expected 1 PURL after dedup, got %d", len(purls))
	}
}

func TestParseFileMalformed(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")

	err := os.WriteFile(path, []byte("not json"), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	_, parseErr := feed.ParseFile(path)
	if parseErr == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestParseFileNotFound(t *testing.T) {
	t.Parallel()

	_, err := feed.ParseFile("/nonexistent/path.json")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestParseFileEmptyPURLsSkipped(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "empty.json")

	data := `{
		"id": "CVE-1",
		"affected": [
			{"package": {"purl": ""}},
			{"package": {}}
		]
	}`

	err := os.WriteFile(path, []byte(data), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	purls, parseErr := feed.ParseFile(path)
	if parseErr != nil {
		t.Fatalf("unexpected error: %v", parseErr)
	}

	if len(purls) != 0 {
		t.Fatalf("expected 0 PURLs for empty entries, got %d", len(purls))
	}
}

func TestParseDirMixed(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	good := `{"id": "CVE-1", "affected": [{"package": {"purl": "pkg:golang/good@1.0"}}]}`
	bad := "not json"
	notJSON := "some text"

	err := os.WriteFile(filepath.Join(dir, "good.json"), []byte(good), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(filepath.Join(dir, "bad.json"), []byte(bad), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(filepath.Join(dir, "readme.txt"), []byte(notJSON), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	purls, success, errors := feed.ParseDir(dir)

	if success != 1 {
		t.Errorf("expected 1 success, got %d", success)
	}

	if errors != 1 {
		t.Errorf("expected 1 error, got %d", errors)
	}

	if len(purls) != 1 {
		t.Errorf("expected 1 PURL, got %d", len(purls))
	}
}

func TestParseDirEmpty(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	purls, success, errors := feed.ParseDir(dir)

	if len(purls) != 0 || success != 0 || errors != 0 {
		t.Errorf("expected empty results for empty dir, got purls=%d success=%d errors=%d",
			len(purls), success, errors)
	}
}

func TestParseDirNonexistent(t *testing.T) {
	t.Parallel()

	purls, success, errors := feed.ParseDir("/nonexistent/dir")

	if len(purls) != 0 || success != 0 || errors != 0 {
		t.Errorf("expected empty results for nonexistent dir, got purls=%d success=%d errors=%d",
			len(purls), success, errors)
	}
}

func TestParseDirSubdirSkipped(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	err := os.Mkdir(filepath.Join(dir, "subdir"), 0o750)
	if err != nil {
		t.Fatal(err)
	}

	good := `{"id": "CVE-1", "affected": [{"package": {"purl": "pkg:golang/x@1.0"}}]}`

	err = os.WriteFile(filepath.Join(dir, "good.json"), []byte(good), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	purls, success, errors := feed.ParseDir(dir)

	if success != 1 || errors != 0 || len(purls) != 1 {
		t.Errorf("unexpected results: purls=%d success=%d errors=%d", len(purls), success, errors)
	}
}

func TestParseDirDeduplicatesAcrossFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	file1 := `{"id": "CVE-1", "affected": [{"package": {"purl": "pkg:golang/dup@1.0"}}]}`
	file2 := `{"id": "CVE-2", "affected": [{"package": {"purl": "pkg:golang/dup@1.0"}}, ` +
		`{"package": {"purl": "pkg:golang/unique@2.0"}}]}`

	err := os.WriteFile(filepath.Join(dir, "a.json"), []byte(file1), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(filepath.Join(dir, "b.json"), []byte(file2), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	purls, success, errors := feed.ParseDir(dir)

	if success != 2 {
		t.Errorf("expected 2 successes, got %d", success)
	}

	if errors != 0 {
		t.Errorf("expected 0 errors, got %d", errors)
	}

	if len(purls) != 2 {
		t.Errorf("expected 2 unique PURLs after dedup, got %d: %v", len(purls), purls)
	}
}

func TestParseFileNotRegular(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	_, err := feed.ParseFile(dir)
	if err == nil {
		t.Error("expected error for directory path")
	}
}

func TestParseFileUnexpectedDelimiter(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")

	err := os.WriteFile(path, []byte(`"just a string"`), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	_, parseErr := feed.ParseFile(path)
	if parseErr == nil {
		t.Error("expected error for non-object/non-array JSON")
	}
}

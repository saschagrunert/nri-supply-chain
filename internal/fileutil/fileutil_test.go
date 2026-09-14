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

package fileutil_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/fileutil"
)

func TestReadLimitedSmallFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "small.txt")

	content := []byte("hello world")

	writeErr := os.WriteFile(path, content, 0o600)
	if writeErr != nil {
		t.Fatalf("writing test file: %v", writeErr)
	}

	data, err := fileutil.ReadLimited(path, 1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bytes.Equal(data, content) {
		t.Errorf("got %q, want %q", data, content)
	}
}

func TestReadLimitedFileTooLarge(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "large.txt")

	content := make([]byte, 2048)

	writeErr := os.WriteFile(path, content, 0o600)
	if writeErr != nil {
		t.Fatalf("writing test file: %v", writeErr)
	}

	_, err := fileutil.ReadLimited(path, 1024)
	if err == nil {
		t.Fatal("expected error for oversized file, got nil")
	}

	if !errors.Is(err, fileutil.ErrFileTooLarge) {
		t.Errorf("expected ErrFileTooLarge, got: %v", err)
	}
}

func TestReadLimitedNonexistent(t *testing.T) {
	t.Parallel()

	_, err := fileutil.ReadLimited("/nonexistent/path/file.txt", 1024)
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}

	if errors.Is(err, fileutil.ErrFileTooLarge) {
		t.Errorf("expected non-ErrFileTooLarge error, got ErrFileTooLarge")
	}
}

func TestCheckCredentialPermissionsSecure(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem")

	writeErr := os.WriteFile(path, []byte("secret"), 0o600)
	if writeErr != nil {
		t.Fatalf("writing test file: %v", writeErr)
	}

	permErr := fileutil.CheckCredentialPermissions(path)
	if permErr != nil {
		t.Fatalf("unexpected error for 0600 file: %v", permErr)
	}
}

func TestCheckCredentialPermissionsInsecure(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem")

	//nolint:gosec // intentionally insecure for test
	writeErr := os.WriteFile(path, []byte("secret"), 0o644)
	if writeErr != nil {
		t.Fatalf("writing test file: %v", writeErr)
	}

	err := fileutil.CheckCredentialPermissions(path)
	if err == nil {
		t.Fatal("expected error for 0644 file, got nil")
	}

	if !errors.Is(err, fileutil.ErrInsecurePermissions) {
		t.Errorf("expected ErrInsecurePermissions, got: %v", err)
	}
}

func TestCheckCredentialPermissionsNonexistent(t *testing.T) {
	t.Parallel()

	err := fileutil.CheckCredentialPermissions("/nonexistent/path/key.pem")
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}

	if errors.Is(err, fileutil.ErrInsecurePermissions) {
		t.Errorf("expected non-ErrInsecurePermissions error, got ErrInsecurePermissions")
	}
}

func TestReadLimitedRejectsEscapingSymlink(t *testing.T) {
	t.Parallel()

	outside := t.TempDir()
	target := filepath.Join(outside, "real.txt")

	writeErr := os.WriteFile(target, []byte("data"), 0o600)
	if writeErr != nil {
		t.Fatalf("writing target file: %v", writeErr)
	}

	link := filepath.Join(t.TempDir(), "link.txt")

	linkErr := os.Symlink(target, link)
	if linkErr != nil {
		t.Fatalf("creating symlink: %v", linkErr)
	}

	_, err := fileutil.ReadLimited(link, 1024)
	if !errors.Is(err, fileutil.ErrSymlink) {
		t.Errorf("expected ErrSymlink, got: %v", err)
	}
}

func TestReadLimitedRejectsParentSymlink(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	mount := filepath.Join(root, "mount")

	mkdirErr := os.Mkdir(mount, 0o750)
	if mkdirErr != nil {
		t.Fatalf("creating mount dir: %v", mkdirErr)
	}

	writeErr := os.WriteFile(filepath.Join(root, "secret"), []byte("data"), 0o600)
	if writeErr != nil {
		t.Fatalf("writing target file: %v", writeErr)
	}

	link := filepath.Join(mount, "config.toml")

	linkErr := os.Symlink("../secret", link)
	if linkErr != nil {
		t.Fatalf("creating symlink: %v", linkErr)
	}

	_, err := fileutil.ReadLimited(link, 1024)
	if !errors.Is(err, fileutil.ErrSymlink) {
		t.Errorf("expected ErrSymlink, got: %v", err)
	}
}

func TestReadLimitedSymlinkErrorMessages(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		target func(dir string) string
		want   string
	}{
		{
			name:   "absolute link inside the directory",
			target: func(dir string) string { return filepath.Join(dir, "real.txt") },
			want:   "absolute or parent-relative symlinks are not supported",
		},
		{
			name:   "parent-relative link back into the directory",
			target: func(dir string) string { return "../" + filepath.Base(dir) + "/real.txt" },
			want:   "absolute or parent-relative symlinks are not supported",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()

			writeErr := os.WriteFile(filepath.Join(dir, "real.txt"), []byte("data"), 0o600)
			if writeErr != nil {
				t.Fatalf("writing target file: %v", writeErr)
			}

			link := filepath.Join(dir, "link.txt")

			linkErr := os.Symlink(test.target(dir), link)
			if linkErr != nil {
				t.Fatalf("creating symlink: %v", linkErr)
			}

			_, err := fileutil.ReadLimited(link, 1024)
			if !errors.Is(err, fileutil.ErrSymlink) {
				t.Fatalf("expected ErrSymlink, got: %v", err)
			}

			if !strings.Contains(err.Error(), test.want) {
				t.Errorf("expected error to contain %q, got: %v", test.want, err)
			}
		})
	}
}

func TestReadLimitedFollowsSymlinkInSameDirectory(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := filepath.Join(dir, "real.txt")

	writeErr := os.WriteFile(target, []byte("data"), 0o600)
	if writeErr != nil {
		t.Fatalf("writing target file: %v", writeErr)
	}

	link := filepath.Join(dir, "link.txt")

	linkErr := os.Symlink("real.txt", link)
	if linkErr != nil {
		t.Fatalf("creating symlink: %v", linkErr)
	}

	data, err := fileutil.ReadLimited(link, 1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if string(data) != "data" {
		t.Errorf("expected %q, got %q", "data", data)
	}
}

// TestReadLimitedConfigMapLayout mirrors how the kubelet projects ConfigMap
// keys: "key" -> "..data/key" and "..data" -> "..<timestamp>".
func TestReadLimitedConfigMapLayout(t *testing.T) {
	t.Parallel()

	mount := t.TempDir()
	versioned := filepath.Join(mount, "..2026_09_14_00_00_00.000000000")

	mkdirErr := os.Mkdir(versioned, 0o750)
	if mkdirErr != nil {
		t.Fatalf("creating versioned dir: %v", mkdirErr)
	}

	writeErr := os.WriteFile(
		filepath.Join(versioned, "config.toml"), []byte("verification = \"warn\"\n"), 0o600,
	)
	if writeErr != nil {
		t.Fatalf("writing config: %v", writeErr)
	}

	for link, target := range map[string]string{
		"..data":      filepath.Base(versioned),
		"config.toml": "..data/config.toml",
	} {
		linkErr := os.Symlink(target, filepath.Join(mount, link))
		if linkErr != nil {
			t.Fatalf("creating symlink %s: %v", link, linkErr)
		}
	}

	data, err := fileutil.ReadLimited(filepath.Join(mount, "config.toml"), 1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bytes.Contains(data, []byte("warn")) {
		t.Errorf("unexpected content %q", data)
	}
}

func TestReadLimitedRejectsDirectory(t *testing.T) {
	t.Parallel()

	_, err := fileutil.ReadLimited(t.TempDir(), 1024)
	if !errors.Is(err, fileutil.ErrNotRegularFile) {
		t.Errorf("expected ErrNotRegularFile, got: %v", err)
	}
}

func TestResolveContainedRegularFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "file.txt")

	writeErr := os.WriteFile(path, []byte("data"), 0o600)
	if writeErr != nil {
		t.Fatalf("writing file: %v", writeErr)
	}

	resolved, err := fileutil.ResolveContained(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resolved != path {
		t.Errorf("expected %q, got %q", path, resolved)
	}
}

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

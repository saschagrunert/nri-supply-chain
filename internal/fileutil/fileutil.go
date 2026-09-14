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

// Package fileutil provides file I/O utilities with safety limits.
package fileutil

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	// MaxCredentialFileSize is the upper bound for credential and key files (1 MiB).
	MaxCredentialFileSize = 1 << 20

	// MaxConfigFileSize is the upper bound for TOML config files (10 MiB).
	MaxConfigFileSize = 10 << 20
)

var (
	// ErrFileTooLarge indicates a file exceeds the maximum allowed size.
	ErrFileTooLarge = errors.New("file exceeds maximum allowed size")

	// ErrInsecurePermissions indicates a credential file has overly permissive mode bits.
	ErrInsecurePermissions = errors.New("file has insecure permissions")

	// ErrSymlink indicates a symbolic link resolves outside the directory
	// containing it.
	ErrSymlink = errors.New("path is a symbolic link")

	// ErrNotRegularFile indicates a path does not refer to a regular file.
	ErrNotRegularFile = errors.New("path is not a regular file")
)

// ReadLimited reads a file up to maxSize bytes. Returns ErrFileTooLarge if the
// file exceeds the limit. Symbolic links are only followed when they resolve
// to a regular file inside the directory containing path, which is how
// Kubernetes projects ConfigMap and Secret keys ("key" -> "..data/key").
// Links escaping that directory, including absolute link targets, return
// ErrSymlink to prevent path traversal. The file is opened relative to its
// directory with os.Root, so a link swapped between checks cannot escape, and
// without blocking, so a FIFO cannot stall the caller.
func ReadLimited(path string, maxSize int64) ([]byte, error) {
	path = filepath.Clean(path)

	file, err := openContained(path)
	if err != nil {
		return nil, err
	}

	defer func() {
		_ = file.Close()
	}()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %q: %w", path, err)
	}

	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %q", ErrNotRegularFile, path)
	}

	data, err := io.ReadAll(io.LimitReader(file, maxSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading %q: %w", path, err)
	}

	if int64(len(data)) > maxSize {
		return nil, fmt.Errorf("%w: %q exceeds %d bytes", ErrFileTooLarge, path, maxSize)
	}

	return data, nil
}

// StatContained returns the file info of path, following symbolic links only
// while they stay inside the directory containing path (see ReadLimited).
// Validators use it so they accept exactly the files ReadLimited can read.
func StatContained(path string) (os.FileInfo, error) {
	path = filepath.Clean(path)

	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("stat %q: %w", path, err)
	}

	defer func() {
		_ = root.Close()
	}()

	info, err := root.Stat(filepath.Base(path))
	if err != nil {
		return nil, containedError(path, "stat", err)
	}

	return info, nil
}

// ResolveContained returns the path to open for path. A path that is not a
// symbolic link is returned unchanged. A symbolic link is resolved and
// returned only if its target stays inside the directory containing path;
// otherwise ErrSymlink is returned. Prefer ReadLimited or StatContained,
// which do not race with the file system between resolving and opening.
func ResolveContained(path string) (string, error) {
	path = filepath.Clean(path)

	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("stat %q: %w", path, err)
	}

	if info.Mode()&os.ModeSymlink == 0 {
		return path, nil
	}

	_, err = StatContained(path)
	if err != nil {
		return "", err
	}

	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolving symlink %q: %w", path, err)
	}

	return target, nil
}

func openContained(path string) (*os.File, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("opening %q: %w", path, err)
	}

	defer func() {
		_ = root.Close()
	}()

	file, err := root.OpenFile(filepath.Base(path), os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, containedError(path, "opening", err)
	}

	return file, nil
}

// containedError reports a failure to access path through its directory
// root. A symbolic link that exists but cannot be followed inside the
// directory is reported as ErrSymlink.
func containedError(path, operation string, err error) error {
	if !errors.Is(err, os.ErrNotExist) {
		info, lstatErr := os.Lstat(path)
		if lstatErr == nil && info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: %q %s: %w", ErrSymlink, path, symlinkProblem(path), err)
		}
	}

	return fmt.Errorf("%s %q: %w", operation, path, err)
}

// symlinkProblem describes why the symbolic link at path cannot be followed.
// Links are resolved inside the directory containing them, where absolute
// targets and targets with ".." elements are refused even if they point back
// into that directory.
func symlinkProblem(path string) string {
	target, err := os.Readlink(path)
	if err == nil && (filepath.IsAbs(target) || hasParentElement(target)) {
		return "is an absolute or parent-relative link (absolute or parent-relative " +
			"symlinks are not supported, use a link relative to the file's directory)"
	}

	return "resolves outside its directory"
}

func hasParentElement(target string) bool {
	for element := range strings.SplitSeq(filepath.ToSlash(target), "/") {
		if element == ".." {
			return true
		}
	}

	return false
}

// maxCredentialFileMode is the most permissive mode allowed for credential files.
const maxCredentialFileMode = 0o600

// CheckCredentialPermissions verifies that a credential or key file is not
// world- or group-readable. Returns ErrInsecurePermissions if the file's
// mode bits exceed 0600.
func CheckCredentialPermissions(path string) error {
	info, err := os.Stat(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("stat %q: %w", path, err)
	}

	mode := info.Mode().Perm()
	if mode&^maxCredentialFileMode != 0 {
		return fmt.Errorf(
			"%w: %q has mode %04o, want %04o or stricter",
			ErrInsecurePermissions, path, mode, maxCredentialFileMode,
		)
	}

	return nil
}

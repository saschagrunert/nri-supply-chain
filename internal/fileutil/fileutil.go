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
)

// ReadLimited reads a file up to maxSize bytes. Returns ErrFileTooLarge if the
// file exceeds the limit.
func ReadLimited(path string, maxSize int64) ([]byte, error) {
	path = filepath.Clean(path)

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening %q: %w", path, err)
	}

	defer func() {
		_ = file.Close()
	}()

	data, err := io.ReadAll(io.LimitReader(file, maxSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading %q: %w", path, err)
	}

	if int64(len(data)) > maxSize {
		return nil, fmt.Errorf("%w: %q exceeds %d bytes", ErrFileTooLarge, path, maxSize)
	}

	return data, nil
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

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

package bundle

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const maxBundleTarSize = 1 << 30 // 1 GiB

// Import extracts a bundle tar into the attestation store directory. Extraction
// is atomic: the tar is first extracted to a temporary directory, validated,
// and then moved to the final store path. If extraction or validation fails,
// the store path is not modified. When verifyKeyPath is non-empty, the bundle
// signature is verified before committing.
func Import(bundlePath, storePath, verifyKeyPath string) error {
	parentDir := filepath.Dir(storePath)

	mkdirErr := os.MkdirAll(parentDir, bundleDirMode)
	if mkdirErr != nil {
		return fmt.Errorf("creating parent directory: %w", mkdirErr)
	}

	tmpDir, err := os.MkdirTemp(parentDir, ".bundle-import-*")
	if err != nil {
		return fmt.Errorf("creating temp directory: %w", err)
	}

	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(tmpDir)
		}
	}()

	extractErr := extractTarGz(bundlePath, tmpDir)
	if extractErr != nil {
		return extractErr
	}

	store, err := OpenStore(tmpDir)
	if err != nil {
		return fmt.Errorf("validating imported bundle: %w", err)
	}

	if verifyKeyPath != "" {
		sigErr := VerifyManifestSignature(store.Manifest(), verifyKeyPath)
		if sigErr != nil {
			return fmt.Errorf("bundle signature verification failed: %w", sigErr)
		}
	}

	integrityErr := VerifyBlobIntegrity(store)
	if integrityErr != nil {
		return fmt.Errorf("bundle integrity check failed: %w", integrityErr)
	}

	swapErr := atomicSwapStore(tmpDir, storePath)
	if swapErr != nil {
		return swapErr
	}

	cleanup = false

	return nil
}

func extractTarGz(bundlePath, storePath string) error {
	bundleFile, err := os.Open(bundlePath) //nolint:gosec // path from user CLI flag
	if err != nil {
		return fmt.Errorf("opening bundle: %w", err)
	}
	defer func() { _ = bundleFile.Close() }()

	gzipReader, err := gzip.NewReader(bundleFile)
	if err != nil {
		return fmt.Errorf("opening gzip reader: %w", err)
	}
	defer func() { _ = gzipReader.Close() }()

	tarReader := tar.NewReader(gzipReader)

	var totalSize int64

	for {
		header, readErr := tarReader.Next()
		if readErr == io.EOF {
			break
		}

		if readErr != nil {
			return fmt.Errorf("reading tar: %w", readErr)
		}

		totalSize += header.Size
		if totalSize > maxBundleTarSize {
			return fmt.Errorf("%w: %d bytes", ErrBundleTooLarge, maxBundleTarSize)
		}

		entryErr := extractTarEntry(tarReader, header, storePath)
		if entryErr != nil {
			return entryErr
		}
	}

	return nil
}

func extractTarEntry(tarReader *tar.Reader, header *tar.Header, storePath string) error {
	//nolint:gosec // validated by path traversal check below
	target := filepath.Join(storePath, header.Name)

	cleanStore := filepath.Clean(storePath) + string(filepath.Separator)
	cleanTarget := filepath.Clean(target)

	if cleanTarget != filepath.Clean(storePath) &&
		!strings.HasPrefix(cleanTarget, cleanStore) {
		return fmt.Errorf("%w: %s", ErrPathTraversal, header.Name)
	}

	switch header.Typeflag {
	case tar.TypeDir:
		mkdirErr := os.MkdirAll(target, bundleDirMode)
		if mkdirErr != nil {
			return fmt.Errorf("creating directory %s: %w", target, mkdirErr)
		}

	case tar.TypeReg:
		extractErr := extractFile(tarReader, target, header.Size)
		if extractErr != nil {
			return extractErr
		}
	}

	return nil
}

func extractFile(reader io.Reader, target string, size int64) error {
	dir := filepath.Dir(target)

	mkdirErr := os.MkdirAll(dir, bundleDirMode)
	if mkdirErr != nil {
		return fmt.Errorf("creating directory %s: %w", dir, mkdirErr)
	}

	//nolint:gosec // path validated above
	outFile, err := os.OpenFile(
		target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, bundleFileMode,
	)
	if err != nil {
		return fmt.Errorf("creating file %s: %w", target, err)
	}

	_, copyErr := io.Copy(outFile, io.LimitReader(reader, size+1))
	if copyErr != nil {
		_ = outFile.Close()

		return fmt.Errorf("extracting %s: %w", target, copyErr)
	}

	closeErr := outFile.Close()
	if closeErr != nil {
		return fmt.Errorf("closing extracted file %s: %w", target, closeErr)
	}

	return nil
}

func atomicSwapStore(tmpDir, storePath string) error {
	backupPath := storePath + ".old"
	_ = os.RemoveAll(backupPath)

	_, statErr := os.Stat(storePath)
	if statErr == nil {
		renameErr := os.Rename(storePath, backupPath)
		if renameErr != nil {
			return fmt.Errorf("backing up existing store: %w", renameErr)
		}
	}

	renameErr := os.Rename(tmpDir, storePath)
	if renameErr != nil {
		_, backupStat := os.Stat(backupPath)
		if backupStat == nil {
			_ = os.Rename(backupPath, storePath)
		}

		return fmt.Errorf("moving bundle to store: %w", renameErr)
	}

	_ = os.RemoveAll(backupPath)

	return nil
}

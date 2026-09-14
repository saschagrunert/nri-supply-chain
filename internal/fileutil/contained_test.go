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

//go:build unix

package fileutil_test

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/fileutil"
)

const (
	readTimeout = 5 * time.Second

	// dataLink is the symlink the kubelet swaps on ConfigMap updates.
	dataLink = "..data"
)

func TestReadLimitedFIFODoesNotBlock(t *testing.T) {
	t.Parallel()

	fifo := filepath.Join(t.TempDir(), "fifo")

	err := syscall.Mkfifo(fifo, 0o600)
	if err != nil {
		t.Skipf("creating FIFO: %v", err)
	}

	done := make(chan error, 1)

	go func() {
		_, readErr := fileutil.ReadLimited(fifo, 1024)
		done <- readErr
	}()

	select {
	case readErr := <-done:
		if !errors.Is(readErr, fileutil.ErrNotRegularFile) {
			t.Errorf("expected ErrNotRegularFile, got: %v", readErr)
		}
	case <-time.After(readTimeout):
		t.Fatal("ReadLimited blocked on a FIFO")
	}
}

func TestReadLimitedFIFOBehindContainedSymlinkDoesNotBlock(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0o600)
	if err != nil {
		t.Skipf("creating FIFO: %v", err)
	}

	link := filepath.Join(dir, "key.pub")

	err = os.Symlink("fifo", link)
	if err != nil {
		t.Fatalf("creating symlink: %v", err)
	}

	done := make(chan error, 1)

	go func() {
		_, readErr := fileutil.ReadLimited(link, 1024)
		done <- readErr
	}()

	select {
	case readErr := <-done:
		if !errors.Is(readErr, fileutil.ErrNotRegularFile) {
			t.Errorf("expected ErrNotRegularFile, got: %v", readErr)
		}
	case <-time.After(readTimeout):
		t.Fatal("ReadLimited blocked on a FIFO behind a symlink")
	}
}

func TestReadLimitedRejectsNestedEscapingSymlink(t *testing.T) {
	t.Parallel()

	outside := t.TempDir()

	err := os.WriteFile(filepath.Join(outside, "secret"), []byte("data"), 0o600)
	if err != nil {
		t.Fatalf("writing target: %v", err)
	}

	dir := t.TempDir()

	// key -> hop (inside), hop -> outside/secret (escapes).
	err = os.Symlink(filepath.Join(outside, "secret"), filepath.Join(dir, "hop"))
	if err != nil {
		t.Fatalf("creating symlink: %v", err)
	}

	err = os.Symlink("hop", filepath.Join(dir, "key"))
	if err != nil {
		t.Fatalf("creating symlink: %v", err)
	}

	_, err = fileutil.ReadLimited(filepath.Join(dir, "key"), 1024)
	if !errors.Is(err, fileutil.ErrSymlink) {
		t.Errorf("expected ErrSymlink, got: %v", err)
	}
}

func TestStatContained(t *testing.T) {
	t.Parallel()

	outside := t.TempDir()

	err := os.WriteFile(filepath.Join(outside, "secret"), []byte("data"), 0o600)
	if err != nil {
		t.Fatalf("writing target: %v", err)
	}

	mount := t.TempDir()
	dataDir := filepath.Join(mount, "..2026_09_14")

	err = os.Mkdir(dataDir, 0o750)
	if err != nil {
		t.Fatalf("creating data dir: %v", err)
	}

	err = os.WriteFile(filepath.Join(dataDir, "key.pub"), []byte("key"), 0o600)
	if err != nil {
		t.Fatalf("writing key: %v", err)
	}

	for link, target := range map[string]string{
		dataLink:  "..2026_09_14",
		"key.pub": "..data/key.pub",
		"escape":  filepath.Join(outside, "secret"),
		"missing": "..data/missing",
		"subdir":  dataLink,
	} {
		err = os.Symlink(target, filepath.Join(mount, link))
		if err != nil {
			t.Fatalf("creating symlink %s: %v", link, err)
		}
	}

	info, err := fileutil.StatContained(filepath.Join(mount, "key.pub"))
	if err != nil {
		t.Fatalf("unexpected error for contained symlink: %v", err)
	}

	if !info.Mode().IsRegular() {
		t.Errorf("expected the regular target, got mode %v", info.Mode())
	}

	_, err = fileutil.StatContained(filepath.Join(mount, "escape"))
	if !errors.Is(err, fileutil.ErrSymlink) {
		t.Errorf("expected ErrSymlink for escaping symlink, got: %v", err)
	}

	_, err = fileutil.StatContained(filepath.Join(mount, "missing"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected ErrNotExist for dangling symlink, got: %v", err)
	}

	info, err = fileutil.StatContained(filepath.Join(mount, "subdir"))
	if err != nil {
		t.Fatalf("unexpected error for directory symlink: %v", err)
	}

	if info.Mode().IsRegular() {
		t.Error("expected a directory, got a regular file")
	}
}

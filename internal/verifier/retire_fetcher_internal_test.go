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

package verifier

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/bundle"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
)

const retireTestDigest = "sha256:" +
	"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func writeEmptyBundleStore(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()

	createdAt := time.Now().UTC().Format(time.RFC3339)
	files := map[string]string{
		"oci-layout":           `{"imageLayoutVersion":"1.0.0"}`,
		"index.json":           `{"schemaVersion":2,"manifests":[]}`,
		"bundle-manifest.json": `{"version":1,"createdAt":"` + createdAt + `","images":{}}`,
	}

	for name, content := range files {
		err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600)
		if err != nil {
			t.Fatal(err)
		}
	}

	err := os.MkdirAll(filepath.Join(dir, "blobs", "sha256"), 0o750)
	if err != nil {
		t.Fatal(err)
	}

	return dir
}

func fetchRetireTest(fetcher attestation.Fetcher) error {
	_, err := fetcher.Fetch(context.Background(), "registry.example.com/app:v1",
		&attestation.FetchOptions{Digest: retireTestDigest})
	if err != nil {
		return fmt.Errorf("fetching: %w", err)
	}

	return nil
}

// TestRetireSnapshotClosesReplacedBundleFetcher checks that a bundle fetcher
// replaced by a reload releases its store (and with it the pinned store
// directory) once the old snapshot is retired, while a fetcher kept by the
// next snapshot stays usable.
func TestRetireSnapshotClosesReplacedBundleFetcher(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Offline.Mode = config.OfflineModeOffline
	cfg.Offline.AttestationStore = writeEmptyBundleStore(t)
	cfg.VerificationTimeout.Duration = time.Millisecond

	oldFetcher, err := createBundleFetcher(cfg, nil)
	if err != nil {
		t.Fatalf("createBundleFetcher() error: %v", err)
	}

	newFetcher, err := createBundleFetcher(cfg, nil)
	if err != nil {
		t.Fatalf("createBundleFetcher() error: %v", err)
	}

	t.Cleanup(func() { _ = newFetcher.Close() })

	prev := &snapshot{config: cfg, fetcher: oldFetcher}
	next := &snapshot{config: cfg, fetcher: newFetcher}
	same := &snapshot{config: cfg, fetcher: newFetcher}

	retireSnapshot(prev, next)
	retireSnapshot(next, same)

	deadline := time.Now().Add(10 * time.Second)

	for !errors.Is(fetchRetireTest(oldFetcher), bundle.ErrFetcherClosed) {
		if time.Now().After(deadline) {
			t.Fatal("expected the replaced bundle fetcher to be closed")
		}

		time.Sleep(time.Millisecond)
	}

	// Give a wrongly scheduled close of the kept fetcher time to run.
	time.Sleep(20 * time.Millisecond)

	err = fetchRetireTest(newFetcher)
	if !errors.Is(err, bundle.ErrNoAttestationsForDigest) {
		t.Errorf("kept fetcher Fetch() error = %v, want %v", err, bundle.ErrNoAttestationsForDigest)
	}
}

// TestStopClosesBundleFetcher checks that stopping the verifier releases the
// bundle store held by the current fetcher.
func TestStopClosesBundleFetcher(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Offline.Mode = config.OfflineModeOffline
	cfg.Offline.AttestationStore = writeEmptyBundleStore(t)

	fetcher, err := createBundleFetcher(cfg, nil)
	if err != nil {
		t.Fatalf("createBundleFetcher() error: %v", err)
	}

	verif, err := New(t.Context(), config.DefaultConfig(), metrics.New(), nil)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	snap := *verif.state.Load()
	snap.fetcher = fetcher
	verif.state.Store(&snap)

	verif.Stop()

	err = fetchRetireTest(fetcher)
	if !errors.Is(err, bundle.ErrFetcherClosed) {
		t.Errorf("Fetch() after Stop error = %v, want %v", err, bundle.ErrFetcherClosed)
	}
}

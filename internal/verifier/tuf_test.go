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

//nolint:testpackage // testing unexported functions
package verifier

import (
	"context"
	"strings"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
)

func TestBuildTrustedRootFetchFuncNilWhenNoIssuers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		issuers []string
	}{
		{
			name:    "nil issuers",
			issuers: nil,
		},
		{
			name:    "empty issuers slice",
			issuers: []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cfg := config.DefaultConfig()
			cfg.Policy.Issuers = test.issuers

			fn := buildTrustedRootFetchFunc(cfg)
			if fn != nil {
				t.Errorf("expected nil fetch func when issuers=%v, got non-nil", test.issuers)
			}
		})
	}
}

func TestBuildTrustedRootFetchFuncNonNilWhenIssuersExist(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Policy.Issuers = []string{"https://accounts.google.com"}

	fn := buildTrustedRootFetchFunc(cfg)
	if fn == nil {
		t.Fatal("expected non-nil fetch func when issuers are configured")
	}
}

func TestBuildTrustedRootFetchFuncCanceledContext(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Policy.Issuers = []string{"https://accounts.google.com"}

	fn := buildTrustedRootFetchFunc(cfg)
	if fn == nil {
		t.Fatal("expected non-nil fetch func")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := fn(ctx)
	if err == nil {
		t.Fatal("expected error from canceled context")
	}

	const wantMsg = "context canceled before fetching trusted root"
	if !strings.Contains(err.Error(), wantMsg) {
		t.Errorf("expected error to contain %q, got: %v", wantMsg, err)
	}
}

func TestFetchTrustedRootSyncSingleRootWithMirror(t *testing.T) {
	t.Parallel()

	// A single effective root with a TUFMirror should dispatch to
	// fetchTrustedRootFromMirror. By providing a nonexistent TUFRoot
	// path, readTUFRootBytes fails before any network call, proving
	// the dispatch went to the mirror path.
	cfg := config.DefaultConfig()
	cfg.Sigstore.Roots = []config.SigstoreRootSource{
		{
			Name:      "test",
			TUFMirror: "https://mirror.example.com",
			TUFRoot:   "/nonexistent/tuf-root.json",
		},
	}

	_, err := fetchTrustedRootSync(cfg)
	if err == nil {
		t.Fatal("expected error from nonexistent TUF root file")
	}

	if !strings.Contains(err.Error(), "/nonexistent/tuf-root.json") {
		t.Errorf("expected error to reference the TUF root path, got: %v", err)
	}
}

func TestFetchTrustedRootSyncMultipleRoots(t *testing.T) {
	t.Parallel()

	// Multiple effective roots dispatch to fetchTrustedRootFromFirstRoot.
	// The first root with a TUFMirror is selected. A nonexistent TUFRoot
	// causes readTUFRootBytes to fail, proving the dispatch path.
	cfg := config.DefaultConfig()
	cfg.Sigstore.Roots = []config.SigstoreRootSource{
		{
			Name:      "first",
			TUFMirror: "https://first.example.com",
			TUFRoot:   "/nonexistent/first-root.json",
		},
		{
			Name:      "second",
			TUFMirror: "https://second.example.com",
			TUFRoot:   "/nonexistent/second-root.json",
		},
	}

	_, err := fetchTrustedRootSync(cfg)
	if err == nil {
		t.Fatal("expected error from nonexistent TUF root file")
	}

	// The error should reference the first root's path, not the second.
	if !strings.Contains(err.Error(), "/nonexistent/first-root.json") {
		t.Errorf("expected error to reference the first root path, got: %v", err)
	}
}

func TestFetchTrustedRootFromFirstRootSelectsFirstMirror(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		roots       []config.SigstoreRootSource
		wantErrPath string
	}{
		{
			name: "skips empty mirrors and selects first non-empty",
			roots: []config.SigstoreRootSource{
				{
					Name:      "no-mirror",
					TUFMirror: "",
					TUFRoot:   "",
				},
				{
					Name:      "has-mirror",
					TUFMirror: "https://mirror.example.com",
					TUFRoot:   "/nonexistent/root.json",
				},
				{
					Name:      "other-mirror",
					TUFMirror: "https://other.example.com",
					TUFRoot:   "/nonexistent/other.json",
				},
			},
			wantErrPath: "/nonexistent/root.json",
		},
		{
			name: "first root has mirror",
			roots: []config.SigstoreRootSource{
				{
					Name:      "first",
					TUFMirror: "https://first.example.com",
					TUFRoot:   "/nonexistent/first.json",
				},
				{
					Name:      "second",
					TUFMirror: "https://second.example.com",
					TUFRoot:   "/nonexistent/second.json",
				},
			},
			wantErrPath: "/nonexistent/first.json",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := fetchTrustedRootFromFirstRoot(test.roots)
			if err == nil {
				t.Fatal("expected error from nonexistent TUF root file")
			}

			if !strings.Contains(err.Error(), test.wantErrPath) {
				t.Errorf("expected error to reference %q, got: %v", test.wantErrPath, err)
			}
		})
	}
}

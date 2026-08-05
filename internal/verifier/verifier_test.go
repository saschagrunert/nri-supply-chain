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

package verifier_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/registry"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

const (
	testDigest = "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4" +
		"e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

	testTUFMirrorURL = "https://tuf.example.com"

	testRootNameGitHub = "github"

	testGitHubTUFMirror = "https://tuf-repo.github.com"

	testNsProduction = "production"

	testUnreachableOCIRef = "localhost:1/nonexistent:v1"
)

type delayFetcher struct {
	delay   time.Duration
	started chan struct{}
}

func (f *delayFetcher) Fetch(
	ctx context.Context, _ string, _ *attestation.FetchOptions,
) ([]attestation.VerifiedAttestation, error) {
	if f.started != nil {
		close(f.started)
	}

	select {
	case <-time.After(f.delay):
		return nil, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("fetch interrupted: %w", ctx.Err())
	}
}

func TestNewFetcher(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()

	fetcher, err := verifier.NewFetcher(context.Background(), cfg, nil)
	testutil.AssertNoError(t, err)

	if fetcher == nil {
		t.Fatal("expected non-nil OCIFetcher from NewFetcher")
	}
}

func TestNewFetcherEmptyTUFRoot(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	rootPath := filepath.Join(dir, "root.json")
	testutil.AssertNoError(t, os.WriteFile(rootPath, []byte{}, 0o600))

	cfg := config.DefaultConfig()
	cfg.Sigstore.TUFMirror = testTUFMirrorURL //nolint:staticcheck // backward compatibility
	cfg.Sigstore.TUFRoot = rootPath           //nolint:staticcheck // backward compatibility

	_, err := verifier.NewFetcher(context.Background(), cfg, nil)
	if err == nil {
		t.Fatal("expected error for empty TUF root file")
	}
}

func TestNewFetcherWithSharedCache(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Registries = []config.Registry{
		{
			Prefix:   "docker.io",
			Mirror:   "mirror.example.com",
			CACert:   "",
			Insecure: false,
		},
	}

	cache := registry.NewTransportCache(cfg.Registries)

	fetcher, err := verifier.NewFetcher(context.Background(), cfg, cache)
	testutil.AssertNoError(t, err)

	if fetcher == nil {
		t.Fatal("expected non-nil OCIFetcher from NewFetcher with shared cache")
	}
}

func TestVerify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		imageRef    string
		setupDir    func(t *testing.T) string
		mode        config.VerificationMode
		wantAllowed bool
		wantErr     error
	}{
		{
			name:     "disabled mode allows",
			imageRef: "",
			setupDir: func(_ *testing.T) string {
				return ""
			},
			mode:        config.ModeDisabled,
			wantAllowed: true,
			wantErr:     nil,
		},
		{
			name:     "warn mode allows with deny policy",
			imageRef: "",
			setupDir: func(t *testing.T) string {
				t.Helper()

				dir := t.TempDir()
				testutil.WritePolicy(t, dir, "default.json", `{
					"trust": {"builders": [{"id": "test", "maxLevel": 2}]},
					"slsa": {"missingPolicy": "deny"}
				}`)

				return dir
			},
			mode:        config.ModeWarn,
			wantAllowed: true,
			wantErr:     nil,
		},
		{
			name:     "enforce mode rejects with deny policy",
			imageRef: "",
			setupDir: func(t *testing.T) string {
				t.Helper()

				dir := t.TempDir()
				testutil.WritePolicy(t, dir, "default.json", `{
					"trust": {"builders": [{"id": "test", "maxLevel": 2}]},
					"slsa": {"missingPolicy": "deny"}
				}`)

				return dir
			},
			mode:        config.ModeEnforce,
			wantAllowed: false,
			wantErr:     verifier.ErrVerificationFailed,
		},
		{
			name:     "excluded image allowed",
			imageRef: "gcr.io/internal/app",
			setupDir: func(t *testing.T) string {
				t.Helper()

				dir := t.TempDir()
				testutil.WritePolicy(t, dir, "default.json", `{
					"exclude": ["gcr.io/internal/*"],
					"trust": {"builders": [{"id": "test", "maxLevel": 3}]},
					"slsa": {"missingPolicy": "deny"}
				}`)

				return dir
			},
			mode:        config.ModeEnforce,
			wantAllowed: true,
			wantErr:     nil,
		},
		{
			name:     "no builders configured allows",
			imageRef: "",
			setupDir: func(t *testing.T) string {
				t.Helper()

				dir := t.TempDir()
				testutil.WritePolicy(t, dir, "default.json", `{}`)

				return dir
			},
			mode:        config.ModeEnforce,
			wantAllowed: true,
			wantErr:     nil,
		},
		{
			name:     "allow policy allows",
			imageRef: "",
			setupDir: func(t *testing.T) string {
				t.Helper()

				dir := t.TempDir()
				testutil.WritePolicy(t, dir, "default.json", `{
					"trust": {"builders": [{"id": "test", "maxLevel": 3}]},
					"slsa": {"missingPolicy": "allow"}
				}`)

				return dir
			},
			mode:        config.ModeEnforce,
			wantAllowed: true,
			wantErr:     nil,
		},
		{
			name:     "warn policy allows with reason",
			imageRef: "",
			setupDir: func(t *testing.T) string {
				t.Helper()

				dir := t.TempDir()
				testutil.WritePolicy(t, dir, "default.json", `{
					"trust": {"builders": [{"id": "test", "maxLevel": 3}]},
					"slsa": {"missingPolicy": "warn"}
				}`)

				return dir
			},
			mode:        config.ModeEnforce,
			wantAllowed: true,
			wantErr:     nil,
		},
		{
			name:     "fallback empty policy denies in enforce",
			imageRef: "",
			setupDir: func(t *testing.T) string {
				t.Helper()

				return t.TempDir()
			},
			mode:        config.ModeEnforce,
			wantAllowed: false,
			wantErr:     verifier.ErrVerificationFailed,
		},
		{
			name:     "fallback empty policy allows in warn",
			imageRef: "",
			setupDir: func(t *testing.T) string {
				t.Helper()

				return t.TempDir()
			},
			mode:        config.ModeWarn,
			wantAllowed: true,
			wantErr:     nil,
		},
		{
			name:     "VEX deny policy rejects",
			imageRef: "",
			setupDir: func(t *testing.T) string {
				t.Helper()

				dir := t.TempDir()
				testutil.WritePolicy(t, dir, "default.json", `{
					"slsa": {"missingPolicy": "allow"},
					"vex": {"missingPolicy": "deny"}
				}`)

				return dir
			},
			mode:        config.ModeEnforce,
			wantAllowed: false,
			wantErr:     verifier.ErrVerificationFailed,
		},
		{
			name:     "disabled skips nonexistent policy dir",
			imageRef: "",
			setupDir: func(_ *testing.T) string {
				return "/nonexistent/path"
			},
			mode:        config.ModeDisabled,
			wantAllowed: true,
			wantErr:     nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			dir := test.setupDir(t)

			cfg := config.DefaultConfig()
			cfg.Verification = test.mode

			if dir != "" {
				cfg.PolicyDir = dir
			}

			imageRef := test.imageRef
			if imageRef == "" {
				imageRef = "nginx:latest"
			}

			verif, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
			testutil.AssertNoError(t, err)

			result, err := verif.Verify(
				context.Background(), imageRef, testDigest, "", "default", "",
			)

			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) {
					t.Errorf("expected error %v, got %v", test.wantErr, err)
				}

				return
			}

			testutil.AssertNoError(t, err)

			if result.Allowed != test.wantAllowed {
				t.Errorf("expected allowed=%v, got allowed=%v (reason: %s)",
					test.wantAllowed, result.Allowed, result.Reason)
			}
		})
	}
}

func TestVerifyCache(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir
	cfg.CacheTTL = config.Duration{Duration: time.Hour}

	verif, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)

	result1, err := verif.Verify(
		context.Background(), "nginx:latest", testDigest, "", "default", "",
	)
	testutil.AssertNoError(t, err)

	result2, err := verif.Verify(
		context.Background(), "nginx:latest", testDigest, "", "default", "",
	)
	testutil.AssertNoError(t, err)

	if result1.Reason != result2.Reason {
		t.Errorf("expected cached result to match: %q vs %q",
			result1.Reason, result2.Reason)
	}
}

func TestVerifyCacheWarnMode(t *testing.T) {
	t.Parallel()

	// Warn mode with deny policy: the underlying check fails (no provenance),
	// but warn mode overrides to Allowed=true. The cached result must also
	// be Allowed=true on subsequent lookups.
	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{
		"trust": {"builders": [{"id": "test", "maxLevel": 2}]},
		"slsa": {"missingPolicy": "deny"}
	}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir
	cfg.CacheTTL = config.Duration{Duration: time.Hour}

	verif, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)

	const cacheDigest = "sha256:11111111111111111111111111111111" +
		"11111111111111111111111111111111"

	result1, err := verif.Verify(
		context.Background(), "nginx:latest",
		cacheDigest, "", "default", "",
	)
	testutil.AssertNoError(t, err)

	if !result1.Allowed {
		t.Fatalf("first call: expected Allowed=true in warn mode, got false (reason: %s)",
			result1.Reason)
	}

	result2, err := verif.Verify(
		context.Background(), "nginx:latest",
		cacheDigest, "", "default", "",
	)
	testutil.AssertNoError(t, err)

	if !result2.Allowed {
		t.Fatalf(
			"second call (cache hit): expected Allowed=true in warn mode, got false (reason: %s)",
			result2.Reason,
		)
	}

	if result1.Reason != result2.Reason {
		t.Errorf("expected cached reason to match: %q vs %q",
			result1.Reason, result2.Reason)
	}
}

func TestVerifyCacheEnforceMode(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{
		"trust": {"builders": [{"id": "test", "maxLevel": 2}]},
		"slsa": {"missingPolicy": "deny"}
	}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.PolicyDir = dir
	cfg.CacheTTL = config.Duration{Duration: time.Hour}

	verif, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)

	const enforceDigest = "sha256:22222222222222222222222222222222" +
		"22222222222222222222222222222222"

	_, err = verif.Verify(
		context.Background(), "nginx:latest",
		enforceDigest, "", "default", "",
	)

	if !errors.Is(err, verifier.ErrVerificationFailed) {
		t.Fatalf("first call: expected ErrVerificationFailed, got %v", err)
	}

	_, err = verif.Verify(
		context.Background(), "nginx:latest",
		enforceDigest, "", "default", "",
	)

	if !errors.Is(err, verifier.ErrVerificationFailed) {
		t.Fatalf(
			"second call (cache hit): expected ErrVerificationFailed, got %v", err,
		)
	}
}

func TestVerifyNamespacePolicy(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{
		"trust": {"builders": [{"id": "test", "maxLevel": 3}]},
		"slsa": {"missingPolicy": "deny"}
	}`)
	testutil.WritePolicy(t, dir, "staging.json", `{
		"slsa": {"missingPolicy": "allow"}
	}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.PolicyDir = dir

	verif, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)

	_, err = verif.Verify(
		context.Background(), "nginx:latest", testDigest, "", "default", "",
	)
	if err == nil {
		t.Error("expected error for default namespace")
	}

	const stagingDigest = "sha256:b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4" +
		"e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3"

	result, err := verif.Verify(
		context.Background(), "nginx:latest",
		stagingDigest, "", "staging", "",
	)
	testutil.AssertNoError(t, err)

	if !result.Allowed {
		t.Error("expected allowed for staging namespace")
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		setup   func(t *testing.T) *config.Config
		wantErr bool
	}{
		{
			name: "invalid policy",
			setup: func(t *testing.T) *config.Config {
				t.Helper()

				dir := t.TempDir()
				testutil.WritePolicy(t, dir, "bad.json", `{invalid json}`)

				cfg := config.DefaultConfig()
				cfg.Verification = config.ModeWarn
				cfg.PolicyDir = dir

				return cfg
			},
			wantErr: true,
		},
		{
			name: "disabled skips policy load",
			setup: func(_ *testing.T) *config.Config {
				cfg := config.DefaultConfig()
				cfg.PolicyDir = "/nonexistent/path"

				return cfg
			},
			wantErr: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cfg := test.setup(t)
			_, err := verifier.New(t.Context(), cfg, metrics.New(), nil)

			if test.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestReload(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		newCfg  func(t *testing.T) *config.Config
		wantErr bool
	}{
		{
			name: "success",
			newCfg: func(t *testing.T) *config.Config {
				t.Helper()

				dir := t.TempDir()
				testutil.WritePolicy(t, dir, "default.json", `{}`)

				cfg := config.DefaultConfig()
				cfg.Verification = config.ModeEnforce
				cfg.PolicyDir = dir

				return cfg
			},
			wantErr: false,
		},
		{
			name: "invalid policy",
			newCfg: func(t *testing.T) *config.Config {
				t.Helper()

				dir := t.TempDir()
				testutil.WritePolicy(t, dir, "bad.json", `{invalid json}`)

				cfg := config.DefaultConfig()
				cfg.Verification = config.ModeEnforce
				cfg.PolicyDir = dir

				return cfg
			},
			wantErr: true,
		},
		{
			name: "reload to disabled",
			newCfg: func(_ *testing.T) *config.Config {
				return config.DefaultConfig()
			},
			wantErr: false,
		},
		{
			name: "creates new fetcher",
			newCfg: func(t *testing.T) *config.Config {
				t.Helper()

				dir := t.TempDir()
				testutil.WritePolicy(t, dir, "default.json", `{}`)

				cfg := config.DefaultConfig()
				cfg.Verification = config.ModeWarn
				cfg.PolicyDir = dir

				return cfg
			},
			wantErr: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			testutil.WritePolicy(t, dir, "default.json", `{}`)

			cfg := config.DefaultConfig()
			cfg.Verification = config.ModeWarn
			cfg.PolicyDir = dir

			verif, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
			testutil.AssertNoError(t, err)

			newCfg := test.newCfg(t)
			err = verif.Reload(t.Context(), newCfg)

			if test.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				return
			}

			testutil.AssertNoError(t, err)
		})
	}
}

func TestReloadPreservesCacheWhenConfigUnchanged(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir
	cfg.CacheTTL = config.Duration{Duration: time.Hour}

	verif, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)

	const reloadDigest = "sha256:33333333333333333333333333333333" +
		"33333333333333333333333333333333"

	result1, err := verif.Verify(
		context.Background(), "nginx:latest",
		reloadDigest, "", "default", "",
	)
	testutil.AssertNoError(t, err)

	reloadCfg := config.DefaultConfig()
	reloadCfg.Verification = config.ModeWarn
	reloadCfg.PolicyDir = dir
	reloadCfg.CacheTTL = config.Duration{Duration: time.Hour}

	err = verif.Reload(t.Context(), reloadCfg)
	testutil.AssertNoError(t, err)

	result2, err := verif.Verify(
		context.Background(), "nginx:latest", reloadDigest, "", "default", "",
	)
	testutil.AssertNoError(t, err)

	if result1.Reason != result2.Reason {
		t.Errorf("expected cached result to survive reload: %q vs %q",
			result1.Reason, result2.Reason)
	}
}

func TestReloadClearsCacheWhenCacheFailureTTLChanges(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir
	cfg.CacheTTL = config.Duration{Duration: time.Hour}
	cfg.CacheFailureTTL = config.Duration{Duration: 5 * time.Minute}

	// Verify that changing only CacheFailureTTL is detected.
	changed := config.DefaultConfig()
	changed.Verification = cfg.Verification
	changed.PolicyDir = cfg.PolicyDir
	changed.CacheTTL = cfg.CacheTTL
	changed.CacheFailureTTL = config.Duration{Duration: 10 * time.Minute}
	changed.FetchFailurePolicy = cfg.FetchFailurePolicy
	changed.FetchTimeout = cfg.FetchTimeout

	if !verifier.ExportCacheAffectingFieldsChanged(cfg, changed) {
		t.Error("expected cache invalidation when CacheFailureTTL changes")
	}

	// Confirm no invalidation when CacheFailureTTL is the same.
	same := config.DefaultConfig()
	same.Verification = cfg.Verification
	same.PolicyDir = cfg.PolicyDir
	same.CacheTTL = cfg.CacheTTL
	same.CacheFailureTTL = cfg.CacheFailureTTL
	same.FetchFailurePolicy = cfg.FetchFailurePolicy
	same.FetchTimeout = cfg.FetchTimeout

	if verifier.ExportCacheAffectingFieldsChanged(cfg, same) {
		t.Error("expected no cache invalidation when CacheFailureTTL is unchanged")
	}
}

func TestReloadClearsCacheWhenTUFMirrorChanges(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir
	cfg.CacheTTL = config.Duration{Duration: time.Hour}

	// Verify that changing Sigstore.TUFMirror triggers cache invalidation.
	changed := config.DefaultConfig()
	changed.Verification = cfg.Verification
	changed.PolicyDir = cfg.PolicyDir
	changed.CacheTTL = cfg.CacheTTL
	changed.CacheFailureTTL = cfg.CacheFailureTTL
	changed.FetchFailurePolicy = cfg.FetchFailurePolicy
	changed.FetchTimeout = cfg.FetchTimeout
	changed.Sigstore.TUFMirror = testTUFMirrorURL //nolint:staticcheck // backward compatibility

	if !verifier.ExportCacheAffectingFieldsChanged(cfg, changed) {
		t.Error("expected cache invalidation when Sigstore.TUFMirror changes")
	}

	// Confirm no invalidation when TUFMirror is the same.
	same := config.DefaultConfig()
	same.Verification = cfg.Verification
	same.PolicyDir = cfg.PolicyDir
	same.CacheTTL = cfg.CacheTTL
	same.CacheFailureTTL = cfg.CacheFailureTTL
	same.FetchFailurePolicy = cfg.FetchFailurePolicy
	same.FetchTimeout = cfg.FetchTimeout
	same.Sigstore.TUFMirror = cfg.Sigstore.TUFMirror //nolint:staticcheck // backward compatibility

	if verifier.ExportCacheAffectingFieldsChanged(cfg, same) {
		t.Error("expected no cache invalidation when Sigstore.TUFMirror is unchanged")
	}
}

func TestReloadClearsCacheWhenTUFRootChanges(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir
	cfg.CacheTTL = config.Duration{Duration: time.Hour}
	cfg.Sigstore.TUFMirror = testTUFMirrorURL //nolint:staticcheck // backward compatibility

	// Verify that changing Sigstore.TUFRoot triggers cache invalidation.
	changed := config.DefaultConfig()
	changed.Verification = cfg.Verification
	changed.PolicyDir = cfg.PolicyDir
	changed.CacheTTL = cfg.CacheTTL
	changed.CacheFailureTTL = cfg.CacheFailureTTL
	changed.FetchFailurePolicy = cfg.FetchFailurePolicy
	changed.FetchTimeout = cfg.FetchTimeout
	changed.Sigstore.TUFMirror = cfg.Sigstore.TUFMirror  //nolint:staticcheck // backward compatibility
	changed.Sigstore.TUFRoot = "/etc/sigstore/root.json" //nolint:staticcheck // backward compatibility

	if !verifier.ExportCacheAffectingFieldsChanged(cfg, changed) {
		t.Error("expected cache invalidation when Sigstore.TUFRoot changes")
	}

	// Confirm no invalidation when TUFRoot is the same.
	same := config.DefaultConfig()
	same.Verification = cfg.Verification
	same.PolicyDir = cfg.PolicyDir
	same.CacheTTL = cfg.CacheTTL
	same.CacheFailureTTL = cfg.CacheFailureTTL
	same.FetchFailurePolicy = cfg.FetchFailurePolicy
	same.FetchTimeout = cfg.FetchTimeout
	same.Sigstore.TUFMirror = cfg.Sigstore.TUFMirror //nolint:staticcheck // backward compatibility
	same.Sigstore.TUFRoot = cfg.Sigstore.TUFRoot     //nolint:staticcheck // backward compatibility

	if verifier.ExportCacheAffectingFieldsChanged(cfg, same) {
		t.Error("expected no cache invalidation when Sigstore.TUFRoot is unchanged")
	}
}

func TestReloadCreatesFetcherWhenTUFMirrorChanges(t *testing.T) {
	t.Parallel()

	var requestReceived atomic.Bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestReceived.Store(true)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir

	verif, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)

	newCfg := config.DefaultConfig()
	newCfg.Verification = config.ModeWarn
	newCfg.PolicyDir = dir
	newCfg.Sigstore.TUFMirror = server.URL //nolint:staticcheck // backward compatibility

	err = verif.Reload(context.Background(), newCfg)
	testutil.AssertNoError(t, err)

	if !requestReceived.Load() {
		t.Error("expected TUF mirror to be contacted after Reload with new TUF mirror config")
	}
}

func TestCacheAffectingFieldsChangedRegistries(t *testing.T) {
	t.Parallel()

	base := config.DefaultConfig()
	base.Verification = config.ModeWarn
	base.PolicyDir = t.TempDir()

	withRegistries := config.DefaultConfig()
	withRegistries.Verification = base.Verification
	withRegistries.PolicyDir = base.PolicyDir
	withRegistries.FetchTimeout = base.FetchTimeout
	withRegistries.CacheTTL = base.CacheTTL
	withRegistries.CacheFailureTTL = base.CacheFailureTTL
	withRegistries.FetchFailurePolicy = base.FetchFailurePolicy
	withRegistries.Registries = []config.Registry{
		{
			Prefix:   "ghcr.io",
			Mirror:   "mirror.internal",
			CACert:   "",
			Insecure: false,
		},
	}

	if !verifier.ExportCacheAffectingFieldsChanged(base, withRegistries) {
		t.Error("expected cache invalidation when registries are added")
	}

	if verifier.ExportCacheAffectingFieldsChanged(base, base) {
		t.Error("expected no cache invalidation when registries are unchanged")
	}

	modifiedMirror := config.DefaultConfig()
	modifiedMirror.Verification = base.Verification
	modifiedMirror.PolicyDir = base.PolicyDir
	modifiedMirror.FetchTimeout = base.FetchTimeout
	modifiedMirror.CacheTTL = base.CacheTTL
	modifiedMirror.CacheFailureTTL = base.CacheFailureTTL
	modifiedMirror.FetchFailurePolicy = base.FetchFailurePolicy
	modifiedMirror.Registries = []config.Registry{
		{
			Prefix:   "ghcr.io",
			Mirror:   "other-mirror.internal",
			CACert:   "",
			Insecure: false,
		},
	}

	if !verifier.ExportCacheAffectingFieldsChanged(withRegistries, modifiedMirror) {
		t.Error("expected cache invalidation when registry mirror changes")
	}

	if !verifier.ExportCacheAffectingFieldsChanged(withRegistries, base) {
		t.Error("expected cache invalidation when registries are removed")
	}
}

func TestReloadClearsCacheWhenPolicyChanges(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir
	cfg.CacheTTL = config.Duration{Duration: time.Hour}

	verif, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)

	const policyDigest = "sha256:44444444444444444444444444444444" +
		"44444444444444444444444444444444"

	result1, err := verif.Verify(
		context.Background(), "nginx:latest",
		policyDigest, "", "default", "",
	)
	testutil.AssertNoError(t, err)

	testutil.WritePolicy(t, dir, "default.json", `{"slsa":{"missingPolicy":"deny"}}`)

	reloadCfg := config.DefaultConfig()
	reloadCfg.Verification = config.ModeWarn
	reloadCfg.PolicyDir = dir
	reloadCfg.CacheTTL = config.Duration{Duration: time.Hour}

	err = verif.Reload(t.Context(), reloadCfg)
	testutil.AssertNoError(t, err)

	result2, err := verif.Verify(
		context.Background(), "nginx:latest",
		policyDigest, "", "default", "",
	)
	testutil.AssertNoError(t, err)

	if result1.Reason == result2.Reason {
		t.Error("expected cache to be cleared after policy change")
	}
}

func TestReady(t *testing.T) {
	t.Parallel()

	t.Run("disabled mode is ready", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()

		verif, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
		testutil.AssertNoError(t, err)

		ready, reason := verif.Ready()
		if !ready {
			t.Errorf("expected ready=true for disabled mode, got reason=%q", reason)
		}
	})

	t.Run("enabled with policies is ready", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		testutil.WritePolicy(t, dir, "default.json", `{}`)

		cfg := config.DefaultConfig()
		cfg.Verification = config.ModeWarn
		cfg.PolicyDir = dir

		verif, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
		testutil.AssertNoError(t, err)

		ready, reason := verif.Ready()
		if !ready {
			t.Errorf("expected ready=true, got reason=%q", reason)
		}
	})

	t.Run("enabled with no policies is not ready", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()

		cfg := config.DefaultConfig()
		cfg.Verification = config.ModeWarn
		cfg.PolicyDir = dir

		verif, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
		testutil.AssertNoError(t, err)

		ready, reason := verif.Ready()
		if ready {
			t.Error("expected ready=false when enabled with no policies")
		}

		if reason != "no policies loaded" {
			t.Errorf("expected reason %q, got %q", "no policies loaded", reason)
		}
	})
}

func TestResultHasFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		result   *types.Result
		expected bool
	}{
		{
			name: "allowed result has no failures",
			result: &types.Result{
				Allowed:      true,
				Reason:       "ok",
				CheckResults: nil,
			},
			expected: false,
		},
		{
			name: "disallowed result has failures",
			result: &types.Result{
				Allowed:      false,
				Reason:       "denied",
				CheckResults: nil,
			},
			expected: true,
		},
		{
			name: "allowed with failed check has failures",
			result: &types.Result{
				Allowed: true,
				Reason:  "partial",
				CheckResults: []types.CheckResult{{
					Type: types.CheckTypeSLSA, Passed: false,
					Status: types.StatusFail, Detail: "err", Err: nil,
					Metadata: nil,
				}},
			},
			expected: true,
		},
		{
			name: "allowed with passing checks has no failures",
			result: &types.Result{
				Allowed: true,
				Reason:  "ok",
				CheckResults: []types.CheckResult{{
					Type: types.CheckTypeSLSA, Passed: true,
					Status: types.StatusPass, Detail: "ok", Err: nil,
					Metadata: nil,
				}},
			},
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := verifier.ExportResultHasFailures(test.result)
			if got != test.expected {
				t.Errorf("expected %v, got %v", test.expected, got)
			}
		})
	}
}

func TestResultShouldUseShorterTTL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		result   *types.Result
		expected bool
	}{
		{
			name: "failed result uses shorter TTL",
			result: &types.Result{
				Allowed:      false,
				Reason:       "denied",
				CheckResults: nil,
			},
			expected: true,
		},
		{
			name: "fetch type with passing check uses shorter TTL",
			result: &types.Result{
				Allowed: true,
				Reason:  "ok",
				CheckResults: []types.CheckResult{{
					Type: types.CheckTypeFetch, Passed: true,
					Status: types.StatusWarn, Detail: "fetch failed", Err: nil,
					Metadata: nil,
				}},
			},
			expected: true,
		},
		{
			name: "non-fetch passing result does not use shorter TTL",
			result: &types.Result{
				Allowed: true,
				Reason:  "ok",
				CheckResults: []types.CheckResult{{
					Type: types.CheckTypeSLSA, Passed: true,
					Status: types.StatusPass, Detail: "ok", Err: nil,
					Metadata: nil,
				}},
			},
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := verifier.ExportResultShouldUseShorterTTL(test.result)
			if got != test.expected {
				t.Errorf("expected %v, got %v", test.expected, got)
			}
		})
	}
}

func TestWarnEnforceDefaultsDoesNotPanicForWarnMode(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn

	policies := map[string]*policy.Policy{
		"": {},
	}

	// Should not panic; no warnings emitted for non-enforce mode.
	verifier.WarnEnforceDefaults(cfg, policies)
}

func TestWarnEnforceDefaultsEmitsForEnforceMode(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce

	policies := map[string]*policy.Policy{
		"": {},
	}

	// Should not panic; warnings are emitted but we just verify it runs.
	verifier.WarnEnforceDefaults(cfg, policies)
}

func TestEnforcing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		mode     config.VerificationMode
		expected bool
	}{
		{name: "disabled", mode: config.ModeDisabled, expected: false},
		{name: "warn", mode: config.ModeWarn, expected: false},
		{name: "enforce", mode: config.ModeEnforce, expected: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cfg := config.DefaultConfig()
			cfg.Verification = test.mode

			verif, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
			testutil.AssertNoError(t, err)

			if got := verif.Enforcing(); got != test.expected {
				t.Errorf("expected %v, got %v", test.expected, got)
			}
		})
	}
}

func TestHandleMissingAttestationUnknownPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		pol        types.Action
		wantPassed bool
		wantStatus types.CheckStatus
	}{
		{
			name:       "allow policy passes",
			pol:        types.ActionAllow,
			wantPassed: true,
			wantStatus: types.StatusPass,
		},
		{
			name:       "warn policy passes with warn status",
			pol:        types.ActionWarn,
			wantPassed: true,
			wantStatus: types.StatusWarn,
		},
		{
			name:       "deny policy fails",
			pol:        types.ActionDeny,
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name:       "unknown policy defaults to deny",
			pol:        "invalid-value",
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name:       "empty policy defaults to deny",
			pol:        "",
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
		{
			name:       "random string defaults to deny",
			pol:        "something-unexpected",
			wantPassed: false,
			wantStatus: types.StatusFail,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			result := verifier.ExportHandleMissingAttestation(
				test.pol, types.CheckTypeSLSA, "test detail",
			)

			if result.Passed != test.wantPassed {
				t.Errorf("expected Passed=%v, got %v", test.wantPassed, result.Passed)
			}

			if result.Status != test.wantStatus {
				t.Errorf("expected Status=%q, got %q", test.wantStatus, result.Status)
			}

			if result.Type != types.CheckTypeSLSA {
				t.Errorf("expected Type=%q, got %q", types.CheckTypeSLSA, result.Type)
			}
		})
	}
}

func TestCombineResults(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		slsa        *types.CheckResult
		vex         *types.CheckResult
		wantAllowed bool
		wantReason  string
		wantChecks  int
	}{
		{
			name:        "both nil",
			slsa:        nil,
			vex:         nil,
			wantAllowed: true,
			wantReason:  "",
			wantChecks:  0,
		},
		{
			name:        "both pass",
			slsa:        types.PassResult(types.CheckTypeSLSA, "ok"),
			vex:         types.PassResult(types.CheckTypeVEX, "ok"),
			wantAllowed: true,
			wantReason:  "",
			wantChecks:  2,
		},
		{
			name:        "slsa fails",
			slsa:        types.FailResult(types.CheckTypeSLSA, "missing", nil),
			vex:         types.PassResult(types.CheckTypeVEX, "ok"),
			wantAllowed: false,
			wantReason:  "missing",
			wantChecks:  2,
		},
		{
			name:        "both fail",
			slsa:        types.FailResult(types.CheckTypeSLSA, "slsa bad", nil),
			vex:         types.FailResult(types.CheckTypeVEX, "vex bad", nil),
			wantAllowed: false,
			wantReason:  "slsa bad; vex bad",
			wantChecks:  2,
		},
		{
			name:        "slsa warn",
			slsa:        types.WarnResult(types.CheckTypeSLSA, "slsa warning"),
			vex:         types.PassResult(types.CheckTypeVEX, "ok"),
			wantAllowed: true,
			wantReason:  "slsa warning",
			wantChecks:  2,
		},
		{
			name:        "only slsa",
			slsa:        types.PassResult(types.CheckTypeSLSA, "ok"),
			vex:         nil,
			wantAllowed: true,
			wantReason:  "",
			wantChecks:  1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			result := verifier.ExportCombineResults(test.slsa, test.vex)
			if result.Allowed != test.wantAllowed {
				t.Errorf("expected Allowed=%v, got %v", test.wantAllowed, result.Allowed)
			}

			if result.Reason != test.wantReason {
				t.Errorf("expected Reason=%q, got %q", test.wantReason, result.Reason)
			}

			if len(result.CheckResults) != test.wantChecks {
				t.Errorf("expected %d checks, got %d", test.wantChecks, len(result.CheckResults))
			}
		})
	}
}

func TestApplyCheckResult(t *testing.T) {
	t.Parallel()

	const testCheckType types.CheckType = "test"

	t.Run("fail sets allowed false and appends reason", func(t *testing.T) {
		t.Parallel()

		result := &types.Result{Allowed: true, Reason: "existing", CheckResults: nil}
		check := types.FailResult(testCheckType, "new failure", nil)
		verifier.ExportApplyCheckResult(result, check)

		if result.Allowed {
			t.Error("expected Allowed=false")
		}

		if result.Reason != "existing; new failure" {
			t.Errorf("expected concatenated reason, got %q", result.Reason)
		}
	})

	t.Run("warn appends reason without setting allowed false", func(t *testing.T) {
		t.Parallel()

		result := &types.Result{Allowed: true, Reason: "", CheckResults: nil}
		check := types.WarnResult(testCheckType, "warning detail")
		verifier.ExportApplyCheckResult(result, check)

		if !result.Allowed {
			t.Error("expected Allowed=true")
		}

		if result.Reason != "warning detail" {
			t.Errorf("expected warning reason, got %q", result.Reason)
		}
	})

	t.Run("pass leaves result unchanged", func(t *testing.T) {
		t.Parallel()

		result := &types.Result{Allowed: true, Reason: "", CheckResults: nil}
		check := types.PassResult(testCheckType, "ok")
		verifier.ExportApplyCheckResult(result, check)

		if !result.Allowed {
			t.Error("expected Allowed=true")
		}

		if result.Reason != "" {
			t.Errorf("expected empty reason, got %q", result.Reason)
		}
	})
}

func TestNewValidateRuntimeError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{
		"trust": {
			"verifiers": [{"id": "v1", "keys": ["/nonexistent/key.pub"]}]
		}
	}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir

	_, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
	if err == nil {
		t.Fatal("expected error for nonexistent verifier key file")
	}
}

func TestNewValidateEnforceError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{
		"trust": {
			"issuers": ["https://example.com"],
			"builders": [{"id": "test", "maxLevel": 1}]
		}
	}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.PolicyDir = dir

	_, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
	if !errors.Is(err, policy.ErrSANPatternsRequired) {
		t.Fatalf("expected ErrSANPatternsRequired, got %v", err)
	}
}

func TestVerifyExcludeDoubleStarPattern(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{
		"exclude": ["registry.k8s.io/**"],
		"trust": {"builders": [{"id": "test", "maxLevel": 3}]},
		"slsa": {"missingPolicy": "deny"}
	}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.PolicyDir = dir

	verif, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)

	result, err := verif.Verify(
		context.Background(),
		"registry.k8s.io/coredns/coredns:v1.12.0",
		testDigest, "", "default", "",
	)
	testutil.AssertNoError(t, err)

	if !result.Allowed {
		t.Errorf("expected ** exclude to match nested path, got denied: %s",
			result.Reason)
	}
}

func TestVerifyWarnModeAllowsOnContextCancel(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{
		"trust": {"builders": [{"id": "test", "maxLevel": 2}]},
		"slsa": {"missingPolicy": "deny"}
	}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir
	cfg.CacheTTL = config.Duration{Duration: 0}

	verif, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := verif.Verify(ctx, "nginx:latest", testDigest, "", "default", "")
	testutil.AssertNoError(t, err)

	if !result.Allowed {
		t.Errorf("expected allowed=true in warn mode on context cancel, got: %s", result.Reason)
	}
}

func TestVerifyEnforceModeRejectsOnContextCancel(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{
		"trust": {"builders": [{"id": "test", "maxLevel": 2}]},
		"slsa": {"missingPolicy": "deny"}
	}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.PolicyDir = dir
	cfg.CacheTTL = config.Duration{Duration: 0}

	verif, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = verif.Verify(ctx, "nginx:latest", testDigest, "", "default", "")
	if err == nil {
		t.Error("expected error in enforce mode on context cancel")
	}
}

func TestVerifyIncludeAllowsMatchingImage(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{
		"include": ["docker.io/myorg/**"],
		"trust": {"builders": [{"id": "test", "maxLevel": 3}]},
		"slsa": {"missingPolicy": "allow"}
	}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.PolicyDir = dir

	verif, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)

	result, err := verif.Verify(
		context.Background(),
		"docker.io/myorg/app:latest",
		testDigest, "", "default", "",
	)
	testutil.AssertNoError(t, err)

	if !result.Allowed {
		t.Errorf("expected included image to be verified and allowed, got denied: %s",
			result.Reason)
	}
}

func TestVerifyIncludeSkipsNonMatchingImage(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{
		"include": ["docker.io/myorg/**"],
		"trust": {"builders": [{"id": "test", "maxLevel": 3}]},
		"slsa": {"missingPolicy": "deny"}
	}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.PolicyDir = dir

	verif, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)

	result, err := verif.Verify(
		context.Background(),
		"gcr.io/other/app:latest",
		testDigest, "", "default", "",
	)
	testutil.AssertNoError(t, err)

	if !result.Allowed {
		t.Error("expected non-included image to be allowed (skipped)")
	}
}

func TestVerifyEmptyIncludeVerifiesEverything(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{
		"trust": {"builders": [{"id": "test", "maxLevel": 3}]},
		"slsa": {"missingPolicy": "deny"}
	}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.PolicyDir = dir

	verif, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)

	_, err = verif.Verify(
		context.Background(),
		"nginx:latest",
		testDigest, "", "default", "",
	)

	if !errors.Is(err, verifier.ErrVerificationFailed) {
		t.Errorf("expected verification to run (and fail due to deny policy), got %v", err)
	}
}

func TestVerifyExcludeTakesPrecedenceOverInclude(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{
		"include": ["docker.io/myorg/**"],
		"exclude": ["docker.io/myorg/internal/*"],
		"trust": {"builders": [{"id": "test", "maxLevel": 3}]},
		"slsa": {"missingPolicy": "deny"}
	}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.PolicyDir = dir

	verif, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)

	result, err := verif.Verify(
		context.Background(),
		"docker.io/myorg/internal/tool",
		testDigest, "", "default", "",
	)
	testutil.AssertNoError(t, err)

	if !result.Allowed {
		t.Errorf(
			"expected excluded image to be allowed even though it matches include, got denied: %s",
			result.Reason,
		)
	}
}

func TestVerifyPerNamespaceEnforceMode(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{
		"trust": {"builders": [{"id": "test", "maxLevel": 2}]},
		"slsa": {"missingPolicy": "deny"}
	}`)
	testutil.WritePolicy(t, dir, "production.json", `{
		"mode": "enforce",
		"trust": {"builders": [{"id": "test", "maxLevel": 2}]},
		"slsa": {"missingPolicy": "deny"}
	}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir

	verif, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)

	// Default namespace uses global warn mode, so verification failure is allowed.
	result, err := verif.Verify(
		context.Background(), "nginx:latest", testDigest, "", "default", "",
	)
	testutil.AssertNoError(t, err)

	if !result.Allowed {
		t.Errorf("expected default namespace to allow in warn mode, got denied: %s",
			result.Reason)
	}

	const prodDigest = "sha256:55555555555555555555555555555555" +
		"55555555555555555555555555555555"

	// Production namespace uses per-namespace enforce mode, so verification failure is rejected.
	_, err = verif.Verify(
		context.Background(), "nginx:latest", prodDigest, "", testNsProduction, "",
	)

	if !errors.Is(err, verifier.ErrVerificationFailed) {
		t.Fatalf("expected ErrVerificationFailed for production namespace, got %v", err)
	}
}

func TestVerifyPerNamespaceWarnModeAllows(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{
		"trust": {"builders": [{"id": "test", "maxLevel": 2}]},
		"slsa": {"missingPolicy": "deny"}
	}`)
	testutil.WritePolicy(t, dir, "staging.json", `{
		"mode": "warn",
		"trust": {"builders": [{"id": "test", "maxLevel": 2}]},
		"slsa": {"missingPolicy": "deny"}
	}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir

	verif, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)

	const stagingDigest = "sha256:66666666666666666666666666666666" +
		"66666666666666666666666666666666"

	result, err := verif.Verify(
		context.Background(), "nginx:latest", stagingDigest, "", "staging", "",
	)
	testutil.AssertNoError(t, err)

	if !result.Allowed {
		t.Errorf("expected staging namespace to allow in warn mode, got denied: %s",
			result.Reason)
	}
}

func TestNewRejectsLessStrictNamespaceMode(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{}`)
	testutil.WritePolicy(t, dir, "staging.json", `{
		"mode": "warn"
	}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.PolicyDir = dir

	_, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
	if !errors.Is(err, policy.ErrModeNotStricter) {
		t.Fatalf("expected ErrModeNotStricter, got %v", err)
	}
}

func TestNewAcceptsStricterNamespaceMode(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{}`)
	testutil.WritePolicy(t, dir, "production.json", `{
		"mode": "enforce"
	}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir

	verif, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)

	if verif == nil {
		t.Fatal("expected non-nil verifier")
	}
}

func TestEffectiveModeForNamespace(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{}`)
	testutil.WritePolicy(t, dir, "production.json", `{
		"mode": "enforce"
	}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir

	verif, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)

	mode := verif.EffectiveModeForNamespace("default")
	if mode != config.ModeWarn {
		t.Errorf("expected default namespace mode %q, got %q", config.ModeWarn, mode)
	}

	mode = verif.EffectiveModeForNamespace(testNsProduction)
	if mode != config.ModeEnforce {
		t.Errorf("expected production namespace mode %q, got %q", config.ModeEnforce, mode)
	}

	mode = verif.EffectiveModeForNamespace("unknown")
	if mode != config.ModeWarn {
		t.Errorf("expected unknown namespace to use global mode %q, got %q",
			config.ModeWarn, mode)
	}
}

func TestWarnEnforceDefaultsPerNamespaceMode(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn

	policies := map[string]*policy.Policy{
		"":               {},
		testNsProduction: {Mode: config.ModeEnforce},
	}

	// Should not panic; warnings for production enforce mode should be emitted.
	verifier.WarnEnforceDefaults(cfg, policies)
}

func TestVerifyPerNamespaceEnforceCacheHit(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{
		"trust": {"builders": [{"id": "test", "maxLevel": 2}]},
		"slsa": {"missingPolicy": "deny"}
	}`)
	testutil.WritePolicy(t, dir, "production.json", `{
		"mode": "enforce",
		"trust": {"builders": [{"id": "test", "maxLevel": 2}]},
		"slsa": {"missingPolicy": "deny"}
	}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir
	cfg.CacheTTL = config.Duration{Duration: time.Hour}

	verif, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)

	const cacheDigest = "sha256:77777777777777777777777777777777" +
		"77777777777777777777777777777777"

	// First call: enforce mode rejects.
	_, err = verif.Verify(
		context.Background(), "nginx:latest", cacheDigest, "", testNsProduction, "",
	)
	if !errors.Is(err, verifier.ErrVerificationFailed) {
		t.Fatalf("first call: expected ErrVerificationFailed, got %v", err)
	}

	// Second call (cache hit): enforce mode still rejects.
	_, err = verif.Verify(
		context.Background(), "nginx:latest", cacheDigest, "", testNsProduction, "",
	)
	if !errors.Is(err, verifier.ErrVerificationFailed) {
		t.Fatalf("second call (cache hit): expected ErrVerificationFailed, got %v", err)
	}
}

func TestNewValidateEnforcePerNamespaceMode(t *testing.T) {
	t.Parallel()

	// Per-namespace enforce mode should trigger ValidateEnforce checks even
	// when the global mode is warn.
	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{}`)
	testutil.WritePolicy(t, dir, "production.json", `{
		"mode": "enforce",
		"trust": {
			"issuers": ["https://example.com"],
			"builders": [{"id": "test", "maxLevel": 1}]
		}
	}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir

	_, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
	if !errors.Is(err, policy.ErrSANPatternsRequired) {
		t.Fatalf("expected ErrSANPatternsRequired for per-namespace enforce, got %v", err)
	}
}

func TestReloadRejectsLessStrictNamespaceMode(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir

	verif, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)

	// Reload with a config where global is enforce but a namespace is warn.
	reloadDir := t.TempDir()
	testutil.WritePolicy(t, reloadDir, "default.json", `{}`)
	testutil.WritePolicy(t, reloadDir, "staging.json", `{
		"mode": "warn"
	}`)

	reloadCfg := config.DefaultConfig()
	reloadCfg.Verification = config.ModeEnforce
	reloadCfg.PolicyDir = reloadDir

	err = verif.Reload(t.Context(), reloadCfg)
	if !errors.Is(err, policy.ErrModeNotStricter) {
		t.Fatalf("expected ErrModeNotStricter on reload, got %v", err)
	}
}

func TestVerifyIncludeDoubleStarPattern(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{
		"include": ["docker.io/myorg/**"],
		"trust": {"builders": [{"id": "test", "maxLevel": 3}]},
		"slsa": {"missingPolicy": "allow"}
	}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.PolicyDir = dir

	verif, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)

	result, err := verif.Verify(
		context.Background(),
		"docker.io/myorg/team/app:v1",
		testDigest, "", "default", "",
	)
	testutil.AssertNoError(t, err)

	if !result.Allowed {
		t.Errorf("expected ** include to match nested path, got denied: %s",
			result.Reason)
	}
}

func TestVerifyDetachedVerificationPopulatesCache(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{
		"trust": {"builders": [{"id": "test", "maxLevel": 2}]},
		"slsa": {"missingPolicy": "allow"}
	}`)

	met := metrics.New()

	fetcher := &delayFetcher{
		delay:   500 * time.Millisecond,
		started: make(chan struct{}),
	}

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir
	cfg.CacheTTL = config.Duration{Duration: time.Hour}

	verif, err := verifier.New(t.Context(), cfg, met, fetcher)
	testutil.AssertNoError(t, err)

	defer verif.Stop()

	const detachedDigest = "sha256:88888888888888888888888888888888" +
		"88888888888888888888888888888888"

	// Use a short timeout so the caller's context expires before the
	// fetcher completes, simulating the NRI ttrpc timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	result, err := verif.Verify(ctx, "nginx:latest", detachedDigest, "", "default", "")
	testutil.AssertNoError(t, err)

	if !result.Allowed {
		t.Fatalf("expected allowed=true in warn mode on timeout, got: %s", result.Reason)
	}

	if promtestutil.ToFloat64(met.VerificationInterruptedTotal) < 1 {
		t.Fatal("expected VerificationInterruptedTotal >= 1")
	}

	// Ensure the singleflight goroutine has started (and called
	// inflightWg.Add) before waiting, otherwise Wait returns
	// immediately on slow CI.
	<-fetcher.started
	verif.ExportWaitInflight()

	// A second call with a fresh context should hit the cache.
	hitsBefore := promtestutil.ToFloat64(met.CacheHitsTotal)

	result2, err := verif.Verify(
		context.Background(), "nginx:latest", detachedDigest, "", "default", "",
	)
	testutil.AssertNoError(t, err)

	if !result2.Allowed {
		t.Fatalf("expected cached result to be allowed, got: %s", result2.Reason)
	}

	if promtestutil.ToFloat64(met.CacheHitsTotal) <= hitsBefore {
		t.Error("expected cache hit after detached verification completed")
	}
}

func TestVerifyDetachedVerificationEnforceRetryHitsCache(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{
		"trust": {"builders": [{"id": "test", "maxLevel": 2}]},
		"slsa": {"missingPolicy": "allow"}
	}`)

	met := metrics.New()

	fetcher := &delayFetcher{
		delay:   500 * time.Millisecond,
		started: make(chan struct{}),
	}

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.PolicyDir = dir
	cfg.CacheTTL = config.Duration{Duration: time.Hour}

	verif, err := verifier.New(t.Context(), cfg, met, fetcher)
	testutil.AssertNoError(t, err)

	defer verif.Stop()

	const enforceDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err = verif.Verify(ctx, "nginx:latest", enforceDigest, "", "default", "")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got: %v", err)
	}

	if promtestutil.ToFloat64(met.VerificationInterruptedTotal) < 1 {
		t.Fatal("expected VerificationInterruptedTotal >= 1")
	}

	// Ensure the singleflight goroutine has started (and called
	// inflightWg.Add) before waiting, otherwise Wait returns
	// immediately on slow CI.
	<-fetcher.started
	verif.ExportWaitInflight()

	// Retry with a fresh context should hit the cache and succeed.
	hitsBefore := promtestutil.ToFloat64(met.CacheHitsTotal)

	result, err := verif.Verify(
		context.Background(), "nginx:latest", enforceDigest, "", "default", "",
	)
	testutil.AssertNoError(t, err)

	if !result.Allowed {
		t.Errorf("expected retry to succeed from cache, got: %s", result.Reason)
	}

	if promtestutil.ToFloat64(met.CacheHitsTotal) <= hitsBefore {
		t.Error("expected cache hit on retry after detached verification completed")
	}
}

func TestVerifyImageRuleMatchOverrides(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{
		"trust": {"builders": [{"id": "test", "maxLevel": 3}]},
		"slsa": {"missingPolicy": "deny"},
		"rules": [
			{
				"images": ["docker.io/trusted/**"],
				"slsa": {"missingPolicy": "allow"}
			}
		]
	}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.PolicyDir = dir

	verif, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)

	// Image matching the rule gets allow policy (so missing SLSA is fine).
	result, err := verif.Verify(
		context.Background(),
		"docker.io/trusted/app:latest",
		testDigest, "", "default", "",
	)
	testutil.AssertNoError(t, err)

	if !result.Allowed {
		t.Errorf("expected rule-matched image to be allowed, got denied: %s",
			result.Reason)
	}
}

func TestVerifyImageRuleNoMatchUsesBase(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{
		"trust": {"builders": [{"id": "test", "maxLevel": 3}]},
		"slsa": {"missingPolicy": "deny"},
		"rules": [
			{
				"images": ["docker.io/trusted/**"],
				"slsa": {"missingPolicy": "allow"}
			}
		]
	}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.PolicyDir = dir

	verif, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)

	// Image not matching any rule uses base policy (deny).
	_, err = verif.Verify(
		context.Background(),
		"docker.io/other/app:latest",
		testDigest, "", "default", "",
	)

	if !errors.Is(err, verifier.ErrVerificationFailed) {
		t.Fatalf("expected ErrVerificationFailed for non-matching image, got %v", err)
	}
}

func TestVerifyImageRuleFirstMatchWins(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{
		"trust": {"builders": [{"id": "test", "maxLevel": 3}]},
		"slsa": {"missingPolicy": "deny"},
		"rules": [
			{
				"images": ["docker.io/myorg/**"],
				"slsa": {"missingPolicy": "allow"}
			},
			{
				"images": ["docker.io/**"],
				"slsa": {"missingPolicy": "deny"}
			}
		]
	}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.PolicyDir = dir

	verif, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)

	// Image matches both rules; first rule (allow) should win.
	result, err := verif.Verify(
		context.Background(),
		"docker.io/myorg/app:latest",
		testDigest, "", "default", "",
	)
	testutil.AssertNoError(t, err)

	if !result.Allowed {
		t.Errorf("expected first matching rule to win (allow), got denied: %s",
			result.Reason)
	}
}

func TestResolveImagePolicyNoRules(t *testing.T) {
	t.Parallel()

	pol := &policy.Policy{
		Sections: policy.Sections{
			SLSA: &policy.SLSAPolicy{MissingPolicy: types.ActionDeny},
		},
	}

	resolved, ruleIdx := verifier.ExportResolveImagePolicy(
		context.Background(), pol, "ghcr.io/myorg/app:latest",
	)

	if ruleIdx != -1 {
		t.Errorf("expected ruleIdx -1 for no rules, got %d", ruleIdx)
	}

	if resolved != pol {
		t.Error("expected same policy returned when no rules")
	}
}

func TestResolveImagePolicyRuleMatch(t *testing.T) {
	t.Parallel()

	pol := &policy.Policy{
		Sections: policy.Sections{
			SLSA: &policy.SLSAPolicy{MissingPolicy: types.ActionDeny},
		},
		Rules: []policy.ImageRule{
			{
				Images: []string{"ghcr.io/myorg/**"},
				Sections: policy.Sections{
					SLSA: &policy.SLSAPolicy{MissingPolicy: types.ActionAllow},
				},
			},
		},
	}

	resolved, ruleIdx := verifier.ExportResolveImagePolicy(
		context.Background(), pol, "ghcr.io/myorg/app:latest",
	)

	if ruleIdx != 0 {
		t.Errorf("expected ruleIdx 0, got %d", ruleIdx)
	}

	if resolved.SLSAMissingPolicy() != types.ActionAllow {
		t.Errorf("expected rule SLSA allow, got %v", resolved.SLSAMissingPolicy())
	}

	if resolved.Rules != nil {
		t.Error("expected resolved policy to have nil Rules")
	}
}

func TestResolveImagePolicyNoMatch(t *testing.T) {
	t.Parallel()

	pol := &policy.Policy{
		Sections: policy.Sections{
			SLSA: &policy.SLSAPolicy{MissingPolicy: types.ActionDeny},
		},
		Rules: []policy.ImageRule{
			{
				Images: []string{"ghcr.io/specific/**"},
				Sections: policy.Sections{
					SLSA: &policy.SLSAPolicy{MissingPolicy: types.ActionAllow},
				},
			},
		},
	}

	resolved, ruleIdx := verifier.ExportResolveImagePolicy(
		context.Background(), pol, "docker.io/other/app:latest",
	)

	if ruleIdx != -1 {
		t.Errorf("expected ruleIdx -1 for no match, got %d", ruleIdx)
	}

	if resolved.SLSAMissingPolicy() != types.ActionDeny {
		t.Errorf("expected base SLSA deny, got %v", resolved.SLSAMissingPolicy())
	}
}

func TestCacheNamespaceKey(t *testing.T) {
	t.Parallel()

	t.Run("no rule returns namespace", func(t *testing.T) {
		t.Parallel()

		key := verifier.ExportCacheNamespaceKey("default", -1)
		if key != "default" {
			t.Errorf("expected %q, got %q", "default", key)
		}
	})

	t.Run("with rule includes index", func(t *testing.T) {
		t.Parallel()

		key := verifier.ExportCacheNamespaceKey("default", 0)
		if key == "default" {
			t.Error("expected cache key to differ from plain namespace when rule matched")
		}
	})

	t.Run("different rules produce different keys", func(t *testing.T) {
		t.Parallel()

		key0 := verifier.ExportCacheNamespaceKey("default", 0)
		key1 := verifier.ExportCacheNamespaceKey("default", 1)

		if key0 == key1 {
			t.Error("expected different cache keys for different rule indices")
		}
	})
}

func TestOnPolicyUpdateAppliesNewPolicies(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{
		"trust": {"builders": [{"id": "test", "maxLevel": 2}]},
		"slsa": {"missingPolicy": "deny"}
	}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir

	met := metrics.New()

	verif, err := verifier.New(t.Context(), cfg, met, nil)
	testutil.AssertNoError(t, err)

	const updateDigest = "sha256:cccccccccccccccccccccccccccccccc" +
		"cccccccccccccccccccccccccccccccc"

	// Before update: deny policy produces a failure reason.
	result1, err := verif.Verify(
		context.Background(), "nginx:latest", updateDigest, "", "default", "",
	)
	testutil.AssertNoError(t, err)

	if result1.Reason == "" {
		t.Fatal("expected non-empty reason with deny policy before update")
	}

	// Simulate an OCI policy update that switches to allow.
	updatedPolicies := map[string]*policy.Policy{
		"": {
			Sections: policy.Sections{
				SLSA: &policy.SLSAPolicy{MissingPolicy: "allow"},
			},
		},
	}
	err = verif.ExportOnPolicyUpdate(updatedPolicies)
	testutil.AssertNoError(t, err)

	// After update: allow policy produces no failure reason.
	const postUpdateDigest = "sha256:dddddddddddddddddddddddddddddd" +
		"dddddddddddddddddddddddddddddd"

	result2, err := verif.Verify(
		context.Background(), "nginx:latest", postUpdateDigest, "", "default", "",
	)
	testutil.AssertNoError(t, err)

	if !result2.Allowed {
		t.Errorf("expected allowed after policy update, got denied: %s", result2.Reason)
	}
}

func TestVerifyImageRuleInheritance(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{
		"trust": {"builders": [{"id": "test", "maxLevel": 3}]},
		"slsa": {"missingPolicy": "deny"},
		"rules": [
			{
				"images": ["docker.io/trusted/**"],
				"slsa": {"missingPolicy": "allow"}
			}
		]
	}`)
	testutil.WritePolicy(t, dir, "staging.json", `{
		"inherits": true
	}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.PolicyDir = dir

	verif, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)

	// Staging namespace inherits rules from default.
	result, err := verif.Verify(
		context.Background(),
		"docker.io/trusted/app:latest",
		testDigest, "", "staging", "",
	)
	testutil.AssertNoError(t, err)

	if !result.Allowed {
		t.Errorf("expected inherited rule to allow image, got denied: %s",
			result.Reason)
	}
}

func TestConcurrentVerifyAndReload(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{
		"slsa": {"missingPolicy": "allow"},
		"vex": {"missingPolicy": "allow"}
	}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir
	cfg.CacheTTL = config.Duration{Duration: time.Second}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	verif, err := verifier.New(ctx, cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)

	defer verif.Stop()

	const numVerifiers = 10

	var wg sync.WaitGroup

	for i := range numVerifiers {
		wg.Go(func() {
			digest := fmt.Sprintf("sha256:%064x", i)

			for ctx.Err() == nil {
				_, _ = verif.Verify(ctx, "nginx:latest", digest, "", "default", "")
			}
		})
	}

	wg.Go(func() {
		for ctx.Err() == nil {
			reloadCfg := config.DefaultConfig()
			reloadCfg.Verification = config.ModeWarn
			reloadCfg.PolicyDir = dir
			reloadCfg.CacheTTL = config.Duration{Duration: time.Second}

			_ = verif.Reload(ctx, reloadCfg)
		}
	})

	wg.Wait()
}

func TestResolveNodeName(t *testing.T) {
	t.Run("returns NODE_NAME env var when set", func(t *testing.T) {
		t.Setenv("NODE_NAME", "test-node-42")

		got := verifier.ExportResolveNodeName()
		if got != "test-node-42" {
			t.Errorf("expected %q, got %q", "test-node-42", got)
		}
	})

	t.Run("falls back to hostname when NODE_NAME is unset", func(t *testing.T) {
		t.Setenv("NODE_NAME", "")

		got := verifier.ExportResolveNodeName()

		hostname, err := os.Hostname()
		testutil.AssertNoError(t, err)

		if got != hostname {
			t.Errorf("expected hostname %q, got %q", hostname, got)
		}
	})
}

func TestPolicyHashForNamespace(t *testing.T) {
	t.Parallel()

	const (
		defaultHash = "default-hash"
		prodHash    = "prod-hash"
	)

	t.Run("returns namespace-specific hash when present", func(t *testing.T) {
		t.Parallel()

		hashes := map[string]string{
			"":               defaultHash,
			testNsProduction: prodHash,
		}

		got := verifier.ExportPolicyHashForNamespace(hashes, testNsProduction)
		if got != prodHash {
			t.Errorf("expected %q, got %q", prodHash, got)
		}
	})

	t.Run("falls back to default hash", func(t *testing.T) {
		t.Parallel()

		hashes := map[string]string{
			"": defaultHash,
		}

		got := verifier.ExportPolicyHashForNamespace(hashes, "staging")
		if got != defaultHash {
			t.Errorf("expected %q, got %q", defaultHash, got)
		}
	})

	t.Run("returns empty string when no keys exist", func(t *testing.T) {
		t.Parallel()

		hashes := map[string]string{}

		got := verifier.ExportPolicyHashForNamespace(hashes, "any")
		if got != "" {
			t.Errorf("expected empty string, got %q", got)
		}
	})
}

func TestCreateFetcherWithRoots(t *testing.T) {
	t.Parallel()

	t.Run("sigstore roots creates multi-root fetcher", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Sigstore.Roots = []config.SigstoreRootSource{
			{Name: testRootNameGitHub, TUFMirror: testGitHubTUFMirror, TUFRoot: ""},
		}

		// Note: this will attempt a TUF fetch which will fail, but the fetcher
		// is created and the warm failure is non-fatal.
		fetcher, err := verifier.NewFetcher(context.Background(), cfg, nil)
		testutil.AssertNoError(t, err)

		if fetcher == nil {
			t.Fatal("expected non-nil OCIFetcher")
		}
	})

	t.Run("backward compat scalar fields empty", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		// Empty sigstore config uses default public fetcher.
		fetcher, err := verifier.NewFetcher(context.Background(), cfg, nil)
		testutil.AssertNoError(t, err)

		if fetcher == nil {
			t.Fatal("expected non-nil OCIFetcher from default config")
		}
	})

	t.Run("scalar tuf_mirror does not include public root", func(t *testing.T) {
		t.Parallel()

		cfg := config.DefaultConfig()
		cfg.Sigstore.TUFMirror = "https://tuf.internal.example.com" //nolint:staticcheck // backward compatibility

		// The legacy scalar path must use the single-root constructor
		// (NewOCIFetcherWithTUFMirror), not the multi-root path that
		// would silently include the public Sigstore root.
		fetcher, err := verifier.ExportCreateFetcher(cfg)
		testutil.AssertNoError(t, err)

		if fetcher == nil {
			t.Fatal("expected non-nil OCIFetcher")
		}

		if fetcher.IsMultiRoot() {
			t.Error("scalar tuf_mirror must use single-root path, not multi-root")
		}
	})

	t.Run("single root without public root uses single-root path", func(t *testing.T) {
		t.Parallel()

		falseVal := false
		cfg := config.DefaultConfig()
		cfg.Sigstore.Roots = []config.SigstoreRootSource{
			{Name: "internal", TUFMirror: "https://tuf.internal.example.com", TUFRoot: ""},
		}
		cfg.Sigstore.IncludePublicRoot = &falseVal

		fetcher, err := verifier.NewFetcher(context.Background(), cfg, nil)
		testutil.AssertNoError(t, err)

		if fetcher == nil {
			t.Fatal("expected non-nil OCIFetcher")
		}
	})
}

func TestCacheAffectingFieldsChangedRoots(t *testing.T) {
	t.Parallel()

	base := func() *config.Config {
		cfg := config.DefaultConfig()
		cfg.Sigstore.Roots = []config.SigstoreRootSource{
			{Name: testRootNameGitHub, TUFMirror: testGitHubTUFMirror, TUFRoot: ""},
		}

		return cfg
	}

	t.Run("same roots no change", func(t *testing.T) {
		t.Parallel()

		prev := base()
		next := base()

		if verifier.ExportCacheAffectingFieldsChanged(prev, next) {
			t.Error("expected no change")
		}
	})

	t.Run("different roots triggers change", func(t *testing.T) {
		t.Parallel()

		prev := base()
		next := base()
		next.Sigstore.Roots = append(
			next.Sigstore.Roots,
			config.SigstoreRootSource{
				Name: "extra", TUFMirror: "https://extra.example.com", TUFRoot: "",
			},
		)

		if !verifier.ExportCacheAffectingFieldsChanged(prev, next) {
			t.Error("expected change when roots list grows")
		}
	})

	t.Run("include_public_root change triggers cache invalidation", func(t *testing.T) {
		t.Parallel()

		falseVal := false
		prev := base()
		next := base()
		next.Sigstore.IncludePublicRoot = &falseVal

		if !verifier.ExportCacheAffectingFieldsChanged(prev, next) {
			t.Error("expected change when include_public_root differs")
		}
	})
}

func TestReloadCreatesFetcherWhenRootsChange(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{}`)

	// Start with a default config (public Sigstore).
	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir

	verif, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)

	defer verif.Stop()

	// Reload with a roots config. The reload should succeed.
	cfg2 := config.DefaultConfig()
	cfg2.Verification = config.ModeWarn
	cfg2.PolicyDir = dir
	cfg2.Sigstore.Roots = []config.SigstoreRootSource{
		{Name: testRootNameGitHub, TUFMirror: testGitHubTUFMirror, TUFRoot: ""},
	}

	err = verif.Reload(context.Background(), cfg2)
	testutil.AssertNoError(t, err)
}

func TestStatusDisabledMode(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()

	verif, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)

	status := verif.Status()

	if !status.Ready {
		t.Error("expected ready=true for disabled mode")
	}

	if status.Mode != "disabled" {
		t.Errorf("mode = %q, want %q", status.Mode, "disabled")
	}

	if status.Policies.Source != "local" {
		t.Errorf("source = %q, want %q", status.Policies.Source, "local")
	}

	if status.Policies.Count != 0 {
		t.Errorf("policies count = %d, want 0", status.Policies.Count)
	}

	if len(status.Policies.Namespaces) != 0 {
		t.Errorf("namespaces = %v, want empty", status.Policies.Namespaces)
	}
}

func TestStatusEnabledWithPolicies(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "default.json", `{}`)
	testutil.WritePolicy(t, dir, "production.json", `{}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir

	verif, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)

	status := verif.Status()

	if !status.Ready {
		t.Error("expected ready=true with policies loaded")
	}

	if status.Mode != "warn" {
		t.Errorf("mode = %q, want %q", status.Mode, "warn")
	}

	if status.Policies.Count != 2 {
		t.Errorf("policies count = %d, want 2", status.Policies.Count)
	}

	if len(status.Policies.Namespaces) != 1 {
		t.Fatalf("namespaces = %v, want [production]", status.Policies.Namespaces)
	}

	if status.Policies.Namespaces[0] != testNsProduction {
		t.Errorf("namespace = %q, want %q", status.Policies.Namespaces[0], testNsProduction)
	}
}

func TestStatusEnabledNoPolicies(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir

	verif, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)

	status := verif.Status()

	if status.Ready {
		t.Error("expected ready=false when enabled with no policies")
	}

	if status.Policies.Count != 0 {
		t.Errorf("policies count = %d, want 0", status.Policies.Count)
	}

	if len(status.CircuitBreakers) != 0 {
		t.Errorf("circuit breakers = %v, want empty", status.CircuitBreakers)
	}
}

func TestNewOCIUnreachableStartsPending(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = t.TempDir()
	cfg.Policy.Source = config.PolicySourceOCI
	cfg.Policy.OCIRef = testUnreachableOCIRef
	cfg.Policy.PollInterval = config.Duration{Duration: 30 * time.Second}

	verif, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)

	defer verif.Stop()

	ready, reason := verif.Ready()
	if ready {
		t.Error("expected ready=false in pending state")
	}

	if reason != "no policies loaded" {
		t.Errorf("reason = %q, want %q", reason, "no policies loaded")
	}

	status := verif.Status()
	if status.Ready {
		t.Error("expected status.Ready=false in pending state")
	}

	if status.Policies.Count != 0 {
		t.Errorf("policies count = %d, want 0", status.Policies.Count)
	}
}

func TestNewOCIUnreachableRejectsInEnforceMode(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeEnforce
	cfg.PolicyDir = t.TempDir()
	cfg.Policy.Source = config.PolicySourceOCI
	cfg.Policy.OCIRef = testUnreachableOCIRef
	cfg.Policy.PollInterval = config.Duration{Duration: 30 * time.Second}

	verif, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)

	defer verif.Stop()

	_, verifyErr := verif.Verify(
		t.Context(), "nginx:latest", testDigest, "", "default", "",
	)
	if !errors.Is(verifyErr, verifier.ErrVerificationFailed) {
		t.Errorf("expected ErrVerificationFailed, got %v", verifyErr)
	}
}

func TestNewOCIUnreachableAllowsInWarnMode(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = t.TempDir()
	cfg.Policy.Source = config.PolicySourceOCI
	cfg.Policy.OCIRef = testUnreachableOCIRef
	cfg.Policy.PollInterval = config.Duration{Duration: 30 * time.Second}

	verif, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)

	defer verif.Stop()

	result, verifyErr := verif.Verify(
		t.Context(), "nginx:latest", testDigest, "", "default", "",
	)
	testutil.AssertNoError(t, verifyErr)

	if !result.Allowed {
		t.Errorf("expected allowed=true in warn mode, got reason: %s", result.Reason)
	}
}

func TestNewLocalPolicyFailureStillFails(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	testutil.WritePolicy(t, dir, "bad.json", `{invalid json}`)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = dir

	_, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
	if err == nil {
		t.Error("expected error for local policy load failure")
	}
}

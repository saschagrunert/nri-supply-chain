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
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"
	ociV1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	ociTypes "github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

const testProdPolicy = "prod.json"

// pushPolicyArtifact pushes an OCI policy artifact with the given policy
// files and creation time to ociRef.
func pushPolicyArtifact(t *testing.T, ociRef string, files map[string]string, created string) {
	t.Helper()

	img := empty.Image

	names := make([]string, 0, len(files))
	for file := range files {
		names = append(names, file)
	}

	slices.Sort(names)

	for _, file := range names {
		var err error

		img, err = mutate.Append(img, mutate.Addendum{
			Layer: static.NewLayer(
				[]byte(files[file]), ociTypes.MediaType(policy.PolicyMediaType),
			),
			Annotations: map[string]string{"org.opencontainers.image.title": file},
		})
		testutil.AssertNoError(t, err)
	}

	annotated, ok := mutate.Annotations(img, map[string]string{
		policy.CreatedAnnotation: created,
	}).(ociV1.Image)
	if !ok {
		t.Fatal("expected an annotated image")
	}

	ref, err := name.ParseReference(ociRef)
	testutil.AssertNoError(t, err)
	testutil.AssertNoError(t, remote.Write(ref, annotated))
}

func policyNamespacesContain(verif *verifier.Verifier, namespace string) bool {
	return slices.Contains(verif.Status().Policies.Namespaces, namespace)
}

func TestReloadDoesNotInstallOlderOCIPolicies(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(ggcrregistry.New())
	t.Cleanup(srv.Close)

	ociRef := srv.Listener.Addr().String() + "/policies:latest"

	pushPolicyArtifact(
		t,
		ociRef,
		map[string]string{testDefaultPolicy: `{}`},
		"2026-09-01T00:00:00Z",
	)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = t.TempDir()
	cfg.Policy.Source = config.PolicySourceOCI
	cfg.Policy.OCIRef = ociRef
	cfg.Policy.PollInterval = config.Duration{Duration: 20 * time.Millisecond}

	verif, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)
	t.Cleanup(verif.Stop)

	sawNewer := false

	verif.ExportSetReloadPreparedHook(func() {
		pushPolicyArtifact(t, ociRef, map[string]string{
			testDefaultPolicy: `{}`,
			testProdPolicy:    `{}`,
		}, "2026-09-02T00:00:00Z")

		// Give a running poller several intervals to apply the newer artifact.
		time.Sleep(300 * time.Millisecond)

		sawNewer = policyNamespacesContain(verif, "prod")
	})

	testutil.AssertNoError(t, verif.Reload(t.Context(), cfg))

	if sawNewer && !policyNamespacesContain(verif, "prod") {
		t.Fatal("reload installed OCI policies older than the ones applied during the reload")
	}

	waitForPolicyNamespace(t, verif, "prod")
}

func TestFailedReloadResumesOCIPolling(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(ggcrregistry.New())
	t.Cleanup(srv.Close)

	ociRef := srv.Listener.Addr().String() + "/policies:latest"

	pushPolicyArtifact(
		t,
		ociRef,
		map[string]string{testDefaultPolicy: `{}`},
		"2026-09-01T00:00:00Z",
	)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = t.TempDir()
	cfg.Policy.Source = config.PolicySourceOCI
	cfg.Policy.OCIRef = ociRef
	cfg.Policy.PollInterval = config.Duration{Duration: 20 * time.Millisecond}

	verif, err := verifier.New(t.Context(), cfg, metrics.New(), nil)
	testutil.AssertNoError(t, err)
	t.Cleanup(verif.Stop)

	broken := *cfg
	broken.Policy.OCIRef = srv.Listener.Addr().String() + "/missing:latest"

	err = verif.Reload(t.Context(), &broken)
	if err == nil {
		t.Fatal("expected the reload of a missing OCI artifact to fail")
	}

	pushPolicyArtifact(t, ociRef, map[string]string{
		testDefaultPolicy: `{}`,
		testProdPolicy:    `{}`,
	}, "2026-09-02T00:00:00Z")

	waitForPolicyNamespace(t, verif, "prod")
}

func TestConcurrentReloadsAreSerialized(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(ggcrregistry.New())
	t.Cleanup(srv.Close)

	ociRef := srv.Listener.Addr().String() + "/policies:latest"

	pushPolicyArtifact(
		t,
		ociRef,
		map[string]string{testDefaultPolicy: `{}`},
		"2026-09-01T00:00:00Z",
	)

	cfg := config.DefaultConfig()
	cfg.Verification = config.ModeWarn
	cfg.PolicyDir = t.TempDir()
	cfg.Policy.Source = config.PolicySourceOCI
	cfg.Policy.OCIRef = ociRef
	cfg.Policy.PollInterval = config.Duration{Duration: 20 * time.Millisecond}

	// A fetcher keeps reloads fast and hermetic; without one each reload
	// creates a registry fetcher.
	verif, err := verifier.New(
		t.Context(),
		cfg,
		metrics.New(),
		&mockFetcher{attestations: nil, err: nil},
	)
	testutil.AssertNoError(t, err)
	t.Cleanup(verif.Stop)

	var (
		hookCalls         atomic.Int32
		secondDone        atomic.Bool
		secondOverlapping atomic.Bool
	)

	secondErr := make(chan error, 1)

	verif.ExportSetReloadPreparedHook(func() {
		if hookCalls.Add(1) != 1 {
			return
		}

		go func() {
			secondErr <- verif.Reload(t.Context(), cfg)

			secondDone.Store(true)
		}()

		// A second reload must wait for this one instead of running while
		// it holds a paused poller.
		time.Sleep(300 * time.Millisecond)
		secondOverlapping.Store(secondDone.Load())
	})

	testutil.AssertNoError(t, verif.Reload(t.Context(), cfg))
	testutil.AssertNoError(t, <-secondErr)

	if secondOverlapping.Load() {
		t.Fatal("expected concurrent reloads to be serialized")
	}
}

func waitForPolicyNamespace(t *testing.T, verif *verifier.Verifier, namespace string) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for !policyNamespacesContain(verif, namespace) {
		if time.Now().After(deadline) {
			t.Fatalf("expected OCI polling to apply the policy for namespace %q", namespace)
		}

		time.Sleep(20 * time.Millisecond)
	}
}

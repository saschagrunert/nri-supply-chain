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

package policy_test

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	ociV1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	ociTypes "github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
)

func TestPollerDetectsDigestChange(t *testing.T) {
	t.Parallel()

	var (
		callCount  atomic.Int32
		mu         sync.Mutex
		imgToServe ociV1.Image
	)

	// Start with one image.
	img1 := buildTestPolicyImage(t, `{"slsa":{"missingPolicy":"warn"}}`)
	imgToServe = img1

	fetchFunc := func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
		mu.Lock()
		defer mu.Unlock()

		return imgToServe, nil
	}

	fetcher := policy.NewOCIFetcherWithImageFunc(fetchFunc, nil)

	// Do an initial fetch to get the digest.
	result, err := fetcher.FetchFromOCI(context.Background(), "example.com/test:v1")
	testutil.AssertNoError(t, err)

	reloadCh := make(chan map[string]*policy.Policy, 10)

	poller := policy.NewPoller(
		fetcher,
		"example.com/test:v1",
		50*time.Millisecond,
		func(policies map[string]*policy.Policy) error {
			callCount.Add(1)

			reloadCh <- policies

			return nil
		},
	)
	poller.SetCachedDigest(result.Digest)

	poller.Start(t.Context())

	// Wait for a poll with no changes.
	time.Sleep(500 * time.Millisecond)

	if callCount.Load() != 0 {
		t.Errorf("expected 0 reload calls with same digest, got %d", callCount.Load())
	}

	// Change the image.
	img2 := buildTestPolicyImage(t, `{"slsa":{"missingPolicy":"deny"}}`)

	mu.Lock()
	imgToServe = img2
	mu.Unlock()

	// Wait for the change to be detected.
	select {
	case policies := <-reloadCh:
		if len(policies) == 0 {
			t.Fatal("expected non-empty policies on reload")
		}

		pol := policies[""]
		testutil.AssertEqual(t, "deny", string(pol.SLSAMissingPolicy()))
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for policy reload")
	}

	poller.Stop()
}

func TestPollerStopsCleanly(t *testing.T) {
	t.Parallel()

	img := buildTestPolicyImage(t, `{}`)

	fetchFunc := func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
		return img, nil
	}

	fetcher := policy.NewOCIFetcherWithImageFunc(fetchFunc, nil)

	var reloadCount atomic.Int32

	poller := policy.NewPoller(
		fetcher,
		"example.com/test:v1",
		50*time.Millisecond,
		func(_ map[string]*policy.Policy) error {
			reloadCount.Add(1)

			return nil
		},
	)
	poller.SetCachedDigest("initial-digest")

	ctx := context.Background()
	poller.Start(ctx)

	// Let it run briefly.
	time.Sleep(500 * time.Millisecond)

	// Stop should complete without hanging.
	done := make(chan struct{})

	go func() {
		poller.Stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("poller.Stop() did not complete within timeout")
	}
}

func TestPollerHandlesFetchError(t *testing.T) {
	t.Parallel()

	var callCount atomic.Int32

	fetchFunc := func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
		return nil, errTestFetch
	}

	fetcher := policy.NewOCIFetcherWithImageFunc(fetchFunc, nil)

	poller := policy.NewPoller(
		fetcher,
		"example.com/test:v1",
		50*time.Millisecond,
		func(_ map[string]*policy.Policy) error {
			callCount.Add(1)

			return nil
		},
	)

	ctx, cancel := context.WithCancel(context.Background())
	poller.Start(ctx)

	// Let it attempt a few polls.
	time.Sleep(500 * time.Millisecond)
	cancel()
	poller.Stop()

	// Reload should never be called on fetch errors.
	if callCount.Load() != 0 {
		t.Errorf("expected 0 reload calls on fetch error, got %d", callCount.Load())
	}
}

func TestPollerRetriesOnReloadError(t *testing.T) {
	t.Parallel()

	var (
		reloadCount atomic.Int32
		mu          sync.Mutex
		reloadErr   error = errTestReload
	)

	img := buildTestPolicyImage(t, `{"slsa":{"missingPolicy":"warn"}}`)

	fetchFunc := func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
		return img, nil
	}

	fetcher := policy.NewOCIFetcherWithImageFunc(fetchFunc, nil)

	poller := policy.NewPoller(
		fetcher,
		"example.com/test:v1",
		50*time.Millisecond,
		func(_ map[string]*policy.Policy) error {
			reloadCount.Add(1)

			mu.Lock()
			defer mu.Unlock()

			return reloadErr
		},
	)

	poller.Start(t.Context())

	// Let it attempt several polls; all should be retried because the
	// callback returns an error.
	time.Sleep(500 * time.Millisecond)

	count := reloadCount.Load()
	if count < 2 {
		t.Errorf("expected at least 2 reload attempts (retry behavior), got %d", count)
	}

	// Now let the callback succeed.
	mu.Lock()
	reloadErr = nil
	mu.Unlock()

	prevCount := reloadCount.Load()

	time.Sleep(500 * time.Millisecond)

	// Should have succeeded once more, then stopped retrying.
	afterCount := reloadCount.Load()
	if afterCount <= prevCount {
		t.Errorf("expected at least one more reload after clearing error, got %d -> %d",
			prevCount, afterCount)
	}

	poller.Stop()
}

func buildTestPolicyImage(t *testing.T, policyJSON string) ociV1.Image {
	t.Helper()

	data, err := json.Marshal(json.RawMessage(policyJSON))
	testutil.AssertNoError(t, err)

	layer := &staticLayer{
		content:   data,
		mediaType: ociTypes.MediaType(policy.PolicyMediaType),
		annotations: map[string]string{
			testTitleAnnotation: testDefaultJSON,
		},
	}

	img, err := mutate.Append(empty.Image, mutate.Addendum{
		Layer: layer,
		Annotations: map[string]string{
			testTitleAnnotation: testDefaultJSON,
		},
	})
	testutil.AssertNoError(t, err)

	return img
}

func TestPollerTOCTOURaceDoesNotReload(t *testing.T) {
	t.Parallel()

	// Simulate a TOCTOU race: CheckDigest returns "B" (changed), but
	// FetchFromOCI returns the original digest "A" because the artifact
	// reverted between HEAD and GET. The poller should detect this and
	// skip the reload callback.
	imgA := buildTestPolicyImage(t, `{"slsa":{"missingPolicy":"warn"}}`)
	imgB := buildTestPolicyImage(t, `{"slsa":{"missingPolicy":"deny"}}`)

	digestA, err := imgA.Digest()
	testutil.AssertNoError(t, err)

	// callCount tracks how many times the fetch function is called:
	// 1 = initial FetchFromOCI
	// 2 = CheckDigest during poll (return imgB so digest looks different)
	// 3 = FetchFromOCI during poll (return imgA so digest matches cached)
	var callCount atomic.Int32

	fetchFunc := func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
		n := callCount.Add(1)
		if n == 2 {
			// CheckDigest sees a different image (digest "B").
			return imgB, nil
		}

		// Initial fetch and the re-fetch both return imgA (digest "A").
		return imgA, nil
	}

	fetcher := policy.NewOCIFetcherWithImageFunc(fetchFunc, nil)

	// Do an initial fetch to get digest "A".
	result, err := fetcher.FetchFromOCI(context.Background(), "example.com/test:v1")
	testutil.AssertNoError(t, err)
	testutil.AssertEqual(t, digestA.String(), result.Digest)

	var reloadCount atomic.Int32

	poller := policy.NewPoller(
		fetcher,
		"example.com/test:v1",
		50*time.Millisecond,
		func(_ map[string]*policy.Policy) error {
			reloadCount.Add(1)

			return nil
		},
	)
	poller.SetCachedDigest(result.Digest)

	ctx, cancel := context.WithCancel(context.Background())
	poller.Start(ctx)

	// Wait long enough for at least one poll cycle to run.
	time.Sleep(500 * time.Millisecond)
	cancel()
	poller.Stop()

	// The reload callback should never be called because the re-fetched
	// digest matches the cached one (TOCTOU protection).
	if reloadCount.Load() != 0 {
		t.Errorf("expected 0 reload calls (TOCTOU protection), got %d", reloadCount.Load())
	}
}

var (
	errTestFetch  = testError("test fetch error")
	errTestReload = testError("test reload error")
)

type testError string

func (e testError) Error() string {
	return string(e)
}

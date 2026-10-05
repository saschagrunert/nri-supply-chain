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

package bundle //nolint:testpackage // tests use internal test helpers

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
)

func TestCheckStalenessNoMaxAge(t *testing.T) {
	t.Parallel()

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		CreatedAt: time.Now().Add(-48 * time.Hour),
	}
	result := CheckStaleness(manifest, 0, ExpiryDeny)

	if result.Stale {
		t.Error("should not be stale when maxAge is 0")
	}

	if !result.Allowed {
		t.Error("should be allowed when maxAge is 0")
	}
}

func TestCheckStalenessFresh(t *testing.T) {
	t.Parallel()

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		CreatedAt: time.Now().Add(-1 * time.Hour),
	}
	result := CheckStaleness(manifest, 24*time.Hour, ExpiryDeny)

	if result.Stale {
		t.Error("should not be stale when age < maxAge")
	}

	if !result.Allowed {
		t.Error("should be allowed when not stale")
	}
}

func TestCheckStalenessExpiredAllow(t *testing.T) {
	t.Parallel()

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		CreatedAt: time.Now().Add(-48 * time.Hour),
	}
	result := CheckStaleness(manifest, 24*time.Hour, ExpiryAllow)

	if !result.Stale {
		t.Error("should be stale when age > maxAge")
	}

	if !result.Allowed {
		t.Error("should be allowed with ExpiryAllow policy")
	}
}

func TestCheckStalenessExpiredWarn(t *testing.T) {
	t.Parallel()

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		CreatedAt: time.Now().Add(-48 * time.Hour),
	}
	result := CheckStaleness(manifest, 24*time.Hour, ExpiryWarn)

	if !result.Stale {
		t.Error("should be stale when age > maxAge")
	}

	if !result.Allowed {
		t.Error("should be allowed with ExpiryWarn policy")
	}
}

func TestCheckStalenessExpiredDeny(t *testing.T) {
	t.Parallel()

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		CreatedAt: time.Now().Add(-48 * time.Hour),
	}
	result := CheckStaleness(manifest, 24*time.Hour, ExpiryDeny)

	if !result.Stale {
		t.Error("should be stale when age > maxAge")
	}

	if result.Allowed {
		t.Error("should not be allowed with ExpiryDeny policy")
	}
}

func TestCheckStalenessFutureCreatedAt(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		createdAt   time.Duration
		policy      ExpiryPolicy
		wantStale   bool
		wantFuture  bool
		wantAllowed bool
	}{
		{
			name:        "within clock skew",
			createdAt:   time.Minute,
			policy:      ExpiryDeny,
			wantStale:   false,
			wantFuture:  false,
			wantAllowed: true,
		},
		{
			name:        "far future with deny policy",
			createdAt:   365 * 24 * time.Hour,
			policy:      ExpiryDeny,
			wantStale:   true,
			wantFuture:  true,
			wantAllowed: false,
		},
		{
			name:        "far future with warn policy",
			createdAt:   365 * 24 * time.Hour,
			policy:      ExpiryWarn,
			wantStale:   true,
			wantFuture:  true,
			wantAllowed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
				CreatedAt: time.Now().Add(tt.createdAt),
			}
			result := CheckStaleness(manifest, 24*time.Hour, tt.policy)

			if result.Stale != tt.wantStale || result.Future != tt.wantFuture ||
				result.Allowed != tt.wantAllowed {
				t.Errorf("CheckStaleness() = %+v, want stale=%v future=%v allowed=%v",
					result, tt.wantStale, tt.wantFuture, tt.wantAllowed)
			}
		})
	}
}

func TestFetcherFutureBundleDenied(t *testing.T) {
	t.Parallel()

	manifest := &Manifest{ //nolint:exhaustruct_v5 // test data
		Version:   1,
		CreatedAt: time.Now().UTC().Add(365 * 24 * time.Hour),
		Images:    map[string]*ImageEntry{},
	}

	store, err := OpenStore(createTestStore(t, manifest, nil))
	if err != nil {
		t.Fatalf("OpenStore() error: %v", err)
	}

	fetcher := NewFetcher(store, passthroughVerifier,
		WithMaxAge(24*time.Hour), WithExpiryPolicy(ExpiryDeny),
	)

	_, err = fetcher.Fetch(
		context.Background(), testExampleRef,
		&attestation.FetchOptions{Digest: testImageDigest},
	)
	if !errors.Is(err, ErrBundleExpired) {
		t.Fatalf("Fetch() error = %v, want %v", err, ErrBundleExpired)
	}
}

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
	"testing"
	"time"
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

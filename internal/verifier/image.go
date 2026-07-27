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
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/google/go-containerregistry/pkg/name"
	"golang.org/x/sync/semaphore"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/glob"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

func acquireFetchSlots(
	ctx context.Context, state *snapshot, host string,
) (release func(), err error) {
	hostSem := acquireHostSem(state.hostSem, host)

	err = hostSem.Acquire(ctx, 1)
	if err != nil {
		return nil, fmt.Errorf("per-host fetch concurrency limit: %w", err)
	}

	err = state.fetchSem.Acquire(ctx, 1)
	if err != nil {
		hostSem.Release(1)

		return nil, fmt.Errorf("fetch concurrency limit: %w", err)
	}

	return func() {
		state.fetchSem.Release(1)
		hostSem.Release(1)
	}, nil
}

func acquireHostSem(hostSem *sync.Map, host string) *semaphore.Weighted {
	if val, ok := hostSem.Load(host); ok {
		return val.(*semaphore.Weighted) //nolint:forcetypeassert // hostSem is private, only stores *Weighted
	}

	val, _ := hostSem.LoadOrStore(host, semaphore.NewWeighted(maxConcurrentFetchesPerHost))

	return val.(*semaphore.Weighted) //nolint:forcetypeassert // hostSem is private, only stores *Weighted
}

func registryHost(imageRef string) string {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return imageRef
	}

	return ref.Context().RegistryStr()
}

func buildDigestRef(imageRef, digest string) string {
	if digest == "" || strings.Contains(imageRef, "@") {
		return imageRef
	}

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		slog.Debug("Failed to parse image reference for digest ref",
			"image", imageRef,
			"error", err,
		)

		return imageRef
	}

	return ref.Context().Digest(digest).String()
}

// isExcluded checks whether imageRef matches any exclude glob pattern.
// '*' matches non-'/' characters, '**' matches any characters including '/'.
func isExcluded(ctx context.Context, excludedImages []string, imageRef string) bool {
	for _, pattern := range excludedImages {
		matched, err := glob.Match(pattern, imageRef)
		if err != nil {
			slog.DebugContext(ctx, "Malformed exclude pattern",
				"pattern", pattern,
				"image", imageRef,
				"error", err,
			)

			continue
		}

		if matched {
			return true
		}
	}

	return false
}

func registryBreakerByHost(
	registry *attestation.CircuitBreakerRegistry, host string,
) *attestation.CircuitBreaker {
	if registry == nil {
		return nil
	}

	return registry.Get(host)
}

func recordBreakerFailure(
	ctx context.Context,
	breaker *attestation.CircuitBreaker,
	met *metrics.Metrics,
	host string,
	fetchFailurePolicy types.Action,
) {
	if breaker == nil {
		return
	}

	if tripped := breaker.RecordFailure(); tripped {
		met.CircuitBreakerTripsTotal.WithLabelValues(host).Inc()
		slog.WarnContext(ctx, "Circuit breaker opened after repeated fetch failures, "+
			"subsequent requests will use the configured fetch_failure_policy",
			"registry", host,
			"fetch_failure_policy", fetchFailurePolicy,
		)
	}
}

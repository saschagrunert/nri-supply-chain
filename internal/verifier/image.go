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

const maxHostSemEntries = 1000

func acquireHostSem(hostSem *sync.Map, host string) *semaphore.Weighted {
	if val, ok := hostSem.Load(host); ok {
		return val.(*semaphore.Weighted) //nolint:forcetypeassert // hostSem is private, only stores *Weighted
	}

	sem := semaphore.NewWeighted(maxConcurrentFetchesPerHost)

	val, loaded := hostSem.LoadOrStore(host, sem)
	if loaded {
		return val.(*semaphore.Weighted) //nolint:forcetypeassert // hostSem is private, only stores *Weighted
	}

	count := 0

	hostSem.Range(func(_, _ any) bool {
		count++

		return count <= maxHostSemEntries
	})

	// The just-stored entry is included in the Range count, so "more than
	// maxHostSemEntries" means the map had maxHostSemEntries entries before
	// this store. Between LoadOrStore and Delete, another goroutine can Load
	// the entry and use the semaphore; this is acceptable since the overflow
	// path only triggers at 1000+ distinct registry hosts.
	if count > maxHostSemEntries {
		hostSem.Delete(host)
		slog.Warn("Per-host semaphore map at capacity, using untracked semaphore",
			"host", host, "capacity", maxHostSemEntries)

		return sem
	}

	return val.(*semaphore.Weighted) //nolint:forcetypeassert // hostSem is private, only stores *Weighted
}

// digestRefFromParsed builds a digest reference string using a pre-parsed
// reference, avoiding redundant parsing. Returns imageRef unchanged when
// the parsed reference is nil (e.g. when the initial parse failed).
func digestRefFromParsed(parsedRef name.Reference, imageRef, digest string) string {
	if digest == "" || strings.Contains(imageRef, "@") {
		return imageRef
	}

	if parsedRef == nil {
		slog.Debug("Cannot build digest ref from nil parsed reference",
			"image", imageRef,
		)

		return imageRef
	}

	return parsedRef.Context().Digest(digest).String()
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

// isIncluded checks whether imageRef matches any include glob pattern.
// Returns true if the include list is empty (all images are eligible) or
// if the image matches at least one pattern.
func isIncluded(ctx context.Context, includedImages []string, imageRef string) bool {
	if len(includedImages) == 0 {
		return true
	}

	for _, pattern := range includedImages {
		matched, err := glob.Match(pattern, imageRef)
		if err != nil {
			slog.DebugContext(ctx, "Malformed include pattern",
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

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
	"log/slog"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/guac"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

var (
	errGUACPanic       = errors.New("GUAC query panicked")
	errGUACBreakerOpen = errors.New("GUAC circuit breaker open")
)

// startGUACQuery starts a GUAC query in a goroutine and returns a channel
// that will receive the result. If GUAC is not configured, the returned
// channel receives nil immediately.
func startGUACQuery(
	ctx context.Context, state *snapshot, digest, imageRef string,
) <-chan *types.CheckResult {
	resultCh := make(chan *types.CheckResult, 1)

	if state.guacClient == nil {
		resultCh <- nil

		return resultCh
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("Panic during GUAC query",
					"panic", r, "image", imageRef)

				resultCh <- applyGUACFallback(state, imageRef,
					fmt.Errorf("%w: %v", errGUACPanic, r))
			}
		}()

		resultCh <- timedFetchGUACData(ctx, state, digest, imageRef)
	}()

	return resultCh
}

func timedFetchGUACData(
	ctx context.Context, state *snapshot, digest, imageRef string,
) *types.CheckResult {
	start := time.Now()

	defer func() {
		state.metrics.GUACQueryDuration.WithLabelValues("all").
			Observe(time.Since(start).Seconds())
	}()

	return fetchGUACData(ctx, state, digest, imageRef)
}

func fetchGUACData(
	ctx context.Context, state *snapshot, digest, imageRef string,
) *types.CheckResult {
	if state.guacBreaker != nil && !state.guacBreaker.Allow() {
		slog.WarnContext(ctx, "GUAC circuit breaker open",
			"image", imageRef)

		return applyGUACFallback(state, imageRef,
			fmt.Errorf("%w", errGUACBreakerOpen))
	}

	result := guac.Query(
		ctx,
		state.guacClient,
		digest,
		state.config.Guac.Checks,
		state.config.Guac.MaxDependencies,
	)

	if !result.Passed {
		if state.guacBreaker != nil && !errors.Is(result.Err, guac.ErrGUACAuthError) {
			state.guacBreaker.RecordFailure()
		}

		fallback := applyGUACFallback(state, imageRef, result.Err)
		if fallback != nil && result.Metadata != nil {
			fallback.Metadata = result.Metadata
		}

		return fallback
	}

	if state.guacBreaker != nil {
		state.guacBreaker.RecordSuccess()
	}

	return result
}

func applyGUACFallback(
	state *snapshot, imageRef string, err error,
) *types.CheckResult {
	detail := fmt.Sprintf("GUAC query failed for %s: %s", imageRef, err)

	switch state.config.Guac.FallbackPolicy { //nolint:exhaustive // warn is the default
	case types.ActionAllow:
		return nil

	case types.ActionDeny:
		return types.FailResult(types.CheckTypeGUAC, detail, err)

	default:
		return types.WarnResult(types.CheckTypeGUAC, detail)
	}
}

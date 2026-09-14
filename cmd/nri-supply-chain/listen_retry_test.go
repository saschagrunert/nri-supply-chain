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

package main

import (
	"testing"
	"time"
)

func TestDefaultListenRetryPolicyUsesListenConstants(t *testing.T) {
	t.Parallel()

	policy := defaultListenRetryPolicy()

	if policy.initial != listenRetryInitialBackoff ||
		policy.maximum != listenRetryMaxBackoff ||
		policy.factor != listenRetryBackoffFactor {
		t.Errorf("default listen retry policy = %+v, want the listen retry constants", policy)
	}
}

func TestListenRetryPolicyNext(t *testing.T) {
	t.Parallel()

	policy := listenRetryPolicy{initial: time.Second, maximum: 10 * time.Second, factor: 3}

	got := make([]time.Duration, 0, 4)

	backoff := policy.initial
	for range 4 {
		got = append(got, backoff)
		backoff = policy.next(backoff)
	}

	want := []time.Duration{time.Second, 3 * time.Second, 9 * time.Second, 10 * time.Second}

	for idx := range want {
		if got[idx] != want[idx] {
			t.Fatalf("backoff sequence = %v, want %v", got, want)
		}
	}

	constant := listenRetryPolicy{initial: time.Second, maximum: time.Minute, factor: 0}
	if next := constant.next(time.Second); next != time.Second {
		t.Errorf("factor 0 next = %s, want the delay to stay constant", next)
	}
}

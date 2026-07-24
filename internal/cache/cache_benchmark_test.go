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

package cache_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/cache"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const benchDigest = "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4" +
	"e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

func BenchmarkCacheGet(b *testing.B) {
	testCache := cache.New(time.Hour)

	result := &types.Result{Allowed: true, Reason: "ok", CheckResults: nil}
	testCache.Set(benchDigest, "default", result)

	b.ResetTimer()

	for range b.N {
		testCache.Get(benchDigest, "default")
	}
}

func BenchmarkCacheGetMiss(b *testing.B) {
	testCache := cache.New(time.Hour)

	const missDigest = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" +
		"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

	b.ResetTimer()

	for range b.N {
		testCache.Get(missDigest, "default")
	}
}

func BenchmarkCacheSet(b *testing.B) {
	testCache := cache.New(time.Hour)
	result := &types.Result{Allowed: true, Reason: "ok", CheckResults: nil}

	b.ResetTimer()

	for idx := range b.N {
		testCache.Set(fmt.Sprintf("sha256:%d", idx), "default", result)
	}
}

func BenchmarkCacheGetParallel(b *testing.B) {
	testCache := cache.New(time.Hour)

	result := &types.Result{Allowed: true, Reason: "ok", CheckResults: nil}
	testCache.Set(benchDigest, "default", result)

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			testCache.Get(benchDigest, "default")
		}
	})
}

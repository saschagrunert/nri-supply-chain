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
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/cache"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

func FuzzCacheGetSet(f *testing.F) {
	f.Add("sha256:abc123def456", "default", true)
	f.Add(
		"sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"kube-system",
		false,
	)
	f.Add("", "", true)
	f.Add("sha256:abc", "a]b[c\x00d", false)
	f.Add("digest-without-algo", "namespace/with/slashes", true)

	f.Fuzz(func(t *testing.T, digest, namespace string, allowed bool) {
		c := cache.New(time.Minute)
		defer c.Stop()

		result := &types.Result{Allowed: allowed, Reason: "", CheckResults: nil}
		c.Set(digest, namespace, result)

		got := c.Get(digest, namespace)
		if got == nil {
			return
		}

		if got.Allowed != allowed {
			t.Errorf("Get returned Allowed=%v, want %v", got.Allowed, allowed)
		}
	})
}

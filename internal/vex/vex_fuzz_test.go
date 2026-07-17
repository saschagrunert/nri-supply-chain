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

package vex_test

import (
	"context"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/vex"
)

func FuzzVerify(f *testing.F) {
	f.Add([]byte(`{"subject":[],"predicate":{"statements":[]}}`))
	f.Add([]byte(`{}`))

	f.Fuzz(func(_ *testing.T, data []byte) {
		//nolint:errcheck,gosec // fuzz: we test for panics
		vex.Verify(
			context.Background(), data, &policy.Policy{},
			"docker.io/library/nginx:latest", "sha256:abc123",
		)
	})
}

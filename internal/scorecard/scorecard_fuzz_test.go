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

package scorecard_test

import (
	"context"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/scorecard"
)

func FuzzVerify(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"_type":"bad"}`))
	f.Add([]byte(`{
		"_type":"https://in-toto.io/Statement/v1",
		"subject":[{"name":"test","digest":{"sha256":"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"}}],
		"predicateType":"https://scorecard.dev/result/v0.1",
		"predicate":{
			"date":"2026-08-20T12:00:00Z",
			"repo":{"name":"github.com/example/project","commit":"abc123"},
			"scorecard":{"version":"v5.4.0","commit":"def456"},
			"score":8.4,
			"checks":[{"name":"Code-Review","score":8},{"name":"Fuzzing","score":-1}]
		}
	}`))

	f.Fuzz(func(_ *testing.T, data []byte) {
		scorecard.Verify(context.Background(), data, &policy.Policy{}, testDigest)
	})
}

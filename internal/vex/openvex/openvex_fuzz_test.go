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

package openvex_test

import (
	"context"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/vex/openvex"
)

func FuzzVerify(f *testing.F) {
	const testDigest = "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4" +
		"e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

	const testPURL = "pkg:oci/nginx@sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4" +
		"e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

	f.Add([]byte(`{"@context":"https://openvex.dev/ns/v0.2.0","@id":"test","statements":[]}`))
	f.Add([]byte(`{}`))

	f.Add([]byte(`{"@context":"https://openvex.dev/ns/v0.2.0","@id":"test","statements":[` +
		`{"vulnerability":{"name":"CVE-2024-0001"},` +
		`"products":[{"@id":"` + testPURL + `"}],` +
		`"status":"affected"}]}`))

	f.Add([]byte(`{"@context":"https://openvex.dev/ns/v0.2.0","@id":"test","statements":[` +
		`{"vulnerability":{"name":"CVE-2024-0002"},` +
		`"products":[{"@id":"` + testPURL + `"}],` +
		`"status":"under_investigation"}]}`))

	f.Add([]byte(`{"@context":"https://openvex.dev/ns/v0.2.0","@id":"test","statements":[` +
		`{"vulnerability":{"name":"CVE-2024-0003"},` +
		`"products":[{"@id":"` + testPURL + `"}],` +
		`"status":"not_affected"}]}`))

	f.Fuzz(func(_ *testing.T, data []byte) {
		openvex.Verify(context.Background(), data, testDigest, testPURL)
	})
}

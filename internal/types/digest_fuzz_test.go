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

package types_test

import (
	"strings"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

func FuzzParseDigest(f *testing.F) {
	f.Add("sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
	f.Add("sha512:abcdef")
	f.Add("")
	f.Add(":")
	f.Add("sha256:")
	f.Add(":abc")
	f.Add("invalid")

	f.Fuzz(func(t *testing.T, digest string) {
		algo, hash := types.ParseDigest(digest)
		if algo != "" && hash == "" {
			t.Error("algo set but hash empty")
		}

		if algo == "" && hash != "" {
			t.Error("algo empty but hash set")
		}

		if algo != "" {
			if !strings.Contains(digest, algo+":"+hash) {
				t.Errorf("parsed values %q:%q not in input %q", algo, hash, digest)
			}
		}
	})
}

func FuzzExtractDigest(f *testing.F) {
	f.Add("sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
	f.Add(
		"docker.io/library/nginx@sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
	)
	f.Add("")
	f.Add("no-digest-here")
	f.Add("@")
	f.Add("image@invalid")

	f.Fuzz(func(t *testing.T, entry string) {
		result := types.ExtractDigest(entry)
		if result != "" {
			algo, _ := types.ParseDigest(result)
			if algo == "" {
				t.Errorf("ExtractDigest returned %q but ParseDigest rejects it", result)
			}
		}
	})
}

func FuzzMatchDigestInMap(f *testing.F) {
	f.Add(
		"sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
		"sha256",
		"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
	)
	f.Add("", "", "")
	f.Add("invalid", "sha256", "abc")

	f.Fuzz(func(t *testing.T, digest, mapAlgo, mapHash string) {
		digests := map[string]string{}
		if mapAlgo != "" {
			digests[mapAlgo] = mapHash
		}

		got := types.MatchDigestInMap(digest, digests)

		algo, hash := types.ParseDigest(digest)
		if algo != "" && algo == mapAlgo && hash == mapHash && !got {
			t.Errorf("expected match for %q with map[%q]=%q", digest, mapAlgo, mapHash)
		}
	})
}

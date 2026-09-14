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
	"slices"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

func digestRequest(digest, indexDigest string) types.VerifyRequest {
	return types.VerifyRequest{
		ImageRef: "", Digest: digest, IndexDigest: indexDigest, Namespace: "", ServiceAccount: "",
	}
}

func TestRelatedDigests(t *testing.T) {
	t.Parallel()

	const (
		platform = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
		index    = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	)

	tests := []struct {
		name         string
		req          types.VerifyRequest
		attestDigest string
		want         []string
	}{
		{
			name:         "attestations on index digest relate the platform digest",
			req:          digestRequest(platform, index),
			attestDigest: index,
			want:         []string{platform},
		},
		{
			name:         "attestations on platform digest relate the index digest",
			req:          digestRequest(platform, index),
			attestDigest: platform,
			want:         []string{index},
		},
		{
			name:         "single manifest has no related digests",
			req:          digestRequest(platform, ""),
			attestDigest: platform,
			want:         []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := relatedDigests(&test.req, test.attestDigest); !slices.Equal(got, test.want) {
				t.Errorf("relatedDigests() = %v, want %v", got, test.want)
			}
		})
	}
}

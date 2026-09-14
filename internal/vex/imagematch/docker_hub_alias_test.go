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

package imagematch_test

import (
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/vex/imagematch"
)

func TestDockerHubAliasesMatch(t *testing.T) {
	t.Parallel()

	aliases := []string{
		"docker.io",
		"index.docker.io",
		"registry-1.docker.io",
		"registry.hub.docker.com",
	}

	for _, imageAlias := range aliases {
		for _, docAlias := range aliases {
			t.Run(imageAlias+"/"+docAlias, func(t *testing.T) {
				t.Parallel()

				// Official images may be written without the library
				// namespace on any Docker Hub alias.
				img := imagematch.New(imageAlias+"/nginx:1.27@"+testDigest, testDigest, nil)

				for _, identifier := range []string{
					"pkg:docker/library/nginx@1.27",
					"pkg:docker/nginx?repository_url=" + docAlias,
					"pkg:oci/nginx?repository_url=" + docAlias + "/library/nginx",
					"pkg:docker/" + docAlias + "/library/nginx",
				} {
					if got := img.Classify(identifier); got != imagematch.KindImage {
						t.Errorf("Classify(%q) for image on %s = %d, want KindImage",
							identifier, imageAlias, got)
					}
				}

				other := "pkg:oci/nginx?repository_url=ghcr.io/library/nginx"
				if got := img.Classify(other); got != imagematch.KindOtherImage {
					t.Errorf("expected other registry to be another image, got %d", got)
				}
			})
		}
	}
}

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

package vsa_test

import (
	"strings"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/vsa"
)

func TestVerifyResourceURIDockerHubAliases(t *testing.T) {
	t.Parallel()

	digest := testImageRef[strings.Index(testImageRef, "@")+1:]

	aliases := []string{
		"docker.io",
		"index.docker.io",
		"registry-1.docker.io",
		"registry.hub.docker.com",
	}

	for _, resourceAlias := range aliases {
		for _, imageAlias := range aliases {
			t.Run(resourceAlias+"/"+imageAlias, func(t *testing.T) {
				t.Parallel()

				stmt := validVSAStatement()
				stmt.Predicate.ResourceURI = resourceAlias + "/library/nginx@" + digest

				result, err := vsa.Verify(
					t.Context(),
					testutil.MustMarshal(t, stmt),
					trustedPolicy(),
					imageAlias+"/nginx@"+digest,
					nil,
				)
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				if !result.Check.Passed {
					t.Errorf("expected %s resource URI to bind %s image, got: %s",
						resourceAlias, imageAlias, result.Check.Detail)
				}
			})
		}
	}
}

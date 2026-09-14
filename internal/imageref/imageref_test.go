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

package imageref_test

import (
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/imageref"
)

const testNginxRepository = "docker.io/library/nginx"

func TestNormalizeRegistry(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"docker.io":               imageref.DockerHubRegistry,
		"index.docker.io":         imageref.DockerHubRegistry,
		"registry-1.docker.io":    imageref.DockerHubRegistry,
		"registry.hub.docker.com": imageref.DockerHubRegistry,
		"Registry-1.Docker.IO":    imageref.DockerHubRegistry,
		"GHCR.io":                 "ghcr.io",
		"docker.io.evil.com":      "docker.io.evil.com",
		"hub.docker.com":          "hub.docker.com",
		"localhost:5000":          "localhost:5000",
	}

	for input, want := range tests {
		if got := imageref.NormalizeRegistry(input); got != want {
			t.Errorf("NormalizeRegistry(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestNormalizeRepository(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"index.docker.io/library/nginx":      testNginxRepository,
		"registry-1.docker.io/nginx":         testNginxRepository,
		"registry.hub.docker.com/myorg/app":  "docker.io/myorg/app",
		"docker.io/nginx":                    testNginxRepository,
		"ghcr.io/org/app":                    "ghcr.io/org/app",
		"ghcr.io/app":                        "ghcr.io/app",
		"quay.io/org/nested/app":             "quay.io/org/nested/app",
		"nginx":                              "nginx",
		"Registry-1.Docker.IO/library/nginx": testNginxRepository,
	}

	for input, want := range tests {
		if got := imageref.NormalizeRepository(input); got != want {
			t.Errorf("NormalizeRepository(%q) = %q, want %q", input, got, want)
		}
	}
}

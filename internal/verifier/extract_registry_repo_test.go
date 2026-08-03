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

package verifier_test

import (
	"testing"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

const testRegistryGHCR = "ghcr.io"

func TestExtractRegistryRepo(t *testing.T) {
	t.Parallel()

	t.Run("nil ref returns imageRef for both", func(t *testing.T) {
		t.Parallel()

		reg, repo := verifier.ExportExtractRegistryRepo(nil, "some-image:tag")
		if reg != "some-image:tag" {
			t.Errorf("expected reg %q, got %q", "some-image:tag", reg)
		}

		if repo != "some-image:tag" {
			t.Errorf("expected repo %q, got %q", "some-image:tag", repo)
		}
	})

	t.Run("digest ref extracts correctly", func(t *testing.T) {
		t.Parallel()

		const imageRef = "docker.io/library/nginx@sha256:" +
			"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4" +
			"e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

		ref, err := name.ParseReference(imageRef)
		if err != nil {
			t.Fatalf("failed to parse reference: %v", err)
		}

		reg, repo := verifier.ExportExtractRegistryRepo(ref, imageRef)
		if reg != "index.docker.io" {
			t.Errorf("expected reg %q, got %q", "index.docker.io", reg)
		}

		if repo != "library/nginx" {
			t.Errorf("expected repo %q, got %q", "library/nginx", repo)
		}
	})

	t.Run("tag ref", func(t *testing.T) {
		t.Parallel()

		const imageRef = "ghcr.io/myorg/myimage:v1"

		ref, err := name.ParseReference(imageRef)
		if err != nil {
			t.Fatalf("failed to parse reference: %v", err)
		}

		reg, repo := verifier.ExportExtractRegistryRepo(ref, imageRef)
		if reg != testRegistryGHCR {
			t.Errorf("expected reg %q, got %q", testRegistryGHCR, reg)
		}

		if repo != "myorg/myimage" {
			t.Errorf("expected repo %q, got %q", "myorg/myimage", repo)
		}
	})

	t.Run("bare image with docker.io default", func(t *testing.T) {
		t.Parallel()

		const imageRef = "nginx:latest"

		ref, err := name.ParseReference(imageRef)
		if err != nil {
			t.Fatalf("failed to parse reference: %v", err)
		}

		reg, repo := verifier.ExportExtractRegistryRepo(ref, imageRef)
		if reg != "index.docker.io" {
			t.Errorf("expected reg %q, got %q", "index.docker.io", reg)
		}

		if repo != "library/nginx" {
			t.Errorf("expected repo %q, got %q", "library/nginx", repo)
		}
	})
}

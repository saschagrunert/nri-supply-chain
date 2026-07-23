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

package registry_test

import (
	"errors"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	ociregistry "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/saschagrunert/nri-supply-chain/internal/registry"
)

func pushIndex(
	t *testing.T, server *httptest.Server, repoTag string, addenda ...mutate.IndexAddendum,
) v1.ImageIndex {
	t.Helper()

	addr := strings.TrimPrefix(server.URL, "http://")
	imgRef := addr + "/" + repoTag

	idx := mutate.AppendManifests(empty.Index, addenda...)

	ref, err := name.ParseReference(imgRef)
	if err != nil {
		t.Fatalf("parsing reference: %v", err)
	}

	err = remote.WriteIndex(ref, idx, remote.WithTransport(server.Client().Transport))
	if err != nil {
		t.Fatalf("pushing index: %v", err)
	}

	return idx
}

func getDescriptor(t *testing.T, server *httptest.Server, repoTag string) *remote.Descriptor {
	t.Helper()

	addr := strings.TrimPrefix(server.URL, "http://")
	imgRef := addr + "/" + repoTag

	ref, err := name.ParseReference(imgRef)
	if err != nil {
		t.Fatalf("parsing reference: %v", err)
	}

	desc, err := remote.Get(ref, remote.WithTransport(server.Client().Transport))
	if err != nil {
		t.Fatalf("fetching descriptor: %v", err)
	}

	return desc
}

func makeImage(t *testing.T, arch, os string) v1.Image {
	t.Helper()

	img, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{
		Architecture: arch,
		OS:           os,
	})
	if err != nil {
		t.Fatalf("creating image (%s/%s): %v", os, arch, err)
	}

	return img
}

func TestResolveIndexDigestMatchingPlatform(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(ociregistry.New())
	t.Cleanup(server.Close)

	img := makeImage(t, runtime.GOARCH, runtime.GOOS)

	pushIndex(t, server, "match:latest",
		mutate.IndexAddendum{
			Add: img,
			Descriptor: v1.Descriptor{
				Platform: &v1.Platform{
					Architecture: runtime.GOARCH,
					OS:           runtime.GOOS,
				},
			},
		},
	)

	desc := getDescriptor(t, server, "match:latest")

	digest, err := registry.ResolveIndexDigest(desc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.HasPrefix(digest, "sha256:") {
		t.Errorf("digest = %q, expected sha256: prefix", digest)
	}
}

func TestResolveIndexDigestMultiplePlatforms(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(ociregistry.New())
	t.Cleanup(server.Close)

	amdImg := makeImage(t, "amd64", "linux")
	armImg := makeImage(t, "arm64", "linux")

	idx := pushIndex(t, server, "multi:latest",
		mutate.IndexAddendum{
			Add: amdImg,
			Descriptor: v1.Descriptor{
				Platform: &v1.Platform{Architecture: "amd64", OS: "linux"},
			},
		},
		mutate.IndexAddendum{
			Add: armImg,
			Descriptor: v1.Descriptor{
				Platform: &v1.Platform{Architecture: "arm64", OS: "linux"},
			},
		},
	)

	desc := getDescriptor(t, server, "multi:latest")

	digest, err := registry.ResolveIndexDigest(desc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	idxDigest, err := idx.Digest()
	if err != nil {
		t.Fatalf("getting index digest: %v", err)
	}

	if digest == idxDigest.String() {
		t.Error("expected platform-specific digest, got index digest")
	}

	if !strings.HasPrefix(digest, "sha256:") {
		t.Errorf("digest = %q, expected sha256: prefix", digest)
	}
}

func TestResolveIndexDigestNoPlatformMatch(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(ociregistry.New())
	t.Cleanup(server.Close)

	img := makeImage(t, "s390x", "zos")

	pushIndex(t, server, "nomatch:latest",
		mutate.IndexAddendum{
			Add: img,
			Descriptor: v1.Descriptor{
				Platform: &v1.Platform{Architecture: "s390x", OS: "zos"},
			},
		},
	)

	desc := getDescriptor(t, server, "nomatch:latest")

	_, err := registry.ResolveIndexDigest(desc)
	if err == nil {
		t.Fatal("expected error for non-matching platform")
	}

	if !errors.Is(err, registry.ErrNoPlatformMatch) {
		t.Errorf("expected ErrNoPlatformMatch, got: %v", err)
	}
}

func TestResolveIndexDigestEmptyIndex(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(ociregistry.New())
	t.Cleanup(server.Close)

	pushIndex(t, server, "empty:latest")

	desc := getDescriptor(t, server, "empty:latest")

	_, err := registry.ResolveIndexDigest(desc)
	if err == nil {
		t.Fatal("expected error for empty index")
	}

	if !errors.Is(err, registry.ErrNoPlatformMatch) {
		t.Errorf("expected ErrNoPlatformMatch, got: %v", err)
	}
}

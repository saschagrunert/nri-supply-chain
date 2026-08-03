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
	"context"
	"errors"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/crane"
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
					Variant:      registry.PlatformVariant(runtime.GOARCH),
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
				Platform: &v1.Platform{Architecture: "arm64", OS: "linux", Variant: "v8"},
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

func TestResolveDigestPlainImage(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(ociregistry.New())
	t.Cleanup(server.Close)

	addr := strings.TrimPrefix(server.URL, "http://")
	imgRef := addr + "/plain:latest"

	img, err := mutate.ConfigFile(empty.Image, nil)
	if err != nil {
		t.Fatalf("creating test image: %v", err)
	}

	err = crane.Push(img, imgRef, crane.Insecure)
	if err != nil {
		t.Fatalf("pushing test image: %v", err)
	}

	digest, indexDigest, err := registry.ResolveDigest(
		context.Background(), imgRef,
		remote.WithTransport(server.Client().Transport),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.HasPrefix(digest, "sha256:") {
		t.Errorf("digest = %q, expected sha256: prefix", digest)
	}

	if indexDigest != "" {
		t.Errorf("indexDigest = %q, expected empty for plain image", indexDigest)
	}
}

func TestResolveDigestManifestList(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(ociregistry.New())
	t.Cleanup(server.Close)

	addr := strings.TrimPrefix(server.URL, "http://")
	imgRef := addr + "/multiarch:latest"

	img := makeImage(t, runtime.GOARCH, runtime.GOOS)

	idx := pushIndex(t, server, "multiarch:latest",
		mutate.IndexAddendum{
			Add: img,
			Descriptor: v1.Descriptor{
				Platform: &v1.Platform{
					Architecture: runtime.GOARCH,
					OS:           runtime.GOOS,
					Variant:      registry.PlatformVariant(runtime.GOARCH),
				},
			},
		},
	)

	digest, indexDigest, err := registry.ResolveDigest(
		context.Background(), imgRef,
		remote.WithTransport(server.Client().Transport),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.HasPrefix(digest, "sha256:") {
		t.Errorf("digest = %q, expected sha256: prefix", digest)
	}

	idxDigest, err := idx.Digest()
	if err != nil {
		t.Fatalf("getting index digest: %v", err)
	}

	if indexDigest != idxDigest.String() {
		t.Errorf("indexDigest = %q, expected %q", indexDigest, idxDigest.String())
	}

	if digest == idxDigest.String() {
		t.Error("expected platform-specific digest, got index digest")
	}
}

func TestResolveDigestInvalidRef(t *testing.T) {
	t.Parallel()

	_, _, err := registry.ResolveDigest(context.Background(), ":::invalid")
	if err == nil {
		t.Fatal("expected error for invalid image reference")
	}

	if !strings.Contains(err.Error(), "parsing image reference") {
		t.Errorf("error = %q, expected to contain 'parsing image reference'", err)
	}
}

func TestResolveDigestNetworkError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(ociregistry.New())
	server.Close() // Close immediately to force network error.

	addr := strings.TrimPrefix(server.URL, "http://")
	imgRef := addr + "/unreachable:latest"

	_, _, err := registry.ResolveDigest(
		context.Background(), imgRef,
		remote.WithTransport(server.Client().Transport),
	)
	if err == nil {
		t.Fatal("expected error for closed server")
	}
}

func TestHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ref  string
		want string
	}{
		{
			name: "docker.io reference",
			ref:  "docker.io/library/nginx:latest",
			want: testRegistryDockerIO,
		},
		{
			name: "ghcr.io reference",
			ref:  "ghcr.io/owner/repo:v1",
			want: "ghcr.io",
		},
		{
			name: "localhost reference",
			ref:  "localhost:5000/test/image:v1",
			want: "localhost:5000",
		},
		{
			name: "invalid reference returns input",
			ref:  "not a valid ref %%",
			want: "not a valid ref %%",
		},
		{
			name: "empty string returns empty",
			ref:  "",
			want: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := registry.Host(test.ref)
			if got != test.want {
				t.Errorf("Host(%q) = %q, want %q", test.ref, got, test.want)
			}
		})
	}
}

func TestPlatformVariant(t *testing.T) {
	t.Parallel()

	tests := []struct {
		arch string
		want string
	}{
		{"arm64", "v8"},
		{"arm", "v7"},
		{"amd64", ""},
		{"s390x", ""},
		{"ppc64le", ""},
		{"riscv64", ""},
	}

	for _, test := range tests {
		t.Run(test.arch, func(t *testing.T) {
			t.Parallel()

			got := registry.PlatformVariant(test.arch)
			if got != test.want {
				t.Errorf("PlatformVariant(%q) = %q, want %q", test.arch, got, test.want)
			}
		})
	}
}

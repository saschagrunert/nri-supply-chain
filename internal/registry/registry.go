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

// Package registry provides shared OCI registry helpers for digest resolution.
package registry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// ErrNoPlatformMatch indicates that no image in a manifest list matches the current platform.
var ErrNoPlatformMatch = errors.New("no matching platform image in manifest list")

// Host extracts the registry host from an image reference string.
// On parse failure it returns imageRef unchanged.
func Host(imageRef string) string {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return imageRef
	}

	return ref.Context().RegistryStr()
}

func resolveDigest(
	ctx context.Context,
	imageRef string,
	opts ...remote.Option,
) (digest, indexDigest string, err error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return "", "", fmt.Errorf("parsing image reference: %w", err)
	}

	opts = append(opts, remote.WithContext(ctx))

	desc, err := remote.Get(ref, opts...)
	if err != nil {
		return "", "", fmt.Errorf("resolving image digest: %w", err)
	}

	if desc.MediaType.IsIndex() {
		platformDigest, indexErr := resolveIndexDigest(desc)
		if indexErr != nil {
			return "", "", fmt.Errorf("resolving index digest: %w", indexErr)
		}

		return platformDigest, desc.Digest.String(), nil
	}

	return desc.Digest.String(), "", nil
}

func resolveWithKeychain(
	ctx context.Context, imageRef string,
) (digest, indexDigest string, err error) {
	return resolveDigest(ctx, imageRef, AuthOption())
}

func resolveIndexDigest(desc *remote.Descriptor) (string, error) {
	idx, err := desc.ImageIndex()
	if err != nil {
		return "", fmt.Errorf("reading image index: %w", err)
	}

	manifest, err := idx.IndexManifest()
	if err != nil {
		return "", fmt.Errorf("reading index manifest: %w", err)
	}

	return selectPlatformDigest(manifest.Manifests, runtime.GOOS, runtime.GOARCH)
}

// selectPlatformDigest returns the digest of the first index entry for the
// given OS and architecture. Variants are compared in normalized form, like
// containerd does: an empty arm64 variant means v8 and an empty arm variant
// means v7, so an entry written by BuildKit without a variant matches a node
// that reports one.
func selectPlatformDigest(manifests []v1.Descriptor, goos, goarch string) (string, error) {
	variant := platformVariant(goarch)

	for i := range manifests {
		entry := &manifests[i]

		if platformMatches(entry.Platform, goos, goarch, variant) {
			slog.Debug("Resolved manifest list to platform image",
				"platform", entry.Platform.String(),
				"digest", entry.Digest.String(),
			)

			return entry.Digest.String(), nil
		}
	}

	if variant != "" {
		return "", fmt.Errorf(
			"%w for %s/%s/%s", ErrNoPlatformMatch, goos, goarch, variant,
		)
	}

	return "", fmt.Errorf("%w for %s/%s", ErrNoPlatformMatch, goos, goarch)
}

// platformMatches reports whether an index entry platform runs on the node
// platform. An empty node variant matches every variant.
func platformMatches(platform *v1.Platform, goos, goarch, variant string) bool {
	if platform == nil || platform.OS != goos || platform.Architecture != goarch {
		return false
	}

	if variant == "" {
		return true
	}

	return normalizeVariant(goarch, platform.Variant) == normalizeVariant(goarch, variant)
}

// normalizeVariant spells a CPU variant with its "v" prefix and fills in the
// default variant of arm64 (v8) and arm (v7).
func normalizeVariant(arch, variant string) string {
	if variant != "" && !strings.HasPrefix(variant, "v") {
		variant = "v" + variant
	}

	if variant != "" {
		return variant
	}

	switch arch {
	case "arm64":
		return "v8"
	case "arm":
		return "v7"
	default:
		return ""
	}
}

// platformVariant returns the CPU variant of the node architecture.
func platformVariant(arch string) string {
	return normalizeVariant(arch, "")
}

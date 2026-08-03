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

	"github.com/google/go-containerregistry/pkg/authn"
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

// ResolveDigest resolves an image reference to its digest, handling manifest lists
// by selecting the platform-specific image.
func ResolveDigest(
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
		platformDigest, indexErr := ResolveIndexDigest(desc)
		if indexErr != nil {
			return "", "", fmt.Errorf("resolving index digest: %w", indexErr)
		}

		return platformDigest, desc.Digest.String(), nil
	}

	return desc.Digest.String(), "", nil
}

// ResolveWithDefaultKeychain resolves an image reference to its digest using the
// default container keychain for authentication.
func ResolveWithDefaultKeychain(
	ctx context.Context, imageRef string,
) (digest, indexDigest string, err error) {
	return ResolveDigest(ctx, imageRef, remote.WithAuthFromKeychain(authn.DefaultKeychain))
}

// ResolveIndexDigest extracts the platform-specific digest from a manifest list descriptor.
func ResolveIndexDigest(desc *remote.Descriptor) (string, error) {
	idx, err := desc.ImageIndex()
	if err != nil {
		return "", fmt.Errorf("reading image index: %w", err)
	}

	manifest, err := idx.IndexManifest()
	if err != nil {
		return "", fmt.Errorf("reading index manifest: %w", err)
	}

	platform := v1.Platform{
		Architecture: runtime.GOARCH,
		OS:           runtime.GOOS,
		Variant:      PlatformVariant(runtime.GOARCH),
	}

	for i := range manifest.Manifests {
		entry := &manifest.Manifests[i]

		if entry.Platform != nil && entry.Platform.Satisfies(platform) {
			slog.Debug("Resolved manifest list to platform image",
				"platform", platform.String(),
				"digest", entry.Digest.String(),
			)

			return entry.Digest.String(), nil
		}
	}

	variant := PlatformVariant(runtime.GOARCH)
	if variant != "" {
		return "", fmt.Errorf(
			"%w for %s/%s/%s", ErrNoPlatformMatch,
			runtime.GOOS, runtime.GOARCH, variant,
		)
	}

	return "", fmt.Errorf("%w for %s/%s", ErrNoPlatformMatch, runtime.GOOS, runtime.GOARCH)
}

// PlatformVariant returns the platform variant for the given architecture.
// For arm64, this is "v8". For arm, this defaults to "v7" (matching Go's
// default GOARM=7; the actual GOARM value is not exposed at runtime).
// All other architectures return an empty string.
func PlatformVariant(arch string) string {
	switch arch {
	case "arm64":
		return "v8"
	case "arm":
		return "v7"
	default:
		return ""
	}
}

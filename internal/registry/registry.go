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
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

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

	return selectPlatformDigest(manifest.Manifests, hostPlatform())
}

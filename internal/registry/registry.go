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
	"errors"
	"fmt"
	"log/slog"
	"runtime"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// ErrNoPlatformMatch indicates that no image in a manifest list matches the current platform.
var ErrNoPlatformMatch = errors.New("no matching platform image in manifest list")

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

	return "", fmt.Errorf("%w for %s/%s", ErrNoPlatformMatch, runtime.GOOS, runtime.GOARCH)
}

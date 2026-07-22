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

package plugin

import "context"

// ExportResolveImage exposes resolveImage for external tests.
func ExportResolveImage(annotations map[string]string) (imageRef, digest string) {
	return resolveImage(annotations)
}

// ExportPrewarmImage is an exported alias for prewarmImage.
type ExportPrewarmImage = prewarmImage

// NewExportPrewarmImage creates a prewarmImage for external tests.
func NewExportPrewarmImage(imageRef, digest, namespace string) ExportPrewarmImage {
	return prewarmImage{
		imageRef:  imageRef,
		digest:    digest,
		namespace: namespace,
	}
}

// ExportPrewarmCache exposes prewarmCache for external tests.
func (p *Plugin) ExportPrewarmCache(ctx context.Context, images []ExportPrewarmImage) {
	p.prewarmCache(ctx, images)
}

// ExportSetDigestResolver replaces the digest resolver for testing.
func (p *Plugin) ExportSetDigestResolver(fn DigestResolveFunc) {
	p.digestResolver = fn
}

// ExportDefaultDigestResolver exposes defaultDigestResolver for testing.
func ExportDefaultDigestResolver(ctx context.Context, imageRef string) (string, error) {
	return defaultDigestResolver(ctx, imageRef)
}

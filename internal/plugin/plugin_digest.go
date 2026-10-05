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

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/containerd/nri/pkg/api"
	"github.com/google/go-containerregistry/pkg/name"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/registry"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

func (p *Plugin) registryAwareResolver(
	ctx context.Context, imageRef string,
) (digest, indexDigest string, err error) {
	digest, indexDigest, fallbackUsed, resolveErr := registry.ResolveWithRegistries(
		ctx, imageRef, p.transportCache.Load(),
	)
	if resolveErr != nil {
		return "", "", fmt.Errorf("resolving digest: %w", resolveErr)
	}

	if fallbackUsed {
		p.metrics.MirrorFallbackTotal.WithLabelValues(registry.Host(imageRef), "digest").Inc()
	}

	return digest, indexDigest, nil
}

// resolveDigestIfMissing resolves the platform and index digests of a
// request without a digest, bounded by the digest resolve timeout. unresolved
// is true when the runtime digest is used as is (see resolveImageDigests).
func (p *Plugin) resolveDigestIfMissing(
	ctx context.Context,
	req *types.VerifyRequest,
	runtimeDigest string,
	pod *api.PodSandbox,
	ctr *api.Container,
) (resolvedDigest, resolvedIndexDigest string, unresolved bool, resolveErr error) {
	if req.ImageRef == "" || req.Digest != "" {
		return req.Digest, req.IndexDigest, false, nil
	}

	resolveCtx, cancel := context.WithTimeout(
		ctx, time.Duration(p.digestResolveTimeout.Load()),
	)
	resolved, indexDigest, fromTag, unresolved, err := p.resolveImageDigests(
		resolveCtx, req.ImageRef, runtimeDigest,
	)

	cancel()

	if err != nil {
		slog.WarnContext(ctx, "Failed to resolve image digest",
			"pod", req.Namespace+"/"+pod.GetName(),
			"container", ctr.GetName(),
			"image", req.ImageRef,
			"error", err,
		)

		return "", "", false, fmt.Errorf("resolving digest for %s: %w", req.ImageRef, err)
	}

	if fromTag && p.verifier.EffectiveModeForNamespace(req.Namespace) == config.ModeEnforce {
		// The registry may point the tag at a different image than the one
		// the runtime runs (e.g. a cached image with IfNotPresent).
		slog.WarnContext(ctx,
			"Runtime did not report the image digest, verifying the digest the registry "+
				"currently resolves the reference to",
			"pod", req.Namespace+"/"+pod.GetName(),
			"container", ctr.GetName(),
			"image", req.ImageRef,
			"digest", resolved,
		)
	}

	return resolved, indexDigest, unresolved, nil
}

// resolveImageDigests resolves the platform manifest digest of an image and,
// for multi-platform images, its index digest, as used for attestation
// lookup. With a runtime digest (which may be an index or a manifest digest)
// the digest-pinned reference is resolved, so the result cannot differ from
// the image the runtime runs; when the registry cannot be reached the runtime
// digest is used as is and unresolved is true. Without a runtime digest the
// tag is resolved and fromTag is true.
func (p *Plugin) resolveImageDigests(
	ctx context.Context, imageRef, runtimeDigest string,
) (digest, indexDigest string, fromTag, unresolved bool, err error) {
	if runtimeDigest == "" {
		digest, indexDigest, err = p.digestResolver(ctx, imageRef)

		return digest, indexDigest, true, false, err
	}

	digest, indexDigest, err = p.resolveRuntimeDigest(ctx, imageRef, runtimeDigest)
	if err != nil {
		slog.WarnContext(ctx,
			"Failed to resolve the runtime image digest, verifying it as the manifest digest",
			"image", imageRef,
			"digest", runtimeDigest,
			"error", err,
		)

		return runtimeDigest, "", false, true, nil
	}

	return digest, indexDigest, false, false, nil
}

// resolveRuntimeDigest resolves the platform manifest and index digests of
// the image the runtime reports by runtimeDigest via the digest-pinned
// reference, without falling back to the runtime digest.
func (p *Plugin) resolveRuntimeDigest(
	ctx context.Context, imageRef, runtimeDigest string,
) (digest, indexDigest string, err error) {
	pinned := pinnedReference(imageRef, runtimeDigest)

	digest, indexDigest, err = p.digestResolver(ctx, pinned)
	if err != nil {
		return "", "", err
	}

	if digest == "" {
		return "", "", fmt.Errorf(
			"registry returned no digest for %s: %w", pinned, verifier.ErrEmptyDigest,
		)
	}

	return digest, indexDigest, nil
}

// pinnedReference returns the reference of imageRef's repository pinned to
// digest.
func pinnedReference(imageRef, digest string) string {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		repository, _, _ := strings.Cut(imageRef, "@")

		return repository + "@" + digest
	}

	return ref.Context().Name() + "@" + digest
}

// resolveContainerImage returns the image reference and repository digest of
// a container from the runtime annotations or a digest-pinned image name, and
// the digest the runtime reports in the NRI container image. The runtime
// digest can be an image index digest or a manifest digest, so it is only
// used when no repository digest is known, after resolving it (see
// resolveImageDigests).
func resolveContainerImage(ctr *api.Container) (imageRef, digest, runtimeDigest string) {
	imageRef, digest = resolveImage(ctr.GetAnnotations())

	image := ctr.GetImage()

	if imageRef == "" {
		imageRef = image.GetName()
	}

	if digest == "" {
		if _, pinned, ok := strings.Cut(image.GetName(), "@"); ok {
			digest = validDigestOrEmpty(pinned)
		}
	}

	return imageRef, digest, validDigestOrEmpty(image.GetDigest())
}

func resolveImage(annotations map[string]string) (imageRef, digest string) {
	imageRef, digest = resolveCRIOImage(annotations)

	if imageRef != "" && digest != "" {
		return imageRef, digest
	}

	cImg := annotations[AnnotationContainerdImage]
	cRef := validDigestOrEmpty(annotations[AnnotationContainerdImageRef])

	if cRef == "" && cImg != "" {
		if _, d, ok := strings.Cut(cImg, "@"); ok {
			cRef = validDigestOrEmpty(d)
		}
	}

	if cImg != "" && cRef != "" {
		return cImg, cRef
	}

	if imageRef == "" {
		imageRef = cImg
	}

	if digest == "" {
		digest = cRef
	}

	return imageRef, digest
}

func resolveCRIOImage(annotations map[string]string) (imageRef, digest string) {
	imageRef = annotations[AnnotationImageName]
	if imageRef == "" {
		imageRef = annotations[AnnotationImage]
	}

	if repoDigests := annotations[AnnotationImageRepoDigests]; repoDigests != "" {
		first, _, _ := strings.Cut(repoDigests, ",")
		if _, d, ok := strings.Cut(first, "@"); ok {
			digest = validDigestOrEmpty(d)
		}
	}

	if digest == "" {
		digest = validDigestOrEmpty(annotations[AnnotationImageRef])
	}

	if digest == "" {
		if _, d, ok := strings.Cut(annotations[AnnotationImageRef], "@"); ok {
			digest = validDigestOrEmpty(d)
		}
	}

	return imageRef, digest
}

var relevantAnnotationKeys = []string{ //nolint:gochecknoglobals // static lookup set
	AnnotationImageName,
	AnnotationImage,
	AnnotationImageRef,
	AnnotationImageRepoDigests,
	AnnotationContainerdImage,
	AnnotationContainerdImageRef,
}

func filterRelevantAnnotations(annotations map[string]string) map[string]string {
	filtered := make(map[string]string, len(relevantAnnotationKeys))

	for _, key := range relevantAnnotationKeys {
		if val, ok := annotations[key]; ok {
			filtered[key] = val
		}
	}

	return filtered
}

func validDigestOrEmpty(ref string) string {
	algo, _ := types.ParseDigest(ref)
	if algo == "" {
		return ""
	}

	return ref
}

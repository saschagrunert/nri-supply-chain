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

// Package plugin implements the NRI hooks for supply chain attestation verification.
package plugin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"golang.org/x/sync/semaphore"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

// ErrMissingAnnotations indicates that required image annotations are absent.
var ErrMissingAnnotations = errors.New("missing image annotations")

// ErrNoPlatformMatch indicates that no image in a manifest list matches the current platform.
var ErrNoPlatformMatch = errors.New("no matching platform image in manifest list")

// DigestResolveFunc resolves an image reference to its platform-specific digest
// via a registry. When the tag points to a manifest list, indexDigest returns
// the manifest list digest (for attestation lookup); otherwise it is empty.
type DigestResolveFunc func(ctx context.Context, imageRef string) (digest, indexDigest string, err error)

const (
	prewarmConcurrency = 5
	prewarmTimeout     = 5 * time.Minute
)

type prewarmImage struct {
	imageRef    string
	digest      string
	indexDigest string
	namespace   string
}

const (
	// AnnotationImageName is the CRI-O annotation for the user-specified image reference.
	AnnotationImageName = "io.kubernetes.cri-o.ImageName"
	// AnnotationImage is the CRI-O annotation containing the image ID.
	AnnotationImage = "io.kubernetes.cri-o.Image"
	// AnnotationImageRef is the CRI-O annotation for the resolved image digest.
	AnnotationImageRef = "io.kubernetes.cri-o.ImageRef"
	// AnnotationImageRepoDigests contains the comma-separated digest references.
	AnnotationImageRepoDigests = "io.kubernetes.cri-o.ImageRepoDigests"

	// AnnotationContainerdImage is the containerd annotation for the image name.
	AnnotationContainerdImage = "io.kubernetes.cri.image-name"
	// AnnotationContainerdImageRef is the containerd annotation for the image digest.
	AnnotationContainerdImageRef = "io.kubernetes.cri.image-ref"
)

// Plugin implements the NRI CreateContainer and Configure hooks
// for supply chain attestation verification.
type Plugin struct {
	verifier       *verifier.Verifier
	metrics        *metrics.Metrics
	configPath     string
	connected      atomic.Bool
	digestResolver DigestResolveFunc
	fetchTimeout   time.Duration
}

// New creates a new Plugin with the given verifier, metrics, and config file path.
func New(
	v *verifier.Verifier, met *metrics.Metrics, configPath string, fetchTimeout time.Duration,
) *Plugin {
	return &Plugin{
		verifier:       v,
		metrics:        met,
		configPath:     configPath,
		connected:      atomic.Bool{},
		digestResolver: defaultDigestResolver,
		fetchTimeout:   fetchTimeout,
	}
}

func defaultDigestResolver(
	ctx context.Context, imageRef string,
) (digest, indexDigest string, err error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return "", "", fmt.Errorf("parsing image reference: %w", err)
	}

	desc, err := remote.Get(ref,
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithContext(ctx),
	)
	if err != nil {
		return "", "", fmt.Errorf("resolving image digest: %w", err)
	}

	if desc.MediaType.IsIndex() {
		platformDigest, indexErr := resolveIndexDigest(desc)
		if indexErr != nil {
			return "", "", indexErr
		}

		return platformDigest, desc.Digest.String(), nil
	}

	return desc.Digest.String(), "", nil
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

// Connected returns true if the plugin has successfully connected to the NRI runtime.
func (p *Plugin) Connected() bool {
	return p.connected.Load()
}

// VerifierReady returns true if the verifier is ready to serve requests.
func (p *Plugin) VerifierReady() (ready bool, reason string) {
	return p.verifier.Ready()
}

// SetDisconnected marks the plugin as disconnected from the NRI runtime.
func (p *Plugin) SetDisconnected() {
	p.connected.Store(false)
}

// Configure is called when the plugin connects to the NRI runtime.
func (p *Plugin) Configure(
	ctx context.Context, cfg, rt, version string,
) (stub.EventMask, error) {
	slog.Info("Connected to runtime", "runtime", rt, "version", version)

	if p.configPath == "" && cfg != "" {
		parsed, err := config.LoadFromString(cfg)
		if err != nil {
			return 0, fmt.Errorf("parsing NRI config: %w", err)
		}

		err = parsed.ValidateRuntime()
		if err != nil {
			return 0, fmt.Errorf("validating NRI config: %w", err)
		}

		err = p.verifier.Reload(ctx, parsed)
		if err != nil {
			return 0, fmt.Errorf("applying NRI config: %w", err)
		}
	}

	p.connected.Store(true)

	return 0, nil
}

// Synchronize is called by NRI after Configure to deliver the list of
// running pods and containers. It spawns a background goroutine to
// pre-verify images from existing containers, warming the cache.
func (p *Plugin) Synchronize(
	ctx context.Context, pods []*api.PodSandbox, containers []*api.Container,
) ([]*api.ContainerUpdate, error) {
	podNS := make(map[string]string, len(pods))

	for _, pod := range pods {
		podNS[pod.GetId()] = pod.GetNamespace()
	}

	images := p.collectPrewarmImages(ctx, containers, podNS)

	if len(images) == 0 {
		return nil, nil
	}

	// Use context.WithoutCancel so the pre-warm goroutine is not
	// interrupted when the ttrpc request context completes.
	go p.prewarmCache(context.WithoutCancel(ctx), images)

	return nil, nil
}

// CreateContainer is called for each new container before it is created.
// It verifies supply chain attestations and rejects the container on failure.
func (p *Plugin) CreateContainer(
	ctx context.Context, pod *api.PodSandbox, ctr *api.Container,
) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	annotations := ctr.GetAnnotations()
	imageRef, digest := resolveImage(annotations)
	namespace := pod.GetNamespace()

	slog.DebugContext(ctx, "NRI container info",
		"container_id", ctr.GetId(),
		"container_name", ctr.GetName(),
		"annotations", annotations,
		"labels", ctr.GetLabels(),
	)

	digest, indexDigest := p.resolveDigestIfMissing(ctx, imageRef, digest, namespace, pod, ctr)

	if imageRef == "" || digest == "" {
		return p.handleMissingAnnotations(
			ctx, namespace, pod, ctr, imageRef, digest, len(annotations),
		)
	}

	result, err := p.verifier.Verify(ctx, imageRef, digest, indexDigest, namespace)
	if err != nil {
		slog.ErrorContext(ctx, "Container rejected",
			"pod", namespace+"/"+pod.GetName(),
			"container", ctr.GetName(),
			"image", imageRef,
			"error", err,
		)

		return nil, nil, fmt.Errorf("supply chain verification: %w", err)
	}

	slog.InfoContext(ctx, "Container verified",
		"pod", namespace+"/"+pod.GetName(),
		"container", ctr.GetName(),
		"image", imageRef,
		"allowed", result.Allowed,
	)

	return nil, nil, nil
}

func (p *Plugin) handleMissingAnnotations(
	ctx context.Context, namespace string,
	pod *api.PodSandbox, ctr *api.Container,
	imageRef, digest string, annotationCount int,
) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	if p.verifier.Enforcing() {
		slog.ErrorContext(ctx, "Missing image annotations in enforce mode",
			"pod", namespace+"/"+pod.GetName(),
			"container", ctr.GetName(),
			"image_ref", imageRef,
			"digest", digest,
			"annotation_count", annotationCount,
		)

		return nil, nil, fmt.Errorf(
			"%w for container %s", ErrMissingAnnotations, ctr.GetName(),
		)
	}

	slog.WarnContext(ctx, "Missing image annotations, skipping verification",
		"pod", namespace+"/"+pod.GetName(),
		"container", ctr.GetName(),
		"image_ref", imageRef,
		"digest", digest,
		"annotation_count", annotationCount,
	)

	p.metrics.VerificationSkippedTotal.WithLabelValues("missing_annotations", namespace).Inc()

	return nil, nil, nil
}

func (p *Plugin) resolveDigestIfMissing(
	ctx context.Context,
	imageRef, digest, namespace string,
	pod *api.PodSandbox,
	ctr *api.Container,
) (resolvedDigest, resolvedIndexDigest string) {
	if imageRef == "" || digest != "" {
		return digest, ""
	}

	resolveCtx, cancel := context.WithTimeout(ctx, p.fetchTimeout)
	resolved, indexDigest, err := p.digestResolver(resolveCtx, imageRef)

	cancel()

	if err != nil {
		slog.WarnContext(ctx, "Failed to resolve image digest",
			"pod", namespace+"/"+pod.GetName(),
			"container", ctr.GetName(),
			"image", imageRef,
			"error", err,
		)

		return digest, ""
	}

	return resolved, indexDigest
}

func (p *Plugin) collectPrewarmImages(
	ctx context.Context, containers []*api.Container, podNS map[string]string,
) []prewarmImage {
	var images []prewarmImage

	seen := make(map[string]struct{})

	for _, ctr := range containers {
		annotations := ctr.GetAnnotations()
		imageRef, digest := resolveImage(annotations)

		var indexDigest string

		if imageRef != "" && digest == "" {
			resolveCtx, cancel := context.WithTimeout(ctx, p.fetchTimeout)
			resolved, idxDig, err := p.digestResolver(resolveCtx, imageRef)

			cancel()

			if err != nil {
				slog.DebugContext(ctx, "Skipping prewarm, failed to resolve digest",
					"container", ctr.GetName(),
					"image", imageRef,
					"error", err,
				)
			} else {
				digest = resolved
				indexDigest = idxDig
			}
		}

		if imageRef == "" || digest == "" {
			continue
		}

		namespace := podNS[ctr.GetPodSandboxId()]

		key := digest + "\x00" + namespace

		if _, ok := seen[key]; ok {
			continue
		}

		seen[key] = struct{}{}

		images = append(images, prewarmImage{
			imageRef:    imageRef,
			digest:      digest,
			indexDigest: indexDigest,
			namespace:   namespace,
		})
	}

	return images
}

func (p *Plugin) prewarmCache(ctx context.Context, images []prewarmImage) {
	ctx, cancel := context.WithTimeout(ctx, prewarmTimeout)
	defer cancel()

	total := len(images)
	slog.Info("Pre-warming cache", "images", total)

	sem := semaphore.NewWeighted(prewarmConcurrency)
	verified := atomic.Int32{}

	for idx := range images {
		img := images[idx]

		err := sem.Acquire(ctx, 1)
		if err != nil {
			slog.Warn("Pre-warm cache cancelled", "error", err)

			break
		}

		go func() {
			defer sem.Release(1)

			_, verifyErr := p.verifier.Verify(
				ctx, img.imageRef, img.digest, img.indexDigest, img.namespace,
			)
			if verifyErr != nil {
				slog.Debug("Pre-warm verification failed",
					"image", img.imageRef,
					"error", verifyErr,
				)
			}

			count := verified.Add(1)
			slog.Debug("Pre-warming cache progress",
				"verified", count,
				"total", total,
			)
		}()
	}

	// Wait for all in-flight pre-warm goroutines to finish.
	err := sem.Acquire(ctx, prewarmConcurrency)
	if err != nil {
		slog.Warn("Pre-warm cache wait cancelled", "error", err)

		return
	}

	slog.Info("Pre-warming cache complete",
		"verified", verified.Load(),
		"total", total,
	)
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

	return imageRef, digest
}

func validDigestOrEmpty(ref string) string {
	algo, _ := types.ParseDigest(ref)
	if algo == "" {
		return ""
	}

	return ref
}

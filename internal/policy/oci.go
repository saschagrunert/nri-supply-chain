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

package policy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	ociV1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/saschagrunert/nri-supply-chain/internal/registry"
)

const (
	// PolicyMediaType is the preferred media type for OCI policy layers.
	PolicyMediaType = "application/vnd.nri-supply-chain.policy.v1+json"

	// titleAnnotation is the OCI annotation for the layer filename.
	titleAnnotation = "org.opencontainers.image.title"

	// CreatedAnnotation is the OCI manifest annotation holding the RFC 3339
	// creation time of the policy artifact. It is covered by the manifest
	// digest (and therefore by the artifact signature) and is used to
	// refuse rolling back to an older policy artifact.
	CreatedAnnotation = "org.opencontainers.image.created"

	maxOCIPolicyLayerSize = 1 << 20 // 1 MiB per layer
	maxOCIPolicyLayers    = 1000

	// maxCreatedClockSkew is how far in the future an artifact creation time
	// may be before it is rejected.
	maxCreatedClockSkew = 5 * time.Minute
)

var (
	// ErrOCIPolicyLayerTooLarge indicates a policy layer exceeds the size limit.
	ErrOCIPolicyLayerTooLarge = errors.New("OCI policy layer exceeds size limit")

	// ErrTooManyOCIPolicyLayers indicates the artifact has too many layers.
	ErrTooManyOCIPolicyLayers = errors.New("OCI policy artifact has too many layers")

	// ErrNonJSONPolicyLayer indicates a policy-typed layer has a non-JSON filename.
	ErrNonJSONPolicyLayer = errors.New("OCI policy layer has non-JSON filename")

	// ErrOCIPolicyLayerUntitled indicates a policy layer has no title
	// annotation, so it cannot be mapped to a namespace.
	ErrOCIPolicyLayerUntitled = errors.New(
		"OCI policy layer has no " + titleAnnotation + " annotation",
	)

	// ErrNoOCIPolicies indicates an OCI policy artifact contains no policies.
	ErrNoOCIPolicies = errors.New("OCI policy artifact contains no policies")

	// ErrOCIPolicyRollback indicates a fetched policy artifact is older than
	// one that was already applied, or lost its creation timestamp.
	ErrOCIPolicyRollback = errors.New("OCI policy artifact is older than the applied policy")

	// ErrInvalidCreatedAnnotation indicates a malformed creation timestamp.
	ErrInvalidCreatedAnnotation = errors.New(
		"invalid " + CreatedAnnotation + " annotation, must be RFC 3339",
	)
)

// OCIFetchResult holds the policies and manifest digest returned by FetchFromOCI.
type OCIFetchResult struct {
	Policies map[string]*Policy
	Digest   string
	// Created is the artifact creation time from the manifest annotation, or
	// the zero time when the annotation is absent.
	Created time.Time
}

// ImageFetchFunc pulls an OCI image by reference.
type ImageFetchFunc func(ref name.Reference, options ...remote.Option) (ociV1.Image, error)

// HeadFetchFunc performs a HEAD request for an OCI reference and returns its descriptor.
type HeadFetchFunc func(ref name.Reference, options ...remote.Option) (*ociV1.Descriptor, error)

// OCIFetcher pulls policy files from an OCI registry artifact.
type OCIFetcher struct {
	fetchImage      ImageFetchFunc
	fetchHead       HeadFetchFunc
	transportCache  *registry.TransportCache
	verifySignature SignatureVerifyFunc

	// newestCreated is the newest artifact creation time returned by this
	// fetcher. Older artifacts are rejected to prevent rollbacks.
	newestCreated time.Time
	createdMu     sync.Mutex
}

// NewOCIFetcher creates a new OCI policy fetcher.
func NewOCIFetcher(tc *registry.TransportCache) *OCIFetcher {
	return &OCIFetcher{
		fetchImage:      remote.Image,
		fetchHead:       remote.Head,
		transportCache:  tc,
		verifySignature: nil,
		newestCreated:   time.Time{},
		createdMu:       sync.Mutex{},
	}
}

// NewOCIFetcherWithSignatureVerification creates an OCI policy fetcher that
// verifies Sigstore signatures on the policy artifact before extracting
// policies.
func NewOCIFetcherWithSignatureVerification(
	tc *registry.TransportCache, verifyFn SignatureVerifyFunc,
) *OCIFetcher {
	return &OCIFetcher{
		fetchImage:      remote.Image,
		fetchHead:       remote.Head,
		transportCache:  tc,
		verifySignature: verifyFn,
		newestCreated:   time.Time{},
		createdMu:       sync.Mutex{},
	}
}

// NewOCIFetcherWithImageFunc creates an OCI policy fetcher with a custom image
// fetch function, useful for testing. CheckDigest falls back to fetching the
// full image to derive the digest, matching the mock's behavior.
func NewOCIFetcherWithImageFunc(
	fn ImageFetchFunc, tc *registry.TransportCache,
) *OCIFetcher {
	return &OCIFetcher{
		fetchImage:      fn,
		fetchHead:       nil,
		transportCache:  tc,
		verifySignature: nil,
		newestCreated:   time.Time{},
		createdMu:       sync.Mutex{},
	}
}

// SetTransportCache replaces the transport cache used for registry connections.
// This is not safe for concurrent use; callers must ensure the fetcher is not
// in active use (e.g., the poller is stopped).
func (f *OCIFetcher) SetTransportCache(tc *registry.TransportCache) {
	f.transportCache = tc
}

// CheckDigest returns the manifest digest for the given OCI reference without
// downloading layers. When a HEAD function is available (production path), it
// issues a single HEAD request. When using a custom image fetch function
// (testing), it falls back to fetching the image to derive the digest.
func (f *OCIFetcher) CheckDigest(
	ctx context.Context, ociRef string,
) (string, error) {
	ref, err := name.ParseReference(ociRef)
	if err != nil {
		return "", fmt.Errorf("parsing OCI policy reference %q: %w", ociRef, err)
	}

	remoteOpts, err := f.buildRemoteOptions(ctx, ociRef)
	if err != nil {
		return "", err
	}

	if f.fetchHead != nil {
		desc, headErr := f.fetchHead(ref, remoteOpts...)
		if headErr != nil {
			return "", fmt.Errorf("HEAD request for OCI policy artifact %q: %w", ociRef, headErr)
		}

		return desc.Digest.String(), nil
	}

	img, err := f.fetchImage(ref, remoteOpts...)
	if err != nil {
		return "", fmt.Errorf("pulling OCI policy artifact %q: %w", ociRef, err)
	}

	digest, err := img.Digest()
	if err != nil {
		return "", fmt.Errorf("reading manifest digest: %w", err)
	}

	return digest.String(), nil
}

// FetchFromOCI pulls a policy artifact from the given OCI reference, extracts
// JSON policy files from its layers, and returns parsed policies keyed by
// namespace (empty string for default.json). The manifest digest is returned
// for change detection. Any invalid policy layer fails the whole fetch, and
// an artifact older than the newest accepted one (based on the
// org.opencontainers.image.created manifest annotation, see
// SeedNewestCreated) is rejected.
func (f *OCIFetcher) FetchFromOCI(
	ctx context.Context, ociRef string,
) (*OCIFetchResult, error) {
	ref, err := name.ParseReference(ociRef)
	if err != nil {
		return nil, fmt.Errorf("parsing OCI policy reference %q: %w", ociRef, err)
	}

	if _, isDigest := ref.(name.Digest); !isDigest {
		slog.WarnContext(ctx,
			"OCI policy fetched by mutable tag reference;"+
				" consider using a digest reference for integrity",
			"ref", ociRef,
		)
	}

	remoteOpts, err := f.buildRemoteOptions(ctx, ociRef)
	if err != nil {
		return nil, err
	}

	img, err := f.fetchImage(ref, remoteOpts...)
	if err != nil {
		return nil, fmt.Errorf("pulling OCI policy artifact %q: %w", ociRef, err)
	}

	if f.verifySignature != nil {
		sigErr := f.verifySignature(ctx, ref, img, remoteOpts)
		if sigErr != nil {
			return nil, fmt.Errorf(
				"OCI policy signature verification failed for %q: %w", ociRef, sigErr,
			)
		}
	}

	digest, err := img.Digest()
	if err != nil {
		return nil, fmt.Errorf("reading manifest digest: %w", err)
	}

	policies, created, err := f.policiesFromImage(img, ociRef)
	if err != nil {
		return nil, err
	}

	return &OCIFetchResult{
		Policies: policies,
		Digest:   digest.String(),
		Created:  created,
	}, nil
}

// NewestCreated returns the newest accepted artifact creation time, or the
// zero time when none was accepted yet.
func (f *OCIFetcher) NewestCreated() time.Time {
	f.createdMu.Lock()
	defer f.createdMu.Unlock()

	return f.newestCreated
}

// SeedNewestCreated raises the rollback guard to created. Callers use it to
// record an artifact once its policies were accepted (FetchFromOCI only checks
// the guard), and to seed a fetcher that replaces another one (e.g. on config
// reload) so it keeps rejecting artifacts older than the ones already
// applied. Older values are ignored.
func (f *OCIFetcher) SeedNewestCreated(created time.Time) {
	f.createdMu.Lock()
	defer f.createdMu.Unlock()

	if created.After(f.newestCreated) {
		f.newestCreated = created
	}
}

// policiesFromImage extracts and resolves the policies of a pulled artifact
// and enforces the rollback protection.
func (f *OCIFetcher) policiesFromImage(
	img ociV1.Image, ociRef string,
) (map[string]*Policy, time.Time, error) {
	policies, err := extractPoliciesFromImage(img)
	if err != nil {
		return nil, time.Time{}, err
	}

	err = applyInheritance(policies)
	if err != nil {
		return nil, time.Time{}, err
	}

	created, err := artifactCreated(img)
	if err != nil {
		return nil, time.Time{}, err
	}

	err = f.checkRollback(created)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("OCI policy artifact %q: %w", ociRef, err)
	}

	return policies, created, nil
}

func artifactCreated(img ociV1.Image) (time.Time, error) {
	manifest, err := img.Manifest()
	if err != nil {
		return time.Time{}, fmt.Errorf("reading OCI policy manifest: %w", err)
	}

	if manifest == nil {
		return time.Time{}, nil
	}

	raw := manifest.Annotations[CreatedAnnotation]
	if raw == "" {
		return time.Time{}, nil
	}

	created, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: got %q", ErrInvalidCreatedAnnotation, raw)
	}

	return created, nil
}

// checkRollback rejects artifacts older than the newest accepted one. Once an
// artifact with a creation timestamp was accepted, artifacts without one are
// rejected as well, since stripping the annotation would otherwise bypass the
// check. Creation times too far in the future are rejected, because accepting
// one would block every later update. The check does not record created: the
// caller does that via SeedNewestCreated once the policies were applied, so a
// rejected artifact never raises the guard.
func (f *OCIFetcher) checkRollback(created time.Time) error {
	if created.After(time.Now().Add(maxCreatedClockSkew)) {
		return fmt.Errorf(
			"%w: created %s is in the future",
			ErrInvalidCreatedAnnotation, created.Format(time.RFC3339),
		)
	}

	f.createdMu.Lock()
	defer f.createdMu.Unlock()

	if f.newestCreated.IsZero() {
		return nil
	}

	if created.IsZero() {
		return fmt.Errorf(
			"%w: missing %s annotation, previously applied artifact was created %s",
			ErrOCIPolicyRollback, CreatedAnnotation, f.newestCreated.Format(time.RFC3339),
		)
	}

	if created.Before(f.newestCreated) {
		return fmt.Errorf(
			"%w: created %s, previously applied artifact was created %s",
			ErrOCIPolicyRollback,
			created.Format(time.RFC3339), f.newestCreated.Format(time.RFC3339),
		)
	}

	return nil
}

func (f *OCIFetcher) buildRemoteOptions(
	ctx context.Context, imageRef string,
) ([]remote.Option, error) {
	opts := []remote.Option{
		registry.AuthOption(),
		remote.WithContext(ctx),
	}

	if f.transportCache == nil {
		return opts, nil
	}

	_, transportOpt, _, regErr := registry.OptionsForRegistries(
		f.transportCache, imageRef,
	)
	if regErr != nil {
		return nil, fmt.Errorf("building registry options for policy fetch: %w", regErr)
	}

	if transportOpt != nil {
		opts = append(opts, transportOpt)
	}

	return opts, nil
}

func extractPoliciesFromImage(img ociV1.Image) (map[string]*Policy, error) {
	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("reading OCI policy layers: %w", err)
	}

	if len(layers) > maxOCIPolicyLayers {
		return nil, fmt.Errorf(
			"%w: got %d, max %d",
			ErrTooManyOCIPolicyLayers, len(layers), maxOCIPolicyLayers,
		)
	}

	manifest, err := img.Manifest()
	if err != nil {
		return nil, fmt.Errorf("reading OCI policy manifest: %w", err)
	}

	policies := make(map[string]*Policy, len(layers))
	sources := make(map[string]string, len(layers))

	for idx, layer := range layers {
		annotations := layerAnnotations(manifest, idx)

		pol, namespace, ok, err := processOCIPolicyLayer(layer, idx, annotations)
		if err != nil {
			return nil, err
		}

		if !ok {
			continue
		}

		title := annotations[titleAnnotation]
		if previous, exists := sources[namespace]; exists {
			return nil, fmt.Errorf(
				"%w %q: layers %q and %q",
				ErrDuplicatePolicyNamespace, namespaceLabel(namespace), previous, title,
			)
		}

		sources[namespace] = title
		policies[namespace] = pol
	}

	if len(policies) == 0 {
		return nil, fmt.Errorf("%w: %d layers", ErrNoOCIPolicies, len(layers))
	}

	return policies, nil
}

func layerAnnotations(manifest *ociV1.Manifest, idx int) map[string]string {
	if manifest == nil || idx >= len(manifest.Layers) {
		return nil
	}

	return manifest.Layers[idx].Annotations
}

func namespaceLabel(namespace string) string {
	if namespace == "" {
		return DefaultPolicyLabel
	}

	return namespace
}

// processOCIPolicyLayer parses a single layer. Layers with non-policy media
// types, and generic JSON or tar layers without a JSON title, are skipped.
// Every layer that is identified as a policy must be valid, otherwise the
// whole artifact is rejected so a namespace policy is never dropped silently.
func processOCIPolicyLayer( //nolint:nonamedreturns // named returns for clarity
	layer ociV1.Layer, idx int, annotations map[string]string,
) (pol *Policy, namespace string, ok bool, err error) {
	mediaType, err := layer.MediaType()
	if err != nil {
		return nil, "", false, fmt.Errorf("reading OCI policy layer %d media type: %w", idx, err)
	}

	if !isPolicyMediaType(string(mediaType)) {
		return nil, "", false, nil
	}

	strict := string(mediaType) == PolicyMediaType
	filename := annotations[titleAnnotation]

	switch {
	case filename == "" && strict:
		return nil, "", false, fmt.Errorf("%w: layer %d", ErrOCIPolicyLayerUntitled, idx)
	case filename == "":
		slog.Warn("Skipping untitled OCI policy layer", "index", idx, "media_type", mediaType)

		return nil, "", false, nil
	case !strings.HasSuffix(filename, policyFileExtension):
		return handleNonJSONLayer(strict, idx, filename)
	}

	namespace, err = NamespaceFromFilename(filename)
	if err != nil {
		return nil, "", false, fmt.Errorf("OCI policy layer %d: %w", idx, err)
	}

	data, err := readLayer(layer, idx)
	if err != nil {
		return nil, "", false, fmt.Errorf(
			"reading OCI policy layer %d %q: %w", idx, filename, err,
		)
	}

	pol, err = decodePolicy(data, fmt.Sprintf("policy %q", filename))
	if err != nil {
		return nil, "", false, fmt.Errorf(
			"invalid OCI policy layer %d %q: %w", idx, filename, err,
		)
	}

	return pol, namespace, true, nil
}

func handleNonJSONLayer( //nolint:nonamedreturns // named returns for clarity
	strict bool, idx int, filename string,
) (pol *Policy, namespace string, ok bool, err error) {
	if strict {
		return nil, "", false, fmt.Errorf(
			"%w: layer %d (%s) filename %q",
			ErrNonJSONPolicyLayer, idx, PolicyMediaType, filename,
		)
	}

	slog.Debug("Skipping non-JSON OCI policy layer",
		"index", idx,
		"filename", filename,
	)

	return nil, "", false, nil
}

func isPolicyMediaType(mediaType string) bool {
	switch mediaType {
	case PolicyMediaType, "application/json",
		"application/vnd.oci.image.layer.v1.tar+gzip",
		"application/vnd.oci.image.layer.v1.tar",
		"":
		return true
	default:
		return false
	}
}

func readLayer(layer ociV1.Layer, idx int) ([]byte, error) {
	reader, err := layer.Uncompressed()
	if err != nil {
		return nil, fmt.Errorf("opening layer %d: %w", idx, err)
	}

	defer func() {
		closeErr := reader.Close()
		if closeErr != nil {
			slog.Warn("Failed to close OCI policy layer reader",
				"index", idx,
				"error", closeErr,
			)
		}
	}()

	data, err := io.ReadAll(io.LimitReader(reader, maxOCIPolicyLayerSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading layer %d: %w", idx, err)
	}

	if int64(len(data)) > maxOCIPolicyLayerSize {
		return nil, fmt.Errorf(
			"%w: layer %d exceeds %d bytes",
			ErrOCIPolicyLayerTooLarge, idx, maxOCIPolicyLayerSize,
		)
	}

	return data, nil
}

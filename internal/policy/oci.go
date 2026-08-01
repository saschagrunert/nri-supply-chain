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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
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

	maxOCIPolicyLayerSize = 1 << 20 // 1 MiB per layer
	maxOCIPolicyLayers    = 1000
)

var (
	// ErrOCIPolicyLayerTooLarge indicates a policy layer exceeds the size limit.
	ErrOCIPolicyLayerTooLarge = errors.New("OCI policy layer exceeds size limit")

	// ErrTooManyOCIPolicyLayers indicates the artifact has too many layers.
	ErrTooManyOCIPolicyLayers = errors.New("OCI policy artifact has too many layers")
)

// OCIFetchResult holds the policies and manifest digest returned by FetchFromOCI.
type OCIFetchResult struct {
	Policies map[string]*Policy
	Digest   string
}

// ImageFetchFunc pulls an OCI image by reference.
type ImageFetchFunc func(ref name.Reference, options ...remote.Option) (ociV1.Image, error)

// OCIFetcher pulls policy files from an OCI registry artifact.
type OCIFetcher struct {
	fetchImage     ImageFetchFunc
	transportCache *registry.TransportCache
}

// NewOCIFetcher creates a new OCI policy fetcher.
func NewOCIFetcher(tc *registry.TransportCache) *OCIFetcher {
	return &OCIFetcher{
		fetchImage:     remote.Image,
		transportCache: tc,
	}
}

// NewOCIFetcherWithImageFunc creates an OCI policy fetcher with a custom image
// fetch function, useful for testing.
func NewOCIFetcherWithImageFunc(
	fn ImageFetchFunc, tc *registry.TransportCache,
) *OCIFetcher {
	return &OCIFetcher{
		fetchImage:     fn,
		transportCache: tc,
	}
}

// CheckDigest fetches the manifest for the given OCI reference and returns
// its digest without downloading layers. Use this for cheap change detection
// before calling FetchFromOCI.
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
// for change detection.
func (f *OCIFetcher) FetchFromOCI(
	ctx context.Context, ociRef string,
) (*OCIFetchResult, error) {
	ref, err := name.ParseReference(ociRef)
	if err != nil {
		return nil, fmt.Errorf("parsing OCI policy reference %q: %w", ociRef, err)
	}

	remoteOpts, err := f.buildRemoteOptions(ctx, ociRef)
	if err != nil {
		return nil, err
	}

	img, err := f.fetchImage(ref, remoteOpts...)
	if err != nil {
		return nil, fmt.Errorf("pulling OCI policy artifact %q: %w", ociRef, err)
	}

	digest, err := img.Digest()
	if err != nil {
		return nil, fmt.Errorf("reading manifest digest: %w", err)
	}

	policies, err := extractPoliciesFromImage(img)
	if err != nil {
		return nil, err
	}

	err = applyInheritance(policies)
	if err != nil {
		return nil, err
	}

	return &OCIFetchResult{
		Policies: policies,
		Digest:   digest.String(),
	}, nil
}

func (f *OCIFetcher) buildRemoteOptions(
	ctx context.Context, imageRef string,
) ([]remote.Option, error) {
	opts := []remote.Option{
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
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

func extractPoliciesFromImage(
	img ociV1.Image,
) (map[string]*Policy, error) {
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

	for idx, layer := range layers {
		var annotations map[string]string

		if manifest != nil && idx < len(manifest.Layers) {
			annotations = manifest.Layers[idx].Annotations
		}

		pol, namespace, ok := processOCIPolicyLayer(layer, idx, annotations)
		if !ok {
			continue
		}

		if _, exists := policies[namespace]; exists {
			filename := layerFilename(annotations, idx)
			slog.Warn("Duplicate OCI policy layer, overwriting previous",
				"index", idx,
				"filename", filename,
				"namespace", namespace,
			)
		}

		policies[namespace] = pol
	}

	return policies, nil
}

func processOCIPolicyLayer(
	layer ociV1.Layer, idx int, annotations map[string]string,
) (*Policy, string, bool) {
	mediaType, err := layer.MediaType()
	if err != nil {
		slog.Warn("Failed to read OCI policy layer media type",
			"index", idx,
			"error", err,
		)

		return nil, "", false
	}

	if !isPolicyMediaType(string(mediaType)) {
		return nil, "", false
	}

	filename := layerFilename(annotations, idx)
	if !strings.HasSuffix(filename, ".json") {
		slog.Debug("Skipping non-JSON OCI policy layer",
			"index", idx,
			"filename", filename,
		)

		return nil, "", false
	}

	data, err := readLayer(layer, idx)
	if err != nil {
		slog.Warn("Failed to read OCI policy layer",
			"index", idx,
			"filename", filename,
			"error", err,
		)

		return nil, "", false
	}

	pol, err := parseAndValidatePolicy(data, filename)
	if err != nil {
		slog.Warn("Invalid OCI policy layer",
			"index", idx,
			"filename", filename,
			"error", err,
		)

		return nil, "", false
	}

	namespace := strings.TrimSuffix(filename, ".json")
	if namespace == "default" {
		namespace = ""
	}

	return pol, namespace, true
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

func layerFilename(annotations map[string]string, idx int) string {
	if title, ok := annotations[titleAnnotation]; ok && title != "" {
		return title
	}

	return fmt.Sprintf("layer-%d.json", idx)
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

func parseAndValidatePolicy(data []byte, filename string) (*Policy, error) {
	var pol Policy

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	err := dec.Decode(&pol)
	if err != nil {
		return nil, fmt.Errorf("parsing policy %q: %w", filename, err)
	}

	err = dec.Decode(&struct{}{})
	if !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("%w: %q", ErrTrailingContent, filename)
		}

		return nil, fmt.Errorf(
			"parsing policy %q: unexpected trailing content: %w",
			filename, err,
		)
	}

	err = pol.Validate()
	if err != nil {
		return nil, fmt.Errorf("invalid policy %q: %w", filename, err)
	}

	return &pol, nil
}

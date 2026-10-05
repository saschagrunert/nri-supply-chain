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

package attestation

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	ociV1 "github.com/google/go-containerregistry/pkg/v1"
)

//nolint:gochecknoglobals // immutable magic byte prefixes
var (
	gzipMagic = []byte{0x1f, 0x8b}
	zstdMagic = []byte{0x28, 0xb5, 0x2f, 0xfd}
)

// readFirstLayer reads the first layer of an artifact image, bounded by the
// configured attestation size limit. Content problems (no layers, undecodable
// data) wrap errInvalidReferrer or errEmptyAttestation and oversized layers
// wrap errAttestationTooLarge; other errors come from the registry.
func (f *OCIFetcher) readFirstLayer(ctx context.Context, img ociV1.Image) ([]byte, error) {
	manifest, err := img.Manifest()
	if err != nil {
		return nil, fmt.Errorf("reading attestation manifest: %w", err)
	}

	if manifest != nil && len(manifest.Layers) > 0 {
		err = rejectForeignLayer(&manifest.Layers[0])
		if err != nil {
			return nil, err
		}
	}

	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("reading attestation layers: %w", err)
	}

	if len(layers) == 0 {
		return nil, fmt.Errorf("attestation has no layers: %w", errEmptyAttestation)
	}

	return f.readLayer(ctx, layers[0])
}

// rejectForeignLayer refuses layer descriptors that list external URLs.
// go-containerregistry falls back to those URLs when the registry does not
// serve the blob, so a manifest pushed by anyone with push access could make
// the plugin contact arbitrary hosts and turn their responses into transport
// failures. Attestation layers are always served by the registry itself.
func rejectForeignLayer(desc *ociV1.Descriptor) error {
	if len(desc.URLs) == 0 {
		return nil
	}

	return fmt.Errorf("%w: %w: %d URLs", errInvalidReferrer, errForeignLayer, len(desc.URLs))
}

// readLayer downloads the stored (compressed) layer blob first and decodes it
// in memory afterwards. Errors while downloading come from the registry, so
// a network problem is never mistaken for bad content; errors while decoding
// are content errors, so malformed data pushed to a registry is never
// mistaken for a network problem.
func (f *OCIFetcher) readLayer(ctx context.Context, layer ociV1.Layer) ([]byte, error) {
	maxSize := f.maxAttestationSize.Load()

	// Check the declared size first so oversized blobs are never downloaded.
	declared, sizeErr := layer.Size()
	if sizeErr == nil && declared > maxSize {
		return nil, fmt.Errorf(
			"attestation size %d exceeds limit of %d bytes: %w",
			declared, maxSize, errAttestationTooLarge,
		)
	}

	if sizeErr == nil {
		err := reserveDownload(ctx, declared)
		if err != nil {
			return nil, err
		}
	}

	stored, err := readBounded(ctx, layer.Compressed, maxSize)
	if err != nil {
		return nil, err
	}

	err = chargeDownload(ctx, int64(len(stored)))
	if err != nil {
		return nil, err
	}

	return decodeLayer(stored, maxSize)
}

func readBounded(
	ctx context.Context, open func() (io.ReadCloser, error), maxSize int64,
) ([]byte, error) {
	reader, err := open()
	if err != nil {
		return nil, fmt.Errorf("reading attestation layer: %w", err)
	}

	defer func() {
		closeErr := reader.Close()
		if closeErr != nil {
			slog.WarnContext(ctx, "Failed to close attestation layer reader",
				"error", closeErr,
			)
		}
	}()

	data, err := io.ReadAll(io.LimitReader(reader, maxSize+1))
	if err != nil {
		// A body that ends early while downloading is a truncated registry
		// response. It is tagged here, where the bytes come off the wire,
		// because decoding errors of the same kind are content problems.
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, fmt.Errorf("reading attestation layer: %w: %w", errTruncatedResponse, err)
		}

		return nil, fmt.Errorf("reading attestation layer: %w", err)
	}

	if int64(len(data)) > maxSize {
		return nil, fmt.Errorf(
			"attestation size %d exceeds limit of %d bytes: %w",
			len(data), maxSize, errAttestationTooLarge,
		)
	}

	return data, nil
}

// decodeLayer decompresses gzip layer data in memory. Attestation layers are
// normally stored uncompressed and returned unchanged.
func decodeLayer(data []byte, maxSize int64) ([]byte, error) {
	if bytes.HasPrefix(data, zstdMagic) {
		return nil, fmt.Errorf("%w: %w: zstd", errInvalidReferrer, errUnsupportedLayerCodec)
	}

	if !bytes.HasPrefix(data, gzipMagic) {
		return data, nil
	}

	gzipReader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("%w: decompressing attestation layer: %w", errInvalidReferrer, err)
	}

	defer func() { _ = gzipReader.Close() }()

	decoded, err := io.ReadAll(io.LimitReader(gzipReader, maxSize+1))
	if err != nil {
		return nil, fmt.Errorf("%w: decompressing attestation layer: %w", errInvalidReferrer, err)
	}

	if int64(len(decoded)) > maxSize {
		return nil, fmt.Errorf(
			"decompressed attestation size exceeds limit of %d bytes: %w",
			maxSize, errAttestationTooLarge,
		)
	}

	return decoded, nil
}

// extractPredicateType returns the predicateType of an in-toto statement.
// encoding/json matches field names case-insensitively and keeps the last
// match, so a statement with more than one key that folds to "predicateType"
// is ambiguous and yields an empty type rather than a type the decoded
// statement may not carry.
func extractPredicateType(payload []byte) string {
	dec := json.NewDecoder(bytes.NewReader(payload))

	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return ""
	}

	var (
		predicateType string
		found         bool
	)

	for dec.More() {
		key, keyErr := dec.Token()
		if keyErr != nil {
			return ""
		}

		name, ok := key.(string)
		if !ok || !strings.EqualFold(name, "predicateType") {
			var skip json.RawMessage

			skipErr := dec.Decode(&skip)
			if skipErr != nil {
				return ""
			}

			continue
		}

		if found {
			return ""
		}

		valErr := dec.Decode(&predicateType)
		if valErr != nil {
			return ""
		}

		found = true
	}

	return predicateType
}

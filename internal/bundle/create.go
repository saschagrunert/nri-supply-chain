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

// Package bundle provides offline attestation bundle creation, storage, and verification.
package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	ociV1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
)

const (
	bundleFileMode = 0o600
	bundleDirMode  = 0o750
)

// DigestResolver resolves an image reference (potentially a tag) to its digest.
// Returns the resolved digest and any index digest for manifest lists.
type DigestResolver func(ctx context.Context, imageRef string) (digest, indexDigest string, err error)

// RevocationData holds certificate revocation information to embed in the bundle.
type RevocationData struct {
	Type string
	Data []byte
}

// CreateOptions configures bundle creation.
type CreateOptions struct {
	Images         []string
	OutputPath     string
	Fetcher        attestation.Fetcher
	FetchOptions   *attestation.FetchOptions
	TrustedRoots   []*root.TrustedRoot
	SigningKeyPath string
	ResolveDigest  DigestResolver
	RevocationData []RevocationData
}

// Create packages attestations for the given images into a portable bundle.
func Create(ctx context.Context, opts *CreateOptions) error {
	tmpDir, err := os.MkdirTemp("", "nri-bundle-*")
	if err != nil {
		return fmt.Errorf("creating temp directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	ociLayout, err := initOCILayout(tmpDir)
	if err != nil {
		return err
	}

	manifest, err := buildManifest(ctx, ociLayout, opts)
	if err != nil {
		return err
	}

	if opts.SigningKeyPath != "" {
		slog.InfoContext(ctx, "Signing bundle manifest", "key", opts.SigningKeyPath)

		signErr := SignManifest(manifest, opts.SigningKeyPath)
		if signErr != nil {
			return fmt.Errorf("signing bundle manifest: %w", signErr)
		}
	}

	manifestData, err := MarshalManifest(manifest)
	if err != nil {
		return fmt.Errorf("marshaling manifest: %w", err)
	}

	manifestPath := filepath.Join(tmpDir, manifestFileName)

	writeErr := os.WriteFile(manifestPath, manifestData, bundleFileMode)
	if writeErr != nil {
		return fmt.Errorf("writing manifest: %w", writeErr)
	}

	return packageBundle(tmpDir, opts.OutputPath)
}

func buildManifest(
	ctx context.Context, ociLayout layout.Path, opts *CreateOptions,
) (*Manifest, error) {
	now := time.Now().UTC()
	manifest := &Manifest{
		Version:     currentManifestVersion,
		CreatedAt:   now,
		Images:      make(map[string]*ImageEntry),
		TrustedRoot: nil,
		Revocation:  nil,
		Signature:   nil,
	}

	err := bundleAllImages(ctx, ociLayout, opts, manifest, now)
	if err != nil {
		return nil, err
	}

	err = bundleTrustMaterial(ociLayout, opts, manifest)
	if err != nil {
		return nil, err
	}

	return manifest, nil
}

func bundleAllImages(
	ctx context.Context,
	ociLayout layout.Path,
	opts *CreateOptions,
	manifest *Manifest,
	now time.Time,
) error {
	for _, imageRef := range opts.Images {
		ctxErr := ctx.Err()
		if ctxErr != nil {
			return fmt.Errorf("context canceled: %w", ctxErr)
		}

		digest, err := resolveImageDigest(ctx, opts, imageRef)
		if err != nil {
			return err
		}

		if existing, ok := manifest.Images[digest]; ok {
			if digest != imageRef {
				existing.Refs = append(existing.Refs, imageRef)
			}

			continue
		}

		entry, err := bundleImageAttestations(
			ctx, ociLayout, opts, imageRef, digest, now,
		)
		if err != nil {
			return err
		}

		if digest != imageRef {
			entry.Refs = append(entry.Refs, imageRef)
		}

		manifest.Images[digest] = entry
	}

	return nil
}

func resolveImageDigest(
	ctx context.Context, opts *CreateOptions, imageRef string,
) (string, error) {
	if opts.ResolveDigest == nil {
		return imageRef, nil
	}

	digest, _, err := opts.ResolveDigest(ctx, imageRef)
	if err != nil {
		return "", fmt.Errorf("resolving digest for %s: %w", imageRef, err)
	}

	if digest != "" {
		slog.InfoContext(ctx, "Resolved image digest", "image", imageRef, "digest", digest)

		return digest, nil
	}

	return imageRef, nil
}

func bundleTrustMaterial(
	ociLayout layout.Path, opts *CreateOptions, manifest *Manifest,
) error {
	if len(opts.TrustedRoots) > 1 {
		slog.Warn("Multiple trusted roots provided, only the first will be embedded",
			"count", len(opts.TrustedRoots))
	}

	if len(opts.TrustedRoots) > 0 {
		rootEntry, err := writeTrustedRoot(ociLayout, opts.TrustedRoots[0])
		if err != nil {
			return fmt.Errorf("writing trusted root: %w", err)
		}

		manifest.TrustedRoot = rootEntry
	}

	for _, rev := range opts.RevocationData {
		digest, err := writeBlob(ociLayout, rev.Data)
		if err != nil {
			return fmt.Errorf("writing revocation data: %w", err)
		}

		manifest.Revocation = append(manifest.Revocation, RevocationEntry{
			BlobDigest: digest,
			Size:       int64(len(rev.Data)),
			Type:       rev.Type,
		})
	}

	return nil
}

func bundleImageAttestations(
	ctx context.Context,
	ociLayout layout.Path,
	opts *CreateOptions,
	imageRef string,
	digest string,
	now time.Time,
) (*ImageEntry, error) {
	slog.InfoContext(ctx, "Fetching attestations", "image", imageRef, "digest", digest)

	fetchOpts := *opts.FetchOptions
	fetchOpts.Digest = digest

	atts, err := opts.Fetcher.Fetch(ctx, imageRef, &fetchOpts)
	if err != nil {
		return nil, fmt.Errorf("fetching attestations for %s: %w", imageRef, err)
	}

	entry := &ImageEntry{
		Refs:         nil,
		Attestations: make([]AttestationEntry, 0, len(atts)),
		CreatedAt:    now,
	}

	for idx := range atts {
		blobDigest, writeErr := writeBlob(ociLayout, atts[idx].Payload)
		if writeErr != nil {
			return nil, fmt.Errorf("writing attestation blob: %w", writeErr)
		}

		entry.Attestations = append(entry.Attestations, AttestationEntry{
			PredicateType: atts[idx].PredicateType,
			BlobDigest:    blobDigest,
			Size:          int64(len(atts[idx].Payload)),
			SignatureType: string(atts[idx].SignatureType),
		})
	}

	slog.InfoContext(ctx, "Bundled attestations",
		"image", imageRef,
		"count", len(atts),
	)

	return entry, nil
}

func initOCILayout(dir string) (layout.Path, error) {
	layoutErr := os.WriteFile(
		filepath.Join(dir, "oci-layout"),
		[]byte(`{"imageLayoutVersion":"1.0.0"}`),
		bundleFileMode,
	)
	if layoutErr != nil {
		return "", fmt.Errorf("writing oci-layout: %w", layoutErr)
	}

	indexErr := os.WriteFile(
		filepath.Join(dir, "index.json"),
		[]byte(`{"schemaVersion":2,"manifests":[]}`),
		bundleFileMode,
	)
	if indexErr != nil {
		return "", fmt.Errorf("writing index.json: %w", indexErr)
	}

	blobsDir := filepath.Join(dir, "blobs", "sha256")

	err := os.MkdirAll(blobsDir, bundleDirMode)
	if err != nil {
		return "", fmt.Errorf("creating blobs directory: %w", err)
	}

	ociLayout, err := layout.FromPath(dir)
	if err != nil {
		return "", fmt.Errorf("opening OCI layout: %w", err)
	}

	return ociLayout, nil
}

func writeBlob(ociLayout layout.Path, data []byte) (string, error) {
	hash256 := sha256.Sum256(data)
	digestStr := "sha256:" + hex.EncodeToString(hash256[:])

	hash, err := ociV1.NewHash(digestStr)
	if err != nil {
		return "", fmt.Errorf("creating hash: %w", err)
	}

	blobReader := io.NopCloser(bytes.NewReader(data))

	writeErr := ociLayout.WriteBlob(hash, blobReader)
	if writeErr != nil {
		return "", fmt.Errorf("writing blob: %w", writeErr)
	}

	return digestStr, nil
}

func writeTrustedRoot(
	ociLayout layout.Path, trustedRoot *root.TrustedRoot,
) (*TrustedRootEntry, error) {
	data, err := trustedRoot.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("marshaling trusted root: %w", err)
	}

	digest, err := writeBlob(ociLayout, data)
	if err != nil {
		return nil, err
	}

	return &TrustedRootEntry{
		BlobDigest: digest,
		Size:       int64(len(data)),
	}, nil
}

func packageBundle(dir, outputPath string) (retErr error) {
	outputFile, err := os.Create(outputPath) //nolint:gosec // path from user CLI flag
	if err != nil {
		return fmt.Errorf("creating output file: %w", err)
	}
	defer func() {
		closeErr := outputFile.Close()
		if closeErr != nil && retErr == nil {
			retErr = fmt.Errorf("closing output file: %w", closeErr)
		}
	}()

	gzipWriter := gzip.NewWriter(outputFile)
	defer func() {
		closeErr := gzipWriter.Close()
		if closeErr != nil && retErr == nil {
			retErr = fmt.Errorf("closing gzip writer: %w", closeErr)
		}
	}()

	tarWriter := tar.NewWriter(gzipWriter)
	defer func() {
		closeErr := tarWriter.Close()
		if closeErr != nil && retErr == nil {
			retErr = fmt.Errorf("closing tar writer: %w", closeErr)
		}
	}()

	walkErr := filepath.Walk(dir, tarWalkFunc(dir, tarWriter))
	if walkErr != nil {
		return fmt.Errorf("packaging bundle: %w", walkErr)
	}

	return nil
}

func tarWalkFunc(baseDir string, tarWriter *tar.Writer) filepath.WalkFunc {
	return func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("walking bundle directory: %w", walkErr)
		}

		relPath, relErr := filepath.Rel(baseDir, path)
		if relErr != nil {
			return fmt.Errorf("computing relative path: %w", relErr)
		}

		if relPath == "." {
			return nil
		}

		header, headerErr := tar.FileInfoHeader(info, "")
		if headerErr != nil {
			return fmt.Errorf("creating tar header: %w", headerErr)
		}

		header.Name = relPath

		writeErr := tarWriter.WriteHeader(header)
		if writeErr != nil {
			return fmt.Errorf("writing tar header: %w", writeErr)
		}

		if info.IsDir() {
			return nil
		}

		file, openErr := os.Open(path) //nolint:gosec // path from controlled temp directory
		if openErr != nil {
			return fmt.Errorf("opening file for tar: %w", openErr)
		}
		defer func() { _ = file.Close() }()

		_, copyErr := io.Copy(tarWriter, file)
		if copyErr != nil {
			return fmt.Errorf("copying file to tar: %w", copyErr)
		}

		return nil
	}
}

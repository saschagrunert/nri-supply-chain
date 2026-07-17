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

package attestation_test

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	ociV1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
)

const (
	testHashAlgorithm = "sha256"
	testHashHex       = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	testIssuerGoogle  = "https://accounts.google.com"
	testSANUser       = "user@example.com"
	testFetchImageRef = "docker.io/library/nginx:latest"
	testFetchDigest   = "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abcd"
)

var (
	errImageFetch        = errors.New("image fetch failed")
	errLayers            = errors.New("layers error")
	errSignatureMismatch = errors.New("signature mismatch")
	errReferrers         = errors.New("referrers failed")
	errIndexManifest     = errors.New("index manifest error")
)

type fakeImageIndex struct {
	manifests []ociV1.Descriptor
	err       error
}

func (f *fakeImageIndex) MediaType() (types.MediaType, error) {
	return types.OCIImageIndex, nil
}

func (f *fakeImageIndex) Digest() (ociV1.Hash, error) {
	return ociV1.Hash{Algorithm: "", Hex: ""}, nil
}

func (f *fakeImageIndex) Size() (int64, error) { return 0, nil }

func (f *fakeImageIndex) RawManifest() ([]byte, error) { return nil, nil }

//nolint:ireturn // v1.ImageIndex requires this signature
func (f *fakeImageIndex) Image(_ ociV1.Hash) (ociV1.Image, error) {
	return nil, nil //nolint:nilnil // stub
}

//nolint:ireturn // v1.ImageIndex requires this signature
func (f *fakeImageIndex) ImageIndex(_ ociV1.Hash) (ociV1.ImageIndex, error) {
	return nil, nil //nolint:nilnil // stub
}

func (f *fakeImageIndex) IndexManifest() (*ociV1.IndexManifest, error) {
	if f.err != nil {
		return nil, f.err
	}

	return &ociV1.IndexManifest{Manifests: f.manifests}, nil
}

type brokenLayersImage struct {
	ociV1.Image
}

func (b *brokenLayersImage) Layers() ([]ociV1.Layer, error) {
	return nil, errLayers
}

//nolint:ireturn // test helper intentionally returns interface
func fakeImageWithPayload(payload []byte) ociV1.Image {
	layer := static.NewLayer(payload, types.OCILayer)

	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		panic("building test image: " + err.Error())
	}

	return img
}

//nolint:funlen,varnamelen // table-driven test
func TestExtractPayload(t *testing.T) {
	t.Parallel()

	baseRef, err := name.NewDigest(
		"docker.io/library/nginx@sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abcd",
	)
	if err != nil {
		t.Fatalf("creating test digest ref: %v", err)
	}

	descDigest := "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

	tests := []struct {
		name        string
		imageFetch  attestation.ImageFetchFunc
		verifyFunc  attestation.BundleVerifyFunc
		wantErr     bool
		wantErrMsg  string
		wantPayload string
	}{
		{
			name: "successful extraction",
			imageFetch: func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
				return fakeImageWithPayload([]byte(`{"bundle": "data"}`)), nil
			},
			verifyFunc: func(_ context.Context, _ []byte, _ attestation.FetchOptions) ([]byte, error) {
				return []byte(`{"verified": true}`), nil
			},
			wantErr:     false,
			wantErrMsg:  "",
			wantPayload: `{"verified": true}`,
		},
		{
			name: "image fetch error",
			imageFetch: func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
				return nil, errImageFetch
			},
			verifyFunc: func(_ context.Context, _ []byte, _ attestation.FetchOptions) ([]byte, error) {
				return nil, nil
			},
			wantErr:     true,
			wantErrMsg:  "fetching attestation image",
			wantPayload: "",
		},
		{
			name: "empty image with no layers",
			imageFetch: func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
				return empty.Image, nil
			},
			verifyFunc: func(_ context.Context, _ []byte, _ attestation.FetchOptions) ([]byte, error) {
				return nil, nil
			},
			wantErr:     true,
			wantErrMsg:  "no layers",
			wantPayload: "",
		},
		{
			name: "attestation exceeds size limit",
			imageFetch: func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
				oversized := make([]byte, 11<<20)

				return fakeImageWithPayload(oversized), nil
			},
			verifyFunc: func(_ context.Context, _ []byte, _ attestation.FetchOptions) ([]byte, error) {
				return nil, nil
			},
			wantErr:     true,
			wantErrMsg:  "exceeds limit",
			wantPayload: "",
		},
		{
			name: "layers error",
			imageFetch: func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
				return &brokenLayersImage{Image: empty.Image}, nil
			},
			verifyFunc: func(_ context.Context, _ []byte, _ attestation.FetchOptions) ([]byte, error) {
				return nil, nil
			},
			wantErr:     true,
			wantErrMsg:  "reading attestation layers",
			wantPayload: "",
		},
		{
			name: "bundle verification fails",
			imageFetch: func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
				return fakeImageWithPayload([]byte(`{"bundle": "bad"}`)), nil
			},
			verifyFunc: func(_ context.Context, _ []byte, _ attestation.FetchOptions) ([]byte, error) {
				return nil, errSignatureMismatch
			},
			wantErr:     true,
			wantErrMsg:  "signature mismatch",
			wantPayload: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fetcher := attestation.NewTestOCIFetcher(tt.verifyFunc, tt.imageFetch)

			result, err := fetcher.ExtractPayload(
				context.Background(), baseRef, descDigest, nil, attestation.FetchOptions{},
			)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				if tt.wantErrMsg != "" && !strings.Contains(err.Error(), tt.wantErrMsg) {
					t.Errorf("expected error containing %q, got: %v", tt.wantErrMsg, err)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if string(result) != tt.wantPayload {
				t.Errorf("expected payload %q, got %q", tt.wantPayload, string(result))
			}
		})
	}
}

//nolint:funlen,varnamelen // table-driven test
func TestCollectAttestations(t *testing.T) {
	t.Parallel()

	baseRef, err := name.NewDigest(
		"docker.io/library/nginx@sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abcd",
	)
	if err != nil {
		t.Fatalf("creating test digest ref: %v", err)
	}

	const testDigestVal = "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abcd"

	bundleDescriptor := func(predicateType string) ociV1.Descriptor {
		return ociV1.Descriptor{
			ArtifactType: attestation.BundleMediaType,
			Digest: ociV1.Hash{
				Algorithm: testHashAlgorithm,
				Hex:       testHashHex,
			},
			Annotations: map[string]string{
				attestation.AnnotationPredicateType: predicateType,
			},
		}
	}

	tests := []struct {
		name           string
		manifests      []ociV1.Descriptor
		imageFetch     attestation.ImageFetchFunc
		verifyFunc     attestation.BundleVerifyFunc
		cancelCtx      bool
		wantCount      int
		wantHadBundles bool
	}{
		{
			name:      "canceled context returns empty",
			cancelCtx: true,
			manifests: []ociV1.Descriptor{
				bundleDescriptor(attestation.PredicateSLSAProvenanceV1),
			},
			imageFetch: func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
				return nil, errImageFetch
			},
			verifyFunc: func(_ context.Context, _ []byte, _ attestation.FetchOptions) ([]byte, error) {
				return nil, nil
			},
			wantCount:      0,
			wantHadBundles: false,
		},
		{
			name:      "empty manifests",
			manifests: nil,
			imageFetch: func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
				return nil, errImageFetch
			},
			verifyFunc: func(_ context.Context, _ []byte, _ attestation.FetchOptions) ([]byte, error) {
				return nil, nil
			},
			cancelCtx:      false,
			wantCount:      0,
			wantHadBundles: false,
		},
		{
			name: "non-bundle artifact type skipped",
			manifests: []ociV1.Descriptor{
				{ArtifactType: "application/vnd.other.type"},
			},
			imageFetch: func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
				return nil, errImageFetch
			},
			verifyFunc: func(_ context.Context, _ []byte, _ attestation.FetchOptions) ([]byte, error) {
				return nil, nil
			},
			cancelCtx:      false,
			wantCount:      0,
			wantHadBundles: false,
		},
		{
			name: "missing predicate annotation skipped",
			manifests: []ociV1.Descriptor{
				{
					ArtifactType: attestation.BundleMediaType,
					Digest: ociV1.Hash{
						Algorithm: testHashAlgorithm,
						Hex:       testHashHex,
					},
				},
			},
			imageFetch: func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
				return nil, errImageFetch
			},
			verifyFunc: func(_ context.Context, _ []byte, _ attestation.FetchOptions) ([]byte, error) {
				return nil, nil
			},
			cancelCtx:      false,
			wantCount:      0,
			wantHadBundles: false,
		},
		{
			name: "successful extraction",
			manifests: []ociV1.Descriptor{
				bundleDescriptor(attestation.PredicateSLSAProvenanceV1),
			},
			imageFetch: func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
				return fakeImageWithPayload([]byte(`{"bundle": "ok"}`)), nil
			},
			verifyFunc: func(_ context.Context, _ []byte, _ attestation.FetchOptions) ([]byte, error) {
				return []byte(`{"slsa": true}`), nil
			},
			cancelCtx:      false,
			wantCount:      1,
			wantHadBundles: true,
		},
		{
			name: "multiple attestation types",
			manifests: []ociV1.Descriptor{
				bundleDescriptor(attestation.PredicateSLSAProvenanceV1),
				bundleDescriptor(attestation.PredicateOpenVEX),
			},
			imageFetch: func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
				return fakeImageWithPayload([]byte(`{"bundle": "ok"}`)), nil
			},
			verifyFunc: func(_ context.Context, _ []byte, _ attestation.FetchOptions) ([]byte, error) {
				return []byte(`{"payload": true}`), nil
			},
			cancelCtx:      false,
			wantCount:      2,
			wantHadBundles: true,
		},
		{
			name: "extraction failure skipped",
			manifests: []ociV1.Descriptor{
				bundleDescriptor(attestation.PredicateSLSAProvenanceV1),
			},
			imageFetch: func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
				return nil, errImageFetch
			},
			verifyFunc: func(_ context.Context, _ []byte, _ attestation.FetchOptions) ([]byte, error) {
				return nil, nil
			},
			cancelCtx:      false,
			wantCount:      0,
			wantHadBundles: true,
		},
		{
			name: "mixed success and failure",
			manifests: []ociV1.Descriptor{
				bundleDescriptor(attestation.PredicateSLSAProvenanceV1),
				bundleDescriptor(attestation.PredicateOpenVEX),
			},
			imageFetch: func() attestation.ImageFetchFunc {
				callCount := 0

				return func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
					callCount++
					if callCount == 1 {
						return nil, errImageFetch
					}

					return fakeImageWithPayload([]byte(`{"bundle": "ok"}`)), nil
				}
			}(),
			verifyFunc: func(_ context.Context, _ []byte, _ attestation.FetchOptions) ([]byte, error) {
				return []byte(`{"payload": true}`), nil
			},
			cancelCtx:      false,
			wantCount:      1,
			wantHadBundles: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()

			if tt.cancelCtx {
				var cancel context.CancelFunc

				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}

			fetcher := attestation.NewTestOCIFetcher(tt.verifyFunc, tt.imageFetch)

			result, hadBundles := fetcher.CollectAttestations(
				ctx, tt.manifests, baseRef, testDigestVal, nil, attestation.FetchOptions{},
			)

			if len(result) != tt.wantCount {
				t.Errorf("expected %d attestations, got %d", tt.wantCount, len(result))
			}

			if hadBundles != tt.wantHadBundles {
				t.Errorf("expected hadBundles=%v, got %v", tt.wantHadBundles, hadBundles)
			}
		})
	}
}

func TestCollectAttestationsMaxReferrers(t *testing.T) {
	t.Parallel()

	baseRef, err := name.NewDigest(
		"docker.io/library/nginx@sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abcd",
	)
	if err != nil {
		t.Fatalf("creating test digest ref: %v", err)
	}

	maxRef := attestation.ExportMaxReferrers()
	manifests := make([]ociV1.Descriptor, maxRef+10)

	for idx := range manifests {
		manifests[idx] = ociV1.Descriptor{
			ArtifactType: attestation.BundleMediaType,
			Digest: ociV1.Hash{
				Algorithm: testHashAlgorithm,
				Hex:       testHashHex,
			},
			Annotations: map[string]string{
				attestation.AnnotationPredicateType: attestation.PredicateSLSAProvenanceV1,
			},
		}
	}

	fetcher := attestation.NewTestOCIFetcher(
		func(_ context.Context, _ []byte, _ attestation.FetchOptions) ([]byte, error) {
			return []byte(`{"ok": true}`), nil
		},
		func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
			return fakeImageWithPayload([]byte(`{"bundle": "data"}`)), nil
		},
	)

	result, hadBundles := fetcher.CollectAttestations(
		context.Background(), manifests, baseRef, "sha256:test", nil, attestation.FetchOptions{},
	)

	if !hadBundles {
		t.Error("expected hadBundles=true")
	}

	if len(result) > maxRef {
		t.Errorf("expected at most %d results, got %d", maxRef, len(result))
	}
}

func TestCollectAttestationsDigestPreserved(t *testing.T) {
	t.Parallel()

	baseRef, err := name.NewDigest(
		"docker.io/library/nginx@sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abcd",
	)
	if err != nil {
		t.Fatalf("creating test digest ref: %v", err)
	}

	const wantDigest = "sha256:mydigest"

	manifests := []ociV1.Descriptor{
		{
			ArtifactType: attestation.BundleMediaType,
			Digest: ociV1.Hash{
				Algorithm: testHashAlgorithm,
				Hex:       testHashHex,
			},
			Annotations: map[string]string{
				attestation.AnnotationPredicateType: attestation.PredicateSLSAProvenanceV1,
			},
		},
	}

	fetcher := attestation.NewTestOCIFetcher(
		func(_ context.Context, _ []byte, _ attestation.FetchOptions) ([]byte, error) {
			return []byte(`{"ok": true}`), nil
		},
		func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
			return fakeImageWithPayload([]byte(`{"bundle": "data"}`)), nil
		},
	)

	result, _ := fetcher.CollectAttestations(
		context.Background(), manifests, baseRef, wantDigest, nil, attestation.FetchOptions{},
	)

	if len(result) != 1 {
		t.Fatalf("expected 1 attestation, got %d", len(result))
	}

	if result[0].Digest != wantDigest {
		t.Errorf("expected digest %q, got %q", wantDigest, result[0].Digest)
	}

	if result[0].PredicateType != attestation.PredicateSLSAProvenanceV1 {
		t.Errorf("expected predicate type %q, got %q",
			attestation.PredicateSLSAProvenanceV1, result[0].PredicateType)
	}
}

//nolint:varnamelen // table-driven test
func TestBuildCertificateIdentitySANPatterns(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		issuers      []string
		sanPatterns  []string
		wantSANRegex string
	}{
		{
			name:         "no SAN patterns uses wildcard",
			issuers:      []string{testIssuerGoogle},
			sanPatterns:  nil,
			wantSANRegex: ".*",
		},
		{
			name:         "single SAN pattern anchored",
			issuers:      []string{testIssuerGoogle},
			sanPatterns:  []string{testSANUser},
			wantSANRegex: `^(?:user@example\.com)$`,
		},
		{
			name:    "multiple SAN patterns anchored",
			issuers: []string{testIssuerGoogle},
			sanPatterns: []string{
				testSANUser,
				"ci@build.internal",
			},
			wantSANRegex: `^(?:user@example\.com|ci@build\.internal)$`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			certID, err := attestation.ExportBuildCertificateID(tt.issuers, tt.sanPatterns)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			sanRegex := certID.SubjectAlternativeName.Regexp.String()
			if sanRegex != tt.wantSANRegex {
				t.Errorf("expected SAN regex %q, got %q", tt.wantSANRegex, sanRegex)
			}
		})
	}
}

func bundleDescriptor(predicateType string) ociV1.Descriptor {
	return ociV1.Descriptor{
		ArtifactType: attestation.BundleMediaType,
		Digest: ociV1.Hash{
			Algorithm: testHashAlgorithm,
			Hex:       testHashHex,
		},
		Annotations: map[string]string{
			attestation.AnnotationPredicateType: predicateType,
		},
	}
}

//nolint:funlen,varnamelen // table-driven test
func TestFetch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		referrers  attestation.ReferrersFunc
		imageFetch attestation.ImageFetchFunc
		verifyFunc attestation.BundleVerifyFunc
		cancelCtx  bool
		wantCount  int
		wantErr    bool
		wantErrMsg string
	}{
		{
			name: "valid referrers",
			referrers: func(_ name.Digest, _ ...remote.Option) (ociV1.ImageIndex, error) {
				return &fakeImageIndex{
					manifests: []ociV1.Descriptor{
						bundleDescriptor(attestation.PredicateSLSAProvenanceV1),
					},
					err: nil,
				}, nil
			},
			imageFetch: func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
				return fakeImageWithPayload([]byte(`{"bundle": "ok"}`)), nil
			},
			verifyFunc: func(_ context.Context, _ []byte, _ attestation.FetchOptions) ([]byte, error) {
				return []byte(`{"verified": true}`), nil
			},
			cancelCtx:  false,
			wantCount:  1,
			wantErr:    false,
			wantErrMsg: "",
		},
		{
			name: "no referrers",
			referrers: func(_ name.Digest, _ ...remote.Option) (ociV1.ImageIndex, error) {
				return &fakeImageIndex{manifests: nil, err: nil}, nil
			},
			imageFetch: func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
				return nil, errImageFetch
			},
			verifyFunc: func(_ context.Context, _ []byte, _ attestation.FetchOptions) ([]byte, error) {
				return nil, nil
			},
			cancelCtx:  false,
			wantCount:  0,
			wantErr:    false,
			wantErrMsg: "",
		},
		{
			name: "referrers error",
			referrers: func(_ name.Digest, _ ...remote.Option) (ociV1.ImageIndex, error) {
				return nil, errReferrers
			},
			imageFetch: func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
				return nil, errImageFetch
			},
			verifyFunc: func(_ context.Context, _ []byte, _ attestation.FetchOptions) ([]byte, error) {
				return nil, errSignatureMismatch
			},
			cancelCtx:  false,
			wantCount:  0,
			wantErr:    true,
			wantErrMsg: "listing referrers",
		},
		{
			name: "index manifest error",
			referrers: func(_ name.Digest, _ ...remote.Option) (ociV1.ImageIndex, error) {
				return &fakeImageIndex{manifests: nil, err: errIndexManifest}, nil
			},
			imageFetch: func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
				return nil, errImageFetch
			},
			verifyFunc: func(_ context.Context, _ []byte, _ attestation.FetchOptions) ([]byte, error) {
				return nil, errSignatureMismatch
			},
			cancelCtx:  false,
			wantCount:  0,
			wantErr:    true,
			wantErrMsg: "reading referrers index",
		},
		{
			name: "context cancellation",
			referrers: func(_ name.Digest, _ ...remote.Option) (ociV1.ImageIndex, error) {
				return &fakeImageIndex{
					manifests: []ociV1.Descriptor{
						bundleDescriptor(attestation.PredicateSLSAProvenanceV1),
					},
					err: nil,
				}, nil
			},
			imageFetch: func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
				return fakeImageWithPayload([]byte(`{"bundle": "ok"}`)), nil
			},
			verifyFunc: func(_ context.Context, _ []byte, _ attestation.FetchOptions) ([]byte, error) {
				return []byte(`{"ok": true}`), nil
			},
			cancelCtx:  true,
			wantCount:  0,
			wantErr:    true,
			wantErrMsg: "interrupted",
		},
		{
			name: "all bundles fail verification",
			referrers: func(_ name.Digest, _ ...remote.Option) (ociV1.ImageIndex, error) {
				return &fakeImageIndex{
					manifests: []ociV1.Descriptor{
						bundleDescriptor(attestation.PredicateSLSAProvenanceV1),
					},
					err: nil,
				}, nil
			},
			imageFetch: func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
				return nil, errImageFetch
			},
			verifyFunc: func(_ context.Context, _ []byte, _ attestation.FetchOptions) ([]byte, error) {
				return nil, nil
			},
			cancelCtx:  false,
			wantCount:  0,
			wantErr:    true,
			wantErrMsg: "all referrer bundles failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()

			if tt.cancelCtx {
				var cancel context.CancelFunc

				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}

			fetcher := attestation.NewTestOCIFetcherFull(tt.verifyFunc, tt.imageFetch, tt.referrers)

			result, err := fetcher.Fetch(
				ctx, testFetchImageRef, testFetchDigest, attestation.FetchOptions{},
			)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				if tt.wantErrMsg != "" && !strings.Contains(err.Error(), tt.wantErrMsg) {
					t.Errorf("expected error containing %q, got: %v", tt.wantErrMsg, err)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(result) != tt.wantCount {
				t.Errorf("expected %d attestations, got %d", tt.wantCount, len(result))
			}
		})
	}
}

func TestGlobToRegex(t *testing.T) { //nolint:funlen // Table-driven test.
	t.Parallel()

	tests := []struct {
		name    string
		pattern string
		match   string
		noMatch string
	}{
		{
			name:    "literal",
			pattern: "foo@bar.com",
			match:   "foo@bar.com",
			noMatch: "foo@baz.com",
		},
		{
			name:    "star wildcard",
			pattern: "*.example.com",
			match:   "user.example.com",
			noMatch: "a/b.example.com",
		},
		{
			name:    "question mark",
			pattern: "user?.example.com",
			match:   "userA.example.com",
			noMatch: "user.example.com",
		},
		{
			name:    "character class",
			pattern: "[abc].example.com",
			match:   "a.example.com",
			noMatch: "d.example.com",
		},
		{
			name:    "character range",
			pattern: "[a-z].example.com",
			match:   "x.example.com",
			noMatch: "1.example.com",
		},
		{
			name:    "dot is escaped",
			pattern: "foo.bar",
			match:   "foo.bar",
			noMatch: "fooXbar",
		},
		{
			name:    "plus is escaped",
			pattern: "a+b",
			match:   "a+b",
			noMatch: "aab",
		},
		{
			name:    "multiple wildcards",
			pattern: "*@*.example.com",
			match:   "user@host.example.com",
			noMatch: "user@a/b.example.com",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			regex := attestation.ExportGlobToRegex(test.pattern)
			fullRegex := "^" + regex + "$"

			matched, err := regexp.MatchString(fullRegex, test.match)
			if err != nil {
				t.Fatalf("regex error: %v", err)
			}

			if !matched {
				t.Errorf("pattern %q (regex %q) should match %q",
					test.pattern, fullRegex, test.match)
			}

			matched, err = regexp.MatchString(fullRegex, test.noMatch)
			if err != nil {
				t.Fatalf("regex error: %v", err)
			}

			if matched {
				t.Errorf("pattern %q (regex %q) should not match %q",
					test.pattern, fullRegex, test.noMatch)
			}
		})
	}
}

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
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	ociV1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
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
	testIssuerExample = "https://issuer.example.com"
)

var (
	errImageFetch        = errors.New("image fetch failed")
	errLayers            = errors.New("layers error")
	errSignatureMismatch = errors.New("signature mismatch")
	errReferrers         = errors.New("referrers failed")
	errIndexManifest     = errors.New("index manifest error")
	errPlainTest         = errors.New("something")
	errNotReached        = errors.New("not reached")
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

func (f *fakeImageIndex) Image(_ ociV1.Hash) (ociV1.Image, error) {
	return nil, nil
}

func (f *fakeImageIndex) ImageIndex(_ ociV1.Hash) (ociV1.ImageIndex, error) {
	return nil, nil
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

func fakeImageWithPayload(payload []byte) ociV1.Image {
	layer := static.NewLayer(payload, types.OCILayer)

	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		panic("building test image: " + err.Error())
	}

	return img
}

func fakeImageWithAnnotations(payload []byte, annotations map[string]string) ociV1.Image {
	img := fakeImageWithPayload(payload)

	annotated, ok := mutate.Annotations(img, annotations).(ociV1.Image)
	if !ok {
		panic("mutate.Annotations did not return v1.Image")
	}

	img = annotated

	return img
}

func TestExtractPayloadFromImage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		image       ociV1.Image
		verifyFunc  attestation.BundleVerifyFunc
		wantErr     bool
		wantErrMsg  string
		wantPayload string
	}{
		{
			name:  "successful extraction",
			image: fakeImageWithPayload([]byte(`{"bundle": "data"}`)),
			verifyFunc: func(_ context.Context, _ []byte, _ *attestation.FetchOptions) ([]byte, error) {
				return []byte(`{"verified": true}`), nil
			},
			wantErr:     false,
			wantErrMsg:  "",
			wantPayload: `{"verified": true}`,
		},
		{
			name:  "empty image with no layers",
			image: empty.Image,
			verifyFunc: func(_ context.Context, _ []byte, _ *attestation.FetchOptions) ([]byte, error) {
				return nil, nil
			},
			wantErr:     true,
			wantErrMsg:  "no layers",
			wantPayload: "",
		},
		{
			name: "attestation exceeds size limit",
			image: func() ociV1.Image {
				oversized := make([]byte, 11<<20)

				return fakeImageWithPayload(oversized)
			}(),
			verifyFunc: func(_ context.Context, _ []byte, _ *attestation.FetchOptions) ([]byte, error) {
				return nil, nil
			},
			wantErr:     true,
			wantErrMsg:  "exceeds limit",
			wantPayload: "",
		},
		{
			name:  "layers error",
			image: &brokenLayersImage{Image: empty.Image},
			verifyFunc: func(_ context.Context, _ []byte, _ *attestation.FetchOptions) ([]byte, error) {
				return nil, nil
			},
			wantErr:     true,
			wantErrMsg:  "reading attestation layers",
			wantPayload: "",
		},
		{
			name:  "bundle verification fails",
			image: fakeImageWithPayload([]byte(`{"bundle": "bad"}`)),
			verifyFunc: func(_ context.Context, _ []byte, _ *attestation.FetchOptions) ([]byte, error) {
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

			fetcher := attestation.NewTestOCIFetcher(tt.verifyFunc, nil)

			result, err := fetcher.ExtractPayloadFromImage(
				context.Background(), tt.image, &attestation.FetchOptions{},
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
		name              string
		manifests         []ociV1.Descriptor
		imageFetch        attestation.ImageFetchFunc
		verifyFunc        attestation.BundleVerifyFunc
		cancelCtx         bool
		wantCount         int
		wantHadBundles    bool
		wantPredicateType string
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
			verifyFunc: func(_ context.Context, _ []byte, _ *attestation.FetchOptions) ([]byte, error) {
				return nil, nil
			},
			wantCount:         0,
			wantHadBundles:    false,
			wantPredicateType: "",
		},
		{
			name:      "empty manifests",
			manifests: nil,
			imageFetch: func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
				return nil, errImageFetch
			},
			verifyFunc: func(_ context.Context, _ []byte, _ *attestation.FetchOptions) ([]byte, error) {
				return nil, nil
			},
			cancelCtx:         false,
			wantCount:         0,
			wantHadBundles:    false,
			wantPredicateType: "",
		},
		{
			name: "non-bundle artifact type skipped",
			manifests: []ociV1.Descriptor{
				{ArtifactType: "application/vnd.other.type"},
			},
			imageFetch: func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
				return nil, errImageFetch
			},
			verifyFunc: func(_ context.Context, _ []byte, _ *attestation.FetchOptions) ([]byte, error) {
				return nil, nil
			},
			cancelCtx:         false,
			wantCount:         0,
			wantHadBundles:    false,
			wantPredicateType: "",
		},
		{
			name: "OCI empty artifact type accepted",
			manifests: []ociV1.Descriptor{
				{
					ArtifactType: attestation.OCIEmptyMediaType,
					Digest: ociV1.Hash{
						Algorithm: testHashAlgorithm,
						Hex:       testHashHex,
					},
					Annotations: map[string]string{
						attestation.AnnotationPredicateType: attestation.PredicateSLSAProvenanceV1,
					},
				},
			},
			imageFetch: func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
				return fakeImageWithPayload([]byte(`{"bundle": "ok"}`)), nil
			},
			verifyFunc: func(_ context.Context, _ []byte, _ *attestation.FetchOptions) ([]byte, error) {
				return []byte(`{"slsa": true}`), nil
			},
			cancelCtx:         false,
			wantCount:         1,
			wantHadBundles:    true,
			wantPredicateType: "",
		},
		{
			name: "empty artifact type accepted",
			manifests: []ociV1.Descriptor{
				{
					ArtifactType: "",
					Digest: ociV1.Hash{
						Algorithm: testHashAlgorithm,
						Hex:       testHashHex,
					},
					Annotations: map[string]string{
						attestation.AnnotationPredicateType: attestation.PredicateSLSAProvenanceV1,
					},
				},
			},
			imageFetch: func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
				return fakeImageWithPayload([]byte(`{"bundle": "ok"}`)), nil
			},
			verifyFunc: func(_ context.Context, _ []byte, _ *attestation.FetchOptions) ([]byte, error) {
				return []byte(`{"slsa": true}`), nil
			},
			cancelCtx:         false,
			wantCount:         1,
			wantHadBundles:    true,
			wantPredicateType: "",
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
			verifyFunc: func(_ context.Context, _ []byte, _ *attestation.FetchOptions) ([]byte, error) {
				return nil, nil
			},
			cancelCtx:         false,
			wantCount:         0,
			wantHadBundles:    true,
			wantPredicateType: "",
		},
		{
			name: "predicate type resolved from manifest annotations",
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
				annot := map[string]string{
					attestation.AnnotationPredicateType: attestation.PredicateSLSAProvenanceV1,
				}

				return fakeImageWithAnnotations([]byte(`{"bundle": "ok"}`), annot), nil
			},
			verifyFunc: func(_ context.Context, _ []byte, _ *attestation.FetchOptions) ([]byte, error) {
				return []byte(`{"slsa": true}`), nil
			},
			cancelCtx:         false,
			wantCount:         1,
			wantHadBundles:    true,
			wantPredicateType: "",
		},
		{
			name: "predicate type extracted from payload when annotation is generic",
			manifests: []ociV1.Descriptor{
				{
					ArtifactType: attestation.OCIEmptyMediaType,
					Digest: ociV1.Hash{
						Algorithm: testHashAlgorithm,
						Hex:       testHashHex,
					},
				},
			},
			imageFetch: func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
				annot := map[string]string{
					attestation.AnnotationPredicateType: "https://sigstore.dev/cosign/sign/v1",
				}

				return fakeImageWithAnnotations([]byte(`{"bundle": "ok"}`), annot), nil
			},
			verifyFunc: func(
				_ context.Context, _ []byte, _ *attestation.FetchOptions,
			) ([]byte, error) {
				return []byte(
					`{"predicateType":"` + attestation.PredicateSLSAProvenanceV1 + `"}`,
				), nil
			},
			cancelCtx:         false,
			wantCount:         1,
			wantHadBundles:    true,
			wantPredicateType: attestation.PredicateSLSAProvenanceV1,
		},
		{
			name: "successful extraction",
			manifests: []ociV1.Descriptor{
				bundleDescriptor(attestation.PredicateSLSAProvenanceV1),
			},
			imageFetch: func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
				return fakeImageWithPayload([]byte(`{"bundle": "ok"}`)), nil
			},
			verifyFunc: func(_ context.Context, _ []byte, _ *attestation.FetchOptions) ([]byte, error) {
				return []byte(`{"slsa": true}`), nil
			},
			cancelCtx:         false,
			wantCount:         1,
			wantHadBundles:    true,
			wantPredicateType: "",
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
			verifyFunc: func(_ context.Context, _ []byte, _ *attestation.FetchOptions) ([]byte, error) {
				return []byte(`{"payload": true}`), nil
			},
			cancelCtx:         false,
			wantCount:         2,
			wantHadBundles:    true,
			wantPredicateType: "",
		},
		{
			name: "extraction failure skipped",
			manifests: []ociV1.Descriptor{
				bundleDescriptor(attestation.PredicateSLSAProvenanceV1),
			},
			imageFetch: func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
				return nil, errImageFetch
			},
			verifyFunc: func(_ context.Context, _ []byte, _ *attestation.FetchOptions) ([]byte, error) {
				return nil, nil
			},
			cancelCtx:         false,
			wantCount:         0,
			wantHadBundles:    true,
			wantPredicateType: "",
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
			verifyFunc: func(_ context.Context, _ []byte, _ *attestation.FetchOptions) ([]byte, error) {
				return []byte(`{"payload": true}`), nil
			},
			cancelCtx:         false,
			wantCount:         1,
			wantHadBundles:    true,
			wantPredicateType: "",
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
				ctx, tt.manifests, baseRef, testDigestVal, nil, &attestation.FetchOptions{},
			)

			if len(result) != tt.wantCount {
				t.Errorf("expected %d attestations, got %d", tt.wantCount, len(result))
			}

			if hadBundles != tt.wantHadBundles {
				t.Errorf("expected hadBundles=%v, got %v", tt.wantHadBundles, hadBundles)
			}

			if tt.wantPredicateType != "" && len(result) > 0 {
				if result[0].PredicateType != tt.wantPredicateType {
					t.Errorf(
						"expected predicate type %q, got %q",
						tt.wantPredicateType, result[0].PredicateType,
					)
				}
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
		func(_ context.Context, _ []byte, _ *attestation.FetchOptions) ([]byte, error) {
			return []byte(`{"ok": true}`), nil
		},
		func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
			return fakeImageWithPayload([]byte(`{"bundle": "data"}`)), nil
		},
	)

	result, hadBundles := fetcher.CollectAttestations(
		context.Background(), manifests, baseRef,
		testDigest, nil, &attestation.FetchOptions{},
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

	const wantDigest = "sha256:b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3"

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
		func(_ context.Context, _ []byte, _ *attestation.FetchOptions) ([]byte, error) {
			return []byte(`{"ok": true}`), nil
		},
		func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
			return fakeImageWithPayload([]byte(`{"bundle": "data"}`)), nil
		},
	)

	result, _ := fetcher.CollectAttestations(
		context.Background(), manifests, baseRef, wantDigest, nil, &attestation.FetchOptions{},
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
			verifyFunc: func(_ context.Context, _ []byte, _ *attestation.FetchOptions) ([]byte, error) {
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
			verifyFunc: func(_ context.Context, _ []byte, _ *attestation.FetchOptions) ([]byte, error) {
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
			verifyFunc: func(_ context.Context, _ []byte, _ *attestation.FetchOptions) ([]byte, error) {
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
			verifyFunc: func(_ context.Context, _ []byte, _ *attestation.FetchOptions) ([]byte, error) {
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
			verifyFunc: func(_ context.Context, _ []byte, _ *attestation.FetchOptions) ([]byte, error) {
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
			verifyFunc: func(_ context.Context, _ []byte, _ *attestation.FetchOptions) ([]byte, error) {
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
				ctx, testFetchImageRef, testFetchDigest, &attestation.FetchOptions{},
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

func TestCosignAttestationTag(t *testing.T) {
	t.Parallel()

	ref, err := name.NewDigest(
		"docker.io/library/nginx@sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abcd",
	)
	if err != nil {
		t.Fatalf("creating digest ref: %v", err)
	}

	tag := attestation.ExportCosignAttestationTag(ref)

	want := "index.docker.io/library/nginx:sha256-abc123def456abc123def456abc123def456abc123def456abc123def456abcd.att"
	if tag.String() != want {
		t.Errorf("cosign tag = %q, want %q", tag.String(), want)
	}
}

func TestExtractPredicateType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload []byte
		want    string
	}{
		{
			name:    "SLSA provenance",
			payload: []byte(`{"predicateType":"https://slsa.dev/provenance/v1"}`),
			want:    "https://slsa.dev/provenance/v1",
		},
		{
			name:    "invalid JSON",
			payload: []byte(`not json`),
			want:    "",
		},
		{
			name:    "missing field",
			payload: []byte(`{"other":"value"}`),
			want:    "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := attestation.ExportExtractPredicateType(test.payload)
			if got != test.want {
				t.Errorf("extractPredicateType() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestFetchCosignTagAttestations(t *testing.T) {
	t.Parallel()

	ref, err := name.NewDigest(
		"docker.io/library/nginx@sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abcd",
	)
	if err != nil {
		t.Fatalf("creating digest ref: %v", err)
	}

	tests := []struct {
		name       string
		imageFetch attestation.ImageFetchFunc
		verifyFunc attestation.BundleVerifyFunc
		wantCount  int
		wantErr    bool
	}{
		{
			name: "tag not found returns nil",
			imageFetch: func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
				return nil, &transport.Error{StatusCode: http.StatusNotFound}
			},
			verifyFunc: func(_ context.Context, _ []byte, _ *attestation.FetchOptions) ([]byte, error) {
				return nil, nil
			},
			wantCount: 0,
			wantErr:   false,
		},
		{
			name: "valid bundle layer",
			imageFetch: func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
				return fakeImageWithPayload([]byte(`{"bundle": "data"}`)), nil
			},
			verifyFunc: func(_ context.Context, _ []byte, _ *attestation.FetchOptions) ([]byte, error) {
				return []byte(
					`{"predicateType":"https://slsa.dev/provenance/v1"}`,
				), nil
			},
			wantCount: 1,
			wantErr:   false,
		},
		{
			name: "invalid bundle layer skipped",
			imageFetch: func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
				return fakeImageWithPayload([]byte(`not a bundle`)), nil
			},
			verifyFunc: func(_ context.Context, _ []byte, _ *attestation.FetchOptions) ([]byte, error) {
				return nil, errSignatureMismatch
			},
			wantCount: 0,
			wantErr:   false,
		},
		{
			name: "transport error propagated",
			imageFetch: func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
				return nil, &transport.Error{StatusCode: http.StatusInternalServerError}
			},
			verifyFunc: func(_ context.Context, _ []byte, _ *attestation.FetchOptions) ([]byte, error) {
				return nil, nil
			},
			wantCount: 0,
			wantErr:   true,
		},
		{
			name: "broken layers handled",
			imageFetch: func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
				return &brokenLayersImage{Image: empty.Image}, nil
			},
			verifyFunc: func(_ context.Context, _ []byte, _ *attestation.FetchOptions) ([]byte, error) {
				return nil, nil
			},
			wantCount: 0,
			wantErr:   true,
		},
		{
			name: "empty image returns nil",
			imageFetch: func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
				return empty.Image, nil
			},
			verifyFunc: func(_ context.Context, _ []byte, _ *attestation.FetchOptions) ([]byte, error) {
				return nil, nil
			},
			wantCount: 0,
			wantErr:   false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fetcher := attestation.NewTestOCIFetcher(
				test.verifyFunc, test.imageFetch,
			)

			result, err := fetcher.FetchCosignTagAttestations(
				context.Background(), ref, testFetchDigest,
				nil, &attestation.FetchOptions{},
			)

			if test.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(result) != test.wantCount {
				t.Errorf("expected %d attestations, got %d",
					test.wantCount, len(result),
				)
			}
		})
	}
}

func TestFetchFallsBackToCosignTag(t *testing.T) {
	t.Parallel()

	var cosignTagFetched bool

	fetcher := attestation.NewTestOCIFetcherFull(
		func(_ context.Context, _ []byte, _ *attestation.FetchOptions) ([]byte, error) {
			return []byte(`{"predicateType":"https://slsa.dev/provenance/v1"}`), nil
		},
		func(ref name.Reference, _ ...remote.Option) (ociV1.Image, error) {
			if strings.HasSuffix(ref.String(), ".att") {
				cosignTagFetched = true

				return fakeImageWithPayload([]byte(`{"bundle": "ok"}`)), nil
			}

			return nil, errImageFetch
		},
		func(_ name.Digest, _ ...remote.Option) (ociV1.ImageIndex, error) {
			return &fakeImageIndex{manifests: nil, err: nil}, nil
		},
	)

	result, err := fetcher.Fetch(
		context.Background(), testFetchImageRef, testFetchDigest, &attestation.FetchOptions{},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !cosignTagFetched {
		t.Error("cosign tag was not fetched as fallback")
	}

	if len(result) != 1 {
		t.Errorf("expected 1 attestation, got %d", len(result))
	}
}

type fakeNetError struct {
	timeout bool
}

func (e *fakeNetError) Error() string { return "fake net error" }
func (e *fakeNetError) Timeout() bool { return e.timeout }

// Temporary satisfies net.Error but is not used by isTransientError.
func (e *fakeNetError) Temporary() bool { return e.timeout }

func TestIsTransientError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "transport error with Temporary true (429)",
			err:  &transport.Error{StatusCode: http.StatusTooManyRequests},
			want: true,
		},
		{
			name: "transport error with Temporary true (503)",
			err:  &transport.Error{StatusCode: http.StatusServiceUnavailable},
			want: true,
		},
		{
			name: "transport error with Temporary false (404)",
			err:  &transport.Error{StatusCode: http.StatusNotFound},
			want: false,
		},
		{
			name: "net error with timeout true",
			err:  &fakeNetError{timeout: true},
			want: true,
		},
		{
			name: "net error with timeout false",
			err:  &fakeNetError{timeout: false},
			want: false,
		},
		{
			name: "plain error",
			err:  errPlainTest,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := attestation.ExportIsTransientError(tt.err)
			if got != tt.want {
				t.Errorf("isTransientError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFetchRetriesOnTransientError(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32

	ref := "docker.io/library/nginx@sha256:" + strings.Repeat("a", 64)
	digest := "sha256:" + strings.Repeat("a", 64)

	fetcher := attestation.NewTestOCIFetcherFull(
		func(_ context.Context, _ []byte, _ *attestation.FetchOptions) ([]byte, error) {
			return nil, errNotReached
		},
		func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
			return nil, &transport.Error{StatusCode: http.StatusNotFound}
		},
		func(_ name.Digest, _ ...remote.Option) (ociV1.ImageIndex, error) {
			n := calls.Add(1)
			if n == 1 {
				return nil, &transport.Error{StatusCode: http.StatusServiceUnavailable}
			}

			return &fakeImageIndex{manifests: nil, err: nil}, nil
		},
	)

	opts := &attestation.FetchOptions{Timeout: 5 * time.Second}

	_, err := fetcher.Fetch(context.Background(), ref, digest, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if calls.Load() < 2 {
		t.Errorf("expected at least 2 calls to referrers, got %d", calls.Load())
	}
}

func TestFetchExhaustsAllRetries(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32

	ref := "docker.io/library/nginx@sha256:" + strings.Repeat("a", 64)
	digest := "sha256:" + strings.Repeat("a", 64)

	// Every call returns a transient error (503), so all retries are exhausted.
	fetcher := attestation.NewTestOCIFetcherFull(
		func(_ context.Context, _ []byte, _ *attestation.FetchOptions) ([]byte, error) {
			return nil, errNotReached
		},
		func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
			return nil, &transport.Error{StatusCode: http.StatusNotFound}
		},
		func(_ name.Digest, _ ...remote.Option) (ociV1.ImageIndex, error) {
			calls.Add(1)

			return nil, &transport.Error{StatusCode: http.StatusServiceUnavailable}
		},
	)

	opts := &attestation.FetchOptions{Timeout: 10 * time.Second}

	_, err := fetcher.Fetch(context.Background(), ref, digest, opts)
	if err == nil {
		t.Fatal("expected error when all retries are exhausted")
	}

	if !strings.Contains(err.Error(), "listing referrers") {
		t.Errorf("expected listing referrers error, got: %v", err)
	}

	// fetchMaxRetries is 2, so we expect 3 calls (initial + 2 retries).
	if got := calls.Load(); got != 3 {
		t.Errorf("expected 3 calls (initial + 2 retries), got %d", got)
	}
}

func TestSetRateLimit(t *testing.T) {
	t.Parallel()

	t.Run("positive rate", func(t *testing.T) {
		t.Parallel()

		fetcher := attestation.NewOCIFetcherWithVerifier(
			func(_ context.Context, _ []byte, _ *attestation.FetchOptions) ([]byte, error) {
				return nil, nil
			},
		)

		// Should not panic.
		fetcher.SetRateLimit(10.0)
	})

	t.Run("zero rate disables limiter", func(t *testing.T) {
		t.Parallel()

		fetcher := attestation.NewOCIFetcherWithVerifier(
			func(_ context.Context, _ []byte, _ *attestation.FetchOptions) ([]byte, error) {
				return nil, nil
			},
		)

		fetcher.SetRateLimit(10.0)
		fetcher.SetRateLimit(0)
	})

	t.Run("negative rate disables limiter", func(t *testing.T) {
		t.Parallel()

		fetcher := attestation.NewOCIFetcherWithVerifier(
			func(_ context.Context, _ []byte, _ *attestation.FetchOptions) ([]byte, error) {
				return nil, nil
			},
		)

		fetcher.SetRateLimit(-1.0)
	})
}

//nolint:paralleltest // clears a package-level sync.Map that other parallel tests use
func TestResetSANPatternWarnings(t *testing.T) {
	// Call buildCertificateIdentity with no SAN patterns to trigger
	// the warning, then reset and verify a second call does not panic.
	_, err := attestation.ExportBuildCertificateID(
		[]string{testIssuerExample}, nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Reset warnings.
	attestation.ResetSANPatternWarnings()

	// After reset, a second call with the same issuers should work
	// and re-emit the warning (no duplicate suppression).
	_, err = attestation.ExportBuildCertificateID(
		[]string{testIssuerExample}, nil,
	)
	if err != nil {
		t.Fatalf("unexpected error after reset: %v", err)
	}
}

func TestArtifactPolicy(t *testing.T) {
	t.Parallel()

	validDigests := []string{
		"sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abcd",
		"sha512:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789" +
			"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
	}

	for _, digest := range validDigests {
		err := attestation.ExportArtifactPolicy(digest)
		if err != nil {
			t.Errorf("artifactPolicy(%q) unexpected error: %v", digest, err)
		}
	}

	invalidDigests := []string{
		"",
		"sha256abc123",
		"sha256:xyz123",
		"SHA256:abc123",
		"sha256:ABC123",
	}

	for _, digest := range invalidDigests {
		err := attestation.ExportArtifactPolicy(digest)
		if err == nil {
			t.Errorf("artifactPolicy(%q) expected error, got nil", digest)
		}
	}
}

func TestFetchSkipsCosignTagWhenReferrersExist(t *testing.T) {
	t.Parallel()

	var cosignTagFetched bool

	fetcher := attestation.NewTestOCIFetcherFull(
		func(_ context.Context, _ []byte, _ *attestation.FetchOptions) ([]byte, error) {
			return []byte(`{"predicateType":"https://slsa.dev/provenance/v1"}`), nil
		},
		func(ref name.Reference, _ ...remote.Option) (ociV1.Image, error) {
			if strings.HasSuffix(ref.String(), ".att") {
				cosignTagFetched = true
			}

			return fakeImageWithPayload([]byte(`{"bundle": "ok"}`)), nil
		},
		func(_ name.Digest, _ ...remote.Option) (ociV1.ImageIndex, error) {
			return &fakeImageIndex{
				manifests: []ociV1.Descriptor{
					bundleDescriptor(attestation.PredicateSLSAProvenanceV1),
				},
				err: nil,
			}, nil
		},
	)

	result, err := fetcher.Fetch(
		context.Background(), testFetchImageRef, testFetchDigest, &attestation.FetchOptions{},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cosignTagFetched {
		t.Error("cosign tag should not be fetched when OCI referrers exist")
	}

	if len(result) != 1 {
		t.Errorf("expected 1 attestation, got %d", len(result))
	}
}

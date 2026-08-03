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

package policy_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	ociV1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	ociTypes "github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
)

const (
	testDefaultJSON     = "default.json"
	testTitleAnnotation = "org.opencontainers.image.title"
	testWarnPolicyJSON  = `{"slsa":{"missingPolicy":"warn"}}`
)

func TestFetchFromOCIWithMockRegistry(t *testing.T) {
	t.Parallel()

	defaultPolicy := testWarnPolicyJSON
	prodPolicy := `{"slsa":{"missingPolicy":"deny"},"inherits":true}`

	img := buildPolicyImage(t, map[string]string{
		testDefaultJSON:   defaultPolicy,
		"production.json": prodPolicy,
	})

	srv := httptest.NewServer(registry.New())
	defer srv.Close()

	ref := pushImage(t, srv, img, "test/policies:v1")
	fetcher := policy.NewOCIFetcher(nil)

	result, err := fetcher.FetchFromOCI(context.Background(), ref)
	testutil.AssertNoError(t, err)

	if result.Digest == "" {
		t.Error("expected non-empty digest")
	}

	if len(result.Policies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(result.Policies))
	}

	defaultPol, ok := result.Policies[""]
	if !ok {
		t.Fatal("expected default policy")
	}

	testutil.AssertEqual(t, "warn", string(defaultPol.SLSAMissingPolicy()))

	prodPol, ok := result.Policies["production"]
	if !ok {
		t.Fatal("expected production policy")
	}

	testutil.AssertEqual(t, "deny", string(prodPol.SLSAMissingPolicy()))
}

func TestCheckDigest(t *testing.T) {
	t.Parallel()

	img := buildPolicyImage(t, map[string]string{
		testDefaultJSON: testWarnPolicyJSON,
	})

	srv := httptest.NewServer(registry.New())
	defer srv.Close()

	ref := pushImage(t, srv, img, "test/policies:digest")
	fetcher := policy.NewOCIFetcher(nil)

	digest, err := fetcher.CheckDigest(context.Background(), ref)
	testutil.AssertNoError(t, err)

	if digest == "" {
		t.Error("expected non-empty digest")
	}

	// Digest should match what FetchFromOCI returns.
	result, err := fetcher.FetchFromOCI(context.Background(), ref)
	testutil.AssertNoError(t, err)

	testutil.AssertEqual(t, result.Digest, digest)
}

func TestCheckDigestInvalidReference(t *testing.T) {
	t.Parallel()

	fetcher := policy.NewOCIFetcher(nil)

	_, err := fetcher.CheckDigest(context.Background(), "NOT A VALID REF!!!")
	testutil.AssertError(t, err)
}

func TestFetchFromOCIEmptyArtifact(t *testing.T) {
	t.Parallel()

	img := empty.Image

	srv := httptest.NewServer(registry.New())
	defer srv.Close()

	ref := pushImage(t, srv, img, "test/policies:empty")
	fetcher := policy.NewOCIFetcher(nil)

	result, err := fetcher.FetchFromOCI(context.Background(), ref)
	testutil.AssertNoError(t, err)

	testutil.AssertEqual(t, 0, len(result.Policies))
}

func TestFetchFromOCIInvalidJSON(t *testing.T) {
	t.Parallel()

	img := buildPolicyImage(t, map[string]string{
		testDefaultJSON: testWarnPolicyJSON,
		"bad.json":      `{invalid json}`,
	})

	srv := httptest.NewServer(registry.New())
	defer srv.Close()

	ref := pushImage(t, srv, img, "test/policies:bad")
	fetcher := policy.NewOCIFetcher(nil)

	_, err := fetcher.FetchFromOCI(context.Background(), ref)
	testutil.AssertError(t, err)
	testutil.AssertContains(t, err.Error(), "invalid OCI policy layer")
}

func TestFetchFromOCIInvalidReference(t *testing.T) {
	t.Parallel()

	fetcher := policy.NewOCIFetcher(nil)

	_, err := fetcher.FetchFromOCI(context.Background(), "NOT A VALID REF!!!")
	testutil.AssertError(t, err)
}

func TestFetchFromOCIDigestStability(t *testing.T) {
	t.Parallel()

	img := buildPolicyImage(t, map[string]string{
		testDefaultJSON: `{}`,
	})

	srv := httptest.NewServer(registry.New())
	defer srv.Close()

	ref := pushImage(t, srv, img, "test/policies:stable")
	fetcher := policy.NewOCIFetcher(nil)

	result1, err := fetcher.FetchFromOCI(context.Background(), ref)
	testutil.AssertNoError(t, err)

	result2, err := fetcher.FetchFromOCI(context.Background(), ref)
	testutil.AssertNoError(t, err)

	testutil.AssertEqual(t, result1.Digest, result2.Digest)
}

func TestFetchFromOCIInheritance(t *testing.T) {
	t.Parallel()

	defaultPolicy := `{
		"trust": {
			"builders": [{"id": "https://builder.example.com", "maxLevel": 3}]
		},
		"slsa": {"missingPolicy": "deny"}
	}`
	nsPol := `{"inherits": true, "slsa": {"missingPolicy": "warn"}}`

	img := buildPolicyImage(t, map[string]string{
		testDefaultJSON: defaultPolicy,
		"dev.json":      nsPol,
	})

	srv := httptest.NewServer(registry.New())
	defer srv.Close()

	ref := pushImage(t, srv, img, "test/policies:inherit")
	fetcher := policy.NewOCIFetcher(nil)

	result, err := fetcher.FetchFromOCI(context.Background(), ref)
	testutil.AssertNoError(t, err)

	devPol, ok := result.Policies["dev"]
	if !ok {
		t.Fatal("expected dev policy")
	}

	// Should inherit trust from default.
	if devPol.Builders() == nil {
		t.Error("expected inherited trust.builders")
	}

	// But override SLSA.
	testutil.AssertEqual(t, "warn", string(devPol.SLSAMissingPolicy()))
}

// buildPolicyImage creates an OCI image with policy JSON files as layers.
func buildPolicyImage(t *testing.T, files map[string]string) ociV1.Image {
	t.Helper()

	img := empty.Image

	// Sort filenames for deterministic ordering.
	filenames := make([]string, 0, len(files))
	for filename := range files {
		filenames = append(filenames, filename)
	}

	slices.Sort(filenames)

	for _, filename := range filenames {
		content := files[filename]

		layer := &staticLayer{
			content:   []byte(content),
			mediaType: ociTypes.MediaType(policy.PolicyMediaType),
			annotations: map[string]string{
				testTitleAnnotation: filename,
			},
		}

		var err error

		img, err = mutate.Append(img, mutate.Addendum{
			Layer: layer,
			Annotations: map[string]string{
				testTitleAnnotation: filename,
			},
		})
		if err != nil {
			t.Fatalf("appending layer %s: %v", filename, err)
		}
	}

	return img
}

// pushImage pushes an image to the test registry and returns the full ref.
func pushImage(t *testing.T, srv *httptest.Server, img ociV1.Image, path string) string {
	t.Helper()

	// Strip http:// from the server URL for the registry host.
	host := srv.Listener.Addr().String()
	fullRef := fmt.Sprintf("%s/%s", host, path)

	ref, err := name.ParseReference(fullRef)
	if err != nil {
		t.Fatalf("parsing reference %q: %v", fullRef, err)
	}

	err = remote.Write(ref, img)
	if err != nil {
		t.Fatalf("pushing image %q: %v", fullRef, err)
	}

	return fullRef
}

// staticLayer is a simple in-memory OCI layer implementation.
type staticLayer struct {
	content     []byte
	mediaType   ociTypes.MediaType
	annotations map[string]string
}

func (l *staticLayer) Digest() (ociV1.Hash, error) {
	h, _, err := ociV1.SHA256(bytes.NewReader(l.content))
	if err != nil {
		return ociV1.Hash{}, fmt.Errorf("computing digest: %w", err)
	}

	return h, nil
}

func (l *staticLayer) DiffID() (ociV1.Hash, error) {
	h, _, err := ociV1.SHA256(bytes.NewReader(l.content))
	if err != nil {
		return ociV1.Hash{}, fmt.Errorf("computing diff ID: %w", err)
	}

	return h, nil
}

func (l *staticLayer) Compressed() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(l.content)), nil
}

func (l *staticLayer) Uncompressed() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(l.content)), nil
}

func (l *staticLayer) Size() (int64, error) {
	return int64(len(l.content)), nil
}

func (l *staticLayer) MediaType() (ociTypes.MediaType, error) {
	return l.mediaType, nil
}

// Verify the staticLayer implements the Layer interface at compile time.
var _ ociV1.Layer = (*staticLayer)(nil)

func TestFetchFromOCILayerSizeLimit(t *testing.T) {
	t.Parallel()

	// Create content exceeding 1 MiB (maxOCIPolicyLayerSize).
	oversizedContent := testWarnPolicyJSON

	padding := make([]byte, 1<<20+1-len(oversizedContent))
	for i := range padding {
		padding[i] = ' '
	}

	oversizedJSON := oversizedContent[:len(oversizedContent)-1] +
		string(padding) + "}"

	img := buildPolicyImage(t, map[string]string{
		testDefaultJSON: testWarnPolicyJSON,
		"big.json":      oversizedJSON,
	})

	srv := httptest.NewServer(registry.New())
	defer srv.Close()

	ref := pushImage(t, srv, img, "test/policies:big")
	fetcher := policy.NewOCIFetcher(nil)

	_, err := fetcher.FetchFromOCI(context.Background(), ref)
	if err == nil {
		t.Fatal("expected error for oversized layer with PolicyMediaType")
	}

	if !strings.Contains(err.Error(), "OCI policy layer exceeds size limit") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestFetchFromOCITooManyLayers(t *testing.T) {
	t.Parallel()

	// Build an image with more than 1000 layers to trigger
	// ErrTooManyOCIPolicyLayers.
	img := empty.Image

	validPolicy := testWarnPolicyJSON

	for i := range 1001 {
		filename := fmt.Sprintf("layer-%d.json", i)

		layer := &staticLayer{
			content:   []byte(validPolicy),
			mediaType: ociTypes.MediaType(policy.PolicyMediaType),
			annotations: map[string]string{
				testTitleAnnotation: filename,
			},
		}

		var err error

		img, err = mutate.Append(img, mutate.Addendum{
			Layer: layer,
			Annotations: map[string]string{
				testTitleAnnotation: filename,
			},
		})
		if err != nil {
			t.Fatalf("appending layer %d: %v", i, err)
		}
	}

	fetchFunc := func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
		return img, nil
	}

	fetcher := policy.NewOCIFetcherWithImageFunc(fetchFunc, nil)

	_, err := fetcher.FetchFromOCI(context.Background(), "example.com/test:many")
	testutil.AssertError(t, err)

	if !errors.Is(err, policy.ErrTooManyOCIPolicyLayers) {
		t.Errorf("expected ErrTooManyOCIPolicyLayers, got %v", err)
	}
}

func TestFetchFromOCITrailingJSONContent(t *testing.T) {
	t.Parallel()

	// Valid JSON followed by more JSON content. The decoder rejects this
	// because parseAndValidatePolicy checks for trailing content.
	trailingContent := `{"slsa":{"missingPolicy":"warn"}}{"extra":true}`

	img := buildPolicyImage(t, map[string]string{
		testDefaultJSON: `{"slsa":{"missingPolicy":"deny"}}`,
		"trailing.json": trailingContent,
	})

	srv := httptest.NewServer(registry.New())
	defer srv.Close()

	ref := pushImage(t, srv, img, "test/policies:trailing")
	fetcher := policy.NewOCIFetcher(nil)

	_, err := fetcher.FetchFromOCI(context.Background(), ref)
	testutil.AssertError(t, err)
	testutil.AssertContains(t, err.Error(), "invalid OCI policy layer")
}

func TestFetchFromOCIDuplicateLayerFilenames(t *testing.T) {
	t.Parallel()

	// Build an image with two layers that both have the same title
	// annotation. The second layer should overwrite the first.
	firstPolicy := `{"slsa":{"missingPolicy":"warn"}}`
	secondPolicy := `{"slsa":{"missingPolicy":"deny"}}`

	layer1 := &staticLayer{
		content:   []byte(firstPolicy),
		mediaType: ociTypes.MediaType(policy.PolicyMediaType),
		annotations: map[string]string{
			testTitleAnnotation: testDefaultJSON,
		},
	}

	layer2 := &staticLayer{
		content:   []byte(secondPolicy),
		mediaType: ociTypes.MediaType(policy.PolicyMediaType),
		annotations: map[string]string{
			testTitleAnnotation: testDefaultJSON,
		},
	}

	img, err := mutate.Append(empty.Image,
		mutate.Addendum{
			Layer:       layer1,
			Annotations: map[string]string{testTitleAnnotation: testDefaultJSON},
		},
		mutate.Addendum{
			Layer:       layer2,
			Annotations: map[string]string{testTitleAnnotation: testDefaultJSON},
		},
	)
	testutil.AssertNoError(t, err)

	fetchFunc := func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
		return img, nil
	}

	fetcher := policy.NewOCIFetcherWithImageFunc(fetchFunc, nil)

	result, err := fetcher.FetchFromOCI(context.Background(), "example.com/test:dup")
	testutil.AssertNoError(t, err)

	// Only one policy should exist (the second one wins).
	testutil.AssertEqual(t, 1, len(result.Policies))

	pol, ok := result.Policies[""]
	if !ok {
		t.Fatal("expected default policy")
	}

	// The second layer's value should have won.
	testutil.AssertEqual(t, "deny", string(pol.SLSAMissingPolicy()))
}

func TestFetchFromOCIWithCustomFetchFunc(t *testing.T) {
	t.Parallel()

	defaultPolicyJSON, err := json.Marshal(map[string]any{
		"slsa": map[string]string{"missingPolicy": "deny"},
	})
	testutil.AssertNoError(t, err)

	layer := &staticLayer{
		content:   defaultPolicyJSON,
		mediaType: ociTypes.MediaType(policy.PolicyMediaType),
		annotations: map[string]string{
			testTitleAnnotation: testDefaultJSON,
		},
	}

	img, err := mutate.Append(empty.Image, mutate.Addendum{
		Layer: layer,
		Annotations: map[string]string{
			testTitleAnnotation: testDefaultJSON,
		},
	})
	testutil.AssertNoError(t, err)

	fetchFunc := func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
		return img, nil
	}

	fetcher := policy.NewOCIFetcherWithImageFunc(fetchFunc, nil)

	result, err := fetcher.FetchFromOCI(context.Background(), "example.com/test:v1")
	testutil.AssertNoError(t, err)

	testutil.AssertEqual(t, 1, len(result.Policies))

	pol, ok := result.Policies[""]
	if !ok {
		t.Fatal("expected default policy")
	}

	testutil.AssertEqual(t, "deny", string(pol.SLSAMissingPolicy()))
}

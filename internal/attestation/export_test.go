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
	"context"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1" //nolint:depguard // test helper
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1" //nolint:depguard // test helper
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"        //nolint:depguard // test helper
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// ExportDefaultVerifyBundle exposes verifyBundleWithCache (nil cache) for external tests.
func ExportDefaultVerifyBundle(
	ctx context.Context, data []byte,
	opts FetchOptions, //nolint:gocritic // matches BundleVerifyFunc signature
) ([]byte, error) {
	return verifyBundleWithCache(ctx, data, opts, nil)
}

// ExportBuildCertificateID exposes buildCertificateIdentity for external tests.
func ExportBuildCertificateID(issuers, sanPatterns []string) (verify.CertificateIdentity, error) {
	return buildCertificateIdentity(issuers, sanPatterns)
}

// ExportBuildKeyMaterial exposes buildKeyMaterial for external tests.
func ExportBuildKeyMaterial(keys []string) (*root.TrustedPublicKeyMaterial, error) {
	return buildKeyMaterial(keys)
}

// ExportBuildVerificationCfgErr exposes buildVerificationConfig for external tests,
// returning only the error to avoid the dogsled linter issue.
func ExportBuildVerificationCfgErr(
	ctx context.Context,
	opts FetchOptions, //nolint:gocritic // wraps buildVerificationConfig
) error {
	//nolint:dogsled // wraps 4-return function
	_, _, _, err := buildVerificationConfig(ctx, opts, nil)

	return err
}

// ExportBuildVerificationCfgWithCache exposes buildVerificationConfig with a cache
// for external tests.
func ExportBuildVerificationCfgWithCache(
	ctx context.Context,
	opts FetchOptions, //nolint:gocritic // wraps buildVerificationConfig
	cache *trustedRootCache,
) error {
	//nolint:dogsled // wraps 4-return function
	_, _, _, err := buildVerificationConfig(ctx, opts, cache)

	return err
}

// ExportParseDigestRef exposes parseDigestRef for external tests.
func ExportParseDigestRef(imageRef, digest string) (name.Digest, error) {
	return parseDigestRef(imageRef, digest)
}

// ExportExtractVerifiedPayload exposes extractVerifiedPayload for external tests.
func ExportExtractVerifiedPayload(bndl *bundle.Bundle) ([]byte, error) {
	return extractVerifiedPayload(bndl)
}

// ExportErrEmptyAttestation returns the errEmptyAttestation sentinel for external tests.
func ExportErrEmptyAttestation() error { return errEmptyAttestation }

// ExportErrAttestationTooLarge returns the errAttestationTooLarge sentinel for external tests.
func ExportErrAttestationTooLarge() error { return errAttestationTooLarge }

// ExportErrInvalidPayloadType returns the errInvalidPayloadType sentinel for external tests.
func ExportErrInvalidPayloadType() error { return errInvalidPayloadType }

// ExportErrNoTrustedMaterial returns the errNoTrustedMaterial sentinel for external tests.
func ExportErrNoTrustedMaterial() error { return errNoTrustedMaterial }

// ExportErrAllBundlesFailed returns the errAllBundlesFailed sentinel for external tests.
func ExportErrAllBundlesFailed() error { return errAllBundlesFailed }

// ExportMaxReferrers returns the maxReferrers constant for external tests.
func ExportMaxReferrers() int { return maxReferrers }

// VerifyBundle exposes the OCIFetcher's verifyBundle for testing.
func (f *OCIFetcher) VerifyBundle(
	ctx context.Context, data []byte,
	opts FetchOptions, //nolint:gocritic // matches BundleVerifyFunc signature
) ([]byte, error) {
	return f.verifyBundle(ctx, data, opts)
}

// CollectAttestations exposes the OCIFetcher's collectAttestations for testing.
func (f *OCIFetcher) CollectAttestations(
	ctx context.Context,
	manifests []v1.Descriptor,
	ref name.Digest,
	digest string,
	remoteOpts []remote.Option,
	opts FetchOptions, //nolint:gocritic // matches collectAttestations signature
) ([]VerifiedAttestation, bool) {
	return f.collectAttestations(ctx, manifests, ref, digest, remoteOpts, opts)
}

// NewOCIFetcherWithCache creates a fetcher using the real trusted root cache
// and closure-based verification, for testing the cache integration path.
func NewOCIFetcherWithCache() *OCIFetcher {
	return NewOCIFetcher()
}

// TrustedRootFetchFunc is the type alias for trustedRootFetchFunc.
type TrustedRootFetchFunc = trustedRootFetchFunc

// TrustedRootCacheForTest is the exported type alias for trustedRootCache.
type TrustedRootCacheForTest = trustedRootCache

// NewTestTrustedRootCache creates a trustedRootCache with an injectable fetch function for testing.
func NewTestTrustedRootCache(fetchFn TrustedRootFetchFunc) *trustedRootCache {
	return &trustedRootCache{
		mu:        sync.RWMutex{},
		root:      nil,
		fetchedAt: time.Time{},
		fetchRoot: fetchFn,
	}
}

// NewTestTrustedRootCacheWithRoot creates a cache pre-seeded with a root for testing.
func NewTestTrustedRootCacheWithRoot(
	fetchFn TrustedRootFetchFunc, cachedRoot *root.TrustedRoot, fetchedAt time.Time,
) *trustedRootCache {
	return &trustedRootCache{
		mu:        sync.RWMutex{},
		root:      cachedRoot,
		fetchedAt: fetchedAt,
		fetchRoot: fetchFn,
	}
}

// GetTrustedRoot exposes the cache's get method for testing.
func (c *trustedRootCache) GetTrustedRoot(ctx context.Context) (*root.TrustedRoot, error) {
	return c.get(ctx)
}

// ExportTrustedRootCacheTTL returns the cache TTL for testing.
func ExportTrustedRootCacheTTL() time.Duration { return trustedRootCacheTTL }

// ExportTrustedRootMaxStaleness returns the max staleness for testing.
func ExportTrustedRootMaxStaleness() time.Duration { return trustedRootMaxStaleness }

// ExportVerifyBundleWithCacheNil exposes verifyBundleWithCache with a nil cache
// for testing the uncached keyless path.
func ExportVerifyBundleWithCacheNil(
	ctx context.Context, bundleBytes []byte,
	opts FetchOptions, //nolint:gocritic // matches BundleVerifyFunc signature
) ([]byte, error) {
	return verifyBundleWithCache(ctx, bundleBytes, opts, nil)
}

// NewTestOCIFetcher creates a fetcher with injectable dependencies for testing.
func NewTestOCIFetcher(verifier BundleVerifyFunc, imageFetcher ImageFetchFunc) *OCIFetcher {
	return &OCIFetcher{
		verifyBundle: verifier,
		fetchImage:   imageFetcher,
		rootCache:    nil,
	}
}

// ExtractPayload exposes extractPayload for external tests.
//
//nolint:gocritic // hugeParam: test export layer passes FetchOptions by value
func (f *OCIFetcher) ExtractPayload(
	ctx context.Context, baseRef name.Digest, descDigest string,
	remoteOpts []remote.Option, fetchOpts FetchOptions,
) ([]byte, error) {
	return f.extractPayload(ctx, baseRef, descDigest, remoteOpts, fetchOpts)
}

// NewTestBundle creates a bundle with a DSSE envelope for testing.
func NewTestBundle(payloadType, payload string) *bundle.Bundle {
	protoBundle := &protobundle.Bundle{
		MediaType: BundleMediaType,
		Content: &protobundle.Bundle_DsseEnvelope{
			DsseEnvelope: &protodsse.Envelope{
				Payload:     []byte(payload),
				PayloadType: payloadType,
				Signatures: []*protodsse.Signature{
					{Sig: []byte("test-sig"), Keyid: "test-key"},
				},
			},
		},
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_PublicKey{
				PublicKey: &protocommon.PublicKeyIdentifier{
					Hint: "test-hint",
				},
			},
			TlogEntries:               nil,
			TimestampVerificationData: nil,
		},
	}

	bndl, err := bundle.NewBundle(protoBundle)
	if err != nil {
		panic("creating test bundle: " + err.Error())
	}

	return bndl
}

// NewTestMessageSignatureBundle creates a bundle with a message signature (no DSSE envelope).
func NewTestMessageSignatureBundle() *bundle.Bundle {
	protoBundle := &protobundle.Bundle{
		MediaType: BundleMediaType,
		Content: &protobundle.Bundle_MessageSignature{
			MessageSignature: &protocommon.MessageSignature{
				MessageDigest: &protocommon.HashOutput{
					Algorithm: protocommon.HashAlgorithm_SHA2_256,
					Digest:    []byte("test-digest"),
				},
				Signature: []byte("test-sig"),
			},
		},
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_PublicKey{
				PublicKey: &protocommon.PublicKeyIdentifier{
					Hint: "test-hint",
				},
			},
			TlogEntries:               nil,
			TimestampVerificationData: nil,
		},
	}

	bndl, err := bundle.NewBundle(protoBundle)
	if err != nil {
		panic("creating test bundle: " + err.Error())
	}

	return bndl
}

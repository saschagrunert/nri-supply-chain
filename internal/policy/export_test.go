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
	"crypto"

	"github.com/google/go-containerregistry/pkg/name"
	ociV1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// SetImageFetchFunc replaces the image fetch function.
// This is test-only and not safe for concurrent use.
func (f *OCIFetcher) SetImageFetchFunc(fn ImageFetchFunc) {
	f.fetchImage = fn
	f.fetchHead = nil // disable HEAD optimization; mock functions only support GET
}

// PrebuiltVerification exposes prebuiltVerification for tests.
type PrebuiltVerification = prebuiltVerification

// FilterSignatureCandidatesForTest exposes filterSignatureCandidates for tests.
func FilterSignatureCandidatesForTest(manifests []ociV1.Descriptor) []*ociV1.Descriptor {
	return filterSignatureCandidates(manifests)
}

// CollectCandidatesForTest exposes collectCandidates for tests.
func CollectCandidatesForTest(
	manifests []ociV1.Descriptor, match func(string) bool,
) []*ociV1.Descriptor {
	return collectCandidates(manifests, match)
}

// ExtractFirstLayerForTest exposes extractFirstLayer for tests.
func ExtractFirstLayerForTest(ctx context.Context, img ociV1.Image) ([]byte, error) {
	return extractFirstLayer(ctx, img)
}

// BuildPolicyCertificateIdentityForTest exposes buildPolicyCertificateIdentity.
func BuildPolicyCertificateIdentityForTest(
	issuers, sanPatterns []string,
) (verify.CertificateIdentity, error) {
	return buildPolicyCertificateIdentity(issuers, sanPatterns)
}

// BuildPolicyKeyMaterialForTest exposes buildPolicyKeyMaterial for tests.
func BuildPolicyKeyMaterialForTest(keyPaths []string) (*root.TrustedPublicKeyMaterial, error) {
	return buildPolicyKeyMaterial(keyPaths)
}

// LoadPEMPublicKeyForTest exposes loadPEMPublicKey for tests.
func LoadPEMPublicKeyForTest(path string) (crypto.PublicKey, error) {
	return loadPEMPublicKey(path)
}

// PolicyKeyHintForTest exposes policyKeyHint for tests.
func PolicyKeyHintForTest(pub crypto.PublicKey) (string, error) {
	return policyKeyHint(pub)
}

// PrebuildVerificationConfigForTest exposes prebuildVerificationConfig.
func PrebuildVerificationConfigForTest(sigCfg *SignatureConfig) (*prebuiltVerification, error) {
	return prebuildVerificationConfig(sigCfg)
}

// VerifyPolicySignatureForTest exposes verifyPolicySignature for tests.
func VerifyPolicySignatureForTest(
	ctx context.Context,
	ref name.Reference,
	img ociV1.Image,
	remoteOpts []remote.Option,
	prebuilt *prebuiltVerification,
	fetchTrustedRoot FetchTrustedRootFunc,
	fetchImage ImageFetchFunc,
	referrers ReferrersFetchFunc,
) error {
	return verifyPolicySignature(
		ctx, ref, img, remoteOpts,
		prebuilt, fetchTrustedRoot, fetchImage, referrers,
	)
}

// FindSignatureCandidatesForTest exposes findSignatureCandidates for tests.
func FindSignatureCandidatesForTest(
	ref name.Reference,
	digest ociV1.Hash,
	remoteOpts []remote.Option,
	referrers ReferrersFetchFunc,
) ([]*ociV1.Descriptor, error) {
	return findSignatureCandidates(ref, digest, remoteOpts, referrers)
}

// TryCandidatesForTest exposes tryCandidates for tests.
func TryCandidatesForTest(
	ctx context.Context,
	ref name.Reference,
	digest ociV1.Hash,
	candidates []*ociV1.Descriptor,
	remoteOpts []remote.Option,
	trustedMaterial root.TrustedMaterialCollection,
	verifierOpts []verify.VerifierOption,
	policyOpts []verify.PolicyOption,
	fetchImage ImageFetchFunc,
) error {
	return tryCandidates(
		ctx, ref, digest, candidates, remoteOpts,
		trustedMaterial, verifierOpts, policyOpts, fetchImage,
	)
}

// VerifyCandidateForTest exposes verifyCandidate for tests.
func VerifyCandidateForTest(
	ctx context.Context,
	ref name.Reference,
	desc *ociV1.Descriptor,
	digestAlgo string,
	digestHex string,
	remoteOpts []remote.Option,
	sigVerifier *verify.Verifier,
	policyOpts []verify.PolicyOption,
	fetchImage ImageFetchFunc,
) error {
	return verifyCandidate(
		ctx, ref, desc, digestAlgo, digestHex,
		remoteOpts, sigVerifier, policyOpts, fetchImage,
	)
}

// BuildPolicyVerificationConfigForTest exposes buildPolicyVerificationConfig.
func BuildPolicyVerificationConfigForTest(
	ctx context.Context,
	prebuilt *prebuiltVerification,
	fetchTrustedRoot FetchTrustedRootFunc,
) (root.TrustedMaterialCollection, []verify.PolicyOption, error) {
	return buildPolicyVerificationConfig(ctx, prebuilt, fetchTrustedRoot)
}

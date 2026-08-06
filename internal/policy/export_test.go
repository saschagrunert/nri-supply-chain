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

	ociV1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// SetImageFetchFunc replaces the image fetch function.
// This is test-only and not safe for concurrent use.
func (f *OCIFetcher) SetImageFetchFunc(fn ImageFetchFunc) {
	f.fetchImage = fn
	f.fetchHead = nil // disable HEAD optimization; mock functions only support GET
}

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

// HashAlgorithmForKeyForTest exposes hashAlgorithmForKey for tests.
func HashAlgorithmForKeyForTest(pub crypto.PublicKey) crypto.Hash {
	return hashAlgorithmForKey(pub)
}

// PolicyKeyHintForTest exposes policyKeyHint for tests.
func PolicyKeyHintForTest(pub crypto.PublicKey) (string, error) {
	return policyKeyHint(pub)
}

// PrebuildVerificationConfigForTest exposes prebuildVerificationConfig.
func PrebuildVerificationConfigForTest(sigCfg *SignatureConfig) (*prebuiltVerification, error) {
	return prebuildVerificationConfig(sigCfg)
}

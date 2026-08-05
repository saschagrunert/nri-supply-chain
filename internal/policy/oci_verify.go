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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	ociV1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/saschagrunert/nri-supply-chain/internal/fileutil"
	"github.com/saschagrunert/nri-supply-chain/internal/glob"
)

const (
	// maxPolicySignatureReferrers caps the number of referrers examined.
	maxPolicySignatureReferrers = 50

	// maxPolicyBundleSize caps the size of a single Sigstore bundle layer.
	maxPolicyBundleSize = 1 << 20 // 1 MiB

	// bundleArtifactType is the OCI artifact type for Sigstore bundles.
	bundleArtifactType = "application/vnd.dev.sigstore.bundle.v0.3+json"

	// ociEmptyArtifactType is the fallback artifact type used by some registries.
	ociEmptyArtifactType = "application/vnd.oci.empty.v1+json"
)

// SignatureVerifyFunc verifies that the given OCI image has a valid Sigstore
// signature. It is called after pulling the image but before extracting
// policy content.
type SignatureVerifyFunc func(
	ctx context.Context,
	ref name.Reference,
	img ociV1.Image,
	remoteOpts []remote.Option,
) error

var (
	// ErrNoPolicySignature indicates that no valid Sigstore signature was found
	// for an OCI policy artifact.
	ErrNoPolicySignature = errors.New(
		"no valid signature found for OCI policy artifact",
	)

	// errNilSignatureConfig indicates a nil policy signature config was passed.
	errNilSignatureConfig = errors.New("policy signature config must not be nil")

	// errNilFetchImage indicates a nil fetchImage function was passed.
	errNilFetchImage = errors.New("fetchImage function must not be nil")

	// errNilReferrers indicates a nil referrers function was passed.
	errNilReferrers = errors.New("referrers function must not be nil")

	// errNoTrustMaterial indicates neither issuers nor keys were provided.
	errNoTrustMaterial = errors.New(
		"at least one of issuers or keys is required",
	)

	// errNoSignatureLayers indicates a signature image has no layers.
	errNoSignatureLayers = errors.New("signature image has no layers")

	// errBundleTooLarge indicates a signature bundle exceeds the size limit.
	errBundleTooLarge = errors.New("signature bundle exceeds size limit")

	// errNilFetchTrustedRoot indicates fetchTrustedRoot is required but nil.
	errNilFetchTrustedRoot = errors.New(
		"fetchTrustedRoot is required for keyless verification",
	)

	// errNoPEMBlock indicates no PEM block was found in a public key file.
	errNoPEMBlock = errors.New("no PEM block found")

	// errIssuersAndKeysMutuallyExclusive indicates both were set.
	errIssuersAndKeysMutuallyExclusive = errors.New(
		"issuers and keys are mutually exclusive",
	)
)

// SignatureConfig holds trust material for verifying OCI policy
// artifact signatures.
type SignatureConfig struct {
	Issuers     []string
	SANPatterns []string
	Keys        []string
}

// FetchTrustedRootFunc fetches the Sigstore trusted root for keyless
// verification.
type FetchTrustedRootFunc func(context.Context) (*root.TrustedRoot, error)

// ReferrersFetchFunc lists OCI referrers for a digest reference.
type ReferrersFetchFunc func(d name.Digest, options ...remote.Option) (ociV1.ImageIndex, error)

// NewSignatureVerifyFunc builds a SignatureVerifyFunc from the given
// configuration. For keyless verification (issuers), fetchTrustedRoot provides
// the Sigstore trusted root. For key-based verification, PEM public keys are
// loaded from disk at construction time and reused across calls.
func NewSignatureVerifyFunc(
	sigCfg *SignatureConfig,
	fetchTrustedRoot FetchTrustedRootFunc,
	fetchImage ImageFetchFunc,
	referrers ReferrersFetchFunc,
) (SignatureVerifyFunc, error) {
	err := validateSignatureVerifyParams(
		sigCfg, fetchTrustedRoot, fetchImage, referrers,
	)
	if err != nil {
		return nil, err
	}

	prebuilt, err := prebuildVerificationConfig(sigCfg)
	if err != nil {
		return nil, err
	}

	return func(
		ctx context.Context,
		ref name.Reference,
		img ociV1.Image,
		remoteOpts []remote.Option,
	) error {
		return verifyPolicySignature(
			ctx, ref, img, remoteOpts,
			prebuilt, fetchTrustedRoot, fetchImage, referrers,
		)
	}, nil
}

func validateSignatureVerifyParams(
	sigCfg *SignatureConfig,
	fetchTrustedRoot FetchTrustedRootFunc,
	fetchImage ImageFetchFunc,
	referrers ReferrersFetchFunc,
) error {
	if sigCfg == nil {
		return errNilSignatureConfig
	}

	if fetchImage == nil {
		return errNilFetchImage
	}

	if referrers == nil {
		return errNilReferrers
	}

	if len(sigCfg.Issuers) == 0 && len(sigCfg.Keys) == 0 {
		return errNoTrustMaterial
	}

	if len(sigCfg.Issuers) > 0 && len(sigCfg.Keys) > 0 {
		return errIssuersAndKeysMutuallyExclusive
	}

	if len(sigCfg.Issuers) > 0 && fetchTrustedRoot == nil {
		return errNilFetchTrustedRoot
	}

	return nil
}

// prebuiltVerification holds key material and certificate identity that are
// loaded once at construction time and reused across verification calls.
type prebuiltVerification struct {
	keyMaterial  *root.TrustedPublicKeyMaterial
	verifierOpts []verify.VerifierOption
	policyOpts   []verify.PolicyOption
	certID       *verify.CertificateIdentity
}

func prebuildVerificationConfig(sigCfg *SignatureConfig) (*prebuiltVerification, error) {
	prebuilt := &prebuiltVerification{}

	if len(sigCfg.Keys) > 0 {
		keyMaterial, err := buildPolicyKeyMaterial(sigCfg.Keys)
		if err != nil {
			return nil, err
		}

		prebuilt.keyMaterial = keyMaterial
		prebuilt.verifierOpts = append(prebuilt.verifierOpts, verify.WithNoObserverTimestamps())
		prebuilt.policyOpts = append(prebuilt.policyOpts, verify.WithKey())
	}

	if len(sigCfg.Issuers) > 0 {
		certID, err := buildPolicyCertificateIdentity(
			sigCfg.Issuers, sigCfg.SANPatterns,
		)
		if err != nil {
			return nil, err
		}

		prebuilt.certID = &certID
		prebuilt.verifierOpts = append(prebuilt.verifierOpts,
			verify.WithSignedCertificateTimestamps(1),
			verify.WithObserverTimestamps(1),
		)
	}

	return prebuilt, nil
}

func verifyPolicySignature(
	ctx context.Context,
	ref name.Reference,
	img ociV1.Image,
	remoteOpts []remote.Option,
	prebuilt *prebuiltVerification,
	fetchTrustedRoot FetchTrustedRootFunc,
	fetchImage ImageFetchFunc,
	referrers ReferrersFetchFunc,
) error {
	digest, err := img.Digest()
	if err != nil {
		return fmt.Errorf("computing policy image digest: %w", err)
	}

	candidates, err := findSignatureCandidates(
		ref, digest, remoteOpts, referrers,
	)
	if err != nil {
		return err
	}

	trustedMaterial, policyOpts, err := buildPolicyVerificationConfig(
		ctx, prebuilt, fetchTrustedRoot,
	)
	if err != nil {
		return err
	}

	return tryCandidates(
		ctx, ref, digest, candidates, remoteOpts,
		trustedMaterial, prebuilt.verifierOpts, policyOpts, fetchImage,
	)
}

func findSignatureCandidates(
	ref name.Reference,
	digest ociV1.Hash,
	remoteOpts []remote.Option,
	referrers ReferrersFetchFunc,
) ([]*ociV1.Descriptor, error) {
	digestRef := ref.Context().Digest(digest.String())

	idx, err := referrers(digestRef, remoteOpts...)
	if err != nil {
		return nil, fmt.Errorf(
			"listing referrers for policy signature: %w", err,
		)
	}

	manifest, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("reading referrers index: %w", err)
	}

	candidates := filterSignatureCandidates(manifest.Manifests)
	if len(candidates) == 0 {
		slog.Warn("No Sigstore signatures found for OCI policy",
			"ref", ref.String(),
			"digest", digest.String(),
		)

		return nil, ErrNoPolicySignature
	}

	return candidates, nil
}

func tryCandidates(
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
	sigVerifier, err := verify.NewVerifier(trustedMaterial, verifierOpts...)
	if err != nil {
		return fmt.Errorf("creating sigstore verifier: %w", err)
	}

	for _, desc := range candidates {
		if ctx.Err() != nil {
			return fmt.Errorf(
				"context canceled during policy signature verification: %w",
				ctx.Err(),
			)
		}

		verifyErr := verifyCandidate(
			ctx, ref, desc, digest.Algorithm, digest.Hex,
			remoteOpts, sigVerifier, policyOpts, fetchImage,
		)
		if verifyErr == nil {
			slog.Info("OCI policy signature verified",
				"ref", ref.String(),
				"digest", digest.String(),
			)

			return nil
		}

		slog.Debug("Policy signature candidate failed",
			"ref", ref.String(),
			"candidate_digest", desc.Digest.String(),
			"error", verifyErr,
		)
	}

	slog.Warn("OCI policy signature verification failed",
		"ref", ref.String(),
		"digest", digest.String(),
		"error", "all candidates failed",
	)

	return ErrNoPolicySignature
}

func filterSignatureCandidates(manifests []ociV1.Descriptor) []*ociV1.Descriptor {
	// Prefer exact artifact type matches. Fall back to permissive types
	// (empty or ociEmptyArtifactType) only when no exact matches exist,
	// so that junk referrers cannot fill the candidate cap.
	exact := collectCandidates(manifests, func(at string) bool {
		return at == bundleArtifactType
	})

	if len(exact) > 0 {
		return exact
	}

	return collectCandidates(manifests, func(at string) bool {
		return at == ociEmptyArtifactType || at == ""
	})
}

func collectCandidates(
	manifests []ociV1.Descriptor, match func(string) bool,
) []*ociV1.Descriptor {
	var candidates []*ociV1.Descriptor

	for idx := range manifests {
		if !match(manifests[idx].ArtifactType) {
			continue
		}

		if len(candidates) >= maxPolicySignatureReferrers {
			slog.Warn("Policy signature referrer count exceeds limit, skipping remaining",
				"limit", maxPolicySignatureReferrers,
				"total", len(manifests),
			)

			break
		}

		candidates = append(candidates, &manifests[idx])
	}

	return candidates
}

func verifyCandidate(
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
	sigRef := ref.Context().Digest(desc.Digest.String())

	img, err := fetchImage(sigRef, remoteOpts...)
	if err != nil {
		return fmt.Errorf("fetching signature image: %w", err)
	}

	bundleBytes, err := extractFirstLayer(ctx, img)
	if err != nil {
		return fmt.Errorf("extracting signature bundle: %w", err)
	}

	var bndl bundle.Bundle

	err = bndl.UnmarshalJSON(bundleBytes)
	if err != nil {
		return fmt.Errorf("parsing sigstore bundle: %w", err)
	}

	hashBytes, err := hex.DecodeString(digestHex)
	if err != nil {
		return fmt.Errorf("decoding digest hex: %w", err)
	}

	pol := verify.NewPolicy(
		verify.WithArtifactDigest(digestAlgo, hashBytes),
		policyOpts...,
	)

	_, err = sigVerifier.Verify(&bndl, pol)
	if err != nil {
		return fmt.Errorf("verifying sigstore bundle: %w", err)
	}

	return nil
}

func extractFirstLayer(ctx context.Context, img ociV1.Image) ([]byte, error) {
	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("reading signature layers: %w", err)
	}

	if len(layers) == 0 {
		return nil, errNoSignatureLayers
	}

	if ctx.Err() != nil {
		return nil, fmt.Errorf("context canceled: %w", ctx.Err())
	}

	reader, err := layers[0].Uncompressed()
	if err != nil {
		return nil, fmt.Errorf("opening signature layer: %w", err)
	}

	defer func() {
		closeErr := reader.Close()
		if closeErr != nil {
			slog.Warn("Failed to close signature layer reader", "error", closeErr)
		}
	}()

	data, err := io.ReadAll(io.LimitReader(reader, maxPolicyBundleSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading signature layer: %w", err)
	}

	if int64(len(data)) > maxPolicyBundleSize {
		return nil, fmt.Errorf(
			"%w: got %d bytes, limit %d",
			errBundleTooLarge, len(data), maxPolicyBundleSize,
		)
	}

	return data, nil
}

// buildPolicyVerificationConfig assembles trusted material and policy options.
// Key material and certificate identity are pre-loaded at construction time
// (in prebuiltVerification). Only the trusted root is fetched at call time
// to pick up root rotations.
func buildPolicyVerificationConfig(
	ctx context.Context,
	prebuilt *prebuiltVerification,
	fetchTrustedRoot FetchTrustedRootFunc,
) (root.TrustedMaterialCollection, []verify.PolicyOption, error) {
	var (
		materials  root.TrustedMaterialCollection
		policyOpts []verify.PolicyOption
	)

	policyOpts = append(policyOpts, prebuilt.policyOpts...)

	if prebuilt.keyMaterial != nil {
		materials = append(materials, prebuilt.keyMaterial)
	}

	if prebuilt.certID != nil {
		trustedRoot, err := fetchTrustedRoot(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf(
				"fetching trusted root for policy signature: %w", err,
			)
		}

		materials = append(materials, trustedRoot)
		policyOpts = append(policyOpts,
			verify.WithCertificateIdentity(*prebuilt.certID),
		)
	}

	return materials, policyOpts, nil
}

func buildPolicyCertificateIdentity(
	issuers, sanPatterns []string,
) (verify.CertificateIdentity, error) {
	sanRegex := ".*"

	if len(sanPatterns) > 0 {
		converted := make([]string, len(sanPatterns))
		for idx, p := range sanPatterns {
			converted[idx] = glob.ToRegex(p)
		}

		sanRegex = "^(?:" + strings.Join(converted, "|") + ")$"
	}

	if len(issuers) == 1 {
		certID, err := verify.NewShortCertificateIdentity(issuers[0], "", "", sanRegex)
		if err != nil {
			return verify.CertificateIdentity{}, fmt.Errorf(
				"creating certificate identity: %w", err,
			)
		}

		return certID, nil
	}

	escaped := make([]string, len(issuers))
	for idx, issuer := range issuers {
		escaped[idx] = regexp.QuoteMeta(issuer)
	}

	issuerPattern := "^(?:" + strings.Join(escaped, "|") + ")$"

	certID, err := verify.NewShortCertificateIdentity("", issuerPattern, "", sanRegex)
	if err != nil {
		return verify.CertificateIdentity{}, fmt.Errorf(
			"creating certificate identity: %w", err,
		)
	}

	return certID, nil
}

// buildPolicyKeyMaterial loads PEM public keys and builds trusted key material
// for policy signature verification.
func buildPolicyKeyMaterial(keyPaths []string) (*root.TrustedPublicKeyMaterial, error) {
	verifiers := make(map[string]*root.ExpiringKey, len(keyPaths))

	for _, keyPath := range keyPaths {
		pubKey, err := loadPEMPublicKey(keyPath)
		if err != nil {
			return nil, fmt.Errorf("loading public key %q: %w", keyPath, err)
		}

		hashAlgo := hashAlgorithmForKey(pubKey)

		keyVerifier, err := signature.LoadVerifier(pubKey, hashAlgo)
		if err != nil {
			return nil, fmt.Errorf("creating verifier for %q: %w", keyPath, err)
		}

		hint, hintErr := policyKeyHint(pubKey)
		if hintErr != nil {
			return nil, fmt.Errorf("computing key hint for %q: %w", keyPath, hintErr)
		}

		verifiers[hint] = root.NewExpiringKey(keyVerifier, time.Time{}, time.Time{})
	}

	return root.NewTrustedPublicKeyMaterialFromMapping(verifiers), nil
}

func loadPEMPublicKey(path string) (crypto.PublicKey, error) {
	data, err := fileutil.ReadLimited(path, fileutil.MaxCredentialFileSize)
	if err != nil {
		return nil, fmt.Errorf("reading PEM file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%w: %q", errNoPEMBlock, path)
	}

	pub, pkixErr := x509.ParsePKIXPublicKey(block.Bytes)
	if pkixErr == nil {
		return pub, nil
	}

	rsaKey, rsaErr := x509.ParsePKCS1PublicKey(block.Bytes)
	if rsaErr == nil {
		return rsaKey, nil
	}

	return nil, fmt.Errorf(
		"parsing public key (PKIX: %w, PKCS1: %w)", pkixErr, rsaErr,
	)
}

func hashAlgorithmForKey(pub crypto.PublicKey) crypto.Hash {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P384():
			return crypto.SHA384
		case elliptic.P521():
			return crypto.SHA512
		}
	case ed25519.PublicKey:
		return crypto.SHA512
	}

	return crypto.SHA256
}

func policyKeyHint(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshaling public key to PKIX: %w", err)
	}

	sum := sha256.Sum256(der)

	return base64.StdEncoding.EncodeToString(sum[:]), nil
}

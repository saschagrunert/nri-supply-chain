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
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/saschagrunert/nri-supply-chain/internal/glob"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

func verifyBundleWithCache(
	ctx context.Context,
	bundleBytes []byte,
	opts *FetchOptions,
	cachedRoot *trustedRootCache,
) ([]byte, error) {
	err := ctx.Err()
	if err != nil {
		return nil, fmt.Errorf("context canceled before bundle verification: %w", err)
	}

	var bndl bundle.Bundle

	err = bndl.UnmarshalJSON(bundleBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing sigstore bundle: %w", err)
	}

	trustedMaterial, verifierOpts, policyOpts, err := buildVerificationConfig(ctx, opts, cachedRoot)
	if err != nil {
		return nil, err
	}

	verifier, err := verify.NewVerifier(trustedMaterial, verifierOpts...)
	if err != nil {
		return nil, fmt.Errorf("creating sigstore verifier: %w", err)
	}

	artPolicy, artErr := artifactPolicy(opts.Digest)
	if artErr != nil {
		return nil, fmt.Errorf("artifact policy: %w", artErr)
	}

	pol := verify.NewPolicy(
		artPolicy,
		policyOpts...,
	)

	_, err = verifier.Verify(&bndl, pol)
	if err != nil {
		return nil, fmt.Errorf("verifying sigstore bundle: %w", err)
	}

	return extractVerifiedPayload(&bndl)
}

func buildVerificationConfig(
	ctx context.Context,
	opts *FetchOptions,
	cachedRoot *trustedRootCache,
) (root.TrustedMaterialCollection, []verify.VerifierOption, []verify.PolicyOption, error) {
	var (
		materials    root.TrustedMaterialCollection
		verifierOpts []verify.VerifierOption
		policyOpts   []verify.PolicyOption
	)

	if len(opts.TrustedKeys) > 0 {
		keyMaterial, err := buildKeyMaterial(opts.TrustedKeys)
		if err != nil {
			return nil, nil, nil, err
		}

		materials = append(materials, keyMaterial)
		verifierOpts = append(
			verifierOpts,
			keyOnlyVerifierOpts(len(opts.TrustedIssuers) > 0, opts.RequireTransparencyLog)...,
		)
		policyOpts = append(policyOpts, verify.WithKey())
	}

	if len(opts.TrustedIssuers) > 0 {
		issuerMaterial, issuerVerifierOpts, issuerPolicyOpts, err := buildKeylessConfig(
			ctx, opts, cachedRoot,
		)
		if err != nil {
			return nil, nil, nil, err
		}

		materials = append(materials, issuerMaterial)
		verifierOpts = append(verifierOpts, issuerVerifierOpts...)
		policyOpts = append(policyOpts, issuerPolicyOpts...)
	}

	if len(materials) == 0 {
		return nil, nil, nil, fmt.Errorf(
			"%w: provide trusted keys or issuers in policy", errNoTrustedMaterial,
		)
	}

	return materials, verifierOpts, policyOpts, nil
}

func keyOnlyVerifierOpts(hasIssuers, requireTLog bool) []verify.VerifierOption {
	if hasIssuers {
		return nil
	}

	if requireTLog {
		return []verify.VerifierOption{verify.WithTransparencyLog(1)}
	}

	// Key-only without tlog skips timestamp verification. A compromised
	// key cannot be time-bounded after revocation; require tlog in policy
	// to mitigate.
	return []verify.VerifierOption{verify.WithNoObserverTimestamps()}
}

func buildKeyMaterial(keyPaths []string) (*root.TrustedPublicKeyMaterial, error) {
	verifiers := make(map[string]*root.ExpiringKey, len(keyPaths))

	for _, keyPath := range keyPaths {
		// SHA-256 is the only algorithm supported for key hint computation
		// and artifact digest matching. Supporting additional algorithms
		// would require policy-level configuration.
		keyVerifier, err := signature.LoadVerifierFromPEMFile(keyPath, crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("loading public key %q: %w", keyPath, err)
		}

		hint, err := computeKeyHint(keyVerifier)
		if err != nil {
			return nil, fmt.Errorf("computing key hint for %q: %w", keyPath, err)
		}

		// Zero-value time.Time means no validity period bounds; the key
		// is accepted regardless of signing time.
		verifiers[hint] = root.NewExpiringKey(keyVerifier, time.Time{}, time.Time{})
	}

	return root.NewTrustedPublicKeyMaterialFromMapping(verifiers), nil
}

func computeKeyHint(v signature.Verifier) (string, error) {
	pub, err := v.PublicKey()
	if err != nil {
		return "", fmt.Errorf("extracting public key: %w", err)
	}

	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("encoding public key to DER: %w", err)
	}

	sum := sha256.Sum256(der)

	return base64.StdEncoding.EncodeToString(sum[:]), nil
}

func buildKeylessConfig(
	ctx context.Context,
	opts *FetchOptions,
	cachedRoot *trustedRootCache,
) (*root.TrustedRoot, []verify.VerifierOption, []verify.PolicyOption, error) {
	trustedRoot, err := fetchTrustedRootWithContext(ctx, cachedRoot)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("fetching sigstore trusted root: %w", err)
	}

	verifierOpts := []verify.VerifierOption{
		verify.WithSignedCertificateTimestamps(1),
		verify.WithObserverTimestamps(1),
	}

	if opts.RequireTransparencyLog {
		verifierOpts = append(verifierOpts, verify.WithTransparencyLog(1))
	}

	certID, err := buildCertificateIdentity(opts.TrustedIssuers, opts.SANPatterns)
	if err != nil {
		return nil, nil, nil, err
	}

	policyOpts := []verify.PolicyOption{verify.WithCertificateIdentity(certID)}

	return trustedRoot, verifierOpts, policyOpts, nil
}

type trustedRootResult struct {
	root *root.TrustedRoot
	err  error
}

// fetchTrustedRootWithContext wraps root.FetchTrustedRoot with context
// cancellation. On context cancel, the inner goroutine continues until
// the HTTP request completes (the sigstore library does not accept a
// context). The goroutine is bounded by HTTP timeouts and the buffered
// channel prevents it from blocking on send.
func fetchTrustedRootWithContext(
	ctx context.Context, cachedRoot *trustedRootCache,
) (*root.TrustedRoot, error) {
	if cachedRoot != nil {
		return cachedRoot.get(ctx)
	}

	ctxErr := ctx.Err()
	if ctxErr != nil {
		return nil, fmt.Errorf(
			"context canceled before fetching trusted root: %w", ctxErr,
		)
	}

	resultCh := make(chan trustedRootResult, 1)

	go func() {
		r, e := root.FetchTrustedRoot()
		resultCh <- trustedRootResult{root: r, err: e}
	}()

	select {
	case <-ctx.Done():
		slog.WarnContext(ctx, "Context canceled while trusted root fetch is in progress; "+
			"background goroutine will complete when the HTTP request finishes")

		return nil, fmt.Errorf(
			"context canceled during trusted root fetch: %w", ctx.Err(),
		)
	case res := <-resultCh:
		return res.root, res.err
	}
}

func buildCertificateIdentity(issuers, sanPatterns []string) (verify.CertificateIdentity, error) {
	if len(issuers) == 0 {
		return verify.CertificateIdentity{}, errNoIssuers
	}

	sanRegex := ".*"

	if len(sanPatterns) == 0 {
		warnNoSANPatterns(issuers)
	}

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
				"creating certificate identity: %w",
				err,
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
		return verify.CertificateIdentity{}, fmt.Errorf("creating certificate identity: %w", err)
	}

	return certID, nil
}

var warnedSANPatterns sync.Map //nolint:gochecknoglobals // dedup per unique issuer set

// ResetSANPatternWarnings clears the deduplication state so that SAN pattern
// warnings are re-emitted on the next verification cycle. Call this after a
// config reload to ensure warnings reflect the new policy state.
func ResetSANPatternWarnings() {
	warnedSANPatterns.Clear()
}

func warnNoSANPatterns(issuers []string) {
	key := strconv.Itoa(len(issuers)) + "\x00" + strings.Join(issuers, "\x00")

	if _, loaded := warnedSANPatterns.LoadOrStore(key, struct{}{}); loaded {
		return
	}

	slog.Warn("No SAN patterns configured for keyless verification; "+
		"any certificate identity from a trusted issuer will be accepted",
		"issuers", issuers,
	)
}

func extractVerifiedPayload(bndl *bundle.Bundle) ([]byte, error) {
	envelope, err := bndl.Envelope()
	if err != nil {
		return nil, fmt.Errorf("extracting DSSE envelope from bundle: %w", err)
	}

	rawEnvelope := envelope.RawEnvelope()
	if rawEnvelope.PayloadType != dssePayloadType {
		return nil, fmt.Errorf(
			"%w: expected %q, got %q",
			errInvalidPayloadType, dssePayloadType, rawEnvelope.PayloadType,
		)
	}

	payload, err := rawEnvelope.DecodeB64Payload()
	if err != nil {
		return nil, fmt.Errorf("decoding DSSE payload: %w", err)
	}

	return payload, nil
}

var (
	errMalformedDigest = errors.New("malformed digest")
	errEmptyDigest     = errors.New("empty digest")
)

func artifactPolicy(digest string) (verify.ArtifactPolicyOption, error) {
	if digest == "" {
		return nil, errEmptyDigest
	}

	algo, hashHex := types.ParseDigest(digest)
	if algo == "" {
		return nil, fmt.Errorf("%w: %q", errMalformedDigest, digest)
	}

	hashBytes, err := hex.DecodeString(hashHex)
	if err != nil {
		return nil, fmt.Errorf("%w: %q: %w", errMalformedDigest, digest, err)
	}

	return verify.WithArtifactDigest(algo, hashBytes), nil
}

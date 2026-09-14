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
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/saschagrunert/nri-supply-chain/internal/fileutil"
	"github.com/saschagrunert/nri-supply-chain/internal/glob"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

var pemKeyCache sync.Map //nolint:gochecknoglobals // per-process key cache

// ResetPEMKeyCache clears cached PEM public keys so that rotated keys on disk
// are re-read on the next verification cycle. Call this after a config reload
// when policies have changed.
func ResetPEMKeyCache() {
	pemKeyCache.Clear()
}

// rootSource supplies one Sigstore trusted root together with the OIDC
// issuers whose certificates that root may vouch for.
type rootSource struct {
	name string
	// issuers restricts the certificate issuers accepted from this root.
	// Empty means every issuer trusted by the policy is accepted.
	issuers []string
	get     func(ctx context.Context) (*root.TrustedRoot, error)
	// keylessDisabled refuses certificates of every issuer from this root.
	// The root still provides transparency log material for key-based
	// bundles.
	keylessDisabled bool
	// skipSCTs disables the signed certificate timestamp requirement. Only
	// tests set it, for virtual Fulcio instances that issue no SCTs.
	skipSCTs bool
}

func rootSourceFromCache(cachedRoot *trustedRootCache) rootSource {
	src := rootSource{
		name:    "",
		issuers: nil,
		get: func(ctx context.Context) (*root.TrustedRoot, error) {
			return fetchTrustedRootWithContext(ctx, cachedRoot)
		},
		keylessDisabled: false,
		skipSCTs:        false,
	}

	if cachedRoot != nil {
		src.name = cachedRoot.name
		src.issuers = cachedRoot.issuers
	}

	return src
}

func verifyBundleWithCache(
	ctx context.Context,
	bundleBytes []byte,
	opts *FetchOptions,
	cachedRoot *trustedRootCache,
) (*VerifiedBundle, error) {
	return verifyBundleCommon(ctx, bundleBytes, opts, []rootSource{rootSourceFromCache(cachedRoot)})
}

func verifyBundleWithMultipleRoots(
	ctx context.Context,
	bundleBytes []byte,
	opts *FetchOptions,
	rootCaches []*trustedRootCache,
) (*VerifiedBundle, error) {
	sources := make([]rootSource, 0, len(rootCaches))
	for _, cache := range rootCaches {
		sources = append(sources, rootSourceFromCache(cache))
	}

	return verifyBundleCommon(ctx, bundleBytes, opts, sources)
}

// VerifyBundle verifies a sigstore bundle against the given trusted root and
// returns the verified payload and signer. This is the entry point for offline
// verification where the caller supplies a pre-loaded TrustedRoot directly.
// A nil trustedRoot is allowed for key-based bundles verified without a
// transparency log; keyless bundles and transparency log checks fail closed.
func VerifyBundle(
	ctx context.Context,
	bundleBytes []byte,
	opts *FetchOptions,
	trustedRoot *root.TrustedRoot,
) (*VerifiedBundle, error) {
	return VerifyBundleWithIssuers(ctx, bundleBytes, opts, trustedRoot, nil)
}

// VerifyBundleWithIssuers is VerifyBundle with the trusted root restricted to
// vouch only for certificates of the given OIDC issuers. Empty issuers place
// no restriction.
func VerifyBundleWithIssuers(
	ctx context.Context,
	bundleBytes []byte,
	opts *FetchOptions,
	trustedRoot *root.TrustedRoot,
	issuers []string,
) (*VerifiedBundle, error) {
	var roots []StaticRoot

	if trustedRoot != nil {
		roots = []StaticRoot{{
			Name: "bundle", Root: trustedRoot, Issuers: issuers, KeylessDisabled: false,
		}}
	}

	return VerifyBundleWithStaticRoots(ctx, bundleBytes, opts, roots)
}

// StaticRoot is a trusted root supplied directly, for example embedded in an
// offline bundle, together with the OIDC issuers it may vouch for.
type StaticRoot struct {
	// Name labels the root in errors and logs.
	Name string
	// Root is the trusted root material.
	Root *root.TrustedRoot
	// Issuers restricts the certificate issuers the root may vouch for.
	// Empty means no restriction unless KeylessDisabled is set.
	Issuers []string
	// KeylessDisabled refuses certificates of every issuer from this root,
	// while it still provides transparency log material for key-based
	// bundles.
	KeylessDisabled bool
}

// VerifyBundleWithStaticRoots verifies a bundle against pre-loaded trusted
// roots, each restricted to its own issuers. Every root is tried on its own,
// so a certificate is only accepted from a root trusted for its issuer.
func VerifyBundleWithStaticRoots(
	ctx context.Context,
	bundleBytes []byte,
	opts *FetchOptions,
	roots []StaticRoot,
) (*VerifiedBundle, error) {
	sources := make([]rootSource, 0, len(roots))

	for idx := range roots {
		if roots[idx].Root == nil {
			continue
		}

		trustedRoot := roots[idx].Root

		sources = append(sources, rootSource{
			name:    roots[idx].Name,
			issuers: roots[idx].Issuers,
			get: func(context.Context) (*root.TrustedRoot, error) {
				return trustedRoot, nil
			},
			keylessDisabled: roots[idx].KeylessDisabled,
			skipSCTs:        false,
		})
	}

	return verifyBundleCommon(ctx, bundleBytes, opts, sources)
}

func verifyBundleCommon(
	ctx context.Context,
	bundleBytes []byte,
	opts *FetchOptions,
	sources []rootSource,
) (*VerifiedBundle, error) {
	err := ctx.Err()
	if err != nil {
		return nil, fmt.Errorf("context canceled before bundle verification: %w", err)
	}

	var bndl bundle.Bundle

	err = bndl.UnmarshalJSON(bundleBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing sigstore bundle: %w", err)
	}

	artPolicy, err := artifactPolicy(opts.Digest)
	if err != nil {
		return nil, fmt.Errorf("artifact policy: %w", err)
	}

	signer, err := verifySigner(ctx, &bndl, opts, artPolicy, sources)
	if err != nil {
		return nil, err
	}

	payload, err := extractVerifiedPayload(&bndl)
	if err != nil {
		return nil, err
	}

	predicateType := extractPredicateType(payload)
	if predicateType == "" {
		return nil, errMissingPredicateType
	}

	return &VerifiedBundle{
		Payload:       payload,
		PredicateType: predicateType,
		Signer:        signer,
	}, nil
}

// verifySigner verifies the bundle signature with the key-based or keyless
// path, depending on the verification material the bundle carries.
func verifySigner(
	ctx context.Context,
	bndl *bundle.Bundle,
	opts *FetchOptions,
	artPolicy verify.ArtifactPolicyOption,
	sources []rootSource,
) (SignerIdentity, error) {
	verificationContent, err := bndl.VerificationContent()
	if err != nil {
		return SignerIdentity{}, fmt.Errorf("reading bundle verification material: %w", err)
	}

	switch {
	case verificationContent.Certificate() != nil:
		return verifyKeyless(ctx, bndl, opts, artPolicy, sources)
	case verificationContent.PublicKey() != nil:
		return verifyKeyBased(ctx, bndl, opts, artPolicy, sources)
	default:
		return SignerIdentity{}, errUnsupportedSignature
	}
}

// verifyKeyBased verifies a bundle signed with a long-lived public key. Without
// a transparency log requirement the key validity window (notBefore/notAfter)
// is checked against the current time, because the signing time claimed by
// the bundle cannot be trusted. With a transparency log requirement the log's
// integrated time (or a trusted timestamp) is used instead.
func verifyKeyBased(
	ctx context.Context,
	bndl *bundle.Bundle,
	opts *FetchOptions,
	artPolicy verify.ArtifactPolicyOption,
	sources []rootSource,
) (SignerIdentity, error) {
	if len(opts.TrustedKeys) == 0 {
		return SignerIdentity{}, fmt.Errorf("%w: %w", errNoTrustedMaterial, errNoTrustedKeys)
	}

	keys, err := buildKeyMaterial(opts.TrustedKeys)
	if err != nil {
		return SignerIdentity{}, err
	}

	pol := verify.NewPolicy(artPolicy, verify.WithKey())

	if !opts.RequireTransparencyLog {
		result, verifyErr := runVerifier(
			bndl, root.TrustedMaterialCollection{keys.material}, pol, verify.WithCurrentTime(),
		)
		if verifyErr != nil {
			return SignerIdentity{}, verifyErr
		}

		return keys.signerFromResult(result)
	}

	if len(sources) == 0 {
		return SignerIdentity{}, fmt.Errorf(
			"%w: transparency log verification requires one", errNoTrustedRoot,
		)
	}

	var failures rootFailures

	for idx := range sources {
		trustedRoot, rootErr := sources[idx].get(ctx)
		if rootErr != nil {
			failures.unavailable(sources[idx].name, trustedRootError(rootErr))

			continue
		}

		result, verifyErr := runVerifier(
			bndl, root.TrustedMaterialCollection{keys.material, trustedRoot}, pol,
			verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1),
		)
		if verifyErr != nil {
			failures.rejected(verifyErr)

			continue
		}

		return keys.signerFromResult(result)
	}

	return SignerIdentity{}, failures.err()
}

// trustedRootError marks a failure to obtain a Sigstore trusted root as
// unavailable trust material.
func trustedRootError(err error) error {
	return fmt.Errorf("%w: fetching sigstore trusted root: %w", ErrTrustMaterialUnavailable, err)
}

// rootFailures collects why each trusted root did not verify a bundle. One
// unavailable root that was in scope for the bundle means the trust material
// to decide was missing, so the fetch failure policy applies even if other
// roots loaded and rejected the bundle: the unavailable root might have
// verified it.
type rootFailures struct {
	errs []error
}

// unavailable records a root whose trust material could not be loaded. err
// wraps ErrTrustMaterialUnavailable.
func (f *rootFailures) unavailable(rootName string, err error) {
	f.errs = append(f.errs, fmt.Errorf("trusted root %q: %w", rootName, err))
}

func (f *rootFailures) rejected(err error) {
	f.errs = append(f.errs, err)
}

// record classifies a verification error of one root. A root out of scope
// for the bundle is recorded like a rejection: it could not have verified it.
func (f *rootFailures) record(rootName string, err error) {
	if errors.Is(err, ErrTrustMaterialUnavailable) {
		f.unavailable(rootName, err)

		return
	}

	f.rejected(err)
}

func (f *rootFailures) err() error {
	return errors.Join(f.errs...)
}

// verifyKeyless verifies a bundle signed with a Fulcio certificate. Each
// trusted root is tried on its own so a certificate is only accepted when it
// chains to a root that is trusted for the certificate's issuer.
func verifyKeyless(
	ctx context.Context,
	bndl *bundle.Bundle,
	opts *FetchOptions,
	artPolicy verify.ArtifactPolicyOption,
	sources []rootSource,
) (SignerIdentity, error) {
	if len(opts.TrustedIssuers) == 0 {
		return SignerIdentity{}, fmt.Errorf("%w: %w", errNoTrustedMaterial, errNoTrustedIssuers)
	}

	tlogEntries, err := bndl.TlogEntries()
	if err != nil {
		return SignerIdentity{}, fmt.Errorf("reading transparency log entries: %w", err)
	}

	if opts.RequireTransparencyLog && len(tlogEntries) == 0 {
		return SignerIdentity{}, errTransparencyLogNeeded
	}

	if len(sources) == 0 {
		return SignerIdentity{}, fmt.Errorf(
			"%w: keyless verification requires one", errNoTrustedRoot,
		)
	}

	var failures rootFailures

	for idx := range sources {
		signer, verifyErr := verifyKeylessWithRoot(
			ctx, bndl, opts, artPolicy, &sources[idx], len(tlogEntries) > 0,
		)
		if verifyErr == nil {
			return signer, nil
		}

		failures.record(sources[idx].name, verifyErr)
	}

	return SignerIdentity{}, failures.err()
}

func verifyKeylessWithRoot(
	ctx context.Context,
	bndl *bundle.Bundle,
	opts *FetchOptions,
	artPolicy verify.ArtifactPolicyOption,
	src *rootSource,
	hasTlog bool,
) (SignerIdentity, error) {
	issuers, err := rootIssuers(opts, src)
	if err != nil {
		return SignerIdentity{}, err
	}

	certID, err := buildCertificateIdentity(issuers, opts.SANPatterns)
	if err != nil {
		return SignerIdentity{}, err
	}

	trustedRoot, err := src.get(ctx)
	if err != nil {
		return SignerIdentity{}, trustedRootError(err)
	}

	verifierOpts := []verify.VerifierOption{verify.WithObserverTimestamps(1)}

	if !src.skipSCTs {
		verifierOpts = append(verifierOpts, verify.WithSignedCertificateTimestamps(1))
	}

	// Transparency log entries present in the bundle are always verified, so
	// their integrated time can serve as the observer timestamp.
	if hasTlog {
		verifierOpts = append(verifierOpts, verify.WithTransparencyLog(1))
	}

	result, err := runVerifier(
		bndl, trustedRoot, verify.NewPolicy(artPolicy, verify.WithCertificateIdentity(certID)),
		verifierOpts...,
	)
	if err != nil {
		return SignerIdentity{}, err
	}

	if result.Signature == nil || result.Signature.Certificate == nil {
		return SignerIdentity{}, fmt.Errorf(
			"%w: verification result has no certificate", errUnsupportedSignature,
		)
	}

	return SignerIdentity{
		KeyPath:  "",
		KeyPaths: nil,
		Issuer:   result.Signature.Certificate.Issuer,
		SAN:      result.Signature.Certificate.SubjectAlternativeName,
	}, nil
}

// rootIssuers returns the policy issuers a trusted root may vouch for, or an
// error wrapping errRootOutOfScope when it may vouch for none of them.
func rootIssuers(opts *FetchOptions, src *rootSource) ([]string, error) {
	if src.keylessDisabled {
		return nil, fmt.Errorf(
			"%w: %w: trusted root %q is not trusted for any certificate issuer",
			errNoTrustedIssuers, errRootOutOfScope, src.name,
		)
	}

	issuers := scopeIssuers(opts.TrustedIssuers, src.issuers)
	if len(issuers) == 0 {
		return nil, fmt.Errorf(
			"%w: %w: trusted root %q is not trusted for issuers %v",
			errNoTrustedIssuers, errRootOutOfScope, src.name, opts.TrustedIssuers,
		)
	}

	return issuers, nil
}

func runVerifier(
	entity verify.SignedEntity,
	trustedMaterial root.TrustedMaterial,
	pol verify.PolicyBuilder,
	opts ...verify.VerifierOption,
) (*verify.VerificationResult, error) {
	// The predicate is read from the verified DSSE payload directly, so skip
	// materializing it (large SBOM predicates are expensive to parse).
	opts = append(opts, verify.WithoutStatementPredicate())

	verifier, err := verify.NewVerifier(trustedMaterial, opts...)
	if err != nil {
		return nil, fmt.Errorf("creating sigstore verifier: %w", err)
	}

	result, err := verifier.Verify(entity, pol)
	if err != nil {
		return nil, fmt.Errorf("verifying sigstore bundle: %w", err)
	}

	return result, nil
}

// keyEntry is one configured trusted key path with its validity window.
type keyEntry struct {
	path      string
	notBefore time.Time
	notAfter  time.Time
}

func (e *keyEntry) validAt(t time.Time) bool {
	if !e.notBefore.IsZero() && t.Before(e.notBefore) {
		return false
	}

	return e.notAfter.IsZero() || !t.After(e.notAfter)
}

// windowedKey is a trusted public key that may be configured at several paths
// with different validity windows. It is valid at a time when any of its
// entries is, and attribution later narrows the signer to the entries that
// are valid at the verified time.
type windowedKey struct {
	signature.Verifier

	entries []keyEntry
}

// ValidAtTime implements root.TimeConstrainedVerifier.
func (k *windowedKey) ValidAtTime(t time.Time) bool {
	for idx := range k.entries {
		if k.entries[idx].validAt(t) {
			return true
		}
	}

	return false
}

// trustedKeys is the loaded trusted key material together with the
// configured entries of every key, indexed by key hint.
type trustedKeys struct {
	material *root.TrustedPublicKeyMaterial
	byHint   map[string]*windowedKey
}

// signerFromResult attributes a verified key-based signature to the
// configured key paths whose validity windows contain every verified
// timestamp.
func (k *trustedKeys) signerFromResult(result *verify.VerificationResult) (SignerIdentity, error) {
	if result.Signature == nil || result.Signature.PublicKeyID == nil {
		return SignerIdentity{}, fmt.Errorf(
			"%w: verification result has no public key", errUnsupportedSignature,
		)
	}

	key, ok := k.byHint[string(*result.Signature.PublicKeyID)]
	if !ok {
		return SignerIdentity{}, fmt.Errorf(
			"%w: verified key is not a configured trusted key", errNoTrustedKeys,
		)
	}

	times := make([]time.Time, 0, len(result.VerifiedTimestamps))
	for idx := range result.VerifiedTimestamps {
		times = append(times, result.VerifiedTimestamps[idx].Timestamp)
	}

	if len(times) == 0 {
		times = append(times, time.Now())
	}

	var paths []string

	for idx := range key.entries {
		entry := &key.entries[idx]
		if slices.Contains(paths, entry.path) || !validAtAll(entry, times) {
			continue
		}

		paths = append(paths, entry.path)
	}

	if len(paths) == 0 {
		return SignerIdentity{}, fmt.Errorf(
			"%w: no configured key entry is valid at the verified signing time",
			errNoTrustedKeys,
		)
	}

	return SignerIdentity{KeyPath: paths[0], KeyPaths: paths, Issuer: "", SAN: ""}, nil
}

func validAtAll(entry *keyEntry, times []time.Time) bool {
	for _, t := range times {
		if !entry.validAt(t) {
			return false
		}
	}

	return true
}

// scopeIssuers returns the policy issuers a trusted root may vouch for. An
// empty root issuer list places no restriction.
func scopeIssuers(policyIssuers, rootIssuers []string) []string {
	if len(rootIssuers) == 0 {
		return policyIssuers
	}

	scoped := make([]string, 0, len(policyIssuers))

	for _, issuer := range policyIssuers {
		if slices.Contains(rootIssuers, issuer) {
			scoped = append(scoped, issuer)
		}
	}

	return scoped
}

// buildKeyMaterial loads the trusted keys. A key configured at several paths
// or with several validity windows keeps every entry, so one entry's window
// neither extends nor restricts another entry's attribution. Failing to load
// a key file is reported as unavailable trust material.
func buildKeyMaterial(keys []TrustedKeyRef) (*trustedKeys, error) {
	byHint := make(map[string]*windowedKey, len(keys))

	for idx := range keys {
		pubKey, err := loadPublicKeyFromPEM(keys[idx].Path)
		if err != nil {
			return nil, fmt.Errorf(
				"%w: loading public key %q: %w", ErrTrustMaterialUnavailable, keys[idx].Path, err,
			)
		}

		hint, hintErr := computeKeyHint(pubKey)
		if hintErr != nil {
			return nil, fmt.Errorf("computing key hint for %q: %w", keys[idx].Path, hintErr)
		}

		entry := keyEntry{
			path:      keys[idx].Path,
			notBefore: keys[idx].NotBefore,
			notAfter:  keys[idx].NotAfter,
		}

		if existing, ok := byHint[hint]; ok {
			existing.entries = append(existing.entries, entry)

			continue
		}

		keyVerifier, err := signature.LoadVerifier(pubKey, types.HashAlgorithmForKey(pubKey))
		if err != nil {
			return nil, fmt.Errorf("creating verifier for %q: %w", keys[idx].Path, err)
		}

		byHint[hint] = &windowedKey{Verifier: keyVerifier, entries: []keyEntry{entry}}
	}

	material := root.NewTrustedPublicKeyMaterial(
		func(keyID string) (root.TimeConstrainedVerifier, error) {
			key, ok := byHint[keyID]
			if !ok {
				return nil, fmt.Errorf(
					"%w: public key not found for key ID %q",
					errNoTrustedKeys,
					keyID,
				)
			}

			return key, nil
		},
	)

	return &trustedKeys{material: material, byHint: byHint}, nil
}

func loadPublicKeyFromPEM(path string) (crypto.PublicKey, error) {
	data, err := fileutil.ReadLimited(path, fileutil.MaxCredentialFileSize)
	if err != nil {
		return nil, fmt.Errorf("reading PEM file: %w", err)
	}

	contentHash := sha256.Sum256(data)
	cacheKey := path + "\x00" + hex.EncodeToString(contentHash[:])

	if cached, ok := pemKeyCache.Load(cacheKey); ok {
		key, castOK := cached.(crypto.PublicKey)
		if !castOK {
			pemKeyCache.Delete(cacheKey)
		} else {
			return key, nil
		}
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%w in %q", errNoPEMBlock, path)
	}

	pub, pkixErr := x509.ParsePKIXPublicKey(block.Bytes)
	if pkixErr == nil {
		pemKeyCache.Store(cacheKey, pub)

		return pub, nil
	}

	rsaKey, rsaErr := x509.ParsePKCS1PublicKey(block.Bytes)
	if rsaErr == nil {
		pemKeyCache.Store(cacheKey, rsaKey)

		return rsaKey, nil
	}

	return nil, fmt.Errorf("parsing public key: %w", pkixErr)
}

func computeKeyHint(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshaling public key to PKIX: %w", err)
	}

	sum := sha256.Sum256(der)

	return base64.StdEncoding.EncodeToString(sum[:]), nil
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

// ExtractBundlePayload parses a Sigstore bundle and extracts the DSSE payload
// without performing signature verification. It must only be used for
// display purposes (for example the inspect command), never for admission
// decisions.
func ExtractBundlePayload(bundleBytes []byte) ([]byte, error) {
	var bndl bundle.Bundle

	err := bndl.UnmarshalJSON(bundleBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing sigstore bundle: %w", err)
	}

	return extractVerifiedPayload(&bndl)
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

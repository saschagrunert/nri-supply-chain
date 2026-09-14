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

package verifier

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/registry"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
	"github.com/saschagrunert/nri-supply-chain/internal/vsa"
)

// errEmptyDigest indicates a verification request without an image digest.
var errEmptyDigest = errors.New("image digest is empty")

// runChecks fetches and verifies the attestations for a request. It returns
// the result and how long it may be cached (0 means not cacheable).
//
//nolint:funlen // sequential fetch and verification steps
func runChecks(
	ctx context.Context, state *snapshot,
	pol *policy.Policy, mode config.VerificationMode, req *types.VerifyRequest,
) (*types.Result, time.Duration) {
	imageRef, digest := req.ImageRef, req.Digest

	if state.fetcher == nil {
		result := runChecksWithoutFetcher(pol, state.metrics, imageRef)

		return result, resultCacheTTL(state.config, result)
	}

	// Without a digest nothing can be looked up or bound; reject before
	// touching the circuit breaker so such requests never count as registry
	// failures. The result is not cached since it is not tied to an image.
	if digest == "" {
		return emptyDigestResult(imageRef), 0
	}

	parsedRef, parseErr := name.ParseReference(imageRef)
	host := registryHost(parsedRef, parseErr, imageRef)
	breaker := registryBreakerByHost(state.circuitBreakers, host)
	fetchPolicy := state.config.EffectiveFetchFailurePolicy(mode)

	permit, release, blocked := acquireRegistryAccess(
		ctx, state, breaker, host, imageRef, fetchPolicy,
	)
	if blocked != nil {
		// Not cached: a breaker-open or local concurrency limit result would
		// outlive the condition that caused it.
		return blocked, 0
	}

	defer release()

	guacCh := startGUACQuery(ctx, state, digest, imageRef)

	fetched := timedFetchAttestations(ctx, state, req, pol, host, parsedRef)

	recordBreakerOutcome(ctx, breaker, permit, state.metrics, host, fetchPolicy, fetched)

	// A transport failure on any digest means the registry was
	// unreachable on that path, so the full attestation set is unknown.
	// This must follow fetch_failure_policy even when unverified
	// attestations were also found on a different digest.
	if fetched.transportErr != nil {
		result := handleFetchError(
			ctx, state.metrics, fetched.transportErr, imageRef, host, fetchPolicy,
		)

		return result, fetchErrorCacheTTL(state.config)
	}

	unverified := unverifiedAttestationsCheck(ctx, fetched.err, imageRef, host)

	if fetched.err != nil && unverified == nil {
		result := fetchErrorResult(ctx, state.metrics, fetched.err, imageRef, host, fetchPolicy)

		return result, fetchErrorCacheTTL(state.config)
	}

	guacResult := <-guacCh

	attestations := scopeBuilderKeys(ctx, fetched.attestations, pol, imageRef)
	bins := binAttestations(ctx, attestations, imageRef)

	result := runVSAAndParallelChecks(
		ctx, bins, pol, state.metrics, imageRef, fetched.digest, req.Namespace, parsedRef,
		state.config.CheckTimeout.Duration, guacResult, relatedDigests(req, fetched.digest),
	)

	appendGUACResult(result, unverified)

	return result, resultCacheTTL(state.config, result)
}

func emptyDigestResult(imageRef string) *types.Result {
	return resultFromCheck(types.FailResult(
		types.CheckTypeInternal,
		fmt.Sprintf("cannot verify %s: %s", imageRef, errEmptyDigest),
		errEmptyDigest,
	))
}

// unverifiedAttestationsCheck returns a warning check when signed material
// was found for an image but none of it verified. Such attestations are
// treated like absent ones, so an attacker attaching junk referrers cannot
// change a decision, and a foreign signature does not deny an image that is
// otherwise acceptable. It returns nil for any other error, including an
// incomplete attestation set (a limit was exceeded or stored bundle data was
// tampered with), which must deny because a dropped attestation could flip
// the decision.
func unverifiedAttestationsCheck(
	ctx context.Context, fetchErr error, imageRef, host string,
) *types.CheckResult {
	if !isIgnorableVerificationFailure(fetchErr) {
		return nil
	}

	slog.WarnContext(ctx, "Ignoring attestations that failed verification",
		"image", imageRef, "host", host, "error", fetchErr,
	)

	return types.WarnResult(
		types.CheckTypeAttestation,
		fmt.Sprintf(
			"ignored attestations of %s that failed verification: %s", imageRef, fetchErr,
		),
	)
}

// isIgnorableVerificationFailure reports whether err only says that the
// complete attestation set failed verification.
func isIgnorableVerificationFailure(err error) bool {
	return errors.Is(err, attestation.ErrVerificationFailed) &&
		!errors.Is(err, attestation.ErrIncompleteAttestationSet)
}

// acquireRegistryAccess checks the registry circuit breaker and acquires the
// fetch concurrency slots. It returns the breaker permit and a release
// function, or a result to return instead of fetching.
func acquireRegistryAccess(
	ctx context.Context, state *snapshot, breaker *attestation.CircuitBreaker,
	host, imageRef string, fetchPolicy types.Action,
) (permit attestation.Permit, release func(), blocked *types.Result) {
	if breaker != nil {
		var allowed bool

		permit, allowed = breaker.Acquire()
		if !allowed {
			return permit, func() {}, handleFetchError(
				ctx, state.metrics,
				fmt.Errorf("%w: %s", ErrCircuitBreakerOpen, imageRef),
				imageRef, host, fetchPolicy,
			)
		}
	}

	if state.fetchSem == nil {
		return permit, func() {}, nil
	}

	releaseSlots, err := acquireFetchSlots(ctx, state, host)
	if err != nil {
		// A local concurrency limit says nothing about the registry. Only
		// the half-open probe itself hands the probe back.
		if breaker != nil {
			breaker.Release(permit)
		}

		return permit, func() {}, handleFetchError(
			ctx, state.metrics, err, imageRef, host, fetchPolicy,
		)
	}

	return permit, releaseSlots, nil
}

// fetchErrorResult maps a fetch error to a result. An incomplete attestation
// set always denies; every other error follows the effective
// fetch_failure_policy. Attestations that merely failed verification are
// handled by unverifiedAttestationsCheck before.
func fetchErrorResult(
	ctx context.Context, met *metrics.Metrics,
	fetchErr error, imageRef, host string, fetchPolicy types.Action,
) *types.Result {
	if !errors.Is(fetchErr, attestation.ErrVerificationFailed) {
		return handleFetchError(ctx, met, fetchErr, imageRef, host, fetchPolicy)
	}

	slog.WarnContext(ctx, "Attestation set could not be evaluated completely",
		"image", imageRef, "host", host, "error", fetchErr,
	)

	return resultFromCheck(types.FailResult(
		types.CheckTypeAttestation,
		fmt.Sprintf("attestation verification failed for %s: %s", imageRef, fetchErr),
		fetchErr,
	))
}

// resultCacheTTL returns how long a check result may be cached: failures
// and fetch problems use the shorter failure TTL.
func resultCacheTTL(cfg *config.Config, result *types.Result) time.Duration {
	if resultShouldUseShorterTTL(result) && cfg.CacheFailureTTL.Duration > 0 {
		return cfg.CacheFailureTTL.Duration
	}

	return cfg.CacheTTL.Duration
}

// fetchErrorCacheTTL caps how long a fetch error is cached at the circuit
// breaker cooldown, so a recovered registry is retried as soon as the
// breaker would allow it.
func fetchErrorCacheTTL(cfg *config.Config) time.Duration {
	ttl := cfg.CacheFailureTTL.Duration
	if ttl <= 0 {
		ttl = cfg.CacheTTL.Duration
	}

	if cooldown := cfg.CircuitBreakerCooldown.Duration; cooldown > 0 {
		ttl = min(ttl, cooldown)
	}

	return ttl
}

// recordBreakerOutcome updates the registry circuit breaker after a fetch.
// Only transport failures (connection errors, timeouts, 5xx and 429
// responses) on any fetched digest count as failures; any other outcome
// proves the registry answered, including attestations that failed
// verification. While the breaker is half-open only the probe's outcome
// counts.
func recordBreakerOutcome(
	ctx context.Context, breaker *attestation.CircuitBreaker, permit attestation.Permit,
	met *metrics.Metrics, host string, fetchPolicy types.Action, fetched *fetchOutcome,
) {
	if breaker == nil {
		return
	}

	if fetched.transportErr == nil {
		breaker.Succeeded(permit)

		return
	}

	if tripped := breaker.Failed(permit); tripped {
		met.CircuitBreakerTripsTotal.WithLabelValues(host).Inc()
		slog.WarnContext(ctx, "Circuit breaker opened after repeated fetch failures, "+
			"subsequent requests will use the configured fetch_failure_policy",
			"registry", host,
			"fetch_failure_policy", fetchPolicy,
			"error", fetched.transportErr,
		)
	}
}

func isTransportFailure(ctx context.Context, err error) bool {
	if err == nil || errors.Is(err, attestation.ErrVerificationFailed) {
		return false
	}

	// A cancelled verification (shutdown) is not the registry's fault.
	if errors.Is(ctx.Err(), context.Canceled) {
		return false
	}

	transportErr, isTransportErr := errors.AsType[*transport.Error](err)
	if isTransportErr && transportErr.StatusCode == http.StatusTooManyRequests {
		return true
	}

	return registry.IsConnectionError(err) || errors.Is(err, context.DeadlineExceeded)
}

// relatedDigests returns the digests of the image other than the one the
// attestations were fetched for (the platform digest when attestations came
// from the index digest, and vice versa).
func relatedDigests(req *types.VerifyRequest, attestDigest string) []string {
	related := make([]string, 0, 2) //nolint:mnd // platform and index digests

	for _, candidate := range []string{req.Digest, req.IndexDigest} {
		if candidate != "" && candidate != attestDigest {
			related = append(related, candidate)
		}
	}

	return related
}

func runVSAAndParallelChecks(
	ctx context.Context, bins attestationBins,
	pol *policy.Policy, met *metrics.Metrics,
	imageRef, digest, namespace string, parsedRef name.Reference,
	checkTimeout time.Duration,
	guacResult *types.CheckResult,
	related []string,
) *types.Result {
	outcome := checkVSA(ctx, bins[types.CheckTypeVSA], pol, imageRef, digest, met, parsedRef)
	if outcome.rejected != nil {
		return outcome.rejected
	}

	if outcome.passed != nil {
		result := &types.Result{
			Allowed:      true,
			Verified:     false,
			Mode:         "",
			Reason:       "VSA verification passed, skipping direct verification",
			CheckResults: []types.CheckResult{*outcome.passed},
		}

		// CEL rules still apply to VSA-accelerated images. They see the VSA
		// and GUAC results; other attestation types are not present.
		appendGUACResult(result, guacResult)
		appendCELCheck(pol, met, imageRef, digest, namespace, parsedRef, result)

		return result
	}

	missingDetail := outcome.missingDetail(imageRef)

	denied := checkVSAMissing(pol, missingDetail, met)
	if denied != nil {
		return denied
	}

	result := runParallelChecks(
		ctx, bins, pol, met, imageRef, digest, related, parsedRef, checkTimeout,
	)

	appendGUACResult(result, guacResult)
	appendVSAWarning(result, pol, missingDetail)
	appendCELCheck(pol, met, imageRef, digest, namespace, parsedRef, result)

	return result
}

// appendGUACResult appends an optional check result (the GUAC result, or the
// warning about attestations that failed verification) and applies it.
func appendGUACResult(result *types.Result, guacResult *types.CheckResult) {
	if guacResult == nil {
		return
	}

	result.CheckResults = append(result.CheckResults, *guacResult)
	applyCheckResult(result, guacResult)
}

func appendCELCheck(
	pol *policy.Policy, met *metrics.Metrics,
	imageRef, digest, namespace string, parsedRef name.Reference,
	result *types.Result,
) {
	celCheck := runCELCheck(pol, met, imageRef, digest, namespace, parsedRef, result)
	if celCheck != nil {
		result.CheckResults = append(result.CheckResults, *celCheck)
		applyCheckResult(result, celCheck)
	}
}

const maxRegistryHostLen = 253

func registryHost(parsed name.Reference, parseErr error, imageRef string) string {
	if parseErr != nil {
		if len(imageRef) > maxRegistryHostLen {
			return imageRef[:maxRegistryHostLen]
		}

		return imageRef
	}

	return parsed.Context().RegistryStr()
}

type missingCheck struct {
	checkType     types.CheckType
	missingPolicy types.Action
}

func runChecksWithoutFetcher(
	pol *policy.Policy, met *metrics.Metrics, imageRef string,
) *types.Result {
	detail := "no attestation fetcher configured for image " + imageRef

	vsaMissing := pol.MissingPolicyFor(types.CheckTypeVSA)

	met.VerificationDuration.WithLabelValues(string(types.CheckTypeVSA)).Observe(0)

	if vsaMissing != types.ActionAllow && vsaMissing != types.ActionWarn {
		return resultFromCheck(handleMissingAttestation(vsaMissing, types.CheckTypeVSA, detail))
	}

	missingChecks := make([]missingCheck, 0, len(types.AttestationCheckTypes))

	for _, checkType := range types.AttestationCheckTypes {
		if checkType == types.CheckTypeVSA {
			continue
		}

		if checkType == types.CheckTypeNotation && pol.Notation == nil {
			continue
		}

		missingChecks = append(missingChecks,
			missingCheck{checkType, pol.MissingPolicyFor(checkType)},
		)
	}

	results := make([]*types.CheckResult, 0, len(missingChecks))

	for _, mc := range missingChecks {
		checkResult := handleMissingAttestation(mc.missingPolicy, mc.checkType, detail)
		met.VerificationDuration.WithLabelValues(string(mc.checkType)).Observe(0)

		results = append(results, checkResult)
	}

	result := combineResults(results...)

	appendVSAWarning(result, pol, detail)

	return result
}

// fetchOutcome is the result of fetching the attestations of an image from
// its index and platform digests.
type fetchOutcome struct {
	attestations []attestation.VerifiedAttestation
	// digest is the digest the attestations were fetched for.
	digest string
	// err decides the result: the platform digest's error, or the index
	// digest's error when the platform digest had no attestations or when it
	// is more than a verification failure, so signed material that did not
	// verify is never ignored and an incomplete index set is never dropped.
	err error
	// transportErr is the first transport failure on any fetched digest,
	// which is what the circuit breaker counts.
	transportErr error
}

func (o *fetchOutcome) recordTransport(ctx context.Context, err error) {
	if o.transportErr == nil && isTransportFailure(ctx, err) {
		o.transportErr = err
	}
}

func timedFetchAttestations(
	ctx context.Context, state *snapshot, req *types.VerifyRequest,
	pol *policy.Policy, host string, parsedRef name.Reference,
) *fetchOutcome {
	start := time.Now()

	defer func() {
		state.metrics.FetchDuration.WithLabelValues(host).
			Observe(time.Since(start).Seconds())
	}()

	return fetchAttestations(ctx, state, req, pol, parsedRef)
}

// fetchAttestations fetches the attestations of the index digest (when set)
// and falls back to the platform digest. The platform digest decides the
// outcome, except that an index digest error decides when the platform digest
// has no attestations, and always unless the index digest's attestations
// merely failed verification.
func fetchAttestations(
	ctx context.Context, state *snapshot, req *types.VerifyRequest,
	pol *policy.Policy, parsedRef name.Reference,
) *fetchOutcome {
	timeout := state.config.FetchTimeout.Duration
	outcome := &fetchOutcome{attestations: nil, digest: req.Digest, err: nil, transportErr: nil}

	indexErr := fetchIndexAttestations(ctx, state, req, pol, parsedRef, outcome)
	if len(outcome.attestations) > 0 {
		return outcome
	}

	attestations, err := state.fetcher.Fetch(
		ctx,
		req.ImageRef,
		buildFetchOpts(pol, req.Digest, timeout, parsedRef),
	)
	if err != nil {
		outcome.recordTransport(ctx, err)

		// Only the platform digest's error is wrapped, so it alone decides
		// whether this is a verification failure; the index digest's error
		// is kept for diagnostics.
		if indexErr != nil {
			outcome.err = fmt.Errorf(
				"fetching attestations: %w (index digest: %s)", err, indexErr.Error(),
			)
		} else {
			outcome.err = fmt.Errorf("fetching attestations: %w", err)
		}

		return outcome
	}

	// Without attestations on the platform digest, the index digest's error
	// decides: attestations that failed verification there are reported, and
	// an index digest that could not be fetched leaves the attestation set
	// unknown, so the result is incomplete rather than "no attestations".
	if len(attestations) == 0 && indexErr != nil {
		outcome.err = indexErr

		return outcome
	}

	// With attestations on the platform digest, only index digest material
	// that failed verification can be ignored. Any other index digest error
	// (an incomplete set, for example junk referrers exceeding the limits, or
	// a registry error) may have hidden a denying attestation there.
	if indexErr != nil && !isIgnorableVerificationFailure(indexErr) {
		outcome.err = indexErr

		return outcome
	}

	outcome.attestations = attestations

	return outcome
}

// fetchIndexAttestations fetches the attestations of the index digest when
// the image resolved from a manifest list, since cosign attaches attestations
// to the manifest list digest. Found attestations are stored in outcome; the
// returned error describes a failed index digest fetch.
func fetchIndexAttestations(
	ctx context.Context, state *snapshot, req *types.VerifyRequest,
	pol *policy.Policy, parsedRef name.Reference, outcome *fetchOutcome,
) error {
	if req.IndexDigest == "" {
		return nil
	}

	indexOpts := buildFetchOpts(pol, req.IndexDigest, state.config.FetchTimeout.Duration, parsedRef)

	atts, err := state.fetcher.Fetch(ctx, req.ImageRef, indexOpts)
	if err != nil {
		outcome.recordTransport(ctx, err)

		slog.DebugContext(ctx,
			"Index digest fetch failed, falling back to platform digest",
			"indexDigest", req.IndexDigest,
			"platformDigest", req.Digest,
			"error", err,
		)

		return fmt.Errorf("fetching attestations for index digest %s: %w", req.IndexDigest, err)
	}

	if len(atts) == 0 {
		slog.DebugContext(ctx,
			"No attestations on index digest, falling back to platform digest",
			"indexDigest", req.IndexDigest,
			"platformDigest", req.Digest,
		)

		return nil
	}

	outcome.attestations, outcome.digest = atts, req.IndexDigest

	return nil
}

func buildFetchOpts(
	pol *policy.Policy, digest string, timeout time.Duration,
	parsedRef name.Reference,
) *attestation.FetchOptions {
	opts := FetchOptionsForPolicy(pol)
	opts.Timeout = timeout
	opts.Digest = digest
	opts.ParsedRef = parsedRef

	return opts
}

// FetchOptionsForPolicy returns attestation fetch options carrying the trust
// configuration of a policy: keyless issuers and SAN patterns, the keys of
// all trusted verifiers and builders (with their validity windows), and the
// transparency log requirement. Callers set the digest and timeout.
func FetchOptionsForPolicy(pol *policy.Policy) *attestation.FetchOptions {
	opts := &attestation.FetchOptions{
		RequireTransparencyLog: pol.Signatures != nil && pol.Signatures.RequireTransparencyLog,
	}

	if pol.Trust == nil {
		return opts
	}

	opts.TrustedIssuers = pol.Trust.Issuers
	opts.SANPatterns = pol.Trust.SANPatterns
	opts.TrustedKeys = trustedKeyRefs(pol.Trust)

	return opts
}

func trustedKeyRefs(trust *policy.TrustPolicy) []attestation.TrustedKeyRef {
	totalKeys := 0
	for idx := range trust.Verifiers {
		totalKeys += len(trust.Verifiers[idx].Keys)
	}

	for idx := range trust.Builders {
		totalKeys += len(trust.Builders[idx].Keys)
	}

	keys := make([]attestation.TrustedKeyRef, 0, totalKeys)
	verifierKeys := make(map[string]struct{}, totalKeys)

	for idx := range trust.Verifiers {
		for _, keyPath := range trust.Verifiers[idx].Keys {
			verifierKeys[keyPath] = struct{}{}
			keys = append(keys, attestation.TrustedKeyRef{
				Path:      keyPath,
				NotBefore: trust.Verifiers[idx].NotBeforeTime,
				NotAfter:  trust.Verifiers[idx].NotAfterTime,
			})
		}
	}

	for idx := range trust.Builders {
		for _, keyPath := range trust.Builders[idx].Keys {
			// Validation rejects a key path shared by a verifier and a
			// builder, but merging a namespace policy or a rule into its
			// base can still produce one. An unbounded builder entry would
			// attribute the path outside the verifier's validity window, so
			// the verifier entry alone bounds the path wherever it is used.
			if _, verifierKey := verifierKeys[keyPath]; verifierKey {
				continue
			}

			keys = append(keys, attestation.TrustedKeyRef{
				Path:      keyPath,
				NotBefore: time.Time{},
				NotAfter:  time.Time{},
			})
		}
	}

	return keys
}

// scopeBuilderKeys drops attestations signed with a key that is only trusted
// as a builder key, unless they are SLSA provenance. Builder keys join the
// trusted key set so provenance can be verified, but a provenance signing key
// must not be able to vouch for VEX, SBOM or any other attestation type.
// Verifier keys keep their scope.
func scopeBuilderKeys(
	ctx context.Context, attestations []attestation.VerifiedAttestation,
	pol *policy.Policy, imageRef string,
) []attestation.VerifiedAttestation {
	builderOnly := builderOnlyKeys(pol.Trust)
	if len(builderOnly) == 0 {
		return attestations
	}

	scoped := make([]attestation.VerifiedAttestation, 0, len(attestations))

	for idx := range attestations {
		att := &attestations[idx]

		if signedOnlyWithBuilderKeys(&att.Signer, builderOnly) &&
			!isProvenancePredicate(att.PredicateType) {
			slog.WarnContext(ctx, "Ignoring attestation signed with a builder key",
				"image", imageRef,
				"predicateType", att.PredicateType,
				"signer_key", att.Signer.KeyPath,
			)

			continue
		}

		scoped = append(scoped, *att)
	}

	return scoped
}

// signedOnlyWithBuilderKeys reports whether every configured key path that
// verified the signature is a builder-only key. The same key material may be
// configured at several paths, so a signature also verified by a verifier
// key path keeps the verifier scope.
func signedOnlyWithBuilderKeys(
	signer *attestation.SignerIdentity, builderOnly map[string]struct{},
) bool {
	paths := signer.KeyPaths
	if len(paths) == 0 {
		if signer.KeyPath == "" {
			return false
		}

		paths = []string{signer.KeyPath}
	}

	for _, keyPath := range paths {
		if _, builderKey := builderOnly[keyPath]; !builderKey {
			return false
		}
	}

	return true
}

// builderOnlyKeys returns the key paths trusted for builders but not for
// any verifier.
func builderOnlyKeys(trust *policy.TrustPolicy) map[string]struct{} {
	if trust == nil {
		return nil
	}

	keys := make(map[string]struct{})

	for idx := range trust.Builders {
		for _, keyPath := range trust.Builders[idx].Keys {
			keys[keyPath] = struct{}{}
		}
	}

	for idx := range trust.Verifiers {
		for _, keyPath := range trust.Verifiers[idx].Keys {
			delete(keys, keyPath)
		}
	}

	return keys
}

func isProvenancePredicate(predicateType string) bool {
	return predicateType == attestation.PredicateSLSAProvenanceV1 ||
		predicateType == attestation.PredicateSLSAProvenanceV02
}

// vsaOutcome is the combined result of all VSA attestations of an image.
type vsaOutcome struct {
	// passed is the first PASSED VSA signed by its claimed verifier.
	passed *types.CheckResult
	// rejected is set when a VSA signed by its claimed verifier reports
	// FAILED for this image.
	rejected *types.Result
	// failures describes VSAs that were present but not trusted.
	failures []string
}

func (o *vsaOutcome) missingDetail(imageRef string) string {
	if len(o.failures) == 0 {
		return "no VSA attestation found for image " + imageRef
	}

	return fmt.Sprintf(
		"no trusted VSA passed for image %s: %s", imageRef, strings.Join(o.failures, "; "),
	)
}

// checkVSA evaluates the VSA attestations of an image. A VSA only counts when
// the attestation signer is bound to the verifier named in the VSA
// (trust.verifiers[].keys or identities): the verifier ID is just a claim in
// the signed payload, and any trusted signer could otherwise issue a VSA in
// the name of a trusted verifier and skip all other checks.
func checkVSA(
	ctx context.Context, vsaAttestations []attestation.VerifiedAttestation,
	pol *policy.Policy, imageRef, digest string, met *metrics.Metrics,
	parsedRef name.Reference,
) *vsaOutcome {
	outcome := &vsaOutcome{passed: nil, rejected: nil, failures: nil}

	if len(vsaAttestations) == 0 {
		return outcome
	}

	start := time.Now()

	defer func() {
		met.VerificationDuration.WithLabelValues(string(types.CheckTypeVSA)).
			Observe(time.Since(start).Seconds())
	}()

	digestRef := digestRefFromParsed(parsedRef, imageRef, digest)

	for idx := range vsaAttestations {
		if outcome.add(ctx, &vsaAttestations[idx], pol, imageRef, digestRef) {
			break
		}
	}

	return outcome
}

// add evaluates one VSA attestation and reports whether it rejected the
// image, which ends the evaluation.
func (o *vsaOutcome) add(
	ctx context.Context, att *attestation.VerifiedAttestation,
	pol *policy.Policy, imageRef, digestRef string,
) bool {
	vsaResult, err := vsa.Verify(ctx, att.Payload, pol, digestRef, nil)
	if err != nil {
		slog.WarnContext(ctx, "VSA verification error", "error", err)
		o.failures = append(o.failures, err.Error())

		return false
	}

	conclusive := vsaResult.HardReject ||
		(vsaResult.Check.Passed && vsaResult.Check.Status == types.StatusPass)
	if !conclusive {
		o.failures = append(o.failures, vsaResult.Check.Detail)

		return false
	}

	if !signerBoundToVerifiers(&att.Signer, vsaResult.MatchedVerifiers) {
		slog.WarnContext(ctx, "Ignoring VSA not signed by its claimed verifier",
			"image", imageRef,
			"verifier", vsaResult.Check.Metadata["verifierID"],
			"signer_key", att.Signer.KeyPath,
			"signer_issuer", att.Signer.Issuer,
			"signer_san", att.Signer.SAN,
		)

		o.failures = append(
			o.failures,
			"VSA is not signed by a key or identity bound to its verifier",
		)

		return false
	}

	if vsaResult.HardReject {
		o.rejected = resultFromCheck(vsaResult.Check)

		return true
	}

	if o.passed == nil {
		o.passed = vsaResult.Check
	}

	return false
}

func signerBoundToVerifiers(
	signer *attestation.SignerIdentity, verifiers []policy.TrustedVerifier,
) bool {
	for idx := range verifiers {
		if signer.MatchesAny(verifiers[idx].MatchesSigner) {
			return true
		}
	}

	return false
}

func runParallelChecks(
	ctx context.Context, bins attestationBins,
	pol *policy.Policy, met *metrics.Metrics,
	imageRef, digest string,
	related []string,
	parsedRef name.Reference,
	checkTimeout time.Duration,
) *types.Result {
	input := &checkInput{
		bins:           bins,
		pol:            pol,
		imageRef:       imageRef,
		digest:         digest,
		relatedDigests: related,
		parsedRef:      parsedRef,
	}

	results := make([]*types.CheckResult, len(checkSpecs))

	var waitGroup sync.WaitGroup

	for idx := range checkSpecs {
		spec := &checkSpecs[idx]

		waitGroup.Add(1)

		go runParallelCheck(ctx, &waitGroup, &results[idx], spec.checkType, checkTimeout,
			func(ctx context.Context) *types.CheckResult {
				return runAttestationCheck(ctx, spec, input, met)
			})
	}

	waitGroup.Wait()

	return combineResults(results...)
}

func runParallelCheck(
	parentCtx context.Context,
	waitGroup *sync.WaitGroup,
	result **types.CheckResult,
	checkType types.CheckType,
	checkTimeout time.Duration,
	checkFunc func(ctx context.Context) *types.CheckResult,
) {
	defer waitGroup.Done()
	defer func() {
		if r := recover(); r != nil {
			slog.Error("Panic during check",
				"type", checkType,
				"panic", r, "stack", string(debug.Stack()))

			*result = types.FailResult(
				checkType,
				"internal error during "+string(checkType)+" check", nil,
			)
		}
	}()

	ctx, cancel := context.WithTimeout(parentCtx, checkTimeout)
	defer cancel()

	*result = checkFunc(ctx)
}

// attestationBins maps check types to their matching attestations.
type attestationBins map[types.CheckType][]attestation.VerifiedAttestation

func binAttestations(
	ctx context.Context,
	attestations []attestation.VerifiedAttestation,
	imageRef string,
) attestationBins {
	bins := make(attestationBins)

	for idx := range attestations {
		att := attestations[idx]

		if att.SignatureType == attestation.SignatureTypeNotation {
			bins[types.CheckTypeNotation] = append(bins[types.CheckTypeNotation], att)

			continue
		}

		checkTypes, known := predicateCheckTypes[att.PredicateType]

		switch {
		case known:
			for _, checkType := range checkTypes {
				bins[checkType] = append(bins[checkType], att)
			}
		case att.PredicateType == attestation.PredicateCosignSignature:
			slog.DebugContext(ctx,
				"Skipping bare cosign signature attestation",
				"image", imageRef,
			)
		default:
			slog.WarnContext(ctx,
				"Skipping attestation with unrecognized predicate type",
				"predicateType", att.PredicateType,
				"image", imageRef,
			)
		}
	}

	return bins
}

func resultFromCheck(check *types.CheckResult) *types.Result {
	return &types.Result{
		Allowed:      check.Passed,
		Verified:     false,
		Mode:         "",
		Reason:       check.Detail,
		CheckResults: []types.CheckResult{*check},
	}
}

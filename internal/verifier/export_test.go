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
	"log/slog"
	"os"
	"time"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/bundle"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/guac"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/registry"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

// ExportAuditInfo is an exported alias for auditInfo.
type ExportAuditInfo = auditInfo

// NewExportAuditInfo creates an auditInfo for external tests.
func NewExportAuditInfo(
	policyHash, nodeName, podServiceAccount, verificationMode string,
) *ExportAuditInfo {
	return &auditInfo{
		policyHash:        policyHash,
		nodeName:          nodeName,
		podServiceAccount: podServiceAccount,
		verificationMode:  verificationMode,
	}
}

// ExportHandleMissingAttestation exposes handleMissingAttestation for external tests.
func ExportHandleMissingAttestation(
	pol types.Action, checkType types.CheckType, detail string,
) *types.CheckResult {
	return handleMissingAttestation(pol, checkType, detail)
}

// ExportResultHasFailures exposes resultHasFailures for external tests.
func ExportResultHasFailures(result *types.Result) bool {
	return resultHasFailures(result)
}

// ExportCacheAffectingFieldsChanged exposes cacheAffectingFieldsChanged for external tests.
func ExportCacheAffectingFieldsChanged(prev, next *config.Config) bool {
	return cacheAffectingFieldsChanged(prev, next)
}

// ExportCombineResults exposes combineResults for external tests.
func ExportCombineResults(checks ...*types.CheckResult) *types.Result {
	return combineResults(checks...)
}

// ExportApplyCheckResult exposes applyCheckResult for external tests.
func ExportApplyCheckResult(result *types.Result, check *types.CheckResult) {
	applyCheckResult(result, check)
}

// ExportResultShouldUseShorterTTL exposes resultShouldUseShorterTTL for external tests.
func ExportResultShouldUseShorterTTL(result *types.Result) bool {
	return resultShouldUseShorterTTL(result)
}

// ExportAuditEventLogAttrs exposes auditEvent.logAttrs for external tests.
func ExportAuditEventLogAttrs(event *auditEvent) []any {
	return event.logAttrs()
}

// ExportNewAuditEvent creates an auditEvent for external tests.
// Enrichment fields (policy hash, node name, service account, mode) are
// passed via info; nil omits them.
func ExportNewAuditEvent(
	image, digest, namespace string, allowed bool,
	check, status, detail, decision, reason string,
	info *ExportAuditInfo,
) *auditEvent {
	event := &auditEvent{ //nolint:exhaustruct_v5 // enrichment fields set by applyAuditInfo
		Image:     image,
		Digest:    digest,
		Namespace: namespace,
		Allowed:   allowed,
		Check:     check,
		Status:    status,
		Detail:    detail,
		Decision:  decision,
		Reason:    reason,
	}
	applyAuditInfo(event, info)

	return event
}

// ExportLogResult exposes logResult for external tests.
func ExportLogResult(
	ctx context.Context, logger *slog.Logger,
	imageRef, digest, namespace string,
	result *types.Result,
	info *ExportAuditInfo,
) {
	logResult(ctx, logger, imageRef, digest, namespace, result, info)
}

// ExportLogAuditDecision exposes logAuditDecision for external tests.
func ExportLogAuditDecision(
	ctx context.Context, logger *slog.Logger,
	imageRef, digest, namespace, decision, reason string,
	info *ExportAuditInfo,
) {
	logAuditDecision(ctx, logger, imageRef, digest, namespace, decision, reason, info)
}

// ExportAllowResult exposes allowResult for external tests.
func ExportAllowResult(
	ctx context.Context, logger *slog.Logger,
	imageRef, digest, namespace, reason string,
	info *ExportAuditInfo,
) *types.Result {
	return allowResult(ctx, logger, imageRef, digest, namespace, reason, info)
}

// ExportWaitInflight waits for all in-flight singleflight verifications
// to complete without stopping the cache.
func (v *Verifier) ExportWaitInflight() {
	v.flights.wait(nil, false)
}

// ExportCacheNamespaceKey exposes cacheNamespaceKey for external tests.
func ExportCacheNamespaceKey(namespace, imageRef string, ruleIdx int) string {
	return cacheNamespaceKey(namespace, imageRef, ruleIdx)
}

// ExportGeneration returns the result cache generation of the current snapshot.
func (v *Verifier) ExportGeneration() uint64 {
	return v.state.Load().generation
}

// ExportFlightsBegin registers a running verification like a singleflight
// closure does and returns whether it was admitted.
func (v *Verifier) ExportFlightsBegin() bool {
	return v.flights.begin()
}

// ExportFlightsEnd marks a verification registered by ExportFlightsBegin done.
func (v *Verifier) ExportFlightsEnd() {
	v.flights.end()
}

// ExportIsTransportFailure exposes isTransportFailure for external tests.
func ExportIsTransportFailure(ctx context.Context, err error) bool {
	return isTransportFailure(ctx, err)
}

// ExportCheckVSAOutcome evaluates VSA attestations and reports whether a
// VSA passed or rejected the image, with the combined missing detail.
func ExportCheckVSAOutcome(
	ctx context.Context, atts []attestation.VerifiedAttestation,
	pol *policy.Policy, imageRef, digest string, met *metrics.Metrics,
) (passed, rejected bool, detail string) {
	outcome := checkVSA(ctx, atts, pol, imageRef, digest, met, nil)

	return outcome.passed != nil, outcome.rejected != nil, outcome.missingDetail(imageRef)
}

// ExportRunVSAAndParallelChecks runs the VSA and direct checks for the given
// VSA attestations and GUAC result.
func ExportRunVSAAndParallelChecks(
	ctx context.Context, vsaAtts []attestation.VerifiedAttestation,
	pol *policy.Policy, met *metrics.Metrics, imageRef, digest string,
	guacResult *types.CheckResult,
) *types.Result {
	parsedRef, _ := name.ParseReference(imageRef)
	bins := attestationBins{types.CheckTypeVSA: vsaAtts}

	return runVSAAndParallelChecks(
		ctx, bins, pol, met, imageRef, digest, "default", parsedRef, time.Second, guacResult, nil,
	)
}

// ExportSetReloadPreparedHook installs a hook that runs after a reload
// prepared its plan and before it applies it.
func (v *Verifier) ExportSetReloadPreparedHook(hook func()) {
	v.reloadPrepared = hook
}

// ExportBindBuilderSigner exposes the SLSA builder binding hook.
func ExportBindBuilderSigner(
	att *attestation.VerifiedAttestation, matched []policy.TrustedBuilder,
) error {
	return bindBuilderSigner(context.Background(), "image")(att, matched)
}

// ExportScopeBuilderKeys exposes scopeBuilderKeys for external tests.
func ExportScopeBuilderKeys(
	atts []attestation.VerifiedAttestation, pol *policy.Policy,
) []attestation.VerifiedAttestation {
	return scopeBuilderKeys(context.Background(), atts, pol, "image")
}

// ExportTrustFingerprint returns the trust material fingerprint for policies.
func ExportTrustFingerprint(cfg *config.Config, policies map[string]*policy.Policy) string {
	return computeTrustFingerprint(cfg, policies).String()
}

// ExportCheckSpecTypes returns the check types of the check registry in order.
func ExportCheckSpecTypes() []types.CheckType {
	checkTypes := make([]types.CheckType, 0, len(checkSpecs))
	for idx := range checkSpecs {
		checkTypes = append(checkTypes, checkSpecs[idx].checkType)
	}

	return checkTypes
}

// ExportInstallPoller installs an OCI policy poller that never polls, with
// the given maximum staleness, and returns its policy fetcher.
func (v *Verifier) ExportInstallPoller(
	ociRef string,
	maxStaleness time.Duration,
) *policy.OCIFetcher {
	fetcher := policy.NewOCIFetcher(nil)
	done := make(chan struct{})
	close(done)

	v.poller.Store(&policyPoller{
		poller:        policy.NewPoller(fetcher, ociRef, time.Minute, nil),
		fetcher:       fetcher,
		ociRef:        ociRef,
		maxStaleness:  maxStaleness,
		checkInterval: time.Minute,
		cancel:        func() {},
		done:          done,
	})

	return fetcher
}

// ExportOCIRollbackSeed exposes ociRollbackSeed for external tests.
func (v *Verifier) ExportOCIRollbackSeed(ociRef string) time.Time {
	return v.ociRollbackSeed(ociRef)
}

// ExportPredicateCheckTypes exposes the predicate to check type lookup.
func ExportPredicateCheckTypes(predicateType string) []types.CheckType {
	return predicateCheckTypes[predicateType]
}

// ExportExtractRegistryRepo exposes extractRegistryRepo for external tests.
func ExportExtractRegistryRepo(parsedRef name.Reference, imageRef string) (reg, repo string) {
	return extractRegistryRepo(parsedRef, imageRef)
}

// ExportOnPolicyUpdate exposes onPolicyUpdate for external tests.
func (v *Verifier) ExportOnPolicyUpdate(
	ctx context.Context, policies map[string]*policy.Policy,
) error {
	return v.onPolicyUpdate(ctx, policies)
}

// ExportResolveNodeName exposes resolveNodeName for external tests.
func ExportResolveNodeName() string {
	return resolveNodeName()
}

// ExportPolicyHashForNamespace exposes policyHashForNamespace for external tests.
func ExportPolicyHashForNamespace(hashes map[string]string, namespace string) string {
	return policyHashForNamespace(hashes, namespace)
}

// ExportOpenAuditLogger exposes openAuditLogger for external tests.
func ExportOpenAuditLogger(path string) (*slog.Logger, *os.File, error) {
	return openAuditLogger(path)
}

// ExportCloseAuditLogFile exposes closeAuditLogFile for external tests.
func ExportCloseAuditLogFile(f *os.File) {
	closeAuditLogFile(f)
}

// ExportReloadAuditLogger exposes reloadAuditLogger for external tests.
func ExportReloadAuditLogger(
	ctx context.Context, prev *snapshot, cfg *config.Config,
) (*slog.Logger, *os.File) {
	return reloadAuditLogger(ctx, prev, cfg)
}

// ExportNewSnapshot creates a minimal snapshot for testing reload helpers.
func ExportNewSnapshot(cfg *config.Config, logger *slog.Logger, file *os.File) *snapshot {
	return &snapshot{
		config:       cfg,
		auditLogger:  logger,
		auditLogFile: file,
	}
}

// ExportScopeOfflineRoot exposes scopeOfflineRoot for external tests.
func ExportScopeOfflineRoot(
	cfg *config.Config, rootName string,
) (issuers []string, keylessDisabled, known bool) {
	scope := scopeOfflineRoot(cfg, rootName)

	return scope.issuers, scope.keylessDisabled, scope.known
}

// ExportCreateFetcher exposes createFetcher for external tests.
func ExportCreateFetcher(cfg *config.Config) (*attestation.OCIFetcher, error) {
	return createFetcher(cfg)
}

// ExportBundleFetcherFromFetcher exposes bundleFetcherFromFetcher for external tests.
func ExportBundleFetcherFromFetcher(fetcher attestation.Fetcher) *bundle.Fetcher {
	return bundleFetcherFromFetcher(fetcher)
}

// ExportBundleStoreChangedOnDisk exposes bundleStoreChangedOnDisk for external tests.
func ExportBundleStoreChangedOnDisk(fetcher attestation.Fetcher, cfg *config.Config) bool {
	return bundleStoreChangedOnDisk(fetcher, cfg)
}

// ExportSetBundleMetricsOnFetcher exposes setBundleMetricsOnFetcher for external tests.
func ExportSetBundleMetricsOnFetcher(fetcher attestation.Fetcher, met *metrics.Metrics) {
	setBundleMetricsOnFetcher(fetcher, met)
}

// ExportOCIFetcherFromFetcher exposes ociFetcherFromFetcher for external tests.
func ExportOCIFetcherFromFetcher(fetcher attestation.Fetcher) *attestation.OCIFetcher {
	return ociFetcherFromFetcher(fetcher)
}

// ExportCreateFetcherForMode exposes createFetcherForMode for external tests.
func ExportCreateFetcherForMode(
	ctx context.Context, cfg *config.Config,
	transportCache *registry.TransportCache,
	bundleMetrics *bundle.Metrics,
) (attestation.Fetcher, error) {
	return createFetcherForMode(ctx, cfg, transportCache, bundleMetrics)
}

// ExportCreateBundleFetcher exposes createBundleFetcher for external tests.
func ExportCreateBundleFetcher(
	cfg *config.Config, bundleMetrics *bundle.Metrics,
) (*bundle.Fetcher, error) {
	return createBundleFetcher(cfg, bundleMetrics)
}

// ExportNewGUACSnapshot creates a snapshot with GUAC-related fields for testing.
func ExportNewGUACSnapshot(
	cfg *config.Config,
	met *metrics.Metrics,
	client *guac.Client,
	breaker *attestation.CircuitBreaker,
) *snapshot {
	return &snapshot{
		config:      cfg,
		metrics:     met,
		guacClient:  client,
		guacBreaker: breaker,
	}
}

// ExportApplyGUACFallback exposes applyGUACFallback for external tests.
func ExportApplyGUACFallback(
	state *snapshot, imageRef string, err error,
) *types.CheckResult {
	return applyGUACFallback(state, imageRef, err)
}

// ExportFetchGUACData exposes fetchGUACData for external tests.
func ExportFetchGUACData(
	ctx context.Context, state *snapshot, digest, imageRef string,
) *types.CheckResult {
	return fetchGUACData(ctx, state, digest, imageRef)
}

// ExportTimedFetchGUACData exposes timedFetchGUACData for external tests.
func ExportTimedFetchGUACData(
	ctx context.Context, state *snapshot, digest, imageRef string,
) *types.CheckResult {
	return timedFetchGUACData(ctx, state, digest, imageRef)
}

// ExportFetcher returns the attestation fetcher of the current snapshot.
func (v *Verifier) ExportFetcher() attestation.Fetcher {
	return v.state.Load().fetcher
}

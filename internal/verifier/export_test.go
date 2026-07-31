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

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

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
func ExportNewAuditEvent(
	image, digest, namespace string, allowed bool,
	check, status, detail, decision, reason string,
) *auditEvent {
	return &auditEvent{
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
}

// ExportLogResult exposes logResult for external tests.
func ExportLogResult(
	ctx context.Context, logger *slog.Logger,
	imageRef, digest, namespace string,
	result *types.Result,
) {
	logResult(ctx, logger, imageRef, digest, namespace, result)
}

// ExportLogAuditDecision exposes logAuditDecision for external tests.
func ExportLogAuditDecision(
	ctx context.Context, logger *slog.Logger,
	imageRef, digest, namespace, decision, reason string,
) {
	logAuditDecision(ctx, logger, imageRef, digest, namespace, decision, reason)
}

// ExportAllowResult exposes allowResult for external tests.
func ExportAllowResult(
	ctx context.Context, logger *slog.Logger,
	imageRef, digest, namespace, reason string,
) *types.Result {
	return allowResult(ctx, logger, imageRef, digest, namespace, reason)
}

// ExportWaitInflight waits for all in-flight singleflight verifications
// to complete without stopping the cache.
func (v *Verifier) ExportWaitInflight() {
	v.inflightWg.Wait()
}

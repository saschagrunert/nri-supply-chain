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

	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const auditMessage = "Supply chain audit"

// auditInfo bundles security-context fields that enrich audit log entries.
type auditInfo struct {
	policyHash        string
	nodeName          string
	podServiceAccount string
	verificationMode  string
}

// auditEvent defines the structured schema for supply chain audit log entries.
type auditEvent struct {
	Image             string `json:"image"`
	Digest            string `json:"digest"`
	Namespace         string `json:"namespace"`
	Allowed           bool   `json:"allowed,omitempty"`
	Check             string `json:"check,omitempty"`
	Status            string `json:"status,omitempty"`
	Detail            string `json:"detail,omitempty"`
	Decision          string `json:"decision,omitempty"`
	Reason            string `json:"reason,omitempty"`
	PolicyHash        string `json:"policyHash,omitempty"`
	NodeName          string `json:"nodeName,omitempty"`
	PodServiceAccount string `json:"podServiceAccount,omitempty"`
	VerificationMode  string `json:"verificationMode,omitempty"`
}

func (e *auditEvent) logAttrs() []any {
	attrs := []any{
		"image", e.Image,
		"digest", e.Digest,
		"namespace", e.Namespace,
	}

	if e.Check != "" {
		attrs = append(attrs,
			"allowed", e.Allowed,
			"check", e.Check,
			"status", e.Status,
			"detail", e.Detail,
		)
	}

	if e.Decision != "" {
		attrs = append(attrs,
			"allowed", e.Allowed,
			"decision", e.Decision,
			"reason", e.Reason,
		)
	}

	if e.PolicyHash != "" {
		attrs = append(attrs, "policyHash", e.PolicyHash)
	}

	if e.NodeName != "" {
		attrs = append(attrs, "nodeName", e.NodeName)
	}

	if e.PodServiceAccount != "" {
		attrs = append(attrs, "podServiceAccount", e.PodServiceAccount)
	}

	if e.VerificationMode != "" {
		attrs = append(attrs, "verificationMode", e.VerificationMode)
	}

	return attrs
}

func applyAuditInfo(event *auditEvent, info *auditInfo) {
	if info == nil {
		return
	}

	event.PolicyHash = info.policyHash
	event.NodeName = info.nodeName
	event.PodServiceAccount = info.podServiceAccount
	event.VerificationMode = info.verificationMode
}

func logResult(
	ctx context.Context, logger *slog.Logger,
	imageRef, digest, namespace string,
	result *types.Result,
	info *auditInfo,
) {
	if len(result.CheckResults) == 0 {
		decision := "denied"
		if result.Allowed {
			decision = "allowed"
		}

		logAuditDecision(ctx, logger, imageRef, digest, namespace, decision, result.Reason, info)

		return
	}

	for _, checkResult := range result.CheckResults {
		event := &auditEvent{ //nolint:exhaustruct // remaining fields set by applyAuditInfo
			Image:     imageRef,
			Digest:    digest,
			Namespace: namespace,
			Allowed:   result.Allowed,
			Check:     string(checkResult.Type),
			Status:    string(checkResult.Status),
			Detail:    checkResult.Detail,
		}
		applyAuditInfo(event, info)
		logger.InfoContext(ctx, auditMessage, event.logAttrs()...)
	}
}

func logAuditDecision(
	ctx context.Context, logger *slog.Logger,
	imageRef, digest, namespace, decision, reason string,
	info *auditInfo,
) {
	event := &auditEvent{ //nolint:exhaustruct // remaining fields set by applyAuditInfo
		Image:     imageRef,
		Digest:    digest,
		Namespace: namespace,
		Allowed:   decision == "allowed",
		Decision:  decision,
		Reason:    reason,
	}
	applyAuditInfo(event, info)
	logger.InfoContext(ctx, auditMessage, event.logAttrs()...)
}

func allowResult(
	ctx context.Context, logger *slog.Logger,
	imageRef, digest, namespace, reason string,
	info *auditInfo,
) *types.Result {
	logAuditDecision(ctx, logger, imageRef, digest, namespace, "allowed", reason, info)

	return &types.Result{
		Allowed:      true,
		Reason:       reason,
		CheckResults: nil,
	}
}

func recordMetrics(met *metrics.Metrics, result *types.Result, namespace string) {
	for _, checkResult := range result.CheckResults {
		met.VerificationTotal.WithLabelValues(
			string(checkResult.Type), string(checkResult.Status), namespace,
		).Inc()
	}
}

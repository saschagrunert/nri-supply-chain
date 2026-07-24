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
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/glob"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

func logResult(
	ctx context.Context, logger *slog.Logger,
	imageRef, digest, namespace string,
	result *types.Result,
) {
	for _, checkResult := range result.CheckResults {
		logger.InfoContext(ctx, "Supply chain audit",
			"image", imageRef,
			"digest", digest,
			"namespace", namespace,
			"allowed", result.Allowed,
			"check", checkResult.Type,
			"status", checkResult.Status,
			"detail", checkResult.Detail,
		)
	}
}

func logAuditDecision(
	ctx context.Context, logger *slog.Logger,
	imageRef, digest, namespace, decision, reason string,
) {
	logger.InfoContext(ctx, "Supply chain audit",
		"image", imageRef,
		"digest", digest,
		"namespace", namespace,
		"decision", decision,
		"reason", reason,
	)
}

func allowResult(
	ctx context.Context, logger *slog.Logger,
	imageRef, digest, namespace, reason string,
) *types.Result {
	logAuditDecision(ctx, logger, imageRef, digest, namespace, "allowed", reason)

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

func handleMissingPolicy(
	ctx context.Context, cfg *config.Config,
	imageRef, namespace string,
) (*types.Result, error) {
	reason := fmt.Sprintf(
		"no policy found for namespace %q and no default policy configured", namespace,
	)

	return applyEnforcement(ctx, cfg, &types.Result{
		Allowed: false,
		Reason:  reason,
		CheckResults: []types.CheckResult{
			*types.FailResult(types.CheckTypePolicy, "no matching policy found"),
		},
	}, imageRef)
}

func policyForNamespace(
	policies map[string]*policy.Policy, namespace string,
) *policy.Policy {
	if pol, found := policies[namespace]; found {
		return pol
	}

	if pol, found := policies[""]; found {
		return pol
	}

	return nil
}

func registryHost(imageRef string) string {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return imageRef
	}

	return ref.Context().RegistryStr()
}

func recordBreakerFailure(
	ctx context.Context,
	breaker *attestation.CircuitBreaker,
	met *metrics.Metrics,
	host string,
	fetchFailurePolicy types.Action,
) {
	if breaker == nil {
		return
	}

	if tripped := breaker.RecordFailure(); tripped {
		met.CircuitBreakerTripsTotal.WithLabelValues(host).Inc()
		slog.WarnContext(ctx, "Circuit breaker opened after repeated fetch failures, "+
			"subsequent requests will use the configured fetch_failure_policy",
			"registry", host,
			"fetch_failure_policy", fetchFailurePolicy,
		)
	}
}

func registryBreakerByHost(
	registry *attestation.CircuitBreakerRegistry, host string,
) *attestation.CircuitBreaker {
	if registry == nil {
		return nil
	}

	return registry.Get(host)
}

func buildDigestRef(imageRef, digest string) string {
	if digest == "" || strings.Contains(imageRef, "@") {
		return imageRef
	}

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		slog.Debug("Failed to parse image reference for digest ref",
			"image", imageRef,
			"error", err,
		)

		return imageRef
	}

	return ref.Context().Digest(digest).String()
}

// isExcluded checks whether imageRef matches any exclude glob pattern.
// '*' matches non-'/' characters, '**' matches any characters including '/'.
func isExcluded(ctx context.Context, excludedImages []string, imageRef string) bool {
	for _, pattern := range excludedImages {
		matched, err := glob.Match(pattern, imageRef)
		if err != nil {
			slog.DebugContext(ctx, "Malformed exclude pattern",
				"pattern", pattern,
				"image", imageRef,
				"error", err,
			)

			continue
		}

		if matched {
			return true
		}
	}

	return false
}

func validatePoliciesRuntime(policies map[string]*policy.Policy) error {
	for ns, pol := range policies {
		err := pol.ValidateRuntime()
		if err != nil {
			label := ns
			if label == "" {
				label = defaultPolicyLabel
			}

			return fmt.Errorf("policy %q: %w", label, err)
		}
	}

	return nil
}

func validatePoliciesEnforce(
	mode config.VerificationMode, policies map[string]*policy.Policy,
) error {
	if mode != config.ModeEnforce {
		return nil
	}

	for ns, pol := range policies {
		err := pol.ValidateEnforce()
		if err != nil {
			label := ns
			if label == "" {
				label = defaultPolicyLabel
			}

			return fmt.Errorf("policy %q: %w", label, err)
		}
	}

	return nil
}

func hashPolicies(
	policies map[string]*policy.Policy,
) (map[string]string, error) {
	hashes := make(map[string]string, len(policies))

	for namespace, pol := range policies {
		hash, err := pol.Hash()
		if err != nil {
			return nil, fmt.Errorf("policy %q: %w", namespace, err)
		}

		hashes[namespace] = hash
	}

	return hashes, nil
}

func policyHashesEqual(prev, next map[string]string) bool {
	if len(prev) != len(next) {
		return false
	}

	for key, hash := range prev {
		if next[key] != hash {
			return false
		}
	}

	return true
}

func logReloadChanges(
	ctx context.Context,
	prev, next *config.Config,
	prevHashes, nextHashes map[string]string,
	cacheInvalidated bool,
) {
	attrs := []any{
		"cache_invalidated", cacheInvalidated,
	}

	if prev.Verification != next.Verification {
		attrs = append(attrs, "mode_prev", prev.Verification, "mode_next", next.Verification)
	}

	if len(prevHashes) != len(nextHashes) {
		attrs = append(attrs, "policies_prev", len(prevHashes), "policies_next", len(nextHashes))
	} else {
		changed := 0

		for ns, hash := range prevHashes {
			if nextHashes[ns] != hash {
				changed++
			}
		}

		for ns := range nextHashes {
			if _, ok := prevHashes[ns]; !ok {
				changed++
			}
		}

		if changed > 0 {
			attrs = append(attrs, "policies_changed", changed)
		}
	}

	slog.InfoContext(ctx, "Config reload applied", attrs...)
}

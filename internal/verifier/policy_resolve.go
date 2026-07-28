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

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

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
			*types.FailResult(types.CheckTypePolicy, "no matching policy found", nil),
		},
	}, imageRef)
}

func validatePoliciesRuntime(policies map[string]*policy.Policy) error {
	for ns, pol := range policies {
		err := pol.ValidateRuntime()
		if err != nil {
			label := ns
			if label == "" {
				label = DefaultPolicyLabel
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
				label = DefaultPolicyLabel
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
	attrs := []slog.Attr{
		slog.Bool("cache_invalidated", cacheInvalidated),
	}

	if prev.Verification != next.Verification {
		slog.WarnContext(ctx, "Verification mode changed",
			"mode_prev", prev.Verification,
			"mode_next", next.Verification,
		)

		attrs = append(attrs,
			slog.String("mode_prev", string(prev.Verification)),
			slog.String("mode_next", string(next.Verification)),
		)
	}

	changed := 0

	for namespace, hash := range prevHashes {
		if nextHash, ok := nextHashes[namespace]; !ok {
			changed++

			slog.DebugContext(ctx, "Policy removed", "namespace", namespace)
		} else if nextHash != hash {
			changed++

			slog.DebugContext(ctx, "Policy changed", "namespace", namespace)
		}
	}

	for namespace := range nextHashes {
		if _, ok := prevHashes[namespace]; !ok {
			changed++

			slog.DebugContext(ctx, "Policy added", "namespace", namespace)
		}
	}

	if changed > 0 {
		attrs = append(attrs, slog.Int("policies_changed", changed))
	}

	slog.LogAttrs(ctx, slog.LevelInfo, "Config reload applied", attrs...)
}

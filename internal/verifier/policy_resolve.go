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

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

var (
	// ErrPolicyModeWhileDisabled indicates that a policy requests warn or
	// enforce mode while verification is globally disabled.
	ErrPolicyModeWhileDisabled = errors.New(
		"policy mode has no effect while verification is disabled; " +
			"set verification to warn or enforce, or remove the policy mode",
	)

	// ErrNoPolicies indicates a reload or policy update would replace the
	// loaded policies with an empty policy set.
	ErrNoPolicies = errors.New("refusing to replace loaded policies with an empty policy set")
)

func policyLabel(namespace string) string {
	if namespace == "" {
		return policy.DefaultPolicyLabel
	}

	return namespace
}

// refuseEmptyPolicyReload rejects a reload that would replace loaded
// policies with an empty set (e.g. a policy directory that was emptied by
// accident), which would otherwise deny or admit every container.
func refuseEmptyPolicyReload(
	cfg *config.Config, previous, next map[string]*policy.Policy,
) error {
	if cfg.Enabled() && len(previous) > 0 && len(next) == 0 {
		return ErrNoPolicies
	}

	return nil
}

// anyPolicyEnforcing reports whether the global mode or any policy's
// effective mode is enforce.
func anyPolicyEnforcing(cfg *config.Config, policies map[string]*policy.Policy) bool {
	if cfg.Verification == config.ModeEnforce {
		return true
	}

	for _, pol := range policies {
		if pol.EffectiveMode(cfg.Verification) == config.ModeEnforce {
			return true
		}
	}

	return false
}

// validatePoliciesAgainstConfig applies the enforce mode safety checks of the
// operational config to namespaces that enforce through their policy mode,
// not only to a global enforce mode: insecure registries and unsigned OCI
// policy artifacts are rejected as soon as any policy enforces.
func validatePoliciesAgainstConfig(
	cfg *config.Config, policies map[string]*policy.Policy,
) error {
	if !anyPolicyEnforcing(cfg, policies) {
		return nil
	}

	var errs []error

	for idx := range cfg.Registries {
		if cfg.Registries[idx].Insecure {
			errs = append(errs, fmt.Errorf(
				"%w: registries[%d] %q (a policy enforces)",
				config.ErrInsecureRegistryInEnforceMode, idx, cfg.Registries[idx].Prefix,
			))
		}
	}

	if cfg.Policy.Source == config.PolicySourceOCI && !cfg.Policy.SignatureVerificationRequired() {
		errs = append(
			errs,
			fmt.Errorf("%w (a policy enforces)", config.ErrPolicyOCIUnsignedInEnforce),
		)
	}

	return errors.Join(errs...)
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

func handleMissingPolicy(
	ctx context.Context, cfg *config.Config,
	imageRef, namespace string,
) (*types.Result, error) {
	slog.DebugContext(ctx, "No policy found, using global mode",
		"namespace", namespace,
		"mode", cfg.Verification,
	)

	reason := fmt.Sprintf(
		"no policy found for namespace %q and no default policy configured", namespace,
	)

	return applyEnforcement(ctx, cfg.Verification, &types.Result{
		Allowed:  false,
		Verified: false,
		Mode:     "",
		Reason:   reason,
		CheckResults: []types.CheckResult{
			*types.FailResult(types.CheckTypePolicy, "no matching policy found", nil),
		},
	}, imageRef)
}

func validatePoliciesRuntime(policies map[string]*policy.Policy) error {
	var errs []error

	for namespace, pol := range policies {
		err := pol.ValidateRuntime()
		if err != nil {
			errs = append(errs, fmt.Errorf("policy %q: %w", policyLabel(namespace), err))
		}
	}

	return errors.Join(errs...)
}

func validatePoliciesModes(
	mode config.VerificationMode, policies map[string]*policy.Policy,
) error {
	var errs []error

	for namespace, pol := range policies {
		label := policyLabel(namespace)

		// Validate per-namespace mode strictness against global mode.
		err := pol.ValidateModeStrictness(mode)
		if err != nil {
			errs = append(errs, fmt.Errorf("policy %q: %w", label, err))
		}

		// Run enforce-specific checks when the effective mode is enforce
		// (either global enforce, or per-namespace enforce override).
		effectiveMode := pol.EffectiveMode(mode)
		if effectiveMode == config.ModeEnforce {
			err = pol.ValidateEnforce()
			if err != nil {
				errs = append(errs, fmt.Errorf("policy %q: %w", label, err))
			}
		}
	}

	return errors.Join(errs...)
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

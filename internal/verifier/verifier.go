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

// Package verifier performs supply chain attestation verification on container images.
package verifier

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path"
	"sync"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/cache"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/metrics"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
	"github.com/saschagrunert/nri-supply-chain/policy"
)

// ErrVerificationFailed is returned when supply chain verification fails in enforce mode.
var ErrVerificationFailed = errors.New("supply chain verification failed")

type snapshot struct {
	config   *config.Config
	policies map[string]*policy.Policy
	cache    *cache.Cache
	metrics  *metrics.Metrics
}

// Verifier performs supply chain attestation verification on container images.
type Verifier struct {
	mu       sync.RWMutex
	config   *config.Config
	cache    *cache.Cache
	policies map[string]*policy.Policy
	metrics  *metrics.Metrics
}

// New creates a new Verifier with the given configuration and metrics.
func New(cfg *config.Config, met *metrics.Metrics) (*Verifier, error) {
	cfgCopy := *cfg

	verif := &Verifier{
		mu:       sync.RWMutex{},
		config:   &cfgCopy,
		cache:    cache.New(cfgCopy.CacheTTL.Duration),
		policies: nil,
		metrics:  met,
	}

	if cfgCopy.Enabled() {
		policies, err := policy.LoadAll(cfgCopy.PolicyDir)
		if err != nil {
			return nil, fmt.Errorf("loading policies: %w", err)
		}

		verif.policies = policies
	}

	return verif, nil
}

// Verify performs supply chain verification for the given image.
func (v *Verifier) Verify(
	ctx context.Context, imageRef, digest, namespace string,
) (*types.Result, error) {
	state := v.snap()

	if !state.config.Enabled() {
		return &types.Result{
			Allowed:      true,
			Reason:       "verification disabled",
			CheckResults: nil,
		}, nil
	}

	slog.DebugContext(ctx, "Verifying image",
		"image", imageRef,
		"digest", digest,
		"namespace", namespace,
	)

	pol := policyForNamespace(state.policies, namespace)

	if isExcluded(pol.Exclude, imageRef) {
		slog.InfoContext(ctx, "Image excluded from verification", "image", imageRef)

		return &types.Result{
			Allowed:      true,
			Reason:       "image is excluded",
			CheckResults: nil,
		}, nil
	}

	if cached := state.cache.Get(digest, namespace); cached != nil {
		state.metrics.CacheHitsTotal.Inc()
		logResult(ctx, imageRef, digest, namespace, cached)

		return cached, nil
	}

	state.metrics.CacheMissesTotal.Inc()

	result := runChecks(ctx, state.config, pol, state.metrics, imageRef, digest)

	logResult(ctx, imageRef, digest, namespace, result)
	recordMetrics(state.metrics, result)

	result, err := applyEnforcement(ctx, state.config, result, imageRef)
	if err != nil {
		return result, err
	}

	state.cache.Set(digest, namespace, result)

	return result, nil
}

func applyEnforcement(
	ctx context.Context, cfg *config.Config,
	result *types.Result, imageRef string,
) (*types.Result, error) {
	if result.Allowed {
		return result, nil
	}

	if cfg.Verification == config.ModeEnforce {
		return result, fmt.Errorf(
			"%w: %s: %s", ErrVerificationFailed, imageRef, result.Reason,
		)
	}

	slog.WarnContext(ctx, "Verification failed (warn mode, allowing)",
		"image", imageRef,
		"reason", result.Reason,
	)

	return &types.Result{
		Allowed:      true,
		Reason:       result.Reason,
		CheckResults: result.CheckResults,
	}, nil
}

// Reload reloads the verifier's configuration and policies.
func (v *Verifier) Reload(cfg *config.Config) error {
	cfgCopy := *cfg

	var policies map[string]*policy.Policy

	if cfgCopy.Enabled() {
		var err error

		policies, err = policy.LoadAll(cfgCopy.PolicyDir)
		if err != nil {
			return fmt.Errorf("reloading policies: %w", err)
		}
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	v.config = &cfgCopy
	v.cache = cache.New(cfgCopy.CacheTTL.Duration)
	v.policies = policies

	return nil
}

func (v *Verifier) snap() snapshot {
	v.mu.RLock()
	defer v.mu.RUnlock()

	return snapshot{
		config:   v.config,
		policies: v.policies,
		cache:    v.cache,
		metrics:  v.metrics,
	}
}

func runChecks(
	_ context.Context, _ *config.Config,
	pol *policy.Policy, met *metrics.Metrics, imageRef, digest string,
) *types.Result {
	result := &types.Result{
		Allowed:      true,
		Reason:       "",
		CheckResults: nil,
	}

	slsaResult := verifySLSAProvenance(pol, met, imageRef, digest)
	result.CheckResults = append(result.CheckResults, slsaResult)

	if !slsaResult.Passed {
		result.Allowed = false
		result.Reason = slsaResult.Detail
	} else if slsaResult.Status == types.StatusWarn {
		result.Reason = slsaResult.Detail
	}

	return result
}

func verifySLSAProvenance(
	pol *policy.Policy, met *metrics.Metrics, imageRef, _ string,
) types.CheckResult {
	start := time.Now()

	defer func() {
		met.VerificationDuration.WithLabelValues(
			"slsa_provenance",
		).Observe(time.Since(start).Seconds())
	}()

	if len(pol.Builders()) == 0 {
		return types.CheckResult{
			Type:   "slsa_provenance",
			Passed: true,
			Status: types.StatusPass,
			Detail: "no trusted builders configured for image " + imageRef,
		}
	}

	return handleMissingAttestation(
		pol.ProvenanceMissingPolicy(),
		"slsa_provenance",
		fmt.Sprintf(
			"provenance attestation not found for image %s"+
				" (cosign integration pending)",
			imageRef,
		),
	)
}

func handleMissingAttestation(
	pol, checkType, detail string,
) types.CheckResult {
	switch pol {
	case config.PolicyDeny:
		return types.CheckResult{
			Type: checkType, Passed: false,
			Status: types.StatusFail, Detail: detail,
		}
	case config.PolicyWarn:
		return types.CheckResult{
			Type: checkType, Passed: true,
			Status: types.StatusWarn, Detail: detail,
		}
	case config.PolicyAllow:
		return types.CheckResult{
			Type: checkType, Passed: true,
			Status: types.StatusPass, Detail: detail,
		}
	default:
		return types.CheckResult{
			Type: checkType, Passed: false,
			Status: types.StatusFail, Detail: detail,
		}
	}
}

func logResult(
	ctx context.Context,
	imageRef, digest, namespace string,
	result *types.Result,
) {
	for _, checkResult := range result.CheckResults {
		slog.InfoContext(ctx, "Supply chain audit",
			"image", imageRef,
			"digest", digest,
			"namespace", namespace,
			"check", checkResult.Type,
			"status", checkResult.Status,
			"detail", checkResult.Detail,
		)
	}
}

func recordMetrics(met *metrics.Metrics, result *types.Result) {
	for _, checkResult := range result.CheckResults {
		met.VerificationTotal.WithLabelValues(
			checkResult.Type, checkResult.Status,
		).Inc()
	}
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

	return &policy.Policy{
		Trust:      nil,
		Exclude:    nil,
		Provenance: nil,
		VEX:        nil,
		VSA:        nil,
		Signatures: nil,
	}
}

func isExcluded(excludedImages []string, imageRef string) bool {
	for _, pattern := range excludedImages {
		matched, err := path.Match(pattern, imageRef)
		if err != nil {
			slog.Debug("Malformed exclude pattern",
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

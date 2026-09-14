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
	"time"

	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/registry"
)

// loadedPolicies is the outcome of loading and hashing policies.
type loadedPolicies struct {
	policies map[string]*policy.Policy
	hashes   map[string]string
	// policyFetcher is the OCI policy fetcher (nil for local policies). It
	// may be set even when loading failed, so the poller can retry.
	policyFetcher *policy.OCIFetcher
	ociDigest     string
}

func handleOCIStartupFailure(
	ctx context.Context,
	cfg *config.Config,
	loaded *loadedPolicies,
	loadErr error,
) (*loadedPolicies, error) {
	if cfg.Policy.Source != config.PolicySourceOCI || !registry.IsConnectionError(loadErr) {
		return nil, loadErr
	}

	slog.WarnContext(ctx,
		"OCI policy fetch failed at startup, starting in pending state",
		"oci_ref", cfg.Policy.OCIRef,
		"error", loadErr,
	)

	return &loadedPolicies{
		policies:      map[string]*policy.Policy{},
		hashes:        map[string]string{},
		policyFetcher: loaded.policyFetcher,
		ociDigest:     "",
	}, nil
}

// loadAndHashPolicies loads the policies for cfg and validates them against
// the config. rollbackSeed, when non-zero, raises the OCI rollback guard of a
// newly built policy fetcher so artifacts older than already applied ones are
// rejected. The guard is raised to the loaded artifact only after its policies
// passed validation. The returned value is never nil, even on error.
func loadAndHashPolicies(
	ctx context.Context,
	cfg *config.Config,
	fetcher attestation.Fetcher,
	rollbackSeed time.Time,
) (*loadedPolicies, error) {
	loaded := &loadedPolicies{
		policies:      nil,
		hashes:        nil,
		policyFetcher: nil,
		ociDigest:     "",
	}

	var ociCreated time.Time

	if !cfg.Enabled() {
		warnPolicyModesWhileDisabled(ctx, cfg)
	} else {
		created, err := loadPoliciesFromSource(ctx, cfg, fetcher, rollbackSeed, loaded)
		ociCreated = created

		if err != nil {
			return loaded, err
		}

		err = errors.Join(
			validatePoliciesRuntime(loaded.policies),
			validatePoliciesAgainstConfig(cfg, loaded.policies),
		)
		if err != nil {
			return &loadedPolicies{
				policies:      nil,
				hashes:        nil,
				policyFetcher: nil,
				ociDigest:     "",
			}, err
		}
	}

	hashes, err := hashPolicies(loaded.policies)
	if err != nil {
		return &loadedPolicies{policies: nil, hashes: nil, policyFetcher: nil, ociDigest: ""}, err
	}

	loaded.hashes = hashes

	if loaded.policyFetcher != nil {
		loaded.policyFetcher.SeedNewestCreated(ociCreated)
	}

	return loaded, nil
}

// loadPoliciesFromSource loads the local or OCI policies into loaded and
// returns the OCI artifact creation time (zero for local policies).
func loadPoliciesFromSource(
	ctx context.Context, cfg *config.Config, fetcher attestation.Fetcher,
	rollbackSeed time.Time, loaded *loadedPolicies,
) (time.Time, error) {
	if cfg.Policy.Source != config.PolicySourceOCI {
		policies, err := policy.LoadAll(cfg.PolicyDir)
		if err != nil {
			return time.Time{}, fmt.Errorf("loading policies: %w", err)
		}

		loaded.policies = policies

		return time.Time{}, nil
	}

	policyFetcher, err := buildPolicyFetcher(cfg, fetcher)
	if err != nil {
		return time.Time{}, fmt.Errorf("building policy fetcher: %w", err)
	}

	policyFetcher.SeedNewestCreated(rollbackSeed)
	loaded.policyFetcher = policyFetcher

	result, err := policyFetcher.FetchFromOCI(ctx, cfg.Policy.OCIRef)
	if err != nil {
		return time.Time{}, fmt.Errorf("loading OCI policies: %w", err)
	}

	slog.InfoContext(ctx,
		"Loaded policies from OCI artifact",
		"oci_ref", cfg.Policy.OCIRef,
		"digest", result.Digest,
		"count", len(result.Policies),
	)

	loaded.policies = result.Policies
	loaded.ociDigest = result.Digest

	return result.Created, nil
}

func buildPolicyFetcher(
	cfg *config.Config, fetcher attestation.Fetcher,
) (*policy.OCIFetcher, error) {
	fetcherTransportCache := transportCacheFromFetcher(fetcher)

	if !cfg.Policy.SignatureVerificationRequired() {
		return policy.NewOCIFetcher(fetcherTransportCache), nil
	}

	sigCfg := &policy.SignatureConfig{
		Issuers:     cfg.Policy.Issuers,
		SANPatterns: cfg.Policy.SANPatterns,
		Keys:        cfg.Policy.Keys,
	}

	fetchTrustedRoot := buildTrustedRootFetchFunc(cfg)

	verifyFn, err := policy.NewSignatureVerifyFunc(
		sigCfg, fetchTrustedRoot, remote.Image, remote.Referrers,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"creating policy signature verifier: %w", err,
		)
	}

	return policy.NewOCIFetcherWithSignatureVerification(
		fetcherTransportCache, verifyFn,
	), nil
}

// warnPolicyModesWhileDisabled logs local policies that request warn or
// enforce mode while verification is globally disabled. Policies are not used
// in disabled mode, so such a namespace mode has no effect and every container
// is admitted. The global disabled mode is the emergency kill switch, so this
// must never block startup or a reload; the validate subcommand reports the
// same condition as an error. Policies that fail to load are only logged,
// since disabled mode must not depend on a valid policy directory.
func warnPolicyModesWhileDisabled(ctx context.Context, cfg *config.Config) {
	if cfg.Policy.Source == config.PolicySourceOCI || cfg.PolicyDir == "" {
		return
	}

	policies, err := policy.LoadAll(cfg.PolicyDir)
	if err != nil {
		slog.WarnContext(ctx,
			"Verification is disabled and the policy directory could not be loaded",
			"policy_dir", cfg.PolicyDir,
			"error", err,
		)

		return
	}

	for namespace, pol := range policies {
		if pol.Mode != "" && pol.Mode != config.ModeDisabled {
			slog.WarnContext(ctx,
				"Verification is disabled globally; the policy mode has no effect "+
					"and all containers are admitted",
				"policy", policyLabel(namespace),
				"mode", pol.Mode,
			)
		}
	}
}

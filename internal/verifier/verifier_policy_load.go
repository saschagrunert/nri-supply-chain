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

	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
	"github.com/saschagrunert/nri-supply-chain/internal/registry"
)

func handleOCIStartupFailure(
	ctx context.Context,
	cfg *config.Config,
	existingFetcher *policy.OCIFetcher,
	loadErr error,
) (
	policies map[string]*policy.Policy,
	hashes map[string]string,
	policyFetcher *policy.OCIFetcher,
	err error,
) {
	if cfg.Policy.Source != config.PolicySourceOCI || !registry.IsConnectionError(loadErr) {
		return nil, nil, nil, loadErr
	}

	slog.WarnContext(ctx,
		"OCI policy fetch failed at startup, starting in pending state",
		"oci_ref", cfg.Policy.OCIRef,
		"error", loadErr,
	)

	return map[string]*policy.Policy{}, map[string]string{}, existingFetcher, nil
}

func loadAndHashPolicies(
	ctx context.Context,
	cfg *config.Config,
	fetcher attestation.Fetcher,
) (
	policies map[string]*policy.Policy,
	hashes map[string]string,
	policyFetcher *policy.OCIFetcher,
	ociDigest string,
	err error,
) {
	if cfg.Enabled() {
		policies, policyFetcher, ociDigest, err = loadPoliciesFromSource(ctx, cfg, fetcher)
		if err != nil {
			return nil, nil, policyFetcher, "", err
		}

		err = validatePoliciesRuntime(policies)
		if err != nil {
			return nil, nil, nil, "", err
		}
	}

	hashes, err = hashPolicies(policies)
	if err != nil {
		return nil, nil, nil, "", err
	}

	return policies, hashes, policyFetcher, ociDigest, nil
}

func loadPoliciesFromSource(
	ctx context.Context, cfg *config.Config, fetcher attestation.Fetcher,
) (
	policies map[string]*policy.Policy,
	policyFetcher *policy.OCIFetcher,
	ociDigest string,
	err error,
) {
	if cfg.Policy.Source != config.PolicySourceOCI {
		policies, err = policy.LoadAll(cfg.PolicyDir)
		if err != nil {
			return nil, nil, "", fmt.Errorf("loading policies: %w", err)
		}

		return policies, nil, "", nil
	}

	policyFetcher, buildErr := buildPolicyFetcher(cfg, fetcher)
	if buildErr != nil {
		return nil, nil, "", fmt.Errorf("building policy fetcher: %w", buildErr)
	}

	result, err := policyFetcher.FetchFromOCI(ctx, cfg.Policy.OCIRef)
	if err != nil {
		return nil, policyFetcher, "", fmt.Errorf("loading OCI policies: %w", err)
	}

	slog.InfoContext(ctx,
		"Loaded policies from OCI artifact",
		"oci_ref", cfg.Policy.OCIRef,
		"digest", result.Digest,
		"count", len(result.Policies),
	)

	return result.Policies, policyFetcher, result.Digest, nil
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

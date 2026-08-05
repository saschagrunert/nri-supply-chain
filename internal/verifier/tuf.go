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

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
)

// trustedRootResult holds the result of a trusted root fetch for use with
// the goroutine + select context-cancellation pattern.
type trustedRootResult struct {
	root *root.TrustedRoot
	err  error
}

func buildTrustedRootFetchFunc(
	cfg *config.Config,
) policy.FetchTrustedRootFunc {
	if len(cfg.Policy.Issuers) == 0 {
		return nil
	}

	return func(ctx context.Context) (*root.TrustedRoot, error) {
		err := ctx.Err()
		if err != nil {
			return nil, fmt.Errorf(
				"context canceled before fetching trusted root: %w", err,
			)
		}

		resultCh := make(chan trustedRootResult, 1)

		go func() {
			r, e := fetchTrustedRootSync(cfg)
			resultCh <- trustedRootResult{root: r, err: e}
		}()

		select {
		case <-ctx.Done():
			slog.WarnContext(ctx,
				"Context canceled while policy trusted root fetch "+
					"is in progress; background goroutine will "+
					"complete when the HTTP request finishes")

			return nil, fmt.Errorf(
				"context canceled during policy trusted root fetch: %w", ctx.Err(),
			)
		case res := <-resultCh:
			return res.root, res.err
		}
	}
}

func fetchTrustedRootSync(cfg *config.Config) (*root.TrustedRoot, error) {
	effectiveRoots := cfg.Sigstore.EffectiveRoots()

	if len(effectiveRoots) == 0 {
		return fetchPublicTrustedRoot()
	}

	if len(effectiveRoots) == 1 {
		r := &effectiveRoots[0]
		if r.TUFMirror == "" {
			return fetchPublicTrustedRoot()
		}

		return fetchTrustedRootFromMirror(r.TUFMirror, r.TUFRoot)
	}

	return fetchTrustedRootFromFirstRoot(effectiveRoots)
}

func fetchPublicTrustedRoot() (*root.TrustedRoot, error) {
	trustedRoot, err := root.FetchTrustedRoot()
	if err != nil {
		return nil, fmt.Errorf("fetching public trusted root: %w", err)
	}

	return trustedRoot, nil
}

func fetchTrustedRootFromMirror(
	mirror, tufRoot string,
) (*root.TrustedRoot, error) {
	tufRootBytes, err := readTUFRootBytes(tufRoot)
	if err != nil {
		return nil, err
	}

	opts := tuf.DefaultOptions().
		WithRepositoryBaseURL(mirror).
		WithDisableLocalCache()

	if len(tufRootBytes) > 0 {
		opts = opts.WithRoot(tufRootBytes)
	}

	trustedRoot, err := root.FetchTrustedRootWithOptions(opts)
	if err != nil {
		return nil, fmt.Errorf(
			"fetching trusted root with custom mirror: %w", err,
		)
	}

	return trustedRoot, nil
}

// fetchTrustedRootFromFirstRoot returns the trusted root from the first
// configured root with a TUF mirror. Policy signatures are expected to come
// from a single Sigstore instance, unlike image attestations which may span
// multiple roots (handled by TrustedMaterialCollection in the attestation path).
func fetchTrustedRootFromFirstRoot(
	roots []config.SigstoreRootSource,
) (*root.TrustedRoot, error) {
	for idx := range roots {
		r := &roots[idx]
		if r.TUFMirror == "" {
			continue
		}

		return fetchTrustedRootFromMirror(r.TUFMirror, r.TUFRoot)
	}

	return fetchPublicTrustedRoot()
}

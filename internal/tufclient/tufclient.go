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

// Package tufclient builds the TUF client options used to fetch Sigstore
// trusted roots, so every fetch shares the same download behavior.
package tufclient

import (
	"fmt"
	"net/http"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/util"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
)

// DefaultOptions returns the sigstore-go default TUF options with a fetcher
// that attempts every download once.
//
// sigstore-go retries TUF downloads with backoff, which turns a TUF
// repository that fails fast (DNS errors, refused connections, 5xx
// responses) into a delay of several seconds. Trusted root refreshes can run
// on the admission path, and the trusted root cache already handles failures
// with its stale and pre-seeded fallbacks, negative cache and retry
// interval, so a failed download is not retried. Downloads that stall are
// not affected and remain bounded by the cache's fetch deadline.
func DefaultOptions() *tuf.Options {
	opts := tuf.DefaultOptions()

	singleAttempt := fetcher.NewDefaultFetcher()
	// Use a dedicated client: go-tuf modifies the client in place when its
	// transport is set, which must never reach http.DefaultClient.
	singleAttempt.SetHTTPClient(&http.Client{})
	singleAttempt.SetHTTPUserAgent(util.ConstructUserAgent())
	opts.Fetcher = singleAttempt

	return opts
}

// FetchTrustedRoot fetches the public Sigstore trusted root using
// DefaultOptions.
func FetchTrustedRoot() (*root.TrustedRoot, error) {
	trustedRoot, err := root.FetchTrustedRootWithOptions(DefaultOptions())
	if err != nil {
		return nil, fmt.Errorf("fetching trusted root: %w", err)
	}

	return trustedRoot, nil
}

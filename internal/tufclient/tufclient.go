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
	"sync/atomic"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
)

// retriesDisabled makes TUF downloads fail on the first error.
var retriesDisabled atomic.Bool //nolint:gochecknoglobals // process-wide switch set by hermetic tests

// transportSetter is implemented by the go-tuf default fetcher.
type transportSetter interface {
	SetTransport(rt http.RoundTripper) error
}

// DisableRetries makes TUF downloads fail on the first error instead of
// retrying with backoff. Hermetic tests use it: the TUF repository is
// unreachable there, so retrying only delays the expected failure.
func DisableRetries() {
	retriesDisabled.Store(true)
}

// DefaultOptions returns the sigstore-go default TUF options, without
// download retries when DisableRetries was called.
func DefaultOptions() *tuf.Options {
	opts := tuf.DefaultOptions()

	if retriesDisabled.Load() {
		// sigstore-go wraps the transport in a retrying one; restore the
		// plain transport so the download is attempted once.
		if setter, ok := opts.Fetcher.(transportSetter); ok {
			_ = setter.SetTransport(http.DefaultTransport)
		}
	}

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

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

package main

import (
	"os"
	"testing"
)

// unreachableProxy is a loopback address that refuses connections.
const unreachableProxy = "http://127.0.0.1:9"

// TestMain keeps the tests off the network. Every verifier pre-warms the
// public Sigstore trusted root, and a test image reference without a registry
// host resolves to Docker Hub. Routing all HTTP traffic through a proxy that
// refuses connections makes such a request fail at once instead of depending
// on the network. Go never proxies requests to loopback addresses, so the
// in-process test registries keep working.
func TestMain(m *testing.M) {
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		_ = os.Setenv(name, unreachableProxy)
	}

	for _, name := range []string{"NO_PROXY", "no_proxy"} {
		_ = os.Unsetenv(name)
	}

	os.Exit(m.Run())
}

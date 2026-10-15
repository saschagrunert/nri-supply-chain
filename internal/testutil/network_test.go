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

package testutil_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRunHermeticBlocksExternalHosts checks that the package's TestMain
// (RunHermetic) makes external host names unresolvable for lookups and HTTP
// clients, while loopback servers keep working.
func TestRunHermeticBlocksExternalHosts(t *testing.T) {
	t.Parallel()

	_, err := net.DefaultResolver.LookupHost(context.Background(), "registry-1.docker.io")
	if err == nil {
		t.Fatal("expected the lookup of an external host to fail")
	}

	req, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"https://tuf-repo-cdn.sigstore.dev",
		http.NoBody,
	)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		_ = resp.Body.Close()

		t.Fatal("expected a request to an external host to fail")
	}

	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(server.Close)

	req, err = http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("expected a loopback request to work: %v", err)
	}

	_ = resp.Body.Close()
}

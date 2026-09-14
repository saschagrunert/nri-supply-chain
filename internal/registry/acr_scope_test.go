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

package registry_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/registry"
)

const testACRHost = "myregistry.azurecr.io"

var errTokenUnavailable = errors.New("token unavailable")

type scopeRecorder struct {
	mu     sync.Mutex
	scopes []string
}

func (r *scopeRecorder) token(_ context.Context, scope string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.scopes = append(r.scopes, scope)

	return "aad-token-for-" + scope, nil
}

func TestACRHelperPrefersRegistryScope(t *testing.T) {
	t.Parallel()

	recorder := &scopeRecorder{mu: sync.Mutex{}, scopes: nil}

	helper := registry.NewACRHelperWithFuncs(
		recorder.token,
		func(_ context.Context, _ *http.Client, _, accessToken string) (string, error) {
			return "refresh-" + accessToken, nil
		},
	)

	user, password, err := helper.Get(testACRHost)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if user != "<token>" || !strings.HasSuffix(password, registry.ACRRegistryScope) {
		t.Errorf("unexpected credentials %q/%q", user, password)
	}

	if len(recorder.scopes) != 1 || recorder.scopes[0] != registry.ACRRegistryScope {
		t.Errorf("expected only the registry scope to be requested, got %v", recorder.scopes)
	}
}

func TestACRHelperFallsBackToManagementScopeWhenRejected(t *testing.T) {
	t.Parallel()

	recorder := &scopeRecorder{mu: sync.Mutex{}, scopes: nil}

	helper := registry.NewACRHelperWithFuncs(
		recorder.token,
		func(_ context.Context, _ *http.Client, _, accessToken string) (string, error) {
			if strings.HasSuffix(accessToken, registry.ACRRegistryScope) {
				return "", fmt.Errorf("rejected: %w", registry.ErrExchangeUnauthorized)
			}

			return "refresh-management", nil
		},
	)

	_, password, err := helper.Get(testACRHost)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if password != "refresh-management" {
		t.Errorf("password = %q, want management refresh token", password)
	}

	if len(recorder.scopes) != 2 || recorder.scopes[1] != registry.ACRManagementScope {
		t.Errorf("expected registry then management scope, got %v", recorder.scopes)
	}
}

func TestACRHelperCachesFailures(t *testing.T) {
	t.Parallel()

	var (
		mu    sync.Mutex
		calls int
	)

	helper := registry.NewACRHelperWithFuncs(
		func(_ context.Context, _ string) (string, error) {
			mu.Lock()
			defer mu.Unlock()

			calls++

			return "", errTokenUnavailable
		},
		nil,
	)

	for range 3 {
		_, _, err := helper.Get(testACRHost)
		if !errors.Is(err, errTokenUnavailable) {
			t.Fatalf("expected token error, got %v", err)
		}
	}

	if calls != 1 {
		t.Errorf("expected a single token request during backoff, got %d", calls)
	}
}

func TestExchangeACRTokenUnauthorized(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(server.Close)

	_, err := registry.ExchangeACRToken(
		t.Context(), server.Client(), strings.TrimPrefix(server.URL, "https://"), "token",
	)
	if !errors.Is(err, registry.ErrExchangeUnauthorized) {
		t.Fatalf("expected unauthorized exchange error, got %v", err)
	}
}

func TestMirrorFallbackDoesNotReuseInsecureTransport(t *testing.T) {
	t.Parallel()

	// The original registry presents a certificate that is not trusted by
	// the system pool. The mirror entry is insecure, but that setting must not
	// apply when falling back to the original registry.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)

	originalHost := strings.TrimPrefix(server.URL, "https://")

	cache := registry.NewTransportCache([]config.Registry{{
		Prefix:   originalHost,
		Mirror:   "127.0.0.1:1",
		CACert:   "",
		Insecure: true,
	}})

	_, _, fallbackUsed, err := registry.ResolveWithRegistries(
		t.Context(), originalHost+"/test/image:v1", cache,
	)
	if err == nil {
		t.Fatal("expected error")
	}

	if !fallbackUsed {
		t.Fatal("expected fallback to the original registry")
	}

	if !strings.Contains(err.Error(), "certificate") {
		t.Errorf("expected TLS verification failure on fallback, got: %v", err)
	}
}

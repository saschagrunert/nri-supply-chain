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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/registry"
)

const testACRRegistry = "myregistry.azurecr.io"

func TestIsACRHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"azurecr.io", testACRRegistry, true},
		{"azurecr.cn", "myregistry.azurecr.cn", true},
		{"azurecr.us", "myregistry.azurecr.us", true},
		{"with port", "myregistry.azurecr.io:443", true},
		{"with scheme expects bare host", "https://myregistry.azurecr.io", false},
		{"docker hub", testRegistryDockerHub, false},
		{"gcr", "gcr.io", false},
		{"ecr", "123456789.dkr.ecr.us-east-1.amazonaws.com", false},
		{"empty", "", false},
		{"bare domain is not a registry", "azurecr.io", false},
		{"mcr is not ACR", "mcr.microsoft.com", false},
		{"subdomain of mcr", "sub.mcr.microsoft.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := registry.IsACRHost(tt.input)
			if got != tt.expected {
				t.Errorf("IsACRHost(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestStripScheme(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"no scheme", testACRRegistry, testACRRegistry},
		{"https scheme", "https://myregistry.azurecr.io", testACRRegistry},
		{"http scheme", "http://myregistry.azurecr.io", testACRRegistry},
		{"with port", "https://myregistry.azurecr.io:443", "myregistry.azurecr.io:443"},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := registry.StripScheme(tt.input)
			if got != tt.expected {
				t.Errorf("StripScheme(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

type refreshTokenResponse struct {
	RefreshToken string `json:"refresh_token"` //nolint:tagliatelle // ACR API uses snake_case
}

func TestExchangeACRTokenSuccess(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(
		func(responseWriter http.ResponseWriter, request *http.Request) {
			if request.Method != http.MethodPost {
				http.Error(responseWriter, "method not allowed", http.StatusMethodNotAllowed)

				return
			}

			if request.URL.Path != "/oauth2/exchange" {
				http.Error(responseWriter, "not found", http.StatusNotFound)

				return
			}

			parseErr := request.ParseForm()
			if parseErr != nil {
				http.Error(responseWriter, "bad request", http.StatusBadRequest)

				return
			}

			if request.FormValue("grant_type") != "access_token" {
				http.Error(responseWriter, "invalid grant type", http.StatusBadRequest)

				return
			}

			if request.FormValue("access_token") != "test-access-token" {
				http.Error(responseWriter, "missing or wrong access_token", http.StatusBadRequest)

				return
			}

			responseWriter.Header().Set("Content-Type", "application/json")

			resp := refreshTokenResponse{RefreshToken: "test-refresh-token"}

			//nolint:gosec // test helper encoding a mock response
			encodeErr := json.NewEncoder(responseWriter).Encode(resp)
			if encodeErr != nil {
				http.Error(responseWriter, "encode error", http.StatusInternalServerError)

				return
			}
		},
	))

	t.Cleanup(srv.Close)

	serverURL := strings.TrimPrefix(srv.URL, "https://")

	token, err := registry.ExchangeACRToken(
		context.Background(), srv.Client(), serverURL, "test-access-token",
	)
	if err != nil {
		t.Fatalf("ExchangeACRToken() error = %v", err)
	}

	if token != "test-refresh-token" {
		t.Errorf("ExchangeACRToken() = %q, want %q", token, "test-refresh-token")
	}
}

func TestExchangeACRTokenServerError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(
		func(responseWriter http.ResponseWriter, _ *http.Request) {
			http.Error(responseWriter, "internal error", http.StatusInternalServerError)
		},
	))

	t.Cleanup(srv.Close)

	serverURL := strings.TrimPrefix(srv.URL, "https://")

	_, err := registry.ExchangeACRToken(
		context.Background(), srv.Client(), serverURL, "test-access-token",
	)
	if err == nil {
		t.Fatal("ExchangeACRToken() expected error for server error response")
	}

	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention status code 500, got: %v", err)
	}
}

func TestExchangeACRTokenEmptyRefreshToken(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(
		func(responseWriter http.ResponseWriter, _ *http.Request) {
			responseWriter.Header().Set("Content-Type", "application/json")

			resp := refreshTokenResponse{RefreshToken: ""}

			//nolint:gosec // test helper encoding a mock response
			encodeErr := json.NewEncoder(responseWriter).Encode(resp)
			if encodeErr != nil {
				http.Error(responseWriter, "encode error", http.StatusInternalServerError)

				return
			}
		},
	))

	t.Cleanup(srv.Close)

	serverURL := strings.TrimPrefix(srv.URL, "https://")

	_, err := registry.ExchangeACRToken(
		context.Background(), srv.Client(), serverURL, "test-access-token",
	)
	if err == nil {
		t.Fatal("ExchangeACRToken() expected error for empty refresh token")
	}

	if !strings.Contains(err.Error(), "empty refresh token") {
		t.Errorf("error should mention empty refresh token, got: %v", err)
	}
}

func TestExchangeACRTokenContextCancelled(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(
		func(responseWriter http.ResponseWriter, _ *http.Request) {
			responseWriter.Header().Set("Content-Type", "application/json")

			resp := refreshTokenResponse{RefreshToken: "token"}

			//nolint:gosec // test helper encoding a mock response
			_ = json.NewEncoder(responseWriter).Encode(resp)
		},
	))

	t.Cleanup(srv.Close)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	serverURL := strings.TrimPrefix(srv.URL, "https://")

	_, err := registry.ExchangeACRToken(ctx, srv.Client(), serverURL, "test-access-token")
	if err == nil {
		t.Fatal("ExchangeACRToken() expected error for cancelled context")
	}
}

func TestGetReturnsErrorForNonACR(t *testing.T) {
	t.Parallel()

	helper := registry.NewACRHelper()

	_, _, err := helper.Get("docker.io")
	if err == nil {
		t.Fatal("Get() expected error for non-ACR host")
	}

	if err.Error() != registry.ErrNotACR.Error() {
		t.Errorf("Get() error = %q, want %q", err.Error(), registry.ErrNotACR.Error())
	}
}

func TestGetReturnsErrorForMCR(t *testing.T) {
	t.Parallel()

	helper := registry.NewACRHelper()

	_, _, err := helper.Get("mcr.microsoft.com")
	if err == nil {
		t.Fatal("Get() expected error for MCR host")
	}

	if err.Error() != registry.ErrNotACR.Error() {
		t.Errorf("Get() error = %q, want %q", err.Error(), registry.ErrNotACR.Error())
	}
}

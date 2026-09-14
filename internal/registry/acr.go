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

package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/saschagrunert/nri-supply-chain/internal/httputil"
)

const (
	acrTokenUsername   = "<token>"
	acrExchangeTimeout = 10 * time.Second
	// acrRegistryScope requests a token for the container registry audience
	// only. It is preferred over the Azure Resource Manager scope, which
	// grants access to the management plane of the whole subscription.
	acrRegistryScope = "https://containerregistry.azure.net/.default"
	// acrManagementScope is the legacy, broader scope. It is only used when
	// a registry rejects registry-audience tokens.
	acrManagementScope = "https://management.azure.com/.default"
	grantTypeValue     = "access_token"
	acrTokenCacheTTL   = 30 * time.Minute
	// acrFailureBackoff caches credential failures so that every image pull
	// does not repeat a slow Azure token request against a broken setup.
	acrFailureBackoff = 30 * time.Second
)

var (
	errNotACR               = errors.New("not an Azure Container Registry host")
	errExchangeStatus       = errors.New("ACR token exchange failed")
	errExchangeUnauthorized = errors.New("ACR token exchange rejected the access token")
	errEmptyRefreshToken    = errors.New("ACR token exchange returned empty refresh token")
)

type acrExchangeResponse struct {
	RefreshToken string `json:"refresh_token"` //nolint:tagliatelle // ACR API uses snake_case
}

type cachedRefreshToken struct {
	value     string
	expiresAt time.Time
}

type cachedFailure struct {
	err       error
	expiresAt time.Time
}

// accessTokenFunc acquires an Azure AD access token for the given scope.
type accessTokenFunc func(ctx context.Context, scope string) (string, error)

// exchangeFunc exchanges an Azure AD access token for an ACR refresh token.
type exchangeFunc func(ctx context.Context, client *http.Client, host, accessToken string) (string, error)

type acrHelper struct {
	client      *http.Client
	credMu      sync.Mutex
	cred        *azidentity.DefaultAzureCredential
	tokenMu     sync.Mutex
	tokens      map[string]cachedRefreshToken
	failures    map[string]cachedFailure
	defaultOnce sync.Once
	defaultHTTP *http.Client
	accessToken accessTokenFunc
	exchange    exchangeFunc
}

func newACRHelper() *acrHelper {
	return &acrHelper{}
}

// Get returns ACR credentials for the given server URL. If the host is not an
// ACR registry, it returns an error and the multi-keychain falls through to the
// next provider.
func (a *acrHelper) Get(serverURL string) (username, password string, err error) {
	host := stripScheme(serverURL)

	if !isACRHost(host) {
		return "", "", errNotACR
	}

	if cached, ok := a.cachedToken(host); ok {
		return acrTokenUsername, cached, nil
	}

	failure := a.recentFailure(host)
	if failure != nil {
		return "", "", failure
	}

	// authn.Helper.Get has no context parameter, so use a detached timeout.
	ctx, cancel := context.WithTimeout(context.Background(), acrExchangeTimeout)
	defer cancel()

	refreshToken, err := a.acquireRefreshToken(ctx, host)
	if err != nil {
		a.cacheFailure(host, err)

		return "", "", err
	}

	a.cacheToken(host, refreshToken)

	return acrTokenUsername, refreshToken, nil
}

// acquireRefreshToken exchanges a registry-scoped Azure token for an ACR
// refresh token. The broader management scope is only tried when the
// registry rejects the registry-scoped token.
func (a *acrHelper) acquireRefreshToken(ctx context.Context, host string) (string, error) {
	var lastErr error

	for _, scope := range []string{acrRegistryScope, acrManagementScope} {
		token, tokenErr := a.getAccessToken(ctx, scope)
		if tokenErr != nil {
			return "", fmt.Errorf("acquiring Azure token: %w", tokenErr)
		}

		refreshToken, exchangeErr := a.exchangeToken(ctx, host, token)
		if exchangeErr == nil {
			return refreshToken, nil
		}

		lastErr = exchangeErr

		if !errors.Is(exchangeErr, errExchangeUnauthorized) {
			break
		}
	}

	return "", lastErr
}

func (a *acrHelper) getAccessToken(ctx context.Context, scope string) (string, error) {
	if a.accessToken != nil {
		return a.accessToken(ctx, scope)
	}

	cred, err := a.credential()
	if err != nil {
		return "", err
	}

	token, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{scope}})
	if err != nil {
		return "", fmt.Errorf("requesting token for scope %q: %w", scope, err)
	}

	return token.Token, nil
}

func (a *acrHelper) exchangeToken(ctx context.Context, host, accessToken string) (string, error) {
	if a.exchange != nil {
		return a.exchange(ctx, a.httpClient(), host, accessToken)
	}

	return exchangeACRToken(ctx, a.httpClient(), host, accessToken)
}

func (a *acrHelper) credential() (*azidentity.DefaultAzureCredential, error) {
	a.credMu.Lock()
	defer a.credMu.Unlock()

	if a.cred != nil {
		return a.cred, nil
	}

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("default azure credential: %w", err)
	}

	a.cred = cred

	return a.cred, nil
}

func (a *acrHelper) cachedToken(host string) (string, bool) {
	a.tokenMu.Lock()
	defer a.tokenMu.Unlock()

	cached, ok := a.tokens[host]
	if !ok || time.Now().After(cached.expiresAt) {
		return "", false
	}

	return cached.value, true
}

// recentFailure returns the cached credential failure for host, or nil when
// there is none or the backoff has elapsed.
func (a *acrHelper) recentFailure(host string) error {
	a.tokenMu.Lock()
	defer a.tokenMu.Unlock()

	failure, ok := a.failures[host]
	if !ok || time.Now().After(failure.expiresAt) {
		return nil
	}

	return failure.err
}

func (a *acrHelper) cacheFailure(host string, err error) {
	a.tokenMu.Lock()
	defer a.tokenMu.Unlock()

	if a.failures == nil {
		a.failures = make(map[string]cachedFailure)
	}

	a.failures[host] = cachedFailure{err: err, expiresAt: time.Now().Add(acrFailureBackoff)}
}

func (a *acrHelper) cacheToken(host, refreshToken string) {
	a.tokenMu.Lock()
	defer a.tokenMu.Unlock()

	if a.tokens == nil {
		a.tokens = make(map[string]cachedRefreshToken)
	}

	a.tokens[host] = cachedRefreshToken{
		value:     refreshToken,
		expiresAt: time.Now().Add(acrTokenCacheTTL),
	}

	delete(a.failures, host)
}

const acrHTTPClientTimeout = 30 * time.Second

func (a *acrHelper) httpClient() *http.Client {
	if a.client != nil {
		return a.client
	}

	a.defaultOnce.Do(func() {
		a.defaultHTTP = &http.Client{
			Timeout:   acrHTTPClientTimeout,
			Transport: httputil.NewTLSTransport(nil),
		}
	})

	return a.defaultHTTP
}

func stripScheme(serverURL string) string {
	if !strings.Contains(serverURL, "://") {
		return serverURL
	}

	parsed, err := url.Parse(serverURL)
	if err != nil {
		return serverURL
	}

	return parsed.Host
}

func isACRHost(host string) bool {
	hostname := strings.ToLower(host)

	if idx := strings.LastIndex(hostname, ":"); idx != -1 {
		hostname = hostname[:idx]
	}

	for _, suffix := range []string{".azurecr.io", ".azurecr.cn", ".azurecr.us"} {
		if strings.HasSuffix(hostname, suffix) {
			return true
		}
	}

	return false
}

func exchangeACRToken(
	ctx context.Context,
	client *http.Client, serverURL, accessToken string,
) (string, error) {
	exchangeURL := "https://" + serverURL + "/oauth2/exchange"

	form := url.Values{
		"grant_type":   {grantTypeValue},
		"service":      {serverURL},
		grantTypeValue: {accessToken},
	}

	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, exchangeURL, strings.NewReader(form.Encode()),
	)
	if err != nil {
		return "", fmt.Errorf("building ACR token exchange request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("ACR token exchange request: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return "", fmt.Errorf(
			"%w: %w: status %d", errExchangeStatus, errExchangeUnauthorized, resp.StatusCode,
		)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: status %d", errExchangeStatus, resp.StatusCode)
	}

	var exchangeResp acrExchangeResponse

	const maxResponseBody = 1 << 20 // 1 MiB

	err = json.NewDecoder(io.LimitReader(resp.Body, maxResponseBody)).Decode(&exchangeResp)
	if err != nil {
		return "", fmt.Errorf("decoding ACR token exchange response: %w", err)
	}

	if exchangeResp.RefreshToken == "" {
		return "", errEmptyRefreshToken
	}

	return exchangeResp.RefreshToken, nil
}

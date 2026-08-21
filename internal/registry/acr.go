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
	acrScope           = "https://management.azure.com/.default"
	grantTypeValue     = "access_token"
	acrTokenCacheTTL   = 30 * time.Minute
)

var (
	errNotACR            = errors.New("not an Azure Container Registry host")
	errExchangeStatus    = errors.New("ACR token exchange failed")
	errEmptyRefreshToken = errors.New("ACR token exchange returned empty refresh token")
)

type acrExchangeResponse struct {
	RefreshToken string `json:"refresh_token"` //nolint:tagliatelle // ACR API uses snake_case
}

type cachedRefreshToken struct {
	value     string
	expiresAt time.Time
}

type acrHelper struct {
	client      *http.Client
	credMu      sync.Mutex
	cred        *azidentity.DefaultAzureCredential
	tokenMu     sync.Mutex
	tokens      map[string]cachedRefreshToken
	defaultOnce sync.Once
	defaultHTTP *http.Client
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

	// authn.Helper.Get has no context parameter, so use a detached timeout.
	ctx, cancel := context.WithTimeout(context.Background(), acrExchangeTimeout)
	defer cancel()

	cred, credErr := a.credential()
	if credErr != nil {
		return "", "", credErr
	}

	token, tokenErr := cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{acrScope},
	})
	if tokenErr != nil {
		return "", "", fmt.Errorf("acquiring Azure token: %w", tokenErr)
	}

	refreshToken, exchangeErr := exchangeACRToken(ctx, a.httpClient(), host, token.Token)
	if exchangeErr != nil {
		return "", "", exchangeErr
	}

	a.cacheToken(host, refreshToken)

	return acrTokenUsername, refreshToken, nil
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

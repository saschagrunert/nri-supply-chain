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

// Package guac provides a client for querying GUAC (Graph for Understanding
// Artifact Composition) as a supplemental verification data source.
package guac

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/fileutil"
)

var (
	// ErrGUACUnavailable indicates the GUAC endpoint could not be reached.
	ErrGUACUnavailable = errors.New("GUAC endpoint unavailable")

	// ErrGUACQueryFailed indicates a GUAC query returned an error.
	ErrGUACQueryFailed = errors.New("GUAC query failed")

	// ErrGUACAuthError indicates a local auth token read failure (not a
	// server-side issue, so it should not count toward the circuit breaker).
	ErrGUACAuthError = errors.New("GUAC auth token error")

	// ErrGUACCACert indicates a failure loading the CA certificate.
	ErrGUACCACert = errors.New("failed to load GUAC CA certificate")

	// ErrTooManyRedirects indicates the HTTP client followed too many redirects.
	ErrTooManyRedirects = errors.New("stopped after 10 redirects")
)

const (
	maxResponseSize       = 10 << 20 // 10 MiB
	maxRedirects          = 10
	transportMaxIdleConns = 100
	transportIdleTimeout  = 90 * time.Second
	transportTLSTimeout   = 10 * time.Second
	transportContTimeout  = 1 * time.Second
)

// Client queries a GUAC instance for vulnerability, scorecard, and
// dependency data. It uses GUAC's REST API for vulnerabilities and
// dependencies, and GraphQL for Scorecard queries.
type Client struct {
	endpoint      string
	authTokenPath string
	httpClient    *http.Client

	cachedTokenMu    sync.Mutex
	cachedToken      string
	cachedTokenMtime time.Time
}

// NewClient creates a GUAC client for the given endpoint. If caCertPath is
// non-empty, the client loads that PEM file as a trusted root for TLS.
func NewClient(endpoint, authTokenPath, caCertPath string, timeout time.Duration) (*Client, error) {
	transport, err := buildTransport(caCertPath)
	if err != nil {
		return nil, err
	}

	parsedEndpoint, parseErr := url.Parse(endpoint)
	if parseErr != nil {
		return nil, fmt.Errorf("parsing GUAC endpoint: %w", parseErr)
	}

	endpointHost := parsedEndpoint.Host

	return &Client{
		endpoint:      strings.TrimRight(endpoint, "/"),
		authTokenPath: authTokenPath,
		httpClient: &http.Client{
			Timeout:   timeout,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= maxRedirects {
					return ErrTooManyRedirects
				}

				if req.URL.Host != endpointHost {
					req.Header.Del("Authorization")
				}

				return nil
			},
		},
	}, nil
}

// Close releases idle connections held by the underlying HTTP client.
func (c *Client) Close() {
	c.httpClient.CloseIdleConnections()
}

func buildTransport(caCertPath string) (http.RoundTripper, error) {
	var pool *x509.CertPool

	if caCertPath != "" {
		pemData, err := fileutil.ReadLimited(caCertPath, fileutil.MaxCredentialFileSize)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrGUACCACert, err)
		}

		pool, err = x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}

		if !pool.AppendCertsFromPEM(pemData) {
			return nil, fmt.Errorf("%w: no valid certificates in %s", ErrGUACCACert, caCertPath)
		}
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          transportMaxIdleConns,
		IdleConnTimeout:       transportIdleTimeout,
		TLSHandshakeTimeout:   transportTLSTimeout,
		ExpectContinueTimeout: transportContTimeout,
		TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS12,
		},
	}

	return transport, nil
}

// HealthCheck probes the GUAC endpoint for availability.
func (c *Client) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+"/healthz", http.NoBody)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrGUACUnavailable, err)
	}

	err = c.setAuth(req)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrGUACUnavailable, err)
	}

	defer resp.Body.Close() //nolint:errcheck // health check response body is discarded

	// Drain the body so the connection can be reused by the pool.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseSize))

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: health check returned %d", ErrGUACUnavailable, resp.StatusCode)
	}

	return nil
}

// QueryVulnerabilities queries GUAC for vulnerabilities affecting the given
// artifact digest, optionally including transitive dependencies.
func (c *Client) QueryVulnerabilities(
	ctx context.Context, digest string, includeTransitive bool,
) (direct, transitive []Vulnerability, err error) {
	params := url.Values{}
	params.Set("digest", digest)

	if includeTransitive {
		params.Set("includeDependencies", "true")
	}

	reqURL := c.endpoint + "/query/vulnerabilities?" + params.Encode()

	body, err := c.doGet(ctx, reqURL)
	if err != nil {
		return nil, nil, err
	}

	return parseVulnResponse(body, digest)
}

func parseVulnResponse(
	body []byte, digest string,
) (direct, transitive []Vulnerability, err error) {
	var resp restVulnResponse

	err = json.Unmarshal(body, &resp)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"%w: parsing vulnerability response: %w", ErrGUACQueryFailed, err,
		)
	}

	for idx := range resp.Vulnerabilities {
		entry := &resp.Vulnerabilities[idx]

		for _, vulnID := range entry.Vulnerability.VulnerabilityIDs {
			vuln := Vulnerability{
				ID:      vulnID,
				Package: entry.Package,
			}

			if entry.Package == digest {
				direct = append(direct, vuln)
			} else {
				transitive = append(transitive, vuln)
			}
		}
	}

	return direct, transitive, nil
}

// QueryDependencies queries GUAC for the dependency graph of the given
// artifact digest. The maxDeps parameter limits how many dependency PURLs
// are returned; zero or negative means no limit.
func (c *Client) QueryDependencies(
	ctx context.Context, digest string, maxDeps int,
) (*DependencyInfo, error) {
	params := url.Values{}
	params.Set("digest", digest)

	reqURL := c.endpoint + "/query/dependencies?" + params.Encode()

	body, err := c.doGet(ctx, reqURL)
	if err != nil {
		return nil, err
	}

	return parseDepsResponse(body, maxDeps)
}

func parseDepsResponse(body []byte, maxDeps int) (*DependencyInfo, error) {
	var resp restDepsResponse

	err := json.Unmarshal(body, &resp)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: parsing dependency response: %w", ErrGUACQueryFailed, err,
		)
	}

	deps := resp.PURLs
	totalCount := len(deps)

	if maxDeps > 0 && len(deps) > maxDeps {
		deps = deps[:maxDeps]
	}

	return &DependencyInfo{
		Dependencies:    deps,
		DependencyCount: totalCount,
	}, nil
}

const scorecardQuery = `query CertifyScorecard($filter: CertifyScorecardSpec!) {
  scorecards(certifyScorecardSpec: $filter) {
    source {
      type
      namespace
      name
    }
    scorecard {
      aggregateScore
      checks {
        check
        score
      }
    }
  }
}`

// QueryScorecard queries GUAC for OpenSSF Scorecard data. The current
// implementation uses an unscoped filter and returns the first scorecard
// found; digest-based scoping requires a separate artifact-to-source
// resolution query that is not yet implemented.
func (c *Client) QueryScorecard(
	ctx context.Context,
) (*ScorecardResult, error) {
	// Empty filter: returns the first scorecard in the GUAC instance.
	// Scoping to a specific image requires artifact-to-source resolution.
	gqlReq := graphQLRequest{
		Query: scorecardQuery,
		Variables: map[string]any{
			"filter": map[string]any{},
		},
	}

	reqBody, err := json.Marshal(gqlReq)
	if err != nil {
		return nil, fmt.Errorf("%w: marshaling GraphQL request: %w", ErrGUACQueryFailed, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.endpoint+"/query", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("%w: creating GraphQL request: %w", ErrGUACQueryFailed, err)
	}

	req.Header.Set("Content-Type", "application/json")

	err = c.setAuth(req)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGUACUnavailable, err)
	}

	defer resp.Body.Close() //nolint:errcheck // response body is fully read below

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("%w: reading GraphQL response: %w", ErrGUACQueryFailed, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: GraphQL returned %d: %s",
			ErrGUACQueryFailed, resp.StatusCode, truncateBody(body))
	}

	return parseScorecardResponse(body)
}

func parseScorecardResponse(body []byte) (*ScorecardResult, error) {
	var gqlResp graphQLResponse

	err := json.Unmarshal(body, &gqlResp)
	if err != nil {
		return nil, fmt.Errorf("%w: parsing GraphQL response: %w", ErrGUACQueryFailed, err)
	}

	if len(gqlResp.Errors) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrGUACQueryFailed, gqlResp.Errors[0].Message)
	}

	if len(gqlResp.Data.Scorecards) == 0 {
		return &ScorecardResult{}, nil
	}

	entry := &gqlResp.Data.Scorecards[0]
	checks := make(map[string]float64, len(entry.Scorecard.Checks))

	for idx := range entry.Scorecard.Checks {
		checks[entry.Scorecard.Checks[idx].Check] = entry.Scorecard.Checks[idx].Score
	}

	source := entry.Source.Type + "/" + entry.Source.Namespace + "/" + entry.Source.Name

	return &ScorecardResult{
		Aggregate: entry.Scorecard.AggregateScore,
		Checks:    checks,
		Source:    source,
	}, nil
}

func (c *Client) doGet(ctx context.Context, reqURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGUACQueryFailed, err)
	}

	err = c.setAuth(req)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGUACUnavailable, err)
	}

	defer resp.Body.Close() //nolint:errcheck // response body is fully read below

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("%w: reading response: %w", ErrGUACQueryFailed, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d: %s",
			ErrGUACQueryFailed, resp.StatusCode, truncateBody(body))
	}

	return body, nil
}

func (c *Client) setAuth(req *http.Request) error {
	if c.authTokenPath == "" {
		return nil
	}

	token, err := c.readAuthToken()
	if err != nil {
		return fmt.Errorf("%w: reading auth token: %w", ErrGUACAuthError, err)
	}

	req.Header.Set("Authorization", "Bearer "+token)

	return nil
}

func (c *Client) readAuthToken() (string, error) {
	c.cachedTokenMu.Lock()
	defer c.cachedTokenMu.Unlock()

	info, statErr := os.Stat(c.authTokenPath)
	if statErr == nil && c.cachedToken != "" && info.ModTime().Equal(c.cachedTokenMtime) {
		return c.cachedToken, nil
	}

	data, err := fileutil.ReadLimited(c.authTokenPath, fileutil.MaxCredentialFileSize)
	if err != nil {
		return "", fmt.Errorf("reading token file: %w", err)
	}

	token := strings.TrimSpace(string(data))
	c.cachedToken = token

	if statErr == nil {
		c.cachedTokenMtime = info.ModTime()
	}

	return token, nil
}

const maxTruncatedBodyLen = 200

func truncateBody(body []byte) string {
	sanitized := strings.Map(func(r rune) rune {
		if r < ' ' && r != '\n' {
			return ' '
		}

		return r
	}, string(body))

	runes := []rune(sanitized)
	if len(runes) > maxTruncatedBodyLen {
		return string(runes[:maxTruncatedBodyLen]) + "..."
	}

	return sanitized
}

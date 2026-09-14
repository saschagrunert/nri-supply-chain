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
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/saschagrunert/nri-supply-chain/internal/fileutil"
	"github.com/saschagrunert/nri-supply-chain/internal/httputil"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
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
	maxResponseSize = 10 << 20 // 10 MiB
	maxRedirects    = 10
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

	return httputil.NewTLSTransport(pool), nil
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

const (
	// maxScorecardSources bounds the number of source repositories queried
	// for a single artifact. When more sources are linked the lowest score
	// cannot be determined and the scorecard fails closed.
	maxScorecardSources = 20

	// maxScorecardPackages bounds the number of packages whose source links
	// are resolved for a single artifact.
	maxScorecardPackages = 20

	// maxConcurrentScorecardQueries bounds the GraphQL requests sent in
	// parallel while resolving package sources and scorecards.
	maxConcurrentScorecardQueries = 5

	typenameSource  = "Source"
	typenamePackage = "Package"

	// graphQLFilterVariable is the variable name of the query filters.
	graphQLFilterVariable = "filter"
)

const artifactSourcesQuery = `query ArtifactSources($filter: IsOccurrenceSpec!) {
  IsOccurrence(isOccurrenceSpec: $filter) {
    subject {
      __typename
      ... on Source {
        type
        namespaces {
          namespace
          names {
            name
          }
        }
      }
      ... on Package {
        type
        namespaces {
          namespace
          names {
            name
          }
        }
      }
    }
  }
}`

const packageSourcesQuery = `query PackageSources($filter: HasSourceAtSpec!) {
  HasSourceAt(hasSourceAtSpec: $filter) {
    source {
      type
      namespaces {
        namespace
        names {
          name
        }
      }
    }
  }
}`

const scorecardQuery = `query CertifyScorecard($filter: CertifyScorecardSpec!) {
  scorecards(scorecardSpec: $filter) {
    source {
      type
      namespaces {
        namespace
        names {
          name
        }
      }
    }
    scorecard {
      aggregateScore
      timeScanned
      checks {
        check
        score
      }
    }
  }
}`

// sourceKey identifies a GUAC source repository.
type sourceKey struct {
	typ       string
	namespace string
	name      string
}

func (s sourceKey) String() string {
	return s.typ + "/" + s.namespace + "/" + s.name
}

// QueryScorecard queries GUAC for the OpenSSF Scorecard of the source
// repositories linked to the artifact digest, either directly (IsOccurrence
// of a source) or through the packages the artifact is an occurrence of
// (IsOccurrence of a package, then HasSourceAt). Scorecards of unrelated
// repositories are never returned. When the artifact has no known source, an
// empty result is returned. When several sources are linked, the lowest
// aggregate score wins, and a linked source without a scorecard yields an
// empty (zero) result. When more sources or packages are linked than can be
// queried, the result has aggregate 0, Truncated set, and the
// TruncatedScorecardSource sentinel as source, so minimum-score rules fail
// closed and the result cannot be mistaken for an artifact without a linked
// source. Package sources and scorecards are queried concurrently with a
// bounded number of requests in flight.
func (c *Client) QueryScorecard(
	ctx context.Context, digest string,
) (*ScorecardResult, error) {
	sources, truncated, err := c.resolveScorecardSources(ctx, digest)
	if err != nil {
		return nil, err
	}

	if truncated {
		return &ScorecardResult{
			Aggregate: 0, Checks: nil, Source: TruncatedScorecardSource, Truncated: true,
		}, nil
	}

	if len(sources) == 0 {
		return &ScorecardResult{}, nil
	}

	scorecards, err := queryConcurrently(ctx, sources, c.queryScorecardForSource)
	if err != nil {
		return nil, err
	}

	selected := scorecards[0]

	for _, scorecard := range scorecards[1:] {
		if scorecard.Aggregate < selected.Aggregate {
			selected = scorecard
		}
	}

	return selected, nil
}

// resolveScorecardSources returns the source repositories linked to the
// artifact directly or through its packages. truncated is true when more
// packages or sources are linked than can be queried, so the scorecard is
// reported as truncated (fail closed) instead of silently skipping some
// sources.
func (c *Client) resolveScorecardSources(
	ctx context.Context, digest string,
) (sources []sourceKey, truncated bool, err error) {
	sources, packages, err := c.querySources(ctx, digest)
	if err != nil {
		return nil, false, err
	}

	if len(packages) > maxScorecardPackages {
		slog.WarnContext(ctx, "Too many GUAC packages linked to artifact, "+
			"reporting a truncated scorecard", "packages", len(packages))

		return nil, true, nil
	}

	pkgSources, err := queryConcurrently(ctx, packages, c.queryPackageSources)
	if err != nil {
		return nil, false, err
	}

	for _, linked := range pkgSources {
		sources = append(sources, linked...)
	}

	sources = dedupeSources(sources)

	if len(sources) > maxScorecardSources {
		slog.WarnContext(ctx, "Too many GUAC sources linked to artifact, "+
			"reporting a truncated scorecard", "sources", len(sources))

		return nil, true, nil
	}

	return sources, false, nil
}

// queryConcurrently runs query for every key with at most
// maxConcurrentScorecardQueries requests in flight and returns the results
// in key order. The first error cancels the remaining queries.
func queryConcurrently[T any](
	ctx context.Context, keys []sourceKey,
	query func(context.Context, sourceKey) (T, error),
) ([]T, error) {
	results := make([]T, len(keys))

	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(maxConcurrentScorecardQueries)

	for idx := range keys {
		group.Go(func() error {
			result, err := query(groupCtx, keys[idx])
			if err != nil {
				return err
			}

			results[idx] = result

			return nil
		})
	}

	err := group.Wait()
	if err != nil {
		return nil, fmt.Errorf("querying GUAC scorecard data: %w", err)
	}

	return results, nil
}

func (c *Client) querySources(
	ctx context.Context, digest string,
) (sources, packages []sourceKey, err error) {
	algorithm, hexDigest := types.ParseDigest(digest)
	if algorithm == "" {
		return nil, nil, fmt.Errorf(
			"%w: invalid artifact digest %q", ErrGUACQueryFailed, digest,
		)
	}

	body, err := c.postGraphQL(ctx, artifactSourcesQuery, map[string]any{
		graphQLFilterVariable: map[string]any{
			"artifact": map[string]any{"algorithm": algorithm, "digest": hexDigest},
		},
	})
	if err != nil {
		return nil, nil, err
	}

	return parseSourcesResponse(body)
}

// parseSourcesResponse extracts the sources and packages the artifact is an
// occurrence of, deduplicated and sorted.
func parseSourcesResponse(body []byte) (sources, packages []sourceKey, err error) {
	gqlResp, err := decodeGraphQL(body)
	if err != nil {
		return nil, nil, err
	}

	for idx := range gqlResp.Data.IsOccurrence {
		subject := &gqlResp.Data.IsOccurrence[idx].Subject

		switch subject.Typename {
		case typenameSource:
			sources = append(sources, flattenSource(subject)...)
		case typenamePackage:
			packages = append(packages, flattenSource(subject)...)
		}
	}

	return dedupeSources(sources), dedupeSources(packages), nil
}

// queryPackageSources resolves the source repositories of a package through
// HasSourceAt. Links recorded for any version of the package are accepted.
func (c *Client) queryPackageSources(
	ctx context.Context, pkg sourceKey,
) ([]sourceKey, error) {
	body, err := c.postGraphQL(ctx, packageSourcesQuery, map[string]any{
		graphQLFilterVariable: map[string]any{
			"package": map[string]any{
				"type":      pkg.typ,
				"namespace": pkg.namespace,
				"name":      pkg.name,
			},
		},
	})
	if err != nil {
		return nil, err
	}

	return parsePackageSourcesResponse(body)
}

func parsePackageSourcesResponse(body []byte) ([]sourceKey, error) {
	gqlResp, err := decodeGraphQL(body)
	if err != nil {
		return nil, err
	}

	var sources []sourceKey

	for idx := range gqlResp.Data.HasSourceAt {
		sources = append(sources, flattenSource(&gqlResp.Data.HasSourceAt[idx].Source)...)
	}

	return dedupeSources(sources), nil
}

func dedupeSources(keys []sourceKey) []sourceKey {
	slices.SortFunc(keys, func(left, right sourceKey) int {
		return strings.Compare(left.String(), right.String())
	})

	return slices.Compact(keys)
}

func (c *Client) queryScorecardForSource(
	ctx context.Context, source sourceKey,
) (*ScorecardResult, error) {
	body, err := c.postGraphQL(ctx, scorecardQuery, map[string]any{
		graphQLFilterVariable: map[string]any{
			fieldSource: map[string]any{
				"type":      source.typ,
				"namespace": source.namespace,
				"name":      source.name,
			},
		},
	})
	if err != nil {
		return nil, err
	}

	return parseScorecardResponse(body, &source)
}

// parseScorecardResponse extracts the scorecard for the wanted source. Entries
// for other sources are ignored even if the server returns them. A nil want
// accepts the source of the first entry (used for fuzzing the decoder).
func parseScorecardResponse(body []byte, want *sourceKey) (*ScorecardResult, error) {
	gqlResp, err := decodeGraphQL(body)
	if err != nil {
		return nil, err
	}

	var matched []*graphQLScorecardData

	for idx := range gqlResp.Data.Scorecards {
		entry := &gqlResp.Data.Scorecards[idx]

		keys := flattenSource(&entry.Source)
		if len(keys) == 0 {
			continue
		}

		if want == nil {
			want = &keys[0]
		}

		if slices.Contains(keys, *want) {
			matched = append(matched, &entry.Scorecard)
		}
	}

	result := &ScorecardResult{}
	if want != nil {
		result.Source = want.String()
	}

	if len(matched) == 0 {
		return result, nil
	}

	selected := selectScorecard(matched)

	result.Aggregate = selected.AggregateScore
	result.Checks = make(map[string]float64, len(selected.Checks))

	for idx := range selected.Checks {
		result.Checks[selected.Checks[idx].Check] = selected.Checks[idx].Score
	}

	return result, nil
}

// selectScorecard returns the most recently scanned of a source's
// scorecards, because GUAC returns every stored scan in backend order. When
// scans share the latest time, or any scan lacks a valid timeScanned so the
// order is unknown, the lowest aggregate score wins.
func selectScorecard(entries []*graphQLScorecardData) *graphQLScorecardData {
	scanned := make([]time.Time, len(entries))
	ordered := true

	for idx, entry := range entries {
		parsed, err := time.Parse(time.RFC3339, entry.TimeScanned)
		if err != nil {
			ordered = false

			break
		}

		scanned[idx] = parsed
	}

	selected := 0

	for idx := 1; idx < len(entries); idx++ {
		if ordered && !scanned[idx].Equal(scanned[selected]) {
			if scanned[idx].After(scanned[selected]) {
				selected = idx
			}

			continue
		}

		if entries[idx].AggregateScore < entries[selected].AggregateScore {
			selected = idx
		}
	}

	return entries[selected]
}

// flattenSource expands a (possibly nested) GUAC source into keys.
func flattenSource(source *graphQLSource) []sourceKey {
	var keys []sourceKey

	if source.Name != "" {
		keys = append(
			keys,
			sourceKey{typ: source.Type, namespace: source.Namespace, name: source.Name},
		)
	}

	for nsIdx := range source.Namespaces {
		namespace := &source.Namespaces[nsIdx]

		for nameIdx := range namespace.Names {
			keys = append(keys, sourceKey{
				typ:       source.Type,
				namespace: namespace.Namespace,
				name:      namespace.Names[nameIdx].Name,
			})
		}
	}

	return keys
}

func decodeGraphQL(body []byte) (*graphQLResponse, error) {
	var gqlResp graphQLResponse

	err := json.Unmarshal(body, &gqlResp)
	if err != nil {
		return nil, fmt.Errorf("%w: parsing GraphQL response: %w", ErrGUACQueryFailed, err)
	}

	if len(gqlResp.Errors) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrGUACQueryFailed, gqlResp.Errors[0].Message)
	}

	return &gqlResp, nil
}

func (c *Client) postGraphQL(
	ctx context.Context, query string, variables map[string]any,
) ([]byte, error) {
	reqBody, err := json.Marshal(graphQLRequest{Query: query, Variables: variables})
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

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("%w: reading GraphQL response: %w", ErrGUACQueryFailed, err)
	}

	if int64(len(body)) > maxResponseSize {
		return nil, fmt.Errorf("%w: GraphQL response exceeds %d bytes",
			ErrGUACQueryFailed, maxResponseSize)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: GraphQL returned %d: %s",
			ErrGUACQueryFailed, resp.StatusCode, truncateBody(body))
	}

	return body, nil
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

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("%w: reading response: %w", ErrGUACQueryFailed, err)
	}

	if int64(len(body)) > maxResponseSize {
		return nil, fmt.Errorf("%w: response exceeds %d bytes",
			ErrGUACQueryFailed, maxResponseSize)
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

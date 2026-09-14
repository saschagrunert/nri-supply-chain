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

package guac //nolint:testpackage // testing unexported types

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	testVulnTypeOSV = "osv"
	testCVE1234     = "CVE-2024-1234"
	testCVE5678     = "CVE-2024-5678"
	testCheckName   = "Code-Review"
)

func newTestClient(t *testing.T, url, authTokenPath string, timeout time.Duration) *Client {
	t.Helper()

	client, err := NewClient(url, authTokenPath, "", timeout)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	return client
}

func TestHealthCheck(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		client := newTestClient(t, srv.URL, "", 5*time.Second)

		err := client.HealthCheck(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("failure", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer srv.Close()

		client := newTestClient(t, srv.URL, "", 5*time.Second)

		err := client.HealthCheck(context.Background())
		if !errors.Is(err, ErrGUACUnavailable) {
			t.Fatalf("expected ErrGUACUnavailable, got: %v", err)
		}
	})

	t.Run("connection refused", func(t *testing.T) {
		t.Parallel()

		client := newTestClient(t, "http://127.0.0.1:1", "", 1*time.Second)

		err := client.HealthCheck(context.Background())
		if !errors.Is(err, ErrGUACUnavailable) {
			t.Fatalf("expected ErrGUACUnavailable, got: %v", err)
		}
	})
}

func TestQueryVulnerabilities(t *testing.T) {
	t.Parallel()

	t.Run("direct and transitive vulns", func(t *testing.T) {
		t.Parallel()

		digest := "sha256:abc123"

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/query/vulnerabilities" {
				t.Errorf("unexpected path: %s", r.URL.Path)
			}

			if r.URL.Query().Get("digest") != digest {
				t.Errorf("expected digest %s, got %s", digest, r.URL.Query().Get("digest"))
			}

			resp := restVulnResponse{
				Vulnerabilities: []restVulnEntry{
					{
						Package: digest,
						Vulnerability: restVulnDetails{
							Type:             testVulnTypeOSV,
							VulnerabilityIDs: []string{testCVE1234},
						},
					},
					{
						Package: "pkg:npm/lodash@4.17.20",
						Vulnerability: restVulnDetails{
							Type:             testVulnTypeOSV,
							VulnerabilityIDs: []string{testCVE5678},
						},
					},
				},
			}

			w.Header().Set("Content-Type", "application/json")

			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
		}))
		defer srv.Close()

		client := newTestClient(t, srv.URL, "", 5*time.Second)

		direct, transitive, err := client.QueryVulnerabilities(context.Background(), digest, true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(direct) != 1 {
			t.Fatalf("expected 1 direct vuln, got %d", len(direct))
		}

		if direct[0].ID != testCVE1234 {
			t.Errorf("expected %s, got %s", testCVE1234, direct[0].ID)
		}

		if len(transitive) != 1 {
			t.Fatalf("expected 1 transitive vuln, got %d", len(transitive))
		}

		if transitive[0].ID != testCVE5678 {
			t.Errorf("expected %s, got %s", testCVE5678, transitive[0].ID)
		}
	})

	t.Run("empty response", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			err := json.NewEncoder(w).Encode(restVulnResponse{})
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
		}))
		defer srv.Close()

		client := newTestClient(t, srv.URL, "", 5*time.Second)

		direct, transitive, err := client.QueryVulnerabilities(
			context.Background(), "sha256:empty", false,
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(direct) != 0 || len(transitive) != 0 {
			t.Errorf("expected empty results, got %d direct, %d transitive",
				len(direct), len(transitive))
		}
	})

	t.Run("server error", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()

		client := newTestClient(t, srv.URL, "", 5*time.Second)

		_, _, err := client.QueryVulnerabilities(
			context.Background(), "sha256:err", false,
		)
		if !errors.Is(err, ErrGUACQueryFailed) {
			t.Fatalf("expected ErrGUACQueryFailed, got: %v", err)
		}
	})
}

func TestQueryVulnerabilitiesPackageMismatch(t *testing.T) {
	t.Parallel()

	digest := "sha256:abc123"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := restVulnResponse{
			Vulnerabilities: []restVulnEntry{
				{
					Package: "pkg:oci/myimage@sha256:abc123",
					Vulnerability: restVulnDetails{
						Type:             testVulnTypeOSV,
						VulnerabilityIDs: []string{testCVE1234},
					},
				},
				{
					Package: "pkg:npm/lodash@4.17.20",
					Vulnerability: restVulnDetails{
						Type:             testVulnTypeOSV,
						VulnerabilityIDs: []string{testCVE5678},
					},
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")

		err := json.NewEncoder(w).Encode(resp)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
	}))
	defer srv.Close()

	client := newTestClient(t, srv.URL, "", 5*time.Second)

	direct, transitive, err := client.QueryVulnerabilities(context.Background(), digest, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(direct) != 0 {
		t.Errorf("expected 0 direct vulns when package field differs, got %d", len(direct))
	}

	if len(transitive) != 2 {
		t.Errorf("expected 2 transitive vulns, got %d", len(transitive))
	}
}

func TestQueryDependencies(t *testing.T) {
	t.Parallel()

	t.Run("with count limit", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			resp := restDepsResponse{
				PURLs: []string{
					"pkg:npm/a@1.0",
					"pkg:npm/b@2.0",
					"pkg:npm/c@3.0",
					"pkg:npm/d@4.0",
					"pkg:npm/e@5.0",
				},
			}

			w.Header().Set("Content-Type", "application/json")

			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
		}))
		defer srv.Close()

		client := newTestClient(t, srv.URL, "", 5*time.Second)

		info, err := client.QueryDependencies(context.Background(), "sha256:abc", 3)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(info.Dependencies) != 3 {
			t.Errorf("expected 3 deps (count limited), got %d", len(info.Dependencies))
		}

		if info.DependencyCount != 5 {
			t.Errorf(
				"expected DependencyCount=5 (total before truncation), got %d",
				info.DependencyCount,
			)
		}
	})
}

const (
	testArtifactDigest  = "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	testSourceType      = "git"
	testSourceNamespace = "github.com/example"
	testSourceRepo      = "repo"
)

func sourceOccurrence(typ, namespace, name string) graphQLIsOccurrence {
	return graphQLIsOccurrence{
		Subject: graphQLSource{
			Typename: "Source",
			Type:     typ,
			Namespaces: []graphQLSourceNamespace{{
				Namespace: namespace,
				Names:     []graphQLSourceName{{Name: name}},
			}},
		},
	}
}

func nestedScorecard(namespace, name string, aggregate float64) graphQLScorecard {
	return graphQLScorecard{
		Source: graphQLSource{
			Type: testSourceType,
			Namespaces: []graphQLSourceNamespace{{
				Namespace: namespace,
				Names:     []graphQLSourceName{{Name: name}},
			}},
		},
		Scorecard: graphQLScorecardData{
			AggregateScore: aggregate,
			Checks: []graphQLScorecardCheck{
				{Check: testCheckName, Score: 8.0},
				{Check: "Maintained", Score: 10.0},
			},
		},
	}
}

func packageOccurrence(typ, namespace, name string) graphQLIsOccurrence {
	return graphQLIsOccurrence{
		Subject: graphQLSource{
			Typename: "Package",
			Type:     typ,
			Namespaces: []graphQLSourceNamespace{{
				Namespace: namespace,
				Names:     []graphQLSourceName{{Name: name}},
			}},
		},
	}
}

// newGraphQLServer answers the artifact source query with occurrences and
// scorecard queries using the scorecards map keyed by source name. It
// records the scorecard filters it received.
func newGraphQLServer(
	t *testing.T, occurrences []graphQLIsOccurrence, scorecards map[string][]graphQLScorecard,
) *httptest.Server {
	t.Helper()

	return newGraphQLServerWithSources(t, occurrences, scorecards, nil)
}

// newGraphQLServerWithSources additionally answers HasSourceAt queries using
// the sources map keyed by package name.
func newGraphQLServerWithSources(
	t *testing.T, occurrences []graphQLIsOccurrence,
	scorecards map[string][]graphQLScorecard, sources map[string][]graphQLHasSourceAt,
) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/query" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		var req graphQLRequest

		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			t.Errorf("decode request: %v", err)
		}

		var resp graphQLResponse

		switch {
		case strings.Contains(req.Query, "IsOccurrence"):
			resp.Data.IsOccurrence = occurrences
		case strings.Contains(req.Query, "HasSourceAt"):
			filter, _ := req.Variables["filter"].(map[string]any)
			pkg, _ := filter["package"].(map[string]any)
			name, _ := pkg["name"].(string)
			resp.Data.HasSourceAt = sources[name]
		default:
			filter, _ := req.Variables["filter"].(map[string]any)
			source, _ := filter["source"].(map[string]any)
			name, _ := source["name"].(string)
			resp.Data.Scorecards = scorecards[name]

			// GraphQL only returns selected fields.
			if !strings.Contains(req.Query, "timeScanned") {
				resp.Data.Scorecards = slices.Clone(resp.Data.Scorecards)
				for idx := range resp.Data.Scorecards {
					resp.Data.Scorecards[idx].Scorecard.TimeScanned = ""
				}
			}
		}

		w.Header().Set("Content-Type", "application/json")

		err = json.NewEncoder(w).Encode(resp)
		if err != nil {
			t.Errorf("encode: %v", err)
		}
	}))
}

func TestQueryScorecard(t *testing.T) {
	t.Parallel()

	t.Run("scorecard scoped to artifact source", func(t *testing.T) {
		t.Parallel()

		srv := newGraphQLServer(
			t,
			[]graphQLIsOccurrence{
				sourceOccurrence(testSourceType, testSourceNamespace, testSourceRepo),
			},
			map[string][]graphQLScorecard{
				testSourceRepo: {nestedScorecard(testSourceNamespace, testSourceRepo, 7.5)},
			},
		)
		defer srv.Close()

		client := newTestClient(t, srv.URL, "", 5*time.Second)

		result, err := client.QueryScorecard(context.Background(), testArtifactDigest)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Aggregate != 7.5 {
			t.Errorf("expected aggregate 7.5, got %f", result.Aggregate)
		}

		if result.Checks[testCheckName] != 8.0 {
			t.Errorf("expected %s 8.0, got %f", testCheckName, result.Checks[testCheckName])
		}

		if result.Source != "git/github.com/example/repo" {
			t.Errorf("unexpected source: %s", result.Source)
		}
	})

	t.Run("scorecards of other repositories are ignored", func(t *testing.T) {
		t.Parallel()

		srv := newGraphQLServer(
			t,
			[]graphQLIsOccurrence{
				sourceOccurrence(testSourceType, testSourceNamespace, testSourceRepo),
			},
			map[string][]graphQLScorecard{
				testSourceRepo: {nestedScorecard("github.com/other", "popular", 10)},
			},
		)
		defer srv.Close()

		client := newTestClient(t, srv.URL, "", 5*time.Second)

		result, err := client.QueryScorecard(context.Background(), testArtifactDigest)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Aggregate != 0 || len(result.Checks) != 0 {
			t.Errorf("expected empty scorecard for unrelated source, got %+v", result)
		}
	})

	t.Run("lowest score across linked sources wins", func(t *testing.T) {
		t.Parallel()

		srv := newGraphQLServer(t,
			[]graphQLIsOccurrence{
				sourceOccurrence(testSourceType, testSourceNamespace, "good"),
				sourceOccurrence(testSourceType, testSourceNamespace, "weak"),
			},
			map[string][]graphQLScorecard{
				"good": {nestedScorecard(testSourceNamespace, "good", 9)},
				"weak": {nestedScorecard(testSourceNamespace, "weak", 3)},
			},
		)
		defer srv.Close()

		client := newTestClient(t, srv.URL, "", 5*time.Second)

		result, err := client.QueryScorecard(context.Background(), testArtifactDigest)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Aggregate != 3 || result.Source != "git/github.com/example/weak" {
			t.Errorf("expected weakest scorecard, got %+v", result)
		}
	})

	t.Run("artifact without source returns empty scorecard", func(t *testing.T) {
		t.Parallel()

		srv := newGraphQLServer(t, nil, nil)
		defer srv.Close()

		client := newTestClient(t, srv.URL, "", 5*time.Second)

		result, err := client.QueryScorecard(context.Background(), testArtifactDigest)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Aggregate != 0 || result.Source != "" {
			t.Errorf("expected empty scorecard, got %+v", result)
		}
	})

	t.Run("package occurrences are not sources", func(t *testing.T) {
		t.Parallel()

		occurrence := sourceOccurrence("npm", "", "pkg")
		occurrence.Subject.Typename = "Package"

		srv := newGraphQLServer(t, []graphQLIsOccurrence{occurrence}, nil)
		defer srv.Close()

		client := newTestClient(t, srv.URL, "", 5*time.Second)

		result, err := client.QueryScorecard(context.Background(), testArtifactDigest)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Source != "" {
			t.Errorf("expected no source for package occurrence, got %+v", result)
		}
	})

	t.Run("invalid digest", func(t *testing.T) {
		t.Parallel()

		client := newTestClient(t, "http://127.0.0.1:1", "", time.Second)

		_, err := client.QueryScorecard(context.Background(), "not-a-digest")
		if !errors.Is(err, ErrGUACQueryFailed) {
			t.Fatalf("expected ErrGUACQueryFailed, got %v", err)
		}
	})
}

func TestQueryScorecardHistory(t *testing.T) {
	t.Parallel()

	const (
		older = "2026-01-01T00:00:00Z"
		newer = "2026-06-01T00:00:00.5Z"
	)

	scan := func(aggregate float64, scanned string) graphQLScorecard {
		scorecard := nestedScorecard(testSourceNamespace, testSourceRepo, aggregate)
		scorecard.Scorecard.TimeScanned = scanned

		return scorecard
	}

	tests := []struct {
		name  string
		scans []graphQLScorecard
		want  float64
	}{
		{
			name:  "most recent scan wins over older higher score",
			scans: []graphQLScorecard{scan(8, older), scan(4, newer)},
			want:  4,
		},
		{
			name:  "most recent scan wins over older lower score",
			scans: []graphQLScorecard{scan(4, older), scan(8, newer), scan(2, older)},
			want:  8,
		},
		{
			name:  "same scan time uses lowest score",
			scans: []graphQLScorecard{scan(8, newer), scan(4, older), scan(6, newer)},
			want:  6,
		},
		{
			name:  "missing scan time uses lowest score",
			scans: []graphQLScorecard{scan(8, newer), scan(4, older), scan(6, "")},
			want:  4,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := newGraphQLServer(t,
				[]graphQLIsOccurrence{
					sourceOccurrence(testSourceType, testSourceNamespace, testSourceRepo),
				},
				map[string][]graphQLScorecard{testSourceRepo: tc.scans},
			)
			defer srv.Close()

			client := newTestClient(t, srv.URL, "", 5*time.Second)

			result, err := client.QueryScorecard(context.Background(), testArtifactDigest)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Aggregate != tc.want {
				t.Errorf("expected aggregate %f, got %f", tc.want, result.Aggregate)
			}
		})
	}
}

func TestQueryScorecardSourceResolution(t *testing.T) {
	t.Parallel()

	t.Run("sources linked through packages are resolved", func(t *testing.T) {
		t.Parallel()

		srv := newGraphQLServerWithSources(t,
			[]graphQLIsOccurrence{packageOccurrence("npm", "", "app")},
			map[string][]graphQLScorecard{
				testSourceRepo: {nestedScorecard(testSourceNamespace, testSourceRepo, 6.5)},
			},
			map[string][]graphQLHasSourceAt{
				"app": {{Source: graphQLSource{
					Type: testSourceType,
					Namespaces: []graphQLSourceNamespace{{
						Namespace: testSourceNamespace,
						Names:     []graphQLSourceName{{Name: testSourceRepo}},
					}},
				}}},
			},
		)
		defer srv.Close()

		client := newTestClient(t, srv.URL, "", 5*time.Second)

		result, err := client.QueryScorecard(context.Background(), testArtifactDigest)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Aggregate != 6.5 || result.Source != "git/github.com/example/repo" {
			t.Errorf("expected scorecard of the package source, got %+v", result)
		}
	})

	t.Run("lowest score is kept for many sources", func(t *testing.T) {
		t.Parallel()

		names := []string{"a", "b", "c", "d", "e", "f"}
		occurrences := make([]graphQLIsOccurrence, 0, len(names))
		scorecards := make(map[string][]graphQLScorecard, len(names))

		for _, name := range names {
			occurrences = append(occurrences,
				sourceOccurrence(testSourceType, testSourceNamespace, name))
			scorecards[name] = []graphQLScorecard{nestedScorecard(testSourceNamespace, name, 9)}
		}

		// The alphabetically last source has the lowest score.
		scorecards["f"] = []graphQLScorecard{nestedScorecard(testSourceNamespace, "f", 2)}

		srv := newGraphQLServer(t, occurrences, scorecards)
		defer srv.Close()

		client := newTestClient(t, srv.URL, "", 5*time.Second)

		result, err := client.QueryScorecard(context.Background(), testArtifactDigest)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Aggregate != 2 {
			t.Errorf("expected lowest aggregate 2, got %+v", result)
		}
	})

	t.Run("too many sources fail closed", func(t *testing.T) {
		t.Parallel()

		occurrences := make([]graphQLIsOccurrence, 0, maxScorecardSources+1)
		scorecards := make(map[string][]graphQLScorecard, maxScorecardSources+1)

		for idx := range maxScorecardSources + 1 {
			name := fmt.Sprintf("repo-%03d", idx)
			occurrences = append(occurrences,
				sourceOccurrence(testSourceType, testSourceNamespace, name))
			scorecards[name] = []graphQLScorecard{nestedScorecard(testSourceNamespace, name, 9)}
		}

		srv := newGraphQLServer(t, occurrences, scorecards)
		defer srv.Close()

		client := newTestClient(t, srv.URL, "", 5*time.Second)

		result, err := client.QueryScorecard(context.Background(), testArtifactDigest)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Aggregate != 0 {
			t.Errorf("expected zero aggregate when not every source can be checked, got %+v",
				result)
		}
	})
}

func TestAuthToken(t *testing.T) {
	t.Parallel()

	tokenDir := t.TempDir()
	tokenPath := filepath.Join(tokenDir, "token")

	err := os.WriteFile(tokenPath, []byte("test-token-123\n"), 0o600)
	if err != nil {
		t.Fatalf("write token: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-token-123" {
			t.Errorf("expected Bearer test-token-123, got %s", auth)

			w.WriteHeader(http.StatusUnauthorized)

			return
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := newTestClient(t, srv.URL, tokenPath, 5*time.Second)

	healthErr := client.HealthCheck(context.Background())
	if healthErr != nil {
		t.Fatalf("unexpected error: %v", healthErr)
	}
}

func TestAuthTokenMissing(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := newTestClient(t, srv.URL, "/nonexistent/token", 5*time.Second)

	err := client.HealthCheck(context.Background())
	if !errors.Is(err, ErrGUACAuthError) {
		t.Fatalf("expected ErrGUACAuthError, got: %v", err)
	}

	if errors.Is(err, ErrGUACUnavailable) {
		t.Fatalf("auth errors must not be wrapped as ErrGUACUnavailable")
	}
}

func TestQueryScorecardGraphQLError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := graphQLResponse{
			Errors: []graphQLError{
				{Message: "schema validation failed"},
			},
		}

		w.Header().Set("Content-Type", "application/json")

		err := json.NewEncoder(w).Encode(resp)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
	}))
	defer srv.Close()

	client := newTestClient(t, srv.URL, "", 5*time.Second)

	_, err := client.QueryScorecard(context.Background(), testArtifactDigest)
	if !errors.Is(err, ErrGUACQueryFailed) {
		t.Fatalf("expected ErrGUACQueryFailed, got: %v", err)
	}
}

func TestCACert(t *testing.T) {
	t.Parallel()

	t.Run("valid CA cert", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: srv.TLS.Certificates[0].Certificate[0],
		})

		certPath := filepath.Join(t.TempDir(), "ca.pem")

		err := os.WriteFile(certPath, certPEM, 0o600)
		if err != nil {
			t.Fatalf("write cert: %v", err)
		}

		client, clientErr := NewClient(srv.URL, "", certPath, 5*time.Second)
		if clientErr != nil {
			t.Fatalf("NewClient: %v", clientErr)
		}

		healthErr := client.HealthCheck(context.Background())
		if healthErr != nil {
			t.Fatalf("unexpected error: %v", healthErr)
		}
	})

	t.Run("missing CA cert file", func(t *testing.T) {
		t.Parallel()

		_, err := NewClient("http://localhost", "", "/nonexistent/ca.pem", 5*time.Second)
		if !errors.Is(err, ErrGUACCACert) {
			t.Fatalf("expected ErrGUACCACert, got: %v", err)
		}
	})

	t.Run("invalid CA cert content", func(t *testing.T) {
		t.Parallel()

		certPath := filepath.Join(t.TempDir(), "bad.pem")

		err := os.WriteFile(certPath, []byte("not a cert"), 0o600)
		if err != nil {
			t.Fatalf("write: %v", err)
		}

		_, clientErr := NewClient("http://localhost", "", certPath, 5*time.Second)
		if !errors.Is(clientErr, ErrGUACCACert) {
			t.Fatalf("expected ErrGUACCACert, got: %v", clientErr)
		}
	})
}

func TestQueryScorecardResponseTooLarge(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		buf := make([]byte, maxResponseSize+1)
		for i := range buf {
			buf[i] = 'x'
		}

		_, _ = w.Write(buf)
	}))
	defer srv.Close()

	client := newTestClient(t, srv.URL, "", 5*time.Second)

	_, err := client.QueryScorecard(context.Background(), testArtifactDigest)
	if !errors.Is(err, ErrGUACQueryFailed) {
		t.Fatalf("expected ErrGUACQueryFailed for oversized response, got: %v", err)
	}
}

func TestDoGetResponseTooLarge(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)

		buf := make([]byte, maxResponseSize+1)
		for i := range buf {
			buf[i] = 'x'
		}

		_, _ = w.Write(buf)
	}))
	defer srv.Close()

	client := newTestClient(t, srv.URL, "", 5*time.Second)

	_, _, err := client.QueryVulnerabilities(
		context.Background(), "sha256:abc", false,
	)
	if !errors.Is(err, ErrGUACQueryFailed) {
		t.Fatalf("expected ErrGUACQueryFailed for oversized response, got: %v", err)
	}
}

func TestContextCancellation(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	client := newTestClient(t, srv.URL, "", 10*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := client.HealthCheck(ctx)
	if !errors.Is(err, ErrGUACUnavailable) {
		t.Fatalf("expected ErrGUACUnavailable on context cancellation, got: %v", err)
	}
}

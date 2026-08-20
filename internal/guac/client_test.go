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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

func TestQueryScorecard(t *testing.T) {
	t.Parallel()

	t.Run("scorecard result", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/query" {
				t.Errorf("unexpected path: %s", r.URL.Path)
			}

			resp := graphQLResponse{
				Data: graphQLData{
					Scorecards: []graphQLScorecard{
						{
							Source: graphQLSource{
								Type:      "git",
								Namespace: "github.com/example",
								Name:      "repo",
							},
							Scorecard: graphQLScorecardData{
								AggregateScore: 7.5,
								Checks: []graphQLScorecardCheck{
									{Check: testCheckName, Score: 8.0},
									{Check: "Maintained", Score: 10.0},
								},
							},
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

		result, err := client.QueryScorecard(context.Background())
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

	t.Run("empty scorecard", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			resp := graphQLResponse{Data: graphQLData{}}

			w.Header().Set("Content-Type", "application/json")

			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
		}))
		defer srv.Close()

		client := newTestClient(t, srv.URL, "", 5*time.Second)

		result, err := client.QueryScorecard(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Aggregate != 0 {
			t.Errorf("expected aggregate 0, got %f", result.Aggregate)
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

	_, err := client.QueryScorecard(context.Background())
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

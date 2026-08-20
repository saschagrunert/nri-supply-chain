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

package guac //nolint:testpackage // testing unexported functions

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	testGUACCVE1234   = "CVE-2024-1234"
	testGUACCVE5678   = "CVE-2024-5678"
	testGUACCheckName = "Code-Review"
	testGUACVulnType  = "osv"
)

func TestQuery(t *testing.T) {
	t.Parallel()

	t.Run("all checks pass", func(t *testing.T) {
		t.Parallel()

		srv := newTestServer(t)
		defer srv.Close()

		client := newTestClient(t, srv.URL, "", 5*time.Second)

		result := Query(
			context.Background(), client, "sha256:test",
			[]string{CheckCertifyVuln, CheckCertifyScorecard, CheckIsDependency},
			5,
		)

		if result.Type != types.CheckTypeGUAC {
			t.Errorf("expected check type %s, got %s", types.CheckTypeGUAC, result.Type)
		}

		if !result.Passed {
			t.Errorf("expected result to pass")
		}

		if result.Metadata == nil {
			t.Fatal("expected metadata to be set")
		}

		available, ok := result.Metadata["available"].(bool)
		if !ok || !available {
			t.Errorf("expected available=true")
		}
	})

	t.Run("subset of checks", func(t *testing.T) {
		t.Parallel()

		srv := newTestServer(t)
		defer srv.Close()

		client := newTestClient(t, srv.URL, "", 5*time.Second)

		result := Query(
			context.Background(), client, "sha256:test",
			[]string{CheckCertifyVuln},
			5,
		)

		if !result.Passed {
			t.Errorf("expected result to pass")
		}

		depCount, ok := result.Metadata["dependency_count"].(int64)
		if !ok || depCount != 0 {
			t.Errorf("expected dependency_count=0 when is_dependency not checked, got %v", depCount)
		}
	})

	t.Run("unavailable server produces soft fail", func(t *testing.T) {
		t.Parallel()

		client := newTestClient(t, "http://127.0.0.1:1", "", 1*time.Second)

		result := Query(
			context.Background(), client, "sha256:test",
			[]string{CheckCertifyVuln},
			5,
		)

		if result.Passed {
			t.Errorf("expected result not to pass on unavailable server")
		}

		if result.Status != types.StatusWarn {
			t.Errorf("expected soft fail (warn status), got %s", result.Status)
		}

		available, ok := result.Metadata["available"].(bool)
		if !ok || available {
			t.Errorf("expected available=false")
		}
	})
}

func TestBuildCheckResult(t *testing.T) {
	t.Parallel()

	t.Run("with vulnerabilities", func(t *testing.T) {
		t.Parallel()

		qr := &QueryResult{
			Available: true,
			Vulnerabilities: []Vulnerability{
				{ID: testGUACCVE1234},
			},
			TransitiveVulns: []Vulnerability{
				{ID: testGUACCVE5678, Package: "pkg:npm/foo@1.0"},
			},
			Scorecard: &ScorecardResult{
				Aggregate: 7.5,
				Checks:    map[string]float64{testGUACCheckName: 8.0},
			},
			DependencyInfo: &DependencyInfo{
				Dependencies:    []string{"pkg:npm/foo@1.0"},
				DependencyCount: 1,
			},
		}

		result := buildCheckResult(qr)

		if result.Type != types.CheckTypeGUAC {
			t.Errorf("expected type %s, got %s", types.CheckTypeGUAC, result.Type)
		}

		if !result.Passed {
			t.Errorf("expected pass")
		}

		vulns, ok := result.Metadata["vulnerabilities"].([]any)
		if !ok || len(vulns) != 1 {
			t.Errorf("expected 1 vulnerability, got %v", vulns)
		}

		transitiveVulns, ok := result.Metadata["transitive_vulns"].([]any)
		if !ok || len(transitiveVulns) != 1 {
			t.Errorf("expected 1 transitive vulnerability, got %v", transitiveVulns)
		}

		scorecard, ok := result.Metadata["scorecard"].(map[string]any)
		if !ok {
			t.Fatal("expected scorecard map")
		}

		aggregate, ok := scorecard["aggregate"].(float64)
		if !ok || aggregate != 7.5 {
			t.Errorf("expected aggregate 7.5, got %v", aggregate)
		}

		deps, ok := result.Metadata["dependencies"].([]any)
		if !ok || len(deps) != 1 {
			t.Errorf("expected 1 dependency PURL, got %v", deps)
		}

		depCount, ok := result.Metadata["dependency_count"].(int64)
		if !ok || depCount != 1 {
			t.Errorf("expected dependency_count 1, got %v", depCount)
		}
	})

	t.Run("unavailable produces soft fail", func(t *testing.T) {
		t.Parallel()

		qr := &QueryResult{Available: false}

		result := buildCheckResult(qr)

		if result.Passed {
			t.Errorf("expected not passed")
		}

		if result.Status != types.StatusWarn {
			t.Errorf("expected warn status for soft fail, got %s", result.Status)
		}
	})
}

func TestQueryAuthErrorPreserved(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := newTestClient(t, srv.URL, "/nonexistent/token", 5*time.Second)

	result := Query(
		context.Background(), client, "sha256:test",
		[]string{CheckCertifyVuln},
		5,
	)

	if result.Passed {
		t.Fatal("expected failure when auth token is missing")
	}

	if result.Err == nil {
		t.Fatal("expected error to be set")
	}

	if !errors.Is(result.Err, ErrGUACAuthError) {
		t.Errorf("expected ErrGUACAuthError in error chain, got: %v", result.Err)
	}

	if errors.Is(result.Err, ErrGUACUnavailable) {
		t.Errorf("auth errors must not be wrapped as ErrGUACUnavailable")
	}
}

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/query/vulnerabilities":
			resp := restVulnResponse{
				Vulnerabilities: []restVulnEntry{
					{
						Package: r.URL.Query().Get("digest"),
						Vulnerability: restVulnDetails{
							Type:             testGUACVulnType,
							VulnerabilityIDs: []string{"CVE-2024-0001"},
						},
					},
				},
			}

			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}

		case "/query/dependencies":
			resp := restDepsResponse{
				PURLs: []string{"pkg:npm/dep@1.0"},
			}

			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}

		case "/query":
			resp := graphQLResponse{
				Data: graphQLData{
					Scorecards: []graphQLScorecard{
						{
							Source: graphQLSource{
								Type:      "git",
								Namespace: "github.com/test",
								Name:      "repo",
							},
							Scorecard: graphQLScorecardData{
								AggregateScore: 8.0,
								Checks: []graphQLScorecardCheck{
									{Check: testGUACCheckName, Score: 9.0},
								},
							},
						},
					},
				},
			}

			err := json.NewEncoder(w).Encode(resp)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

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

package guac //nolint:testpackage // testing unexported query limits

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func assertTruncatedScorecard(t *testing.T, result *ScorecardResult) {
	t.Helper()

	if !result.Truncated || result.Source != TruncatedScorecardSource || result.Aggregate != 0 {
		t.Errorf("expected a truncated scorecard with the sentinel source, got %+v", result)
	}
}

func TestQueryScorecardTruncation(t *testing.T) {
	t.Parallel()

	t.Run("too many packages", func(t *testing.T) {
		t.Parallel()

		occurrences := make([]graphQLIsOccurrence, 0, maxScorecardPackages+1)
		for idx := range maxScorecardPackages + 1 {
			occurrences = append(
				occurrences,
				packageOccurrence("npm", "", fmt.Sprintf("pkg-%03d", idx)),
			)
		}

		srv := newGraphQLServerWithSources(t, occurrences, nil, nil)
		defer srv.Close()

		result, err := newTestClient(t, srv.URL, "", 5*time.Second).
			QueryScorecard(context.Background(), testArtifactDigest)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		assertTruncatedScorecard(t, result)
	})

	t.Run("too many sources", func(t *testing.T) {
		t.Parallel()

		occurrences := make([]graphQLIsOccurrence, 0, maxScorecardSources+1)
		for idx := range maxScorecardSources + 1 {
			occurrences = append(
				occurrences,
				sourceOccurrence(
					testSourceType,
					testSourceNamespace,
					fmt.Sprintf("repo-%03d", idx),
				),
			)
		}

		srv := newGraphQLServer(t, occurrences, nil)
		defer srv.Close()

		result, err := newTestClient(t, srv.URL, "", 5*time.Second).
			QueryScorecard(context.Background(), testArtifactDigest)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		assertTruncatedScorecard(t, result)
	})
}

func TestQueryScorecardQueriesSourcesConcurrently(t *testing.T) {
	t.Parallel()

	const sources = 8

	occurrences := make([]graphQLIsOccurrence, 0, sources)
	for idx := range sources {
		occurrences = append(occurrences,
			sourceOccurrence(testSourceType, testSourceNamespace, fmt.Sprintf("repo-%d", idx)))
	}

	var inFlight, maxInFlight atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req graphQLRequest

		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			t.Errorf("decode request: %v", err)
		}

		var resp graphQLResponse

		if strings.Contains(req.Query, "IsOccurrence") {
			resp.Data.IsOccurrence = occurrences
		} else {
			current := inFlight.Add(1)

			for {
				seen := maxInFlight.Load()
				if current <= seen || maxInFlight.CompareAndSwap(seen, current) {
					break
				}
			}

			time.Sleep(50 * time.Millisecond)
			inFlight.Add(-1)

			filter, _ := req.Variables["filter"].(map[string]any)
			source, _ := filter["source"].(map[string]any)
			name, _ := source["name"].(string)
			resp.Data.Scorecards = []graphQLScorecard{nestedScorecard(testSourceNamespace, name, 8)}
		}

		w.Header().Set("Content-Type", "application/json")

		err = json.NewEncoder(w).Encode(resp)
		if err != nil {
			t.Errorf("encode: %v", err)
		}
	}))
	defer srv.Close()

	result, err := newTestClient(t, srv.URL, "", 5*time.Second).
		QueryScorecard(context.Background(), testArtifactDigest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Aggregate != 8 {
		t.Errorf("expected aggregate 8, got %+v", result)
	}

	if maxInFlight.Load() < 2 {
		t.Errorf(
			"expected scorecard queries to run concurrently, max in flight %d",
			maxInFlight.Load(),
		)
	}
}

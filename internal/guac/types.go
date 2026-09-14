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

package guac

// Vulnerability represents a single vulnerability result from GUAC.
type Vulnerability struct {
	ID      string `json:"id"`
	Package string `json:"package,omitempty"`
}

// TruncatedScorecardSource is the scorecard source reported when more source
// repositories or packages are linked to an artifact than can be queried.
// It is never empty, so rules treating an empty source as "no linked
// repository" cannot mistake a truncated result for one.
const TruncatedScorecardSource = "guac:truncated"

// ScorecardResult holds OpenSSF Scorecard data from GUAC.
type ScorecardResult struct {
	Aggregate float64            `json:"aggregate"`
	Checks    map[string]float64 `json:"checks,omitempty"`
	Source    string             `json:"source,omitempty"`
	// Truncated is true when not every linked source could be queried. The
	// aggregate is then 0 and Source is TruncatedScorecardSource.
	Truncated bool `json:"truncated,omitempty"`
}

// DependencyInfo holds dependency graph data from GUAC.
type DependencyInfo struct {
	Dependencies    []string `json:"dependencies,omitempty"`
	DependencyCount int      `json:"dependencyCount"`
}

// QueryResult aggregates all GUAC query results for an image. Available is
// true only when every requested query succeeded; the per-query flags record
// which data is present.
type QueryResult struct {
	Available                bool             `json:"available"`
	Vulnerabilities          []Vulnerability  `json:"vulnerabilities,omitempty"`
	TransitiveVulns          []Vulnerability  `json:"transitiveVulns,omitempty"`
	VulnerabilitiesAvailable bool             `json:"vulnerabilitiesAvailable"`
	Scorecard                *ScorecardResult `json:"scorecard,omitempty"`
	ScorecardAvailable       bool             `json:"scorecardAvailable"`
	DependencyInfo           *DependencyInfo  `json:"dependencyInfo,omitempty"`
	DependenciesAvailable    bool             `json:"dependenciesAvailable"`
	Err                      error            `json:"-"`
}

// REST API response types matching GUAC's API.

type restVulnResponse struct {
	Vulnerabilities []restVulnEntry `json:"vulnerabilities,omitempty"`
}

type restVulnEntry struct {
	Metadata      restScanMetadata `json:"metadata"`
	Package       string           `json:"package"`
	Vulnerability restVulnDetails  `json:"vulnerability"`
}

type restScanMetadata struct {
	ScannerURI     string `json:"scannerUri,omitempty"` //nolint:tagliatelle // matches GUAC API
	ScannerVersion string `json:"scannerVersion,omitempty"`
	Origin         string `json:"origin,omitempty"`
}

type restVulnDetails struct {
	Type             string   `json:"type,omitempty"`
	VulnerabilityIDs []string `json:"vulnerabilityIDs,omitempty"`
}

type restDepsResponse struct {
	PURLs []string `json:"purls,omitempty"`
}

// GraphQL types for source resolution and Scorecard queries.

type graphQLRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables,omitempty"`
}

type graphQLResponse struct {
	Data   graphQLData    `json:"data"`
	Errors []graphQLError `json:"errors,omitempty"`
}

type graphQLData struct {
	Scorecards   []graphQLScorecard    `json:"scorecards,omitempty"`
	IsOccurrence []graphQLIsOccurrence `json:"IsOccurrence,omitempty"` //nolint:tagliatelle // GUAC schema
	HasSourceAt  []graphQLHasSourceAt  `json:"HasSourceAt,omitempty"`  //nolint:tagliatelle // GUAC schema
}

type graphQLIsOccurrence struct {
	Subject graphQLSource `json:"subject"`
}

// graphQLHasSourceAt links a package to its source repository.
type graphQLHasSourceAt struct {
	Source graphQLSource `json:"source"`
}

type graphQLScorecard struct {
	Source    graphQLSource        `json:"source"`
	Scorecard graphQLScorecardData `json:"scorecard"`
}

// graphQLSource accepts both GUAC's nested source trie
// (type/namespaces/names) and a flat type/namespace/name form.
type graphQLSource struct {
	Typename   string                   `json:"__typename,omitempty"` //nolint:tagliatelle // GraphQL meta field
	Type       string                   `json:"type"`
	Namespace  string                   `json:"namespace,omitempty"`
	Name       string                   `json:"name,omitempty"`
	Namespaces []graphQLSourceNamespace `json:"namespaces,omitempty"`
}

type graphQLSourceNamespace struct {
	Namespace string              `json:"namespace"`
	Names     []graphQLSourceName `json:"names"`
}

type graphQLSourceName struct {
	Name string `json:"name"`
}

type graphQLScorecardData struct {
	AggregateScore float64                 `json:"aggregateScore"`
	Checks         []graphQLScorecardCheck `json:"checks"`
	TimeScanned    string                  `json:"timeScanned,omitempty"`
}

type graphQLScorecardCheck struct {
	Check string  `json:"check"`
	Score float64 `json:"score"`
}

type graphQLError struct {
	Message string `json:"message"`
}

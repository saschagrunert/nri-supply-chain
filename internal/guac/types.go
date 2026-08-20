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

// ScorecardResult holds OpenSSF Scorecard data from GUAC.
type ScorecardResult struct {
	Aggregate float64            `json:"aggregate"`
	Checks    map[string]float64 `json:"checks,omitempty"`
	Source    string             `json:"source,omitempty"`
}

// DependencyInfo holds dependency graph data from GUAC.
type DependencyInfo struct {
	Dependencies    []string `json:"dependencies,omitempty"`
	DependencyCount int      `json:"dependencyCount"`
}

// QueryResult aggregates all GUAC query results for an image.
type QueryResult struct {
	Available       bool             `json:"available"`
	Vulnerabilities []Vulnerability  `json:"vulnerabilities,omitempty"`
	TransitiveVulns []Vulnerability  `json:"transitiveVulns,omitempty"`
	Scorecard       *ScorecardResult `json:"scorecard,omitempty"`
	DependencyInfo  *DependencyInfo  `json:"dependencyInfo,omitempty"`
	Err             error            `json:"-"`
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

// GraphQL types for Scorecard queries.

type graphQLRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables,omitempty"`
}

type graphQLResponse struct {
	Data   graphQLData    `json:"data"`
	Errors []graphQLError `json:"errors,omitempty"`
}

type graphQLData struct {
	Scorecards []graphQLScorecard `json:"scorecards,omitempty"`
}

type graphQLScorecard struct {
	Source    graphQLSource        `json:"source"`
	Scorecard graphQLScorecardData `json:"scorecard"`
}

type graphQLSource struct {
	Type      string `json:"type"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

type graphQLScorecardData struct {
	AggregateScore float64                 `json:"aggregateScore"`
	Checks         []graphQLScorecardCheck `json:"checks"`
}

type graphQLScorecardCheck struct {
	Check string  `json:"check"`
	Score float64 `json:"score"`
}

type graphQLError struct {
	Message string `json:"message"`
}

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

// ExportParseVulnResponse exposes parseVulnResponse for fuzz testing.
func ExportParseVulnResponse(
	body []byte, digest string,
) (direct, transitive []Vulnerability, err error) {
	return parseVulnResponse(body, digest)
}

// ExportParseDepsResponse exposes parseDepsResponse for fuzz testing.
func ExportParseDepsResponse(body []byte, maxDeps int) (*DependencyInfo, error) {
	return parseDepsResponse(body, maxDeps)
}

// ExportParseScorecardResponse exposes parseScorecardResponse for fuzz testing.
func ExportParseScorecardResponse(body []byte) (*ScorecardResult, error) {
	return parseScorecardResponse(body)
}

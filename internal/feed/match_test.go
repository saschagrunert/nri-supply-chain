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

package feed_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/feed"
	"github.com/saschagrunert/nri-supply-chain/internal/purl"
)

const (
	lodashFeed  = `{"id":"A","affected":[{"package":{"purl":"pkg:npm/lodash"}}]}`
	testNPMX150 = "pkg:npm/x@1.5.0"
)

func parseFeed(t *testing.T, data string) []string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "feed.json")

	err := os.WriteFile(path, []byte(data), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	specs, err := feed.ParseFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	return specs
}

func TestFeedMatching(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		feed      string
		sbomPURLs []string
		wantMatch bool
	}{
		{
			name:      "versionless OSV purl matches versioned SBOM purl",
			feed:      lodashFeed,
			sbomPURLs: []string{"pkg:npm/lodash@4.17.20?arch=x"},
			wantMatch: true,
		},
		{
			name:      "different package does not match",
			feed:      lodashFeed,
			sbomPURLs: []string{"pkg:npm/lodash-es@4.17.20"},
			wantMatch: false,
		},
		{
			name: "unevaluable ecosystem range is unioned with enumerated versions",
			feed: `{"id":"A","affected":[{"package":{"purl":"pkg:deb/debian/openssl"},` +
				`"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.11-1"}]}],` +
				`"versions":["3.0.9-1"]}]}`,
			sbomPURLs: []string{"pkg:deb/debian/openssl@3.0.10-1"},
			wantMatch: true,
		},
		{
			name: "semver ecosystem range is evaluated and unioned with versions",
			feed: `{"id":"A","affected":[{"package":{"purl":"pkg:npm/x"},` +
				`"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}],` +
				`"versions":["3.0.0"]}]}`,
			sbomPURLs: []string{testNPMX150},
			wantMatch: true,
		},
		{
			name: "semver ecosystem range fixed version does not match",
			feed: `{"id":"A","affected":[{"package":{"purl":"pkg:npm/x"},` +
				`"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]}`,
			sbomPURLs: []string{"pkg:npm/x@2.0.0"},
			wantMatch: false,
		},
		{
			name: "enumerated version matches with normalized version",
			feed: `{"id":"A","affected":[{"package":{"purl":"pkg:npm/x"},` +
				`"versions":["1.0"]}]}`,
			sbomPURLs: []string{"pkg:npm/x@1.0.0"},
			wantMatch: true,
		},
		{
			name: "consecutive introduced events keep the lower bound",
			feed: `{"id":"A","affected":[{"package":{"purl":"pkg:npm/x"},` +
				`"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},` +
				`{"introduced":"2.0.0"},{"fixed":"2.5.0"}]}]}]}`,
			sbomPURLs: []string{testNPMX150},
			wantMatch: true,
		},
		{
			name: "versioned OSV purl keeps its ranges",
			feed: `{"id":"A","affected":[{"package":{"purl":"pkg:npm/x@1.0.0"},` +
				`"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]}`,
			sbomPURLs: []string{testNPMX150},
			wantMatch: true,
		},
		{
			name:      "pypi names are PEP 503 normalized",
			feed:      `{"id":"A","affected":[{"package":{"purl":"pkg:pypi/typing_extensions"}}]}`,
			sbomPURLs: []string{"pkg:pypi/typing-extensions@4.0.0"},
			wantMatch: true,
		},
		{
			name:      "pypi ecosystem names are PEP 503 normalized",
			feed:      `{"id":"A","affected":[{"package":{"ecosystem":"PyPI","name":"Typing.Extensions"}}]}`,
			sbomPURLs: []string{"pkg:pypi/typing_extensions@4.0.0"},
			wantMatch: true,
		},
		{
			name: "enumerated version matches",
			feed: `{"id":"A","affected":[{"package":{"purl":"pkg:pypi/requests"},` +
				`"versions":["2.30.0"]}]}`,
			sbomPURLs: []string{"pkg:pypi/requests@2.30.0"},
			wantMatch: true,
		},
		{
			name: "semver range affected version",
			feed: `{"id":"A","affected":[{"package":{"purl":"pkg:golang/github.com/foo/bar"},` +
				`"ranges":[{"type":"SEMVER","events":[{"introduced":"1.2.0"},{"fixed":"1.4.1"}]}]}]}`,
			sbomPURLs: []string{"pkg:golang/github.com/foo/bar@v1.3.9"},
			wantMatch: true,
		},
		{
			name: "semver range fixed version",
			feed: `{"id":"A","affected":[{"package":{"purl":"pkg:golang/github.com/foo/bar"},` +
				`"ranges":[{"type":"SEMVER","events":[{"introduced":"1.2.0"},{"fixed":"1.4.1"}]}]}]}`,
			sbomPURLs: []string{"pkg:golang/github.com/foo/bar@v1.4.1"},
			wantMatch: false,
		},
		{
			name: "semver range with multiple intervals",
			feed: `{"id":"A","affected":[{"package":{"purl":"pkg:npm/x"},` +
				`"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.1"},` +
				`{"introduced":"2.0.0"},{"last_affected":"2.0.5"}]}]}]}`,
			sbomPURLs: []string{"pkg:npm/x@2.0.5"},
			wantMatch: true,
		},
		{
			name: "prerelease sorts before release",
			feed: `{"id":"A","affected":[{"package":{"purl":"pkg:npm/x"},` +
				`"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]}`,
			sbomPURLs: []string{"pkg:npm/x@2.0.0-rc.1"},
			wantMatch: true,
		},
		{
			name: "ecosystem range without versions matches every version",
			feed: `{"id":"A","affected":[{"package":{"purl":"pkg:deb/debian/openssl"},` +
				`"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.11-1"}]}]}]}`,
			sbomPURLs: []string{"pkg:deb/debian/openssl@3.0.11-1?distro=debian-12"},
			wantMatch: true,
		},
		{
			name:      "purl derived from ecosystem and name",
			feed:      `{"id":"A","affected":[{"package":{"ecosystem":"Go","name":"github.com/foo/bar"}}]}`,
			sbomPURLs: []string{"pkg:golang/github.com/foo/bar@v1.0.0"},
			wantMatch: true,
		},
		{
			name:      "maven purl derived from ecosystem and name",
			feed:      `{"id":"A","affected":[{"package":{"ecosystem":"Maven","name":"org.apache:commons"}}]}`,
			sbomPURLs: []string{"pkg:maven/org.apache/commons@1.0"},
			wantMatch: true,
		},
		{
			name:      "distro purl derived from ecosystem with release",
			feed:      `{"id":"A","affected":[{"package":{"ecosystem":"Alpine:v3.18","name":"busybox"}}]}`,
			sbomPURLs: []string{"pkg:apk/alpine/busybox@1.36.1-r2"},
			wantMatch: true,
		},
		{
			name:      "withdrawn entries are skipped",
			feed:      `{"id":"A","withdrawn":"2024-01-01T00:00:00Z","affected":[{"package":{"purl":"pkg:npm/lodash"}}]}`,
			sbomPURLs: []string{"pkg:npm/lodash@4.17.20"},
			wantMatch: false,
		},
		{
			name:      "truncated SBOM purl list matches any feed",
			feed:      lodashFeed,
			sbomPURLs: []string{"pkg:npm/other@1.0.0", purl.TruncatedMarker},
			wantMatch: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			matcher := feed.NewMatcher(parseFeed(t, test.feed))

			if got := matcher.MatchesAny(test.sbomPURLs); got != test.wantMatch {
				t.Errorf("expected match=%v, got %v", test.wantMatch, got)
			}
		})
	}
}

func TestFeedMatchesUpstreamIdentity(t *testing.T) {
	t.Parallel()

	matcher := feed.NewMatcher(parseFeed(t,
		`{"id":"A","affected":[{"package":{"ecosystem":"Debian:12","name":"glibc"}}]}`))

	// SBOM tools name the binary package (libc6) and record the source
	// package in the upstream qualifier.
	packages := []string{"pkg:deb/debian/libc6@2.36-9?arch=amd64&upstream=glibc&distro=debian-12"}

	if !matcher.MatchesAny(packages) {
		t.Error("expected the upstream source package to match the feed")
	}
}

func TestEmptyMatcherMatchesNothing(t *testing.T) {
	t.Parallel()

	matcher := feed.NewMatcher(nil)

	if matcher.MatchesAny([]string{"pkg:npm/x@1", purl.TruncatedMarker}) {
		t.Error("expected empty feed to match nothing")
	}
}

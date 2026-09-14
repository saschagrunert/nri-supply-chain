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
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/feed"
)

func TestFeedMatchingEdgeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		feed      string
		sbomPURL  string
		wantMatch bool
	}{
		{
			name:      "upstream qualifier key is case-insensitive",
			feed:      `{"id":"A","affected":[{"package":{"ecosystem":"Debian:12","name":"glibc"}}]}`,
			sbomPURL:  "pkg:deb/debian/libc6@2.36-9?UPSTREAM=glibc",
			wantMatch: true,
		},
		{
			name:      "trailing slash before the version",
			feed:      lodashFeed,
			sbomPURL:  "pkg:npm/lodash/@1",
			wantMatch: true,
		},
		{
			name: "pub build metadata below the fixed version matches",
			feed: `{"id":"A","affected":[{"package":{"ecosystem":"Pub","name":"x"},` +
				`"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.0.0+1"}]}]}]}`,
			sbomPURL:  "pkg:pub/x@1.0.0",
			wantMatch: true,
		},
		{
			name: "semver ranges still exclude clearly fixed versions",
			feed: `{"id":"A","affected":[{"package":{"ecosystem":"Pub","name":"x"},` +
				`"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.0.0+1"}]}]}]}`,
			sbomPURL:  "pkg:pub/x@1.0.1",
			wantMatch: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			matcher := feed.NewMatcher(parseFeed(t, test.feed))

			if got := matcher.Matches(test.sbomPURL); got != test.wantMatch {
				t.Errorf("expected match=%v, got %v", test.wantMatch, got)
			}
		})
	}
}

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

package glob_test

import (
	"regexp"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/glob"
)

func TestToRegex(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pattern string
		match   string
		noMatch string
	}{
		{
			name:    "literal",
			pattern: "foo@bar.com",
			match:   "foo@bar.com",
			noMatch: "foo@baz.com",
		},
		{
			name:    "star wildcard",
			pattern: "*.example.com",
			match:   "user.example.com",
			noMatch: "a/b.example.com",
		},
		{
			name:    "question mark",
			pattern: "user?.example.com",
			match:   "userA.example.com",
			noMatch: "user.example.com",
		},
		{
			name:    "character class",
			pattern: "[abc].example.com",
			match:   "a.example.com",
			noMatch: "d.example.com",
		},
		{
			name:    "character range",
			pattern: "[a-z].example.com",
			match:   "x.example.com",
			noMatch: "1.example.com",
		},
		{
			name:    "dot is escaped",
			pattern: "foo.bar",
			match:   "foo.bar",
			noMatch: "fooXbar",
		},
		{
			name:    "plus is escaped",
			pattern: "a+b",
			match:   "a+b",
			noMatch: "aab",
		},
		{
			name:    "multiple wildcards",
			pattern: "*@*.example.com",
			match:   "user@host.example.com",
			noMatch: "user@a/b.example.com",
		},
		{
			name:    "backslash in character class escapes next char",
			pattern: `[\d].example.com`,
			match:   `d.example.com`,
			noMatch: "5.example.com",
		},
		{
			name:    "escaped backslash in character class",
			pattern: `[\\].example.com`,
			match:   `\.example.com`,
			noMatch: "x.example.com",
		},
		{
			name:    "escaped hyphen in character class is literal",
			pattern: `[a\-z].example.com`,
			match:   `-.example.com`,
			noMatch: "m.example.com",
		},
		{
			name:    "escaped bracket in character class",
			pattern: `[\]].example.com`,
			match:   `].example.com`,
			noMatch: "q.example.com",
		},
		{
			name:    "escaped star is literal",
			pattern: `\*.example.com`,
			match:   `*.example.com`,
			noMatch: "foo.example.com",
		},
		{
			name:    "escaped question mark is literal",
			pattern: `\?.example.com`,
			match:   `?.example.com`,
			noMatch: "z.example.com",
		},
		{
			name:    "escaped backslash outside class",
			pattern: `\\foo`,
			match:   `\foo`,
			noMatch: "foo",
		},
		{
			name:    "double star matches across slashes",
			pattern: "https://github.com/org/repo/**",
			match:   "https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1.0.0",
			noMatch: "https://github.com/org/other/.github/workflows/release.yml",
		},
		{
			name:    "double star in middle",
			pattern: "https://github.com/**/release.yml",
			match:   "https://github.com/org/repo/.github/workflows/release.yml",
			noMatch: "https://github.com/org/repo/.github/workflows/ci.yml",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			regex := glob.ToRegex(test.pattern)
			fullRegex := "^" + regex + "$"

			matched, err := regexp.MatchString(fullRegex, test.match)
			if err != nil {
				t.Fatalf("regex error: %v", err)
			}

			if !matched {
				t.Errorf("pattern %q (regex %q) should match %q",
					test.pattern, fullRegex, test.match)
			}

			matched, err = regexp.MatchString(fullRegex, test.noMatch)
			if err != nil {
				t.Fatalf("regex error: %v", err)
			}

			if matched {
				t.Errorf("pattern %q (regex %q) should not match %q",
					test.pattern, fullRegex, test.noMatch)
			}
		})
	}
}

func TestMatch(t *testing.T) {
	t.Parallel()

	matched, err := glob.Match("*.example.com", "foo.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !matched {
		t.Error("expected match")
	}

	matched, err = glob.Match("*.example.com", "foo/bar.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if matched {
		t.Error("expected no match")
	}

	// Second call with same pattern should hit cache.
	matched, err = glob.Match("*.example.com", "bar.example.com")
	if err != nil {
		t.Fatalf("unexpected error on cached pattern: %v", err)
	}

	if !matched {
		t.Error("expected match on cached pattern")
	}
}

func TestMatchEdgeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		pattern   string
		text      string
		wantMatch bool
	}{
		{
			name:      "empty pattern matches empty text",
			pattern:   "",
			text:      "",
			wantMatch: true,
		},
		{
			name:      "empty pattern rejects non-empty text",
			pattern:   "",
			text:      "foo",
			wantMatch: false,
		},
		{
			name:      "unclosed bracket treated as literal",
			pattern:   "[abc",
			text:      "[abc",
			wantMatch: true,
		},
		{
			name:      "bracket at end of pattern",
			pattern:   "foo[",
			text:      "foo[",
			wantMatch: true,
		},
		{
			name:      "trailing backslash treated as literal",
			pattern:   `foo\`,
			text:      `foo\`,
			wantMatch: true,
		},
		{
			name:      "negated character class",
			pattern:   "[^abc].txt",
			text:      "x.txt",
			wantMatch: true,
		},
		{
			name:      "negated character class rejects member",
			pattern:   "[^abc].txt",
			text:      "a.txt",
			wantMatch: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			matched, err := glob.Match(test.pattern, test.text)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if matched != test.wantMatch {
				t.Errorf("Match(%q, %q) = %v, want %v",
					test.pattern, test.text, matched, test.wantMatch)
			}
		})
	}
}

func TestResetCache(t *testing.T) {
	t.Parallel()

	_, err := glob.Match("reset-test-*", "reset-test-foo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	glob.ResetCache()

	// After reset, the pattern still works (recompiled on next call).
	matched, err := glob.Match("reset-test-*", "reset-test-bar")
	if err != nil {
		t.Fatalf("unexpected error after reset: %v", err)
	}

	if !matched {
		t.Error("expected match after cache reset")
	}
}

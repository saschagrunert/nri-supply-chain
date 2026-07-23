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

package attestation

import (
	"fmt"
	"regexp"
	"strings"
)

// GlobMatch reports whether text matches the glob pattern.
// '*' matches non-'/' characters, '**' matches any characters including '/'.
func GlobMatch(pattern, text string) (bool, error) {
	re, err := regexp.Compile("^" + globToRegex(pattern) + "$")
	if err != nil {
		return false, fmt.Errorf("compiling glob pattern %q: %w", pattern, err)
	}

	return re.MatchString(text), nil
}

// globToRegex converts a glob pattern to a regex string, consistent with
// path.Match semantics: '*' matches non-'/' characters, '**' matches any
// characters including '/', '?' matches a single non-'/' character, and
// '[...]' character classes have backslash escapes consumed to prevent
// glob/regex semantic divergence (e.g. [\d] in glob matches only 'd', not
// the regex digit class).
func globToRegex(pattern string) string {
	var builder strings.Builder

	runes := []rune(pattern)

	for idx := 0; idx < len(runes); idx++ {
		switch runes[idx] {
		case '\\':
			if idx+1 < len(runes) {
				idx++
				builder.WriteString(regexp.QuoteMeta(string(runes[idx])))
			} else {
				builder.WriteString(regexp.QuoteMeta(`\`))
			}
		case '*':
			var starExpr string

			starExpr, idx = expandStar(runes, idx)
			builder.WriteString(starExpr)
		case '?':
			builder.WriteString("[^/]")
		case '[':
			converted, end := convertBracketExpr(runes, idx)
			builder.WriteString(converted)

			if end > idx {
				idx = end
			}
		default:
			builder.WriteString(regexp.QuoteMeta(string(runes[idx])))
		}
	}

	return builder.String()
}

func expandStar(runes []rune, idx int) (expr string, newIdx int) {
	if idx+1 < len(runes) && runes[idx+1] == '*' {
		return ".*", idx + 1
	}

	return "[^/]*", idx
}

func convertBracketExpr(runes []rune, idx int) (converted string, end int) {
	end = findBracketEnd(runes, idx)
	if end < 0 {
		return regexp.QuoteMeta("["), idx
	}

	class := escapeCharClass(runes[idx : end+1])

	_, compileErr := regexp.Compile(class)
	if compileErr != nil {
		var escaped strings.Builder

		for _, r := range runes[idx : end+1] {
			escaped.WriteString(regexp.QuoteMeta(string(r)))
		}

		return escaped.String(), end
	}

	return class, end
}

func escapeCharClass(runes []rune) string {
	var builder strings.Builder

	builder.WriteRune(runes[0])

	for idx := 1; idx < len(runes)-1; idx++ {
		if runes[idx] == '\\' && idx+1 < len(runes)-1 {
			idx++

			ch := runes[idx]
			if ch == '\\' || ch == ']' || ch == '-' || ch == '^' {
				builder.WriteRune('\\')
			}

			builder.WriteRune(ch)
		} else {
			builder.WriteRune(runes[idx])
		}
	}

	builder.WriteRune(runes[len(runes)-1])

	return builder.String()
}

func findBracketEnd(runes []rune, start int) int {
	idx := start + 1
	if idx < len(runes) && runes[idx] == '^' {
		idx++
	}

	if idx < len(runes) && runes[idx] == ']' {
		idx++
	}

	for idx < len(runes) {
		if runes[idx] == '\\' && idx+1 < len(runes) {
			idx += 2

			continue
		}

		if runes[idx] == ']' {
			return idx
		}

		idx++
	}

	return -1
}

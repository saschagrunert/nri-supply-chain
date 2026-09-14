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

package glob

import "strings"

// MatchSource matches a trust.sources pattern against a normalized source
// repository and the ref it was resolved at. A pattern without a ref
// ("https://host/org/*") is matched against the repository only. A
// ref-pinned pattern ("git+https://host/org/repo@refs/tags/*", the "git+"
// prefix is optional) is split into its repository and ref parts, which must
// match the repository and the ref; an empty ref does not match it.
func MatchSource(pattern, repository, ref string) (bool, error) {
	repositoryPattern, refPattern, pinned := SplitGitRef(pattern)

	matched, err := Match(repositoryPattern, repository)
	if err != nil || !matched {
		return false, err
	}

	if !pinned {
		return true, nil
	}

	if ref == "" {
		return false, nil
	}

	return Match(refPattern, ref)
}

// SplitGitRef removes a "git+" prefix and splits "<repository>@<ref>" at the
// first '@' in the path. found reports whether the path carried an '@'. The
// '@' of a user in the authority is not a ref separator, neither in URLs
// ("git+ssh://git@host/org/repo") nor in scp-like addresses
// ("git@host:org/repo").
func SplitGitRef(uri string) (repository, ref string, found bool) {
	trimmed := strings.TrimPrefix(uri, "git+")

	pathStart := 0

	if schemeEnd := strings.Index(trimmed, "://"); schemeEnd >= 0 {
		authorityStart := schemeEnd + len("://")

		slash := strings.IndexByte(trimmed[authorityStart:], '/')
		if slash < 0 {
			return trimmed, "", false
		}

		pathStart = authorityStart + slash
	} else if colon := strings.IndexByte(trimmed, ':'); colon >= 0 &&
		strings.Contains(trimmed[:colon], "@") && !strings.Contains(trimmed[:colon], "/") {
		// scp-like "user@host:path": the path starts after the colon.
		pathStart = colon + 1
	}

	if at := strings.IndexByte(trimmed[pathStart:], '@'); at >= 0 {
		return trimmed[:pathStart+at], trimmed[pathStart+at+1:], true
	}

	return trimmed, "", false
}

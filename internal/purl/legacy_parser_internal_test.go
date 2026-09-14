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

package purl

import (
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"
	"testing"
)

// legacyParse is the hand-written parser that Parse replaced. It is kept in
// the tests as the reference for the differential test below.
func legacyParse(raw string) (PURL, error) {
	if len(raw) < len(scheme) || !strings.EqualFold(raw[:len(scheme)], scheme) {
		return PURL{}, fmt.Errorf("%w: missing %q scheme: %q", ErrInvalid, scheme, raw)
	}

	rest := strings.TrimLeft(raw[len(scheme):], "/")

	var parsed PURL

	if before, after, found := strings.Cut(rest, "#"); found {
		rest = before
		parsed.Subpath = strings.Trim(legacyDecode(after), "/")
	}

	if before, after, found := strings.Cut(rest, "?"); found {
		rest = before
		parsed.Qualifiers = legacyParseQualifiers(after)
	}

	rest = strings.TrimRight(rest, "/")

	lastSlash := strings.LastIndex(rest, "/")
	if at := strings.LastIndex(rest, "@"); at > lastSlash {
		parsed.Version = legacyDecode(rest[at+1:])
		rest = rest[:at]
	}

	typ, path, found := strings.Cut(rest, "/")
	if !found || typ == "" || path == "" {
		return PURL{}, fmt.Errorf("%w: missing type or name: %q", ErrInvalid, raw)
	}

	parsed.Type = strings.ToLower(typ)

	segments := strings.Split(path, "/")
	for idx := range segments {
		segments[idx] = legacyDecode(segments[idx])
	}

	segments = slices.DeleteFunc(segments, func(s string) bool { return s == "" })
	if len(segments) == 0 {
		return PURL{}, fmt.Errorf("%w: empty name: %q", ErrInvalid, raw)
	}

	parsed.Name = segments[len(segments)-1]
	parsed.Namespace = strings.Join(segments[:len(segments)-1], "/")

	return parsed, nil
}

func legacyParseQualifiers(raw string) map[string]string {
	qualifiers := make(map[string]string)

	for pair := range strings.SplitSeq(raw, "&") {
		key, value, found := strings.Cut(pair, "=")
		if !found || key == "" || value == "" {
			continue
		}

		qualifiers[strings.ToLower(key)] = legacyDecode(value)
	}

	if len(qualifiers) == 0 {
		return nil
	}

	return qualifiers
}

func legacyDecode(component string) string {
	decoded, err := url.PathUnescape(component)
	if err != nil {
		return component
	}

	return decoded
}

// realWorldPURLs is a corpus of package URLs as emitted by SBOM, VEX and
// vulnerability feed producers.
var realWorldPURLs = []string{ //nolint:gochecknoglobals // test corpus
	"pkg:npm/%40angular/core@12.0.0",
	"pkg:npm/@babel/core@7.24.0?arch=x64",
	"pkg:npm/lodash@4.17.21",
	"pkg:npm/lodash/@1",
	"pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1?type=jar",
	"pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.15.2",
	"pkg:pypi/Django@4.2.1",
	"pkg:pypi/typing_extensions@4.12.2",
	"PKG:PyPI/requests@2.0",
	"pkg:golang/github.com/sigstore/sigstore-go@v1.3.0",
	"pkg:golang/github.com/Foo/Bar@v1.2.3#sub/dir",
	"pkg:golang/golang.org/x/net@v0.30.0#http2",
	"pkg:deb/debian/libc6@2.36-9+deb12u4?arch=amd64&distro=debian-12&upstream=glibc",
	"pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.15?arch=amd64&upstream=openssl%403.0.2-0ubuntu1.15",
	"pkg:rpm/redhat/glibc-common@2.34-60.el9?arch=x86_64&upstream=glibc-2.34-60.el9.src.rpm&distro=rhel-9.2",
	"pkg:apk/alpine/musl@1.2.4-r2?arch=x86_64&upstream=musl&distro=3.19.1",
	"pkg:oci/debian@sha256%3Aabc?repository_url=docker.io%2Flibrary%2Fdebian&arch=amd64&tag=12",
	"pkg:oci/nginx@sha256:abc?repository_url=ghcr.io/org/nginx",
	"pkg:docker/library/nginx@1.27?repository_url=index.docker.io",
	"pkg:docker/nginx",
	"pkg:gem/rails@7.1.0",
	"pkg:cargo/serde@1.0.200",
	"pkg:nuget/Newtonsoft.Json@13.0.3",
	"pkg:composer/laravel/framework@11.0.0",
	"pkg:github/package-url/purl-spec@244fd47",
	"pkg:swift/github.com/apple/swift-nio@2.0.0",
	"pkg:cpan/Foo-Bar@1.0",
	"pkg:generic/openssl@3.0.0?download_url=https://openssl.org/source/openssl-3.0.0.tar.gz",
	"pkg:generic/nri-supply-chain/purls-truncated",
	"pkg://npm/foo@1",
}

func TestParseMatchesLegacyParserOnRealWorldPURLs(t *testing.T) {
	t.Parallel()

	for _, input := range realWorldPURLs {
		t.Run(input, func(t *testing.T) {
			t.Parallel()

			want, legacyErr := legacyParse(input)
			if legacyErr != nil {
				t.Fatalf("legacy parser rejected corpus entry: %v", legacyErr)
			}

			got, err := Parse(input)
			if err != nil {
				t.Fatalf("Parse rejected a purl the legacy parser accepted: %v", err)
			}

			// Names and namespaces may be normalized per purl type (for
			// example lowercased for golang), so identity is compared
			// through Key, which lowercases both.
			if got.Key() != want.Key() {
				t.Errorf("Key() = %q, legacy %q", got.Key(), want.Key())
			}

			if got.Type != want.Type || got.Version != want.Version || got.Subpath != want.Subpath {
				t.Errorf("Parse = %+v, legacy %+v", got, want)
			}

			if !maps.Equal(got.Qualifiers, want.Qualifiers) {
				t.Errorf("Qualifiers = %v, legacy %v", got.Qualifiers, want.Qualifiers)
			}

			gotKey, gotVersion := got.UpstreamKey()
			wantKey, wantVersion := want.UpstreamKey()

			if gotKey != wantKey || gotVersion != wantVersion {
				t.Errorf(
					"UpstreamKey() = %q@%q, legacy %q@%q",
					gotKey,
					gotVersion,
					wantKey,
					wantVersion,
				)
			}
		})
	}
}

// TestParseRejectsSpecViolations pins inputs the legacy parser silently
// accepted but that are invalid per the purl specification, so identity
// matching never works on a guessed interpretation.
func TestParseRejectsSpecViolations(t *testing.T) {
	t.Parallel()

	for _, input := range []string{
		"pkg:npm/foo?arch=x86&arch=arm64",
		"pkg:npm/foo?1arch=x86",
		"pkg:npm/fo%zzo@1",
		"pkg:npm/foo?arch=x;y=z",
		"pkg:1npm/foo",
		"pkg:maven/@scope/name",
	} {
		_, legacyErr := legacyParse(input)
		if legacyErr != nil {
			t.Fatalf("legacy parser already rejected %q: %v", input, legacyErr)
		}

		_, err := Parse(input)
		if err == nil {
			t.Errorf("Parse(%q) accepted a purl that violates the specification", input)
		}
	}
}

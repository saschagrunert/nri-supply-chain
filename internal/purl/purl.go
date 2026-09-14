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

// Package purl parses Package URLs (purls) with packageurl-go and derives the
// identity keys used to match identifiers across SBOM, VEX, and vulnerability
// feed documents.
package purl

import (
	"errors"
	"fmt"
	"strings"

	"github.com/package-url/packageurl-go"
)

const (
	scheme = "pkg:"

	typePyPI          = "pypi"
	qualifierUpstream = "upstream"

	// rpmNameVersionReleaseParts is the minimum number of dash-separated
	// parts in an RPM "name-version-release" string.
	rpmNameVersionReleaseParts = 3
)

// TruncatedMarker is appended to purl lists that were capped. Consumers that
// match feeds against such a list must treat it as matching every package so
// truncation never hides an affected component.
const TruncatedMarker = "pkg:generic/nri-supply-chain/purls-truncated"

// ErrInvalid indicates a string is not a parseable Package URL.
var ErrInvalid = errors.New("invalid package URL")

var errMissingTypeOrName = errors.New("missing type or name")

// PURL is a parsed Package URL.
type PURL struct {
	// Type is the lowercase package type (e.g. "npm", "oci", "golang").
	Type string
	// Namespace is the percent-decoded namespace ("" when absent).
	Namespace string
	// Name is the percent-decoded package name.
	Name string
	// Version is the percent-decoded version ("" when absent).
	Version string
	// Qualifiers holds percent-decoded qualifier values keyed by lowercase key.
	Qualifiers map[string]string
	// Subpath is the percent-decoded subpath ("" when absent).
	Subpath string
}

// Parse parses a Package URL string with packageurl-go. Names and namespaces
// are normalized per purl type (for example lowercased for golang and PyPI).
//
// Two deviations from packageurl-go keep identity matching aligned with the
// specification's parsing algorithm and with real-world producers:
//   - Slashes between the name and the version separator or at the end of the
//     path are stripped, as the specification requires ("pkg:npm/lodash/@1"
//     names lodash).
//   - A purl that is well formed but violates a type-specific rule (for
//     example a cpan purl without namespace) is accepted, since its identity
//     is unambiguous.
func Parse(raw string) (PURL, error) {
	if len(raw) < len(scheme) || !strings.EqualFold(raw[:len(scheme)], scheme) {
		return PURL{}, fmt.Errorf("%w: missing %q scheme: %q", ErrInvalid, scheme, raw)
	}

	canonical, typ, err := stripPathSlashes(raw)
	if err != nil {
		return PURL{}, fmt.Errorf("%w: %w: %q", ErrInvalid, err, raw)
	}

	parsed, err := packageurl.FromString(canonical)
	if err != nil {
		// packageurl-go assigns the normalized fields before it checks the
		// type-specific rules. Parsing the same purl as the rule-free
		// generic type tells whether only those rules failed.
		_, genericErr := packageurl.FromString(
			scheme + "generic" + canonical[len(scheme)+len(typ):],
		)
		if genericErr != nil || !packageurl.TypePattern.MatchString(typ) {
			return PURL{}, fmt.Errorf("%w: %w: %q", ErrInvalid, err, raw)
		}
	}

	if parsed.Type == "" || parsed.Name == "" {
		return PURL{}, fmt.Errorf("%w: missing type or name: %q", ErrInvalid, raw)
	}

	return PURL{
		Type:       parsed.Type,
		Namespace:  parsed.Namespace,
		Name:       parsed.Name,
		Version:    parsed.Version,
		Qualifiers: qualifierMap(parsed.Qualifiers),
		Subpath:    parsed.Subpath,
	}, nil
}

// stripPathSlashes returns raw with leading slashes after the scheme, slashes
// before the version separator, and trailing path slashes removed, together
// with the type as written. Qualifiers and subpath are kept verbatim.
func stripPathSlashes(raw string) (canonical, typ string, err error) {
	rest := strings.TrimLeft(raw[len(scheme):], "/")

	suffix := ""
	if idx := strings.IndexAny(rest, "?#"); idx >= 0 {
		rest, suffix = rest[:idx], rest[idx:]
	}

	typ, path, found := strings.Cut(rest, "/")
	if !found || typ == "" {
		return "", "", errMissingTypeOrName
	}

	path = strings.TrimLeft(path, "/")

	// The version separator is the last "@" that does not start the path, so
	// npm scopes such as "@angular/core" are not mistaken for versions.
	if at := strings.LastIndex(path, "@"); at > 0 {
		path = strings.TrimRight(path[:at], "/") + path[at:]
	} else {
		path = strings.TrimRight(path, "/")
	}

	if path == "" {
		return "", "", errMissingTypeOrName
	}

	return scheme + typ + "/" + path + suffix, typ, nil
}

func qualifierMap(qualifiers packageurl.Qualifiers) map[string]string {
	if len(qualifiers) == 0 {
		return nil
	}

	return qualifiers.Map()
}

// Key returns a lowercase "type/namespace/name" identity key that ignores the
// version, qualifiers, and subpath. Lowercasing makes matching tolerant of
// producers that disagree on case, which errs on the side of matching. PyPI
// names are normalized per PEP 503.
func (p *PURL) Key() string {
	return strings.ToLower(p.Type + "/" + p.Namespace + "/" + NormalizeName(p.Type, p.Name))
}

// NormalizeName applies type-specific name normalization for identity
// comparison. PyPI names follow PEP 503: runs of "-", "_", and "." are
// equivalent and comparison is case-insensitive.
func NormalizeName(typ, name string) string {
	if !strings.EqualFold(typ, typePyPI) {
		return name
	}

	var builder strings.Builder

	builder.Grow(len(name))

	separator := false

	for _, char := range strings.ToLower(name) {
		if char == '-' || char == '_' || char == '.' {
			separator = true

			continue
		}

		if separator && builder.Len() > 0 {
			builder.WriteByte('-')
		}

		separator = false

		builder.WriteRune(char)
	}

	return builder.String()
}

// Upstream is the source package a binary package was built from.
type Upstream struct {
	// Name is the source package name.
	Name string
	// Version is the source package version, or the binary package version
	// when the qualifier does not carry one.
	Version string
}

// Upstream returns the source package recorded in the "upstream" qualifier
// (used by Debian, RPM, and Alpine purls). It accepts "name",
// "name@version", and RPM source file names ("name-version-release.src.rpm").
func (p *PURL) Upstream() (Upstream, bool) {
	value := strings.TrimSpace(p.Qualifiers[qualifierUpstream])
	if value == "" {
		return Upstream{Name: "", Version: ""}, false
	}

	upstream := Upstream{Name: value, Version: p.Version}

	if trimmed, isRPM := strings.CutSuffix(value, ".rpm"); isRPM {
		trimmed = strings.TrimSuffix(trimmed, ".src")

		parts := strings.Split(trimmed, "-")
		if len(parts) >= rpmNameVersionReleaseParts {
			upstream.Name = strings.Join(parts[:len(parts)-2], "-")
			upstream.Version = parts[len(parts)-2] + "-" + parts[len(parts)-1]
		}

		return upstream, upstream.Name != ""
	}

	if name, version, found := strings.Cut(value, "@"); found {
		upstream.Name, upstream.Version = name, version
	}

	return upstream, upstream.Name != ""
}

// UpstreamKey returns the identity key of the upstream source package, or ""
// when the purl has no upstream qualifier or it names the package itself.
func (p *PURL) UpstreamKey() (key, version string) {
	upstream, ok := p.Upstream()
	if !ok {
		return "", ""
	}

	source := PURL{
		Type: p.Type, Namespace: p.Namespace, Name: upstream.Name,
		Version: upstream.Version, Qualifiers: nil, Subpath: "",
	}

	key = source.Key()
	if key == p.Key() {
		return "", ""
	}

	return key, upstream.Version
}

// StripQualifiers returns raw without its qualifiers and subpath. It performs
// no validation and returns non-purl input unchanged.
func StripQualifiers(raw string) string {
	if idx := strings.IndexAny(raw, "?#"); idx >= 0 {
		return raw[:idx]
	}

	return raw
}

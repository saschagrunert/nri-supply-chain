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

package feed

import (
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/saschagrunert/nri-supply-chain/internal/purl"
)

const (
	rangeTypeSemver    = "SEMVER"
	rangeTypeEcosystem = "ECOSYSTEM"
	versQualifier      = "vers"
	versPrefix         = "vers:semver/"
	versAny            = "*"
	semverParts        = 3
	purlTypeMaven      = "maven"
	purlTypeDeb        = "deb"
	purlTypeAPK        = "apk"
	purlTypeRPM        = "rpm"
	purlTypeNPM        = "npm"
	purlTypeGolang     = "golang"
	purlTypeCargo      = "cargo"
	purlTypeHex        = "hex"
	purlTypePub        = "pub"
	upstreamQualifier  = "upstream="
)

// semverEcosystemTypes lists purl types whose ecosystem versions order like
// semantic versions, so ECOSYSTEM ranges can be evaluated with semver
// comparison (versions that do not parse still match conservatively).
var semverEcosystemTypes = map[string]struct{}{ //nolint:gochecknoglobals // immutable lookup table
	purlTypeNPM:    {},
	purlTypeGolang: {},
	purlTypeCargo:  {},
	purlTypeHex:    {},
	purlTypePub:    {},
}

// unmappedEcosystems records ecosystems already reported as unmapped so each
// is logged once.
var unmappedEcosystems sync.Map //nolint:gochecknoglobals // log deduplication

// ecosystemPURL describes how an OSV ecosystem maps to a purl.
type ecosystemPURL struct {
	// typ is the purl type.
	typ string
	// namespace is a fixed purl namespace (distributions); empty means the
	// namespace is derived from the package name.
	namespace string
}

// ecosystems maps lowercase OSV ecosystems (without release suffix) to purls.
var ecosystems = map[string]ecosystemPURL{ //nolint:gochecknoglobals // immutable lookup table
	purlTypeNPM: {typ: purlTypeNPM, namespace: ""},
	"pypi":      {typ: "pypi", namespace: ""},
	"go":        {typ: purlTypeGolang, namespace: ""},
	"maven":     {typ: purlTypeMaven, namespace: ""},
	"crates.io": {typ: purlTypeCargo, namespace: ""},
	"rubygems":  {typ: "gem", namespace: ""},
	"nuget":     {typ: "nuget", namespace: ""},
	"packagist": {typ: "composer", namespace: ""},
	purlTypeHex: {typ: purlTypeHex, namespace: ""},
	purlTypePub: {typ: purlTypePub, namespace: ""},
	"debian":    {typ: purlTypeDeb, namespace: "debian"},
	"ubuntu":    {typ: purlTypeDeb, namespace: "ubuntu"},
	"alpine":    {typ: purlTypeAPK, namespace: "alpine"},
	"wolfi":     {typ: purlTypeAPK, namespace: "wolfi"},
	"rocky":     {typ: purlTypeRPM, namespace: "rocky"},
	"almalinux": {typ: purlTypeRPM, namespace: "almalinux"},
	"red hat":   {typ: purlTypeRPM, namespace: "redhat"},
	"suse":      {typ: purlTypeRPM, namespace: "suse"},
}

// affectedSpecs converts an OSV affected entry into purl specs.
//
// OSV defines the affected versions as the union of the enumerated versions
// and the ranges. A version in the OSV purl pins an additional affected
// version. Enumerated versions produce versioned purls. SEMVER ranges (and
// ECOSYSTEM ranges of semver-ordered ecosystems) produce purls with a "vers"
// qualifier. Ranges that cannot be evaluated here (other ECOSYSTEM ranges,
// GIT) produce a versionless purl that matches every version. Specs err on
// the side of matching because they only trigger re-verification.
func affectedSpecs(affected *OSVAffected) []string {
	base := basePURL(&affected.Package)
	if base == "" {
		return nil
	}

	parsedBase, err := purl.Parse(base)
	if err != nil {
		return nil
	}

	var specs []string

	versionless := base
	if parsedBase.Version != "" {
		specs = append(specs, base)
		versionless = stripVersion(base)
	}

	specs = append(specs, versionSpecs(versionless, affected.Versions)...)
	rangeSpecs, unevaluable := semverRangeSpecs(versionless, parsedBase.Type, affected.Ranges)
	specs = append(specs, rangeSpecs...)

	if len(specs) == 0 || unevaluable {
		specs = append(specs, versionless)
	}

	return specs
}

// stripVersion removes the version from a purl without qualifiers.
func stripVersion(raw string) string {
	lastSlash := strings.LastIndex(raw, "/")
	if at := strings.LastIndex(raw, "@"); at > lastSlash {
		return raw[:at]
	}

	return raw
}

func versionSpecs(base string, versions []string) []string {
	specs := make([]string, 0, len(versions))

	for _, version := range versions {
		if version != "" {
			specs = append(specs, base+"@"+url.PathEscape(version))
		}
	}

	return specs
}

// semverRangeSpecs encodes SEMVER ranges (and ECOSYSTEM ranges of
// semver-ordered purl types) as vers qualifiers and reports whether any range
// could not be encoded.
func semverRangeSpecs(
	base, purlType string, ranges []OSVRange,
) (specs []string, unevaluable bool) {
	_, semverEcosystem := semverEcosystemTypes[purlType]

	for idx := range ranges {
		rng := &ranges[idx]

		evaluable := strings.EqualFold(rng.Type, rangeTypeSemver) ||
			(semverEcosystem && strings.EqualFold(rng.Type, rangeTypeEcosystem))
		if !evaluable {
			unevaluable = true

			continue
		}

		for _, constraint := range semverIntervals(rng.Events) {
			specs = append(specs, base+"?"+versQualifier+"="+url.PathEscape(versPrefix+constraint))
		}
	}

	return specs, unevaluable
}

// basePURL returns the affected package purl without qualifiers, deriving it
// from ecosystem and name when the purl field is empty.
func basePURL(pkg *OSVPackage) string {
	if pkg.PURL != "" {
		return purl.StripQualifiers(pkg.PURL)
	}

	return purlFromEcosystem(pkg.Ecosystem, pkg.Name)
}

func purlFromEcosystem(ecosystem, name string) string {
	if ecosystem == "" || name == "" {
		return ""
	}

	// Ecosystems may carry a release suffix such as "Debian:12".
	key, _, _ := strings.Cut(strings.ToLower(ecosystem), ":")

	mapping, ok := ecosystems[key]
	if !ok {
		warnUnmappedEcosystem(ecosystem)

		return ""
	}

	prefix := "pkg:" + mapping.typ + "/"

	switch {
	case mapping.namespace != "":
		return prefix + mapping.namespace + "/" + escapePath(name)
	case mapping.typ == purlTypeMaven:
		group, artifact, found := strings.Cut(name, ":")
		if !found {
			return prefix + escapePath(name)
		}

		return prefix + escapePath(group) + "/" + escapePath(artifact)
	default:
		// npm scopes, golang module paths, and composer vendors keep their
		// slashes as purl namespace separators.
		return prefix + escapePath(name)
	}
}

// warnUnmappedEcosystem logs an OSV ecosystem without a purl mapping once
// and reports whether it logged.
func warnUnmappedEcosystem(ecosystem string) bool {
	if _, loaded := unmappedEcosystems.LoadOrStore(ecosystem, struct{}{}); loaded {
		return false
	}

	slog.Warn("OSV ecosystem has no package URL mapping, "+
		"entries without a purl are ignored", "ecosystem", ecosystem)

	return true
}

func escapePath(path string) string {
	segments := strings.Split(path, "/")
	for idx := range segments {
		segments[idx] = url.PathEscape(segments[idx])
	}

	return strings.Join(segments, "/")
}

// semverIntervals converts OSV events into vers constraints, one per
// affected interval. Introduced opens an interval (an introduced event while
// an interval is already open keeps the earlier lower bound); fixed, limit,
// and last_affected close it.
func semverIntervals(events []OSVEvent) []string {
	var (
		intervals []string
		lower     string
		open      bool
	)

	for idx := range events {
		event := &events[idx]

		if event.Introduced != "" {
			if !open {
				lower = lowerBound(event.Introduced)
				open = true
			}

			continue
		}

		upper := eventUpperBound(event)
		if upper != "" && open {
			intervals = append(intervals, joinConstraints(lower, upper))
			open = false
		}
	}

	if open {
		intervals = append(intervals, joinConstraints(lower, ""))
	}

	return intervals
}

// lowerBound returns the introduced version, or "" for "0", which means the
// range starts at the first version.
func lowerBound(introduced string) string {
	if introduced == "0" {
		return ""
	}

	return introduced
}

func eventUpperBound(event *OSVEvent) string {
	switch {
	case event.Fixed != "":
		return "<" + event.Fixed
	case event.LastAffected != "":
		return "<=" + event.LastAffected
	case event.Limit != "":
		return "<" + event.Limit
	default:
		return ""
	}
}

func joinConstraints(lower, upper string) string {
	parts := make([]string, 0, 2) //nolint:mnd // lower and upper bound

	if lower != "" {
		parts = append(parts, ">="+lower)
	}

	if upper != "" {
		parts = append(parts, upper)
	}

	if len(parts) == 0 {
		return versAny
	}

	return strings.Join(parts, "|")
}

// Matcher matches feed specs produced by ParseFile/ParseDir against package
// URLs from SBOMs.
type Matcher struct {
	specs map[string][]matchSpec
	// names holds the normalized package names of all specs so package URLs
	// with other names are rejected without a full parse.
	names map[string]struct{}
}

type matchSpec struct {
	version     string
	constraints []string
	any         bool
}

// NewMatcher indexes feed specs by package identity. Unparsable specs are
// ignored.
func NewMatcher(feedPURLs []string) *Matcher {
	matcher := &Matcher{
		specs: make(map[string][]matchSpec, len(feedPURLs)),
		names: make(map[string]struct{}, len(feedPURLs)),
	}

	for _, raw := range feedPURLs {
		parsed, err := purl.Parse(raw)
		if err != nil {
			continue
		}

		spec := matchSpec{version: parsed.Version, constraints: nil, any: false}

		if vers := parsed.Qualifiers[versQualifier]; strings.HasPrefix(vers, versPrefix) {
			body := strings.TrimPrefix(vers, versPrefix)
			if body != versAny {
				spec.constraints = strings.Split(body, "|")
			}
		}

		spec.any = spec.version == "" && len(spec.constraints) == 0

		key := parsed.Key()
		matcher.specs[key] = append(matcher.specs[key], spec)
		matcher.names[strings.ToLower(purl.NormalizeName(parsed.Type, parsed.Name))] = struct{}{}
	}

	return matcher
}

// MatchesAny reports whether any of the package URLs matches a feed spec. A
// list containing purl.TruncatedMarker matches whenever the feed is
// non-empty, because the truncated part may contain affected packages.
func (m *Matcher) MatchesAny(packagePURLs []string) bool {
	if len(m.specs) == 0 {
		return false
	}

	for _, raw := range packagePURLs {
		if raw == purl.TruncatedMarker {
			return true
		}

		if m.Matches(raw) {
			return true
		}
	}

	return false
}

// Matches reports whether a single package URL matches a feed spec. The
// package itself and the upstream source package recorded in its "upstream"
// qualifier are both compared, because distribution feeds name source
// packages while SBOMs name binary packages. Package URLs without a version,
// or with versions that cannot be compared, match conservatively.
func (m *Matcher) Matches(packagePURL string) bool {
	if !m.mayMatch(packagePURL) {
		return false
	}

	parsed, err := purl.Parse(packagePURL)
	if err != nil {
		return false
	}

	if m.matchesKey(parsed.Key(), parsed.Version) {
		return true
	}

	upstreamKey, upstreamVersion := parsed.UpstreamKey()

	return upstreamKey != "" && m.matchesKey(upstreamKey, upstreamVersion)
}

func (m *Matcher) matchesKey(key, version string) bool {
	for _, spec := range m.specs[key] {
		if spec.matches(version) {
			return true
		}
	}

	return false
}

// mayMatch is a cheap pre-filter that avoids fully parsing package URLs whose
// name is not in the feed. Package URLs with an upstream qualifier always
// pass because their source package name differs.
func (m *Matcher) mayMatch(packagePURL string) bool {
	// Qualifier keys are case-insensitive, like in purl.Parse.
	if strings.Contains(strings.ToLower(packagePURL), upstreamQualifier) {
		return true
	}

	typ, name, ok := typeAndName(packagePURL)
	if !ok {
		return false
	}

	_, found := m.names[strings.ToLower(purl.NormalizeName(typ, name))]

	return found
}

// typeAndName extracts the type and (decoded) name of a package URL without
// allocating a parsed representation.
func typeAndName(raw string) (typ, name string, ok bool) {
	const scheme = "pkg:"

	if len(raw) < len(scheme) || !strings.EqualFold(raw[:len(scheme)], scheme) {
		return "", "", false
	}

	rest := strings.TrimLeft(raw[len(scheme):], "/")

	if idx := strings.IndexAny(rest, "?#"); idx >= 0 {
		rest = rest[:idx]
	}

	rest = strings.TrimRight(rest, "/")

	typ, path, found := strings.Cut(rest, "/")
	if !found || path == "" {
		return "", "", false
	}

	if at := strings.LastIndex(path, "@"); at > strings.LastIndex(path, "/") {
		path = path[:at]
	}

	// Like purl.Parse, empty path segments (for example a slash before the
	// version) do not count as the name.
	path = strings.TrimRight(path, "/")
	name = path[strings.LastIndex(path, "/")+1:]

	if strings.Contains(name, "%") {
		decoded, err := url.PathUnescape(name)
		if err == nil {
			name = decoded
		}
	}

	return typ, name, name != ""
}

func (s *matchSpec) matches(version string) bool {
	if s.any || version == "" {
		return true
	}

	if s.version != "" {
		return versionsEqual(s.version, version)
	}

	for _, constraint := range s.constraints {
		ok, known := satisfies(version, constraint)
		if !known {
			return true
		}

		if !ok {
			return false
		}
	}

	return true
}

func normalizeVersion(version string) string {
	return strings.TrimPrefix(strings.TrimSpace(version), "v")
}

// versionsEqual compares versions semantically when both parse as semantic
// versions ("1.0" equals "1.0.0"), and textually otherwise.
func versionsEqual(left, right string) bool {
	if cmp, valid := compareSemver(left, right); valid {
		return cmp == 0
	}

	return normalizeVersion(left) == normalizeVersion(right)
}

func satisfies(version, constraint string) (ok, known bool) {
	operators := []string{">=", "<=", ">", "<", "="}

	for _, operator := range operators {
		bound, found := strings.CutPrefix(constraint, operator)
		if !found {
			continue
		}

		cmp, valid := compareSemver(version, bound)
		if !valid {
			return false, false
		}

		// Semantic versioning ignores build metadata, but some ecosystems
		// (for example Pub) order by it. Versions that only differ in build
		// metadata cannot be ordered reliably, so the constraint is unknown
		// and the spec matches conservatively.
		if cmp == 0 && buildMetadata(version) != buildMetadata(bound) {
			return false, false
		}

		return compareWithOperator(operator, cmp), true
	}

	return false, false
}

// compareWithOperator applies a vers comparison operator to the result of
// comparing a version with a bound.
func compareWithOperator(operator string, cmp int) bool {
	switch operator {
	case ">=":
		return cmp >= 0
	case "<=":
		return cmp <= 0
	case ">":
		return cmp > 0
	case "<":
		return cmp < 0
	default:
		return cmp == 0
	}
}

// buildMetadata returns the build metadata of a version ("" when absent).
func buildMetadata(version string) string {
	_, metadata, _ := strings.Cut(normalizeVersion(version), "+")

	return metadata
}

// compareSemver compares two semantic versions (an optional "v" prefix is
// ignored, missing minor or patch parts count as zero, build metadata is
// ignored). The boolean is false when either version is not semver.
func compareSemver(left, right string) (int, bool) {
	leftCore, leftPre, leftOK := splitSemver(left)
	rightCore, rightPre, rightOK := splitSemver(right)

	if !leftOK || !rightOK {
		return 0, false
	}

	for idx := range semverParts {
		if leftCore[idx] != rightCore[idx] {
			if leftCore[idx] < rightCore[idx] {
				return -1, true
			}

			return 1, true
		}
	}

	return comparePrerelease(leftPre, rightPre), true
}

func splitSemver(version string) (core [semverParts]int, prerelease string, ok bool) {
	version = normalizeVersion(version)
	version, _, _ = strings.Cut(version, "+")
	version, prerelease, _ = strings.Cut(version, "-")

	parts := strings.Split(version, ".")
	if len(parts) == 0 || len(parts) > semverParts {
		return core, "", false
	}

	for idx, part := range parts {
		value, err := strconv.Atoi(part)
		if err != nil || value < 0 {
			return core, "", false
		}

		core[idx] = value
	}

	return core, prerelease, true
}

func comparePrerelease(left, right string) int {
	switch {
	case left == right:
		return 0
	case left == "":
		return 1
	case right == "":
		return -1
	}

	leftIDs, rightIDs := strings.Split(left, "."), strings.Split(right, ".")

	for idx := range min(len(leftIDs), len(rightIDs)) {
		if cmp := compareIdentifier(leftIDs[idx], rightIDs[idx]); cmp != 0 {
			return cmp
		}
	}

	switch {
	case len(leftIDs) < len(rightIDs):
		return -1
	case len(leftIDs) > len(rightIDs):
		return 1
	default:
		return 0
	}
}

func compareIdentifier(left, right string) int {
	leftNum, leftErr := strconv.Atoi(left)
	rightNum, rightErr := strconv.Atoi(right)

	switch {
	case leftErr == nil && rightErr == nil:
		return leftNum - rightNum
	case leftErr == nil:
		return -1
	case rightErr == nil:
		return 1
	default:
		return strings.Compare(left, right)
	}
}

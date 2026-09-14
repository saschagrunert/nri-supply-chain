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

// Package openvex implements VEX verification using the OpenVEX format.
package openvex

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	openvex "github.com/openvex/go-vex/pkg/vex"

	"github.com/saschagrunert/nri-supply-chain/internal/purl"
	"github.com/saschagrunert/nri-supply-chain/internal/vex/imagematch"
)

// Result holds the outcome of an OpenVEX verification.
type Result struct {
	// AffectedNames lists vulnerabilities whose effective status is affected
	// (including statements with unknown statuses).
	AffectedNames []string
	// HasUnderInvestigation is true when any effective status is
	// under_investigation.
	HasUnderInvestigation bool
	// MatchedStatements counts the statements that apply to the image after
	// precedence resolution. Zero means the documents say nothing about the
	// image.
	MatchedStatements int
}

// Document is a parsed OpenVEX document.
type Document struct {
	doc *openvex.VEX
}

// Parse parses an OpenVEX predicate.
func Parse(predicate []byte) (*Document, error) {
	doc, err := openvex.Parse(predicate)
	if err != nil {
		return nil, fmt.Errorf("parsing OpenVEX: %w", err)
	}

	return &Document{doc: doc}, nil
}

// Verify parses a single OpenVEX predicate and evaluates it for the image.
func Verify(ctx context.Context, predicate []byte, image *imagematch.Image) (*Result, error) {
	doc, err := Parse(predicate)
	if err != nil {
		return nil, err
	}

	return Evaluate(ctx, []*Document{doc}, image)
}

// candidate is a statement that applies to the image, reduced to what
// precedence resolution needs.
type candidate struct {
	rank      int
	vulnName  string
	timestamp time.Time
	strength  imagematch.Strength
	// lenient and tagConflict mirror statementMatch.lenientOnly and
	// statementMatch.tagConflict.
	lenient     bool
	tagConflict bool
	// packageScope and packageKey are set for a lenient candidate whose
	// statement also names packages: when the lenient match is dropped, the
	// candidate applies to the group of those packages instead.
	packageScope string
	packageKey   string
}

// statementGroup collects the candidates for one vulnerability, product
// scope, and subcomponent scope.
type statementGroup struct {
	productScope string
	candidates   []candidate
}

// Evaluate resolves the statements of all documents that apply to the image.
// Statements apply when a product identifies the image or, because the
// document is bound to the image digest, a package contained in it.
// Statements that can only raise severity (affected, under_investigation,
// unknown statuses) also apply when a product names the image with a
// different tag or namespace, as long as no digest contradicts it. Such
// lenient matches are ignored for a vulnerability that a strict statement
// covers, and lenient matches naming another tag are ignored when any
// statement identifies the image strictly, since the documents then
// distinguish the image from its other versions.
//
// Statements are grouped by vulnerability, product scope (the image or the
// matched packages, including their versions), and subcomponent scope. Within
// a group the result does not depend on statement or document order:
//
//   - among statements of the same match strength, the most recent dated
//     statement wins (statement last_updated or timestamp, falling back to
//     the document timestamp), and equal timestamps resolve to the most
//     restrictive status;
//   - a statement that only names the image or a package is considered when it
//     is not older than the most recent digest-bound statement, and then it can
//     raise the result but never lower it;
//   - a statement without any timestamp ties with every other statement, so
//     it raises the result to its status when that is more restrictive.
//
// Unknown statuses are treated as affected.
func Evaluate(ctx context.Context, docs []*Document, image *imagematch.Image) (*Result, error) {
	groups := make(map[string]*statementGroup)

	for _, doc := range docs {
		docTime := documentTime(doc.doc)

		for idx := range doc.doc.Statements {
			ctxErr := ctx.Err()
			if ctxErr != nil {
				return nil, fmt.Errorf("verification cancelled: %w", ctxErr)
			}

			stmt := &doc.doc.Statements[idx]

			match := matchStatement(ctx, stmt, image)
			if match.strength == imagematch.StrengthNone {
				continue
			}

			if !isKnownStatus(stmt.Status) {
				slog.WarnContext(ctx, "Unrecognized OpenVEX status, treating as affected",
					"status", stmt.Status, "vulnerability", vulnerabilityName(stmt))
			}

			key := statementKey(stmt, match.scope)

			group, exists := groups[key]
			if !exists {
				group = &statementGroup{productScope: match.scope, candidates: nil}
				groups[key] = group
			}

			packageKey := ""
			if match.packageScope != "" {
				packageKey = statementKey(stmt, match.packageScope)
			}

			group.candidates = append(group.candidates, candidate{
				rank:         statusRank(stmt.Status),
				vulnName:     vulnerabilityName(stmt),
				timestamp:    statementTime(stmt, docTime),
				strength:     match.strength,
				lenient:      match.lenientOnly,
				tagConflict:  match.tagConflict,
				packageScope: match.packageScope,
				packageKey:   packageKey,
			})
		}
	}

	dropSupersededLenientCandidates(groups)

	return summarize(groups), nil
}

// dropSupersededLenientCandidates removes lenient matches that strict
// statements make unnecessary: within a group, a statement that identifies
// the image strictly speaks for the vulnerability, so lenient matches (for
// example a different namespace) are ignored; and when any statement
// identifies the image strictly, the documents distinguish the image from
// its other versions, so lenient matches naming another tag describe those
// versions and are ignored too. A dropped candidate whose statement also names
// packages still applies to those packages. Filtering after all statements
// are collected keeps the result independent of statement and document order.
func dropSupersededLenientCandidates(groups map[string]*statementGroup) {
	strictImage := false

	for _, group := range groups {
		if group.productScope != imageScope {
			continue
		}

		hasStrict := slices.ContainsFunc(
			group.candidates, func(cand candidate) bool { return !cand.lenient },
		)
		if hasStrict {
			strictImage = true
		}
	}

	var dropped []candidate

	for key, group := range groups {
		groupHasStrict := slices.ContainsFunc(group.candidates, func(cand candidate) bool {
			return !cand.lenient
		})

		group.candidates = slices.DeleteFunc(group.candidates, func(cand candidate) bool {
			drop := cand.lenient && (groupHasStrict || (strictImage && cand.tagConflict))
			if drop {
				dropped = append(dropped, cand)
			}

			return drop
		})

		if len(group.candidates) == 0 {
			delete(groups, key)
		}
	}

	addPackageCandidates(groups, dropped)
}

// addPackageCandidates adds dropped lenient candidates to the groups of the
// packages their statements name, as strict package-level candidates.
func addPackageCandidates(groups map[string]*statementGroup, dropped []candidate) {
	for _, cand := range dropped {
		if cand.packageScope == "" {
			continue
		}

		group, exists := groups[cand.packageKey]
		if !exists {
			group = &statementGroup{productScope: cand.packageScope, candidates: nil}
			groups[cand.packageKey] = group
		}

		cand.lenient, cand.tagConflict = false, false
		group.candidates = append(group.candidates, cand)
	}
}

func summarize(groups map[string]*statementGroup) *Result {
	result := &Result{
		AffectedNames:         nil,
		HasUnderInvestigation: false,
		MatchedStatements:     0,
	}

	for _, group := range groups {
		rank, vulnName := group.resolve()

		// Package-level resolutions say nothing about whether the image
		// contains the package, so they do not count as statements about the
		// image. Package-level statements that raise severity do.
		if group.productScope == imageScope || rank > rankResolved {
			result.MatchedStatements++
		}

		switch rank {
		case rankUnderInvestigation:
			result.HasUnderInvestigation = true
		case rankAffected:
			result.AffectedNames = append(result.AffectedNames, vulnName)
		}
	}

	slices.Sort(result.AffectedNames)

	return result
}

// resolve computes the effective status rank of a group and the name to
// report. See Evaluate for the rules.
func (g *statementGroup) resolve() (rank int, vulnName string) {
	var (
		digestWinner, nameWinner *candidate
		undatedRank              = -1
	)

	for idx := range g.candidates {
		cand := &g.candidates[idx]

		if vulnName == "" || cand.vulnName < vulnName {
			vulnName = cand.vulnName
		}

		switch {
		case cand.timestamp.IsZero():
			undatedRank = max(undatedRank, cand.rank)
		case cand.strength >= imagematch.StrengthDigest:
			digestWinner = newerOrMoreRestrictive(digestWinner, cand)
		default:
			nameWinner = newerOrMoreRestrictive(nameWinner, cand)
		}
	}

	return max(undatedRank, datedRank(digestWinner, nameWinner)), vulnName
}

// datedRank combines the dated winners of both match strengths: the name
// winner only counts when there is no digest winner or it is not older.
func datedRank(digestWinner, nameWinner *candidate) int {
	rank := -1

	if digestWinner != nil {
		rank = digestWinner.rank
	}

	if nameWinner != nil &&
		(digestWinner == nil || !nameWinner.timestamp.Before(digestWinner.timestamp)) {
		rank = max(rank, nameWinner.rank)
	}

	return rank
}

// newerOrMoreRestrictive returns the more recent of two dated candidates, or
// the more restrictive one when their timestamps are equal.
func newerOrMoreRestrictive(current, cand *candidate) *candidate {
	switch {
	case current == nil:
		return cand
	case cand.timestamp.After(current.timestamp):
		return cand
	case cand.timestamp.Equal(current.timestamp) && cand.rank > current.rank:
		return cand
	default:
		return current
	}
}

func isKnownStatus(status openvex.Status) bool {
	switch status {
	case openvex.StatusNotAffected, openvex.StatusFixed,
		openvex.StatusUnderInvestigation, openvex.StatusAffected:
		return true
	default:
		return false
	}
}

const (
	rankResolved = iota
	rankUnderInvestigation
	rankAffected
)

func statusRank(status openvex.Status) int {
	switch status {
	case openvex.StatusNotAffected, openvex.StatusFixed:
		return rankResolved
	case openvex.StatusUnderInvestigation:
		return rankUnderInvestigation
	case openvex.StatusAffected:
		return rankAffected
	default:
		return rankAffected
	}
}

func documentTime(doc *openvex.VEX) time.Time {
	if doc.LastUpdated != nil && !doc.LastUpdated.IsZero() {
		return *doc.LastUpdated
	}

	if doc.Timestamp != nil {
		return *doc.Timestamp
	}

	return time.Time{}
}

func statementTime(stmt *openvex.Statement, docTime time.Time) time.Time {
	if stmt.LastUpdated != nil && !stmt.LastUpdated.IsZero() {
		return *stmt.LastUpdated
	}

	if stmt.Timestamp != nil && !stmt.Timestamp.IsZero() {
		return *stmt.Timestamp
	}

	return docTime
}

// statementKey groups statements that talk about the same vulnerability in
// the same product scope (the image itself or the matched packages) and
// subcomponent scope of the image.
func statementKey(stmt *openvex.Statement, productScope string) string {
	vuln := string(stmt.Vulnerability.Name)
	if vuln == "" {
		vuln = stmt.Vulnerability.ID
	}

	scopes := make([]string, 0)

	for idx := range stmt.Products {
		for sidx := range stmt.Products[idx].Subcomponents {
			scopes = append(scopes, subcomponentID(&stmt.Products[idx].Subcomponents[sidx]))
		}
	}

	slices.Sort(scopes)
	scopes = slices.Compact(scopes)

	return strings.ToLower(vuln) + "\x00" + productScope + "\x00" + strings.Join(scopes, "\x00")
}

func subcomponentID(sub *openvex.Subcomponent) string {
	if sub.ID != "" {
		return sub.ID
	}

	ids := make([]string, 0, len(sub.Identifiers)+len(sub.Hashes))
	for _, id := range sub.Identifiers {
		ids = append(ids, id)
	}

	for alg, hash := range sub.Hashes {
		ids = append(ids, string(alg)+":"+string(hash))
	}

	slices.Sort(ids)

	return strings.Join(ids, ",")
}

func vulnerabilityName(stmt *openvex.Statement) string {
	if vulnName := string(stmt.Vulnerability.Name); vulnName != "" {
		return vulnName
	}

	if stmt.Vulnerability.ID != "" {
		return stmt.Vulnerability.ID
	}

	return "unknown"
}

// imageScope is the product scope of statements about the image itself.
const imageScope = "image"

// statementMatch describes how a statement applies to the image.
type statementMatch struct {
	// strength is the strongest match over the statement's products.
	strength imagematch.Strength
	// scope is imageScope when a product identifies the image, otherwise the
	// sorted identity keys of the matched packages.
	scope string
	// lenientOnly is set when only lenient name matching identified the
	// image (see imagematch.Image.MatchLenient).
	lenientOnly bool
	// tagConflict is set for a lenient-only match that names another tag of
	// the image.
	tagConflict bool
	// packageScope is set for a lenient-only match to the sorted identity keys
	// of the matched packages, if any.
	packageScope string
}

//nolint:cyclop // sequential product match classification
func matchStatement(
	ctx context.Context, stmt *openvex.Statement, image *imagematch.Image,
) statementMatch {
	match := statementMatch{
		strength: imagematch.StrengthNone, scope: "", lenientOnly: false, tagConflict: false,
		packageScope: "",
	}

	if len(stmt.Products) == 0 {
		slog.WarnContext(
			ctx,
			"VEX statement has no products, skipping (requires explicit product match)",
		)

		return match
	}

	var (
		imageMatched, strictImage, lenientWithoutTagConflict bool
		packages                                             []string
	)

	lenient := statusRank(stmt.Status) > rankResolved

	for idx := range stmt.Products {
		component := componentMatch(&stmt.Products[idx].Component, image, lenient)

		switch component.kind {
		case imagematch.KindImage:
			imageMatched = true
			strictImage = strictImage || !component.lenientOnly
			lenientWithoutTagConflict = lenientWithoutTagConflict ||
				(component.lenientOnly && !component.tagConflict)
		case imagematch.KindPackage:
			packages = append(packages, component.packageKey)
		case imagematch.KindOtherImage, imagematch.KindUnrelated:
			continue
		}

		match.strength = max(match.strength, component.strength)
	}

	slices.Sort(packages)
	packageScope := strings.Join(slices.Compact(packages), ",")

	switch {
	case imageMatched:
		match.scope = imageScope
		match.lenientOnly = !strictImage
		match.tagConflict = match.lenientOnly && !lenientWithoutTagConflict

		if match.lenientOnly {
			match.packageScope = packageScope
		}
	case len(packages) > 0:
		match.scope = packageScope
	}

	return match
}

// componentResult describes how a product component relates to the image.
type componentResult struct {
	kind     imagematch.Kind
	strength imagematch.Strength
	// packageKey is set for KindPackage and includes the package version.
	packageKey string
	// lenientOnly is set when only imagematch.Image.MatchLenient identified
	// the image.
	lenientOnly bool
	// tagConflict is set for a lenient image match whose identifiers all name
	// a tag other than the image tag.
	tagConflict bool
}

// componentMatch classifies a product component. Image identities (digests,
// image purls, hashes) take precedence over package purls; packageKey is set
// for KindPackage and includes the package version, so statements about
// different versions of a package do not override each other. lenient also
// tries imagematch.Image.MatchLenient for statements that can only raise
// severity, when strict matching does not identify the image.
func componentMatch(
	component *openvex.Component, image *imagematch.Image, lenient bool,
) componentResult {
	if hashMatches(component, image) {
		return componentResult{
			kind: imagematch.KindImage, strength: imagematch.StrengthDigest,
			packageKey: "", lenientOnly: false, tagConflict: false,
		}
	}

	strict := matchComponentIdentifiers(component, image.Match)
	if !lenient || strict.kind == imagematch.KindImage {
		return strict
	}

	loose := matchComponentIdentifiers(component, image.MatchLenient)
	if loose.kind != imagematch.KindImage {
		return strict
	}

	loose.lenientOnly = true
	loose.tagConflict = true

	for _, identifier := range componentIdentifiers(component) {
		if kind, _ := image.MatchLenient(identifier); kind == imagematch.KindImage &&
			!image.TagConflicts(identifier) {
			loose.tagConflict = false
		}
	}

	return loose
}

func componentIdentifiers(component *openvex.Component) []string {
	identifiers := make([]string, 0, len(component.Identifiers)+1)
	identifiers = append(identifiers, component.ID)

	for _, identifier := range component.Identifiers {
		identifiers = append(identifiers, identifier)
	}

	return identifiers
}

// matchComponentIdentifiers classifies the identifiers of a component with
// matchIdentifier, keeping the strongest image match.
func matchComponentIdentifiers(
	component *openvex.Component,
	matchIdentifier func(string) (imagematch.Kind, imagematch.Strength),
) componentResult {
	kind, strength, packageKey := imagematch.KindUnrelated, imagematch.StrengthNone, ""

	for _, identifier := range componentIdentifiers(component) {
		idKind, idStrength := matchIdentifier(identifier)

		switch {
		case idKind == imagematch.KindImage && idStrength > strength:
			kind, strength, packageKey = idKind, idStrength, ""
		case idKind == imagematch.KindPackage && kind != imagematch.KindImage:
			parsed, err := purl.Parse(identifier)
			if err == nil {
				kind, strength, packageKey = idKind, idStrength, packageScopeKey(&parsed)
			}
		}
	}

	return componentResult{
		kind: kind, strength: strength, packageKey: packageKey,
		lenientOnly: false, tagConflict: false,
	}
}

// hashMatches reports whether any product hash equals an image digest.
func hashMatches(component *openvex.Component, image *imagematch.Image) bool {
	for algorithm, hash := range component.Hashes {
		if image.MatchesHash(string(algorithm), string(hash)) {
			return true
		}
	}

	return false
}

// packageScopeKey identifies a package and its version. A versionless purl
// gets its own scope, so it can raise severity for the package but never
// resolve a statement about a specific version.
func packageScopeKey(parsed *purl.PURL) string {
	if parsed.Version == "" {
		return parsed.Key()
	}

	return parsed.Key() + "@" + parsed.Version
}

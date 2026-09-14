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

package openvex_test

import (
	"context"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"

	openvexlib "github.com/openvex/go-vex/pkg/vex"

	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/vex/openvex"
)

const (
	orderNamePURL   = "pkg:oci/myimage"
	orderDigestPURL = "pkg:oci/myimage@" + testDigest
	retaggedPURL    = "pkg:oci/myimage?tag=build-42"
)

// parseDoc marshals and parses a document with the given statements.
func parseDoc(
	t *testing.T,
	timestamp *time.Time,
	statements ...openvexlib.Statement,
) *openvex.Document {
	t.Helper()

	doc := openvexlib.VEX{
		Context:    testVEXContext,
		ID:         testDocID,
		Timestamp:  timestamp,
		Statements: statements,
	}

	parsed, err := openvex.Parse(testutil.MustMarshal(t, doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	return parsed
}

func evaluateDocs(t *testing.T, docs []*openvex.Document) *openvex.Result {
	t.Helper()

	result, err := openvex.Evaluate(context.Background(), docs, testImage())
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}

	return result
}

// resultFingerprint is the order-independent part of a result.
type resultFingerprint struct {
	affected           string
	underInvestigation bool
	matched            int
}

func fingerprint(result *openvex.Result) resultFingerprint {
	names := slices.Clone(result.AffectedNames)
	slices.Sort(names)

	return resultFingerprint{
		affected:           strings.Join(names, ","),
		underInvestigation: result.HasUnderInvestigation,
		matched:            result.MatchedStatements,
	}
}

func permutations(size int) [][]int {
	if size == 0 {
		return [][]int{{}}
	}

	var perms [][]int

	for _, perm := range permutations(size - 1) {
		for pos := 0; pos <= len(perm); pos++ {
			next := make([]int, 0, size)
			next = append(next, perm[:pos]...)
			next = append(next, size-1)
			next = append(next, perm[pos:]...)
			perms = append(perms, next)
		}
	}

	return perms
}

// poolEntry is a single-statement document with the facts the reference
// verdict needs.
type poolEntry struct {
	doc       *openvex.Document
	status    openvexlib.Status
	digest    bool
	timestamp *time.Time
}

// statementPool returns single-statement documents covering statuses, match
// strengths, and timestamps (including undated ones).
func statementPool(t *testing.T) []poolEntry {
	t.Helper()

	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	times := []*time.Time{nil, new(base), new(base.Add(time.Hour))}
	statuses := []openvexlib.Status{
		openvexlib.StatusAffected,
		openvexlib.StatusNotAffected,
		openvexlib.StatusUnderInvestigation,
	}
	products := []string{orderDigestPURL, orderNamePURL}

	pool := make([]poolEntry, 0, len(times)*len(statuses)*len(products))

	for _, status := range statuses {
		for _, product := range products {
			for _, timestamp := range times {
				pool = append(pool, poolEntry{
					doc:       parseDoc(t, nil, productStatement(status, product, timestamp)),
					status:    status,
					digest:    product == orderDigestPURL,
					timestamp: timestamp,
				})
			}
		}
	}

	return pool
}

// severity orders statuses for the reference verdict.
func severity(status openvexlib.Status) int {
	return slices.Index([]openvexlib.Status{
		openvexlib.StatusNotAffected,
		openvexlib.StatusUnderInvestigation,
		openvexlib.StatusAffected,
	}, status)
}

// referenceVerdict states the documented precedence for statements about
// one vulnerability of the image, independently of the implementation:
//
//   - an undated statement ties with everything, so the most severe undated
//     status is a lower bound;
//   - per match strength, the latest dated statement counts, and statements
//     with the same timestamp count with their most severe status;
//   - the digest-bound statement counts; the name-only statement counts too,
//     but only when there is no digest-bound one or it is not older;
//   - the verdict is the most severe counting status.
func referenceVerdict(entries []poolEntry) resultFingerprint {
	if len(entries) == 0 {
		return resultFingerprint{affected: "", underInvestigation: false, matched: 0}
	}

	verdict := -1

	latest := map[bool][]poolEntry{}

	for _, entry := range entries {
		if entry.timestamp == nil {
			verdict = max(verdict, severity(entry.status))

			continue
		}

		latest[entry.digest] = append(latest[entry.digest], entry)
	}

	winner := func(candidates []poolEntry) (time.Time, int, bool) {
		if len(candidates) == 0 {
			return time.Time{}, 0, false
		}

		newest := slices.MaxFunc(candidates, func(a, b poolEntry) int {
			return a.timestamp.Compare(*b.timestamp)
		}).timestamp

		worst := -1

		for _, candidate := range candidates {
			if candidate.timestamp.Equal(*newest) {
				worst = max(worst, severity(candidate.status))
			}
		}

		return *newest, worst, true
	}

	digestTime, digestSeverity, hasDigest := winner(latest[true])
	nameTime, nameSeverity, hasName := winner(latest[false])

	if hasDigest {
		verdict = max(verdict, digestSeverity)
	}

	if hasName && (!hasDigest || !nameTime.Before(digestTime)) {
		verdict = max(verdict, nameSeverity)
	}

	fingerprint := resultFingerprint{affected: "", underInvestigation: false, matched: 1}

	switch verdict {
	case severity(openvexlib.StatusAffected):
		fingerprint.affected = testCVE
	case severity(openvexlib.StatusUnderInvestigation):
		fingerprint.underInvestigation = true
	}

	return fingerprint
}

func assertOrderIndependent(t *testing.T, entries []poolEntry, perms [][]int) {
	t.Helper()

	want := referenceVerdict(entries)

	for _, perm := range perms {
		ordered := make([]*openvex.Document, len(perm))
		for pos, docIdx := range perm {
			ordered[pos] = entries[docIdx].doc
		}

		if got := fingerprint(evaluateDocs(t, ordered)); got != want {
			t.Fatalf(
				"permutation %v: got %+v, reference verdict %+v", perm, got, want,
			)
		}
	}
}

func TestEvaluateOrderIndependentExhaustive(t *testing.T) {
	t.Parallel()

	pool := statementPool(t)
	perms := permutations(3)

	for first := range pool {
		for second := range pool {
			for third := range pool {
				assertOrderIndependent(
					t,
					[]poolEntry{pool[first], pool[second], pool[third]},
					perms,
				)
			}
		}
	}
}

func TestEvaluateOrderIndependentRandomized(t *testing.T) {
	t.Parallel()

	pool := statementPool(t)
	rng := rand.New(rand.NewPCG(42, 7)) //nolint:gosec // deterministic test data

	const (
		sets         = 300
		setSize      = 6
		permutations = 40
	)

	for range sets {
		entries := make([]poolEntry, setSize)
		for idx := range entries {
			entries[idx] = pool[rng.IntN(len(pool))]
		}

		perms := make([][]int, permutations)
		for idx := range perms {
			perms[idx] = rng.Perm(setSize)
		}

		assertOrderIndependent(t, entries, perms)
	}
}

func TestEvaluateOrderIndependentScenarios(t *testing.T) {
	t.Parallel()

	t1 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := t1.Add(time.Hour)
	t3 := t2.Add(time.Hour)

	t.Run("newer name-only affected raises digest-bound resolution", func(t *testing.T) {
		t.Parallel()

		scanner := parseDoc(t, nil, productStatement(openvexlib.StatusAffected, orderNamePURL, &t3))
		vendor := parseDoc(t, nil,
			productStatement(openvexlib.StatusAffected, orderDigestPURL, &t1),
			productStatement(openvexlib.StatusNotAffected, orderDigestPURL, &t2),
		)

		for _, docs := range [][]*openvex.Document{{scanner, vendor}, {vendor, scanner}} {
			if result := evaluateDocs(t, docs); len(result.AffectedNames) != 1 {
				t.Errorf("expected affected, got %+v", result)
			}
		}
	})

	t.Run("undated affected ties with a later resolution", func(t *testing.T) {
		t.Parallel()

		t5 := t1.Add(5 * time.Hour)
		t10 := t1.Add(10 * time.Hour)

		doc := parseDoc(t, nil,
			productStatement(openvexlib.StatusAffected, orderDigestPURL, nil),
			productStatement(openvexlib.StatusAffected, orderDigestPURL, &t5),
			productStatement(openvexlib.StatusNotAffected, orderDigestPURL, &t10),
		)

		if result := evaluateDocs(t, []*openvex.Document{doc}); len(result.AffectedNames) != 1 {
			t.Errorf("expected affected, got %+v", result)
		}
	})
}

func TestEvaluatePackageScopeIncludesVersion(t *testing.T) {
	t.Parallel()

	older := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	newer := older.Add(time.Hour)

	tests := []struct {
		name         string
		statements   []openvexlib.Statement
		wantAffected bool
	}{
		{
			name: "fixed for another version does not hide affected",
			statements: []openvexlib.Statement{
				productStatement(openvexlib.StatusAffected, "pkg:npm/lodash@4.17.20", &older),
				productStatement(openvexlib.StatusFixed, "pkg:npm/lodash@4.17.21", &newer),
			},
			wantAffected: true,
		},
		{
			name: "versionless not_affected does not lower a versioned affected",
			statements: []openvexlib.Statement{
				productStatement(openvexlib.StatusAffected, "pkg:npm/lodash@4.17.20", &older),
				productStatement(openvexlib.StatusNotAffected, "pkg:npm/lodash", &newer),
			},
			wantAffected: true,
		},
		{
			name: "versionless affected raises a versioned not_affected",
			statements: []openvexlib.Statement{
				productStatement(openvexlib.StatusNotAffected, "pkg:npm/lodash@4.17.20", &newer),
				productStatement(openvexlib.StatusAffected, "pkg:npm/lodash", &older),
			},
			wantAffected: true,
		},
		{
			name: "same version later fixed resolves",
			statements: []openvexlib.Statement{
				productStatement(openvexlib.StatusAffected, "pkg:npm/lodash@4.17.20", &older),
				productStatement(openvexlib.StatusFixed, "pkg:npm/lodash@4.17.20", &newer),
			},
			wantAffected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			result := evaluateDocs(t, []*openvex.Document{parseDoc(t, nil, test.statements...)})
			if got := len(result.AffectedNames) > 0; got != test.wantAffected {
				t.Errorf("expected affected=%v, got %+v", test.wantAffected, result)
			}
		})
	}
}

func TestEvaluatePackageResolutionKeepsNoMatch(t *testing.T) {
	t.Parallel()

	timestamp := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	result := evaluateDocs(t, []*openvex.Document{parseDoc(t, nil,
		productStatement(openvexlib.StatusNotAffected, "pkg:npm/express@4.0.0", &timestamp),
	)})

	if result.MatchedStatements != 0 || len(result.AffectedNames) != 0 {
		t.Errorf("expected a package-only resolution to leave the image unmatched, got %+v", result)
	}

	result = evaluateDocs(t, []*openvex.Document{parseDoc(t, nil,
		productStatement(openvexlib.StatusAffected, "pkg:npm/express@4.0.0", &timestamp),
	)})

	if result.MatchedStatements != 1 || len(result.AffectedNames) != 1 {
		t.Errorf("expected a package-level affected to count, got %+v", result)
	}
}

func vulnStatement(
	vuln string, status openvexlib.Status, productID string, timestamp *time.Time,
) openvexlib.Statement {
	stmt := productStatement(status, productID, timestamp)
	stmt.Vulnerability = openvexlib.Vulnerability{Name: openvexlib.VulnerabilityID(vuln)}

	return stmt
}

// productsStatement is a statement about testCVE with several products.
func productsStatement(
	status openvexlib.Status, timestamp *time.Time, productIDs ...string,
) openvexlib.Statement {
	stmt := productStatement(status, productIDs[0], timestamp)
	for _, productID := range productIDs[1:] {
		stmt.Products = append(stmt.Products, openvexlib.Product{ID: productID})
	}

	return stmt
}

func TestEvaluateLenientMatchesYieldToStrictStatements(t *testing.T) {
	t.Parallel()

	timestamp := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name       string
		statements []openvexlib.Statement
		wantAffect []string
	}{
		{
			name: "multi-version document: the statement for the image tag wins",
			statements: []openvexlib.Statement{
				vulnStatement(
					testCVE, openvexlib.StatusAffected, "pkg:oci/myimage?tag=v0", &timestamp,
				),
				vulnStatement(
					testCVE, openvexlib.StatusFixed, "pkg:oci/myimage?tag=v1", &timestamp,
				),
			},
			wantAffect: nil,
		},
		{
			name: "a tag for another version does not apply when the document names the image",
			statements: []openvexlib.Statement{
				vulnStatement(
					"CVE-2024-0001", openvexlib.StatusAffected,
					"pkg:oci/myimage?tag=v0", &timestamp,
				),
				vulnStatement(
					"CVE-2024-0002", openvexlib.StatusNotAffected,
					"pkg:oci/myimage?tag=v1", &timestamp,
				),
			},
			wantAffect: nil,
		},
		{
			name: "a strict match for the vulnerability overrides a newer lenient match",
			statements: []openvexlib.Statement{
				vulnStatement(testCVE, openvexlib.StatusFixed, orderDigestPURL, &timestamp),
				vulnStatement(testCVE, openvexlib.StatusAffected, "pkg:docker/otherorg/myimage",
					new(timestamp.Add(time.Hour))),
			},
			wantAffect: nil,
		},
		{
			name: "a dropped tag match keeps the packages of its statement",
			statements: []openvexlib.Statement{
				productsStatement(
					openvexlib.StatusAffected, &timestamp,
					"pkg:oci/myimage?tag=v0", "pkg:npm/lodash@4.17.20",
				),
				vulnStatement(
					"CVE-2024-0002", openvexlib.StatusNotAffected, orderDigestPURL, &timestamp,
				),
			},
			wantAffect: []string{testCVE},
		},
		{
			name: "a lenient match yielding to a strict statement keeps its packages",
			statements: []openvexlib.Statement{
				vulnStatement(testCVE, openvexlib.StatusFixed, orderDigestPURL, &timestamp),
				productsStatement(
					openvexlib.StatusAffected, new(timestamp.Add(time.Hour)),
					"pkg:docker/otherorg/myimage", "pkg:npm/lodash@4.17.20",
				),
			},
			wantAffect: []string{testCVE},
		},
		{
			name: "a retagged image without strict statements still applies",
			statements: []openvexlib.Statement{
				vulnStatement(testCVE, openvexlib.StatusAffected, retaggedPURL, &timestamp),
			},
			wantAffect: []string{testCVE},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			for _, perm := range permutations(len(test.statements)) {
				docs := make([]*openvex.Document, 0, len(perm))
				for _, idx := range perm {
					docs = append(docs, parseDoc(t, nil, test.statements[idx]))
				}

				result := evaluateDocs(t, docs)
				if !slices.Equal(result.AffectedNames, test.wantAffect) {
					t.Fatalf(
						"order %v: affected = %v, want %v",
						perm, result.AffectedNames, test.wantAffect,
					)
				}
			}
		})
	}
}

func TestEvaluateUnresolvedStatusesMatchNamesLeniently(t *testing.T) {
	t.Parallel()

	timestamp := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	otherDigest := "sha256:" + "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

	tests := []struct {
		name        string
		status      openvexlib.Status
		product     string
		wantMatched int
		wantAffect  bool
		wantUI      bool
	}{
		{
			name: "affected with a different tag applies", status: openvexlib.StatusAffected,
			product: retaggedPURL, wantMatched: 1, wantAffect: true, wantUI: false,
		},
		{
			name:    "under_investigation with a different namespace applies",
			status:  openvexlib.StatusUnderInvestigation,
			product: "pkg:docker/otherorg/myimage", wantMatched: 1, wantAffect: false, wantUI: true,
		},
		{
			name:   "not_affected with a different tag stays strict",
			status: openvexlib.StatusNotAffected, product: retaggedPURL,
			wantMatched: 0, wantAffect: false, wantUI: false,
		},
		{
			name:   "affected for a different digest does not apply",
			status: openvexlib.StatusAffected, product: "pkg:oci/myimage@" + otherDigest,
			wantMatched: 0, wantAffect: false, wantUI: false,
		},
		{
			name:   "affected for a different image name does not apply",
			status: openvexlib.StatusAffected, product: "pkg:oci/otherimage?tag=v1",
			wantMatched: 0, wantAffect: false, wantUI: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			result := evaluateDocs(t, []*openvex.Document{
				parseDoc(t, nil, productStatement(test.status, test.product, &timestamp)),
			})

			if result.MatchedStatements != test.wantMatched ||
				(len(result.AffectedNames) > 0) != test.wantAffect ||
				result.HasUnderInvestigation != test.wantUI {
				t.Errorf("unexpected result %+v", result)
			}
		})
	}
}

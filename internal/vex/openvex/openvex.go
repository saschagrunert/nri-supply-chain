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

	openvex "github.com/openvex/go-vex/pkg/vex"
)

// Result holds the outcome of an OpenVEX verification.
type Result struct {
	AffectedNames         []string
	HasUnderInvestigation bool
}

// Verify checks an OpenVEX predicate and returns the verification result.
// The purl parameter is the pre-computed OCI Package URL for the image.
func Verify(
	ctx context.Context,
	predicate []byte,
	imageDigest, purl string,
) (*Result, error) {
	doc, err := openvex.Parse(predicate)
	if err != nil {
		return nil, fmt.Errorf("parsing OpenVEX: %w", err)
	}

	var (
		affectedNames         []string
		hasUnderInvestigation bool
	)

	for idx := range doc.Statements {
		stmt := &doc.Statements[idx]

		if !matchesImage(ctx, stmt, imageDigest, purl) {
			continue
		}

		switch stmt.Status {
		case openvex.StatusAffected:
			affectedNames = append(affectedNames, vulnerabilityName(stmt))

		case openvex.StatusUnderInvestigation:
			hasUnderInvestigation = true

		case openvex.StatusNotAffected, openvex.StatusFixed:
			// These statuses are acceptable.
		}
	}

	return &Result{
		AffectedNames:         affectedNames,
		HasUnderInvestigation: hasUnderInvestigation,
	}, nil
}

func vulnerabilityName(stmt *openvex.Statement) string {
	if vulnName := string(stmt.Vulnerability.Name); vulnName != "" {
		return vulnName
	}

	return "unknown"
}

func matchesImage(ctx context.Context, stmt *openvex.Statement, imageDigest, purl string) bool {
	if len(stmt.Products) == 0 {
		slog.WarnContext(
			ctx,
			"VEX statement has no products, skipping (requires explicit product match)",
		)

		return false
	}

	for idx := range stmt.Products {
		product := &stmt.Products[idx]

		if product.Component.Matches(imageDigest) {
			return true
		}

		if purl != "" && product.Component.Matches(purl) {
			return true
		}
	}

	return false
}

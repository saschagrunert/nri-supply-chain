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
	"context"
	"log/slog"

	"github.com/google/go-containerregistry/pkg/name"
	ociV1 "github.com/google/go-containerregistry/pkg/v1"
)

// referrerSelection is the budgeted set of referrers considered for an image.
type referrerSelection struct {
	bundles   []*ociV1.Descriptor
	notation  []*ociV1.Descriptor
	baselines []*ociV1.Descriptor
	// dropped counts relevant referrers left out because a budget was
	// exhausted or their manifest was oversized.
	dropped int
}

// referrerKind classifies a referrer descriptor for budgeting.
type referrerKind int

const (
	referrerIgnored referrerKind = iota
	referrerBundle
	referrerGenericBundle
	referrerNotation
	referrerBaseline
)

func classifyReferrer(desc *ociV1.Descriptor) referrerKind {
	switch {
	case desc.ArtifactType == bundleMediaType:
		return bundleKind(desc, referrerBundle)
	case isGenericBundleCandidate(desc.ArtifactType):
		return bundleKind(desc, referrerGenericBundle)
	case isNotationCandidate(desc.ArtifactType):
		return referrerNotation
	case isBaselineSBOM(desc.ArtifactType):
		return referrerBaseline
	default:
		return referrerIgnored
	}
}

// bundleKind skips cosign signature bundles, which are not attestations.
func bundleKind(desc *ociV1.Descriptor, kind referrerKind) referrerKind {
	if desc.Annotations[annotationPredicateType] == PredicateCosignSignature {
		return referrerIgnored
	}

	return kind
}

// add places desc into its budgeted bucket and reports whether the referrer
// was dropped because the budget is exhausted or the manifest is oversized.
func (s *referrerSelection) add(kind referrerKind, desc *ociV1.Descriptor) (dropped bool) {
	if kind != referrerIgnored && desc.Size > maxReferrerManifestSize {
		return true
	}

	switch kind {
	case referrerBundle, referrerGenericBundle:
		return !appendBudgeted(&s.bundles, desc, maxReferrers)
	case referrerNotation:
		return !appendBudgeted(&s.notation, desc, maxNotationReferrers)
	case referrerBaseline:
		return !appendBudgeted(&s.baselines, desc, maxBaselineReferrers)
	case referrerIgnored:
		return false
	default:
		return false
	}
}

// appendBudgeted appends desc when the bucket has room and reports whether it
// was added.
func appendBudgeted(bucket *[]*ociV1.Descriptor, desc *ociV1.Descriptor, limit int) bool {
	if len(*bucket) >= limit {
		return false
	}

	*bucket = append(*bucket, desc)

	return true
}

// selectReferrers applies the referrer budget to the distinct referrer
// manifests of an image. Exact Sigstore bundle media types are preferred over
// generic artifact types. Cosign signature bundles (not attestations) and
// unrelated artifact types are skipped before any blob is fetched. Relevant
// referrers that do not fit the budget or whose manifest is oversized are
// counted as dropped; the caller must not evaluate such an incomplete set.
func selectReferrers(ctx context.Context, manifests []ociV1.Descriptor) referrerSelection {
	var (
		selection referrerSelection
		generic   []*ociV1.Descriptor
	)

	seen := make(map[ociV1.Hash]struct{}, len(manifests))

	for idx := range manifests {
		desc := &manifests[idx]

		if _, duplicate := seen[desc.Digest]; duplicate {
			continue
		}

		seen[desc.Digest] = struct{}{}

		kind := classifyReferrer(desc)

		// Generic candidates only get the budget left after exact matches.
		if kind == referrerGenericBundle {
			generic = append(generic, desc)

			continue
		}

		if selection.add(kind, desc) {
			selection.dropped++
		}
	}

	for _, desc := range generic {
		if selection.add(referrerGenericBundle, desc) {
			selection.dropped++
		}
	}

	if selection.dropped > 0 {
		slog.WarnContext(ctx, "Referrer limits exceeded, attestation set is incomplete",
			"dropped", selection.dropped,
			"totalManifests", len(manifests),
			"maxBundles", maxReferrers,
			"maxNotation", maxNotationReferrers,
			"maxBaselines", maxBaselineReferrers,
			"maxManifestSize", maxReferrerManifestSize,
		)
	}

	return selection
}

func isNotationCandidate(artifactType string) bool {
	return artifactType == NotationSignatureMediaType
}

func isBaselineSBOM(artifactType string) bool {
	return artifactType == BaselineSBOMArtifactType
}

func isGenericBundleCandidate(artifactType string) bool {
	return artifactType == ociEmptyMediaType || artifactType == ""
}

func logReferrers(
	ctx context.Context, ref name.Digest, digest string,
	manifests []ociV1.Descriptor,
) {
	if !slog.Default().Enabled(ctx, slog.LevelDebug) {
		return
	}

	slog.DebugContext(ctx, "Referrers lookup result",
		"ref", ref.String(),
		"digest", digest,
		"manifests_count", len(manifests),
	)

	for idx := range manifests {
		if idx >= maxLoggedReferrers {
			break
		}

		slog.DebugContext(ctx, "Referrer manifest",
			"index", idx,
			"artifact_type", manifests[idx].ArtifactType,
			"digest", manifests[idx].Digest.String(),
			"annotations", manifests[idx].Annotations,
		)
	}
}

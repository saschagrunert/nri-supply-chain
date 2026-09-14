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

package verifier

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/google/go-containerregistry/pkg/name"
	"golang.org/x/sync/semaphore"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
	"github.com/saschagrunert/nri-supply-chain/internal/glob"
	"github.com/saschagrunert/nri-supply-chain/internal/imageref"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
)

func acquireFetchSlots(
	ctx context.Context, state *snapshot, host string,
) (release func(), err error) {
	hostSem := acquireHostSem(state.hostSem, host)

	err = hostSem.Acquire(ctx, 1)
	if err != nil {
		return nil, fmt.Errorf("per-host fetch concurrency limit: %w", err)
	}

	err = state.fetchSem.Acquire(ctx, 1)
	if err != nil {
		hostSem.Release(1)

		return nil, fmt.Errorf("fetch concurrency limit: %w", err)
	}

	return func() {
		state.fetchSem.Release(1)
		hostSem.Release(1)
	}, nil
}

const maxHostSemEntries = 1000

type hostSemMap struct {
	m          sync.Map
	count      atomic.Int64
	onOverflow func()
}

func (hsm *hostSemMap) load(host string) (*semaphore.Weighted, bool) {
	value, found := hsm.m.Load(host)
	if !found {
		return nil, false
	}

	weighted, valid := value.(*semaphore.Weighted)

	return weighted, valid
}

func (hsm *hostSemMap) loadOrStore(
	host string, sem *semaphore.Weighted,
) (*semaphore.Weighted, bool) {
	value, loaded := hsm.m.LoadOrStore(host, sem)

	stored, valid := value.(*semaphore.Weighted)
	if !valid {
		return sem, loaded
	}

	return stored, loaded
}

func acquireHostSem(hsm *hostSemMap, host string) *semaphore.Weighted {
	if existing, ok := hsm.load(host); ok {
		return existing
	}

	sem := semaphore.NewWeighted(maxConcurrentFetchesPerHost)

	stored, loaded := hsm.loadOrStore(host, sem)
	if loaded {
		return stored
	}

	newCount := hsm.count.Add(1)

	// Between LoadOrStore and Delete, another goroutine can Load the entry
	// and use the semaphore; this is acceptable since the overflow path
	// only triggers at 1000+ distinct registry hosts.
	if newCount > maxHostSemEntries {
		hsm.m.Delete(host)
		hsm.count.Add(-1)

		slog.Warn("Per-host semaphore map at capacity, using untracked semaphore",
			"host", host, "capacity", maxHostSemEntries)

		if hsm.onOverflow != nil {
			hsm.onOverflow()
		}

		return sem
	}

	return stored
}

// digestRefFromParsed builds a digest reference string using a pre-parsed
// reference, avoiding redundant parsing. Returns imageRef unchanged when
// the parsed reference is nil (e.g. when the initial parse failed).
func digestRefFromParsed(parsedRef name.Reference, imageRef, digest string) string {
	if digest == "" || strings.Contains(imageRef, "@") {
		return imageRef
	}

	if parsedRef == nil {
		slog.Debug("Cannot build digest ref from nil parsed reference",
			"image", imageRef,
		)

		return imageRef
	}

	return parsedRef.Context().Digest(digest).String()
}

// imageMatchForms returns the spellings of an image reference that policy
// patterns are matched against: the reference as reported by the runtime
// and, when it can be parsed, its normalized forms (repository:tag and
// repository@digest, with Docker Hub spelled as "docker.io", plus the bare
// repository for broad matching). When qualifiedOnly is set, normalized
// forms are only added for references that already name a registry host,
// because short names may be resolved to a different registry by the
// container runtime (e.g. unqualified search registries). Relaxing lists
// (exclude, rules) use qualifiedOnly so that they never match more than the
// reference spelled by the runtime; for them the reported reference of a
// digest-pinned image is matched without its tag.
func imageMatchForms(imageRef string, qualifiedOnly bool) []string {
	forms := []string{imageRef}

	if qualifiedOnly {
		// The runtime runs the digest and ignores the tag, so a tag
		// wildcard (e.g. "app:v1.*") must not cover whatever digest is
		// spelled next to a matching tag.
		forms[0] = withoutTagIfDigestPinned(imageRef)

		if !hasRegistryHost(imageRef) {
			return forms
		}
	}

	repository, tag, digest, ok := normalizedReference(imageRef)
	if !ok {
		return forms
	}

	if !qualifiedOnly {
		// The bare repository is only a match target for broad matching;
		// for relaxing lists it would extend a pattern to every tag.
		forms = append(forms, repository)
	}

	// For relaxing lists a digest-pinned reference is only matched by its
	// digest: the runtime runs the digest and ignores the tag, so a tag
	// pattern must not cover whatever digest is spelled next to that tag.
	if tag != "" && (!qualifiedOnly || digest == "") {
		forms = append(forms, repository+":"+tag)
	}

	if digest != "" {
		forms = append(forms, repository+"@"+digest)
	}

	return slices.Compact(forms)
}

// normalizedReference parses an image reference into its fully qualified
// repository name (every Docker Hub alias spelled as docker.io, see
// imageref.NormalizeRepository), tag and digest.
func normalizedReference(imageRef string) (repository, tag, digest string, ok bool) {
	base, digest, hasDigest := strings.Cut(imageRef, "@")
	if !hasDigest {
		base = imageRef
		digest = ""
	}

	ref, err := name.ParseReference(base)
	if err != nil {
		return "", "", "", false
	}

	repository = imageref.NormalizeRepository(ref.Context().Name())

	if tagged, isTag := ref.(name.Tag); isTag && (!hasDigest || explicitTag(base)) {
		tag = tagged.TagStr()
	}

	return repository, tag, digest, true
}

// withoutTagIfDigestPinned removes the tag from a reference that also
// carries a digest ("repo:tag@digest" becomes "repo@digest"). Other
// references are returned unchanged.
func withoutTagIfDigestPinned(imageRef string) string {
	base, digest, hasDigest := strings.Cut(imageRef, "@")
	if !hasDigest || !explicitTag(base) {
		return imageRef
	}

	repository, _ := stripTagPattern(base)

	return repository + "@" + digest
}

// explicitTag reports whether a reference without digest names a tag.
func explicitTag(ref string) bool {
	lastSlash := strings.LastIndex(ref, "/")

	return strings.Contains(ref[lastSlash+1:], ":")
}

// hasRegistryHost reports whether the first path component of a reference
// is a registry host, using the same rule as the Docker CLI.
func hasRegistryHost(imageRef string) bool {
	first, _, hasPath := strings.Cut(imageRef, "/")
	if !hasPath {
		return false
	}

	return strings.ContainsAny(first, ".:") || first == "localhost"
}

func matchesAnyForm(ctx context.Context, kind, pattern string, forms []string) bool {
	for _, form := range forms {
		matched, err := glob.Match(pattern, form)
		if err != nil {
			slog.WarnContext(ctx, "Malformed "+kind+" pattern",
				"pattern", pattern,
				"image", forms[0],
				"error", err,
			)

			return false
		}

		if matched {
			return true
		}
	}

	return false
}

// isExcluded checks whether imageRef matches any exclude glob pattern.
// '*' matches non-'/' characters, '**' matches any characters including '/'.
// Normalized forms are only considered for fully qualified references so an
// exclude never matches more than intended.
func isExcluded(ctx context.Context, excludedImages []string, imageRef string) bool {
	if len(excludedImages) == 0 {
		return false
	}

	forms := imageMatchForms(imageRef, true)

	for _, pattern := range excludedImages {
		if matchesAnyForm(ctx, "exclude", pattern, forms) {
			return true
		}
	}

	return false
}

// isIncluded checks whether imageRef matches any include glob pattern.
// Returns true if the include list is empty (all images are eligible) or
// if the image matches at least one pattern. Matching is deliberately broad
// since an unmatched image skips verification: normalized forms of short
// names are considered, and a pattern with a tag part (e.g. "repo:*") also
// covers digest-pinned references of the same repository.
func isIncluded(ctx context.Context, includedImages []string, imageRef string) bool {
	if len(includedImages) == 0 {
		return true
	}

	forms := imageMatchForms(imageRef, false)
	repositories := digestPinnedRepositories(imageRef)

	for _, pattern := range includedImages {
		if matchesAnyForm(ctx, "include", pattern, forms) {
			return true
		}

		repositoryPattern, hasTag := stripTagPattern(pattern)
		if hasTag && matchesAnyForm(ctx, "include", repositoryPattern, repositories) {
			return true
		}
	}

	return false
}

// digestPinnedRepositories returns the repository spellings of a reference
// pinned by digest without a tag, or nil for other references.
func digestPinnedRepositories(imageRef string) []string {
	base, _, hasDigest := strings.Cut(imageRef, "@")
	if !hasDigest || explicitTag(base) {
		return nil
	}

	repository, _, _, ok := normalizedReference(imageRef)
	if !ok {
		return []string{base}
	}

	return slices.Compact([]string{base, repository})
}

// stripTagPattern removes a trailing ":<tag pattern>" from an image pattern.
func stripTagPattern(pattern string) (string, bool) {
	lastSlash := strings.LastIndex(pattern, "/")

	colon := strings.LastIndex(pattern[lastSlash+1:], ":")
	if colon < 0 {
		return "", false
	}

	return pattern[:lastSlash+1+colon], true
}

// ResolveImagePolicy returns the effective policy for an image reference by
// finding the first matching image rule and applying it on top of the base
// policy. Returns the original policy and -1 if no rule matches.
func ResolveImagePolicy(
	ctx context.Context, pol *policy.Policy, imageRef string,
) (resolved *policy.Policy, ruleIdx int) {
	if len(pol.Rules) == 0 {
		return pol, -1
	}

	for idx := range pol.Rules {
		if matchesImageRule(ctx, pol.Rules[idx].Images, imageRef) {
			slog.DebugContext(ctx, "Image matched policy rule",
				"image", imageRef,
				"ruleIndex", idx,
			)

			return policy.ApplyRule(pol, &pol.Rules[idx]), idx
		}
	}

	return pol, -1
}

// matchesImageRule reports whether any rule pattern matches the image. Rules
// can relax verification, so they use the same conservative forms as exclude.
func matchesImageRule(ctx context.Context, patterns []string, imageRef string) bool {
	forms := imageMatchForms(imageRef, true)

	for _, pattern := range patterns {
		if matchesAnyForm(ctx, "rule image", pattern, forms) {
			return true
		}
	}

	return false
}

func registryBreakerByHost(
	registry *attestation.CircuitBreakerRegistry, host string,
) *attestation.CircuitBreaker {
	if registry == nil {
		return nil
	}

	return registry.Get(host)
}

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

// Package imagematch decides whether identifiers found in VEX documents
// (digests, Package URLs, image references, and hashes) refer to the
// container image being verified.
package imagematch

import (
	"log/slog"
	"net/url"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/saschagrunert/nri-supply-chain/internal/imageref"
	"github.com/saschagrunert/nri-supply-chain/internal/purl"
	"github.com/saschagrunert/nri-supply-chain/internal/types"
)

const (
	purlTypeOCI    = "oci"
	purlTypeDocker = "docker"

	qualifierRepositoryURL = "repository_url"
	qualifierTag           = "tag"
)

// Kind classifies how an identifier relates to the verified image.
type Kind int

const (
	// KindUnrelated means the identifier cannot be interpreted.
	KindUnrelated Kind = iota
	// KindImage means the identifier refers to the verified image.
	KindImage
	// KindOtherImage means the identifier refers to a different image.
	KindOtherImage
	// KindPackage means the identifier refers to a non-image package
	// (for example an npm or golang purl), which is a potential component
	// of the image.
	KindPackage
)

// Strength ranks how specifically an identifier matched. Statements bound to
// the image digest are more authoritative than statements that only name the
// image or one of its packages.
type Strength int

const (
	// StrengthNone means the identifier did not match.
	StrengthNone Strength = iota
	// StrengthName means the identifier matched by name (image name, tag,
	// repository, or a package purl) without a digest.
	StrengthName
	// StrengthDigest means the identifier carries the image digest.
	StrengthDigest
)

// Image identifies the container image being verified.
type Image struct {
	// Digest is the image digest ("sha256:<hex>") the attestations are bound
	// to.
	Digest string
	// Registry is the normalized registry host (Docker Hub aliases collapse
	// to "docker.io").
	Registry string
	// Repository is the repository path without registry (e.g.
	// "library/nginx").
	Repository string
	// Namespace is the repository path without the last segment (e.g.
	// "library"), empty for single-segment repositories.
	Namespace string
	// Name is the last repository path segment (e.g. "nginx").
	Name string
	// Tag is the tag written in the image reference, empty when the
	// reference has no explicit tag.
	Tag string

	digests []parsedDigest
}

type parsedDigest struct {
	algorithm string
	hex       string
}

// New builds an Image from a reference and digest. relatedDigests lists other
// digests of the same image (for example the platform manifest digest when
// the attestations are bound to the index digest); identifiers carrying any
// of them refer to the image. When parsedRef is nil the imageRef string is
// parsed; an unparsable reference yields an Image that matches by digest
// only.
func New(imageRef, digest string, parsedRef name.Reference, relatedDigests ...string) *Image {
	img := &Image{Digest: digest} //nolint:exhaustruct_v5 // remaining fields set below

	for _, candidate := range append([]string{digest}, relatedDigests...) {
		algorithm, hexValue := types.ParseDigest(strings.ToLower(candidate))
		if algorithm != "" {
			img.digests = append(img.digests, parsedDigest{algorithm: algorithm, hex: hexValue})
		}
	}

	ref := parsedRef
	if ref == nil && imageRef != "" {
		var err error

		ref, err = name.ParseReference(imageRef)
		if err != nil {
			slog.Debug("Failed to parse image reference for VEX matching",
				"image", imageRef, "error", err)

			return img
		}
	}

	if ref == nil {
		return img
	}

	repo := ref.Context()
	img.Registry = imageref.NormalizeRegistry(repo.RegistryStr())
	img.Repository = imageref.NormalizeRepositoryPath(repo.RegistryStr(), repo.RepositoryStr())
	img.Name = img.Repository

	if idx := strings.LastIndex(img.Repository, "/"); idx >= 0 {
		img.Namespace = img.Repository[:idx]
		img.Name = img.Repository[idx+1:]
	}

	written := imageRef
	if written == "" {
		written = ref.String()
	}

	img.Tag = explicitTag(written)

	return img
}

// Classify reports how a raw identifier relates to the image. Identifiers are
// percent-decoded before comparison.
func (img *Image) Classify(identifier string) Kind {
	kind, _ := img.Match(identifier)

	return kind
}

// Match reports how a raw identifier relates to the image and how
// specifically it matched. KindImage and KindPackage carry StrengthDigest or
// StrengthName; the other kinds carry StrengthNone.
func (img *Image) Match(identifier string) (Kind, Strength) {
	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		return KindUnrelated, StrengthNone
	}

	if strings.HasPrefix(strings.ToLower(identifier), "pkg:") {
		return img.classifyPURL(identifier)
	}

	decoded, err := url.PathUnescape(identifier)
	if err != nil {
		decoded = identifier
	}

	if algo, hexValue := types.ParseDigest(
		types.ExtractDigest(strings.ToLower(decoded)),
	); algo != "" {
		if img.digestEquals(algo, hexValue) {
			return KindImage, StrengthDigest
		}

		return KindOtherImage, StrengthNone
	}

	return KindUnrelated, StrengthNone
}

// MatchLenient is like Match but applies to statements that can only raise
// severity (for example affected or under investigation). An OCI or docker
// purl whose image name equals the image name refers to the image even when
// its namespace, tag, or repository_url differ, because the document is bound
// to the image digest and such statements must not be dropped by a retag or
// mirror. A purl carrying a different digest, or naming a different image,
// still refers to another image.
func (img *Image) MatchLenient(identifier string) (Kind, Strength) {
	kind, strength := img.Match(identifier)
	if kind != KindOtherImage ||
		!strings.HasPrefix(strings.ToLower(strings.TrimSpace(identifier)), "pkg:") {
		return kind, strength
	}

	parsed, err := purl.Parse(strings.TrimSpace(identifier))
	if err != nil || img.Name == "" || img.ConflictsByDigest(identifier) {
		return kind, strength
	}

	if strings.EqualFold(parsed.Name, img.Name) {
		return KindImage, StrengthName
	}

	return kind, strength
}

// TagConflicts reports whether an OCI or docker purl names a tag (a tag
// qualifier or a tag version) that differs from the tag of the image
// reference. It is false when either tag is unknown.
func (img *Image) TagConflicts(identifier string) bool {
	parsed, err := purl.Parse(strings.TrimSpace(identifier))
	if err != nil || img.Tag == "" ||
		(parsed.Type != purlTypeOCI && parsed.Type != purlTypeDocker) {
		return false
	}

	purlTag := parsed.Qualifiers[qualifierTag]

	if parsed.Version != "" {
		if algo, _ := types.ParseDigest(strings.ToLower(parsed.Version)); algo == "" {
			purlTag = parsed.Version
		}
	}

	return purlTag != "" && purlTag != img.Tag
}

// ConflictsByDigest reports whether an identifier carries a digest (raw,
// inside an image reference, or as an OCI/docker purl version) that is not
// one of the image digests. Name or tag differences alone never conflict.
func (img *Image) ConflictsByDigest(identifier string) bool {
	identifier = strings.TrimSpace(identifier)

	var candidate string

	if strings.HasPrefix(strings.ToLower(identifier), "pkg:") {
		parsed, err := purl.Parse(identifier)
		if err != nil || (parsed.Type != purlTypeOCI && parsed.Type != purlTypeDocker) {
			return false
		}

		candidate = parsed.Version
	} else {
		decoded, err := url.PathUnescape(identifier)
		if err != nil {
			decoded = identifier
		}

		candidate = types.ExtractDigest(decoded)
	}

	algo, hexValue := types.ParseDigest(strings.ToLower(candidate))

	return algo != "" && !img.digestEquals(algo, hexValue)
}

// MatchesHash reports whether a hash entry (algorithm and value) equals one
// of the image digests. Algorithm names are normalized ("SHA-256", "sha256")
// and the value may be bare hex or carry an "<algorithm>:" prefix.
func (img *Image) MatchesHash(algorithm, value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if _, after, found := strings.Cut(value, ":"); found {
		value = after
	}

	normalized := NormalizeAlgorithm(algorithm)

	for _, candidate := range img.digests {
		if NormalizeAlgorithm(candidate.algorithm) == normalized && value == candidate.hex {
			return true
		}
	}

	return false
}

// NormalizeAlgorithm converts hash algorithm names to a lowercase form without
// hyphens or underscores so "SHA-256", "sha_256", and "sha256" compare equal.
func NormalizeAlgorithm(algorithm string) string {
	replacer := strings.NewReplacer("-", "", "_", "")

	return strings.ToLower(replacer.Replace(algorithm))
}

func (img *Image) classifyPURL(identifier string) (Kind, Strength) {
	parsed, err := purl.Parse(identifier)
	if err != nil {
		return KindUnrelated, StrengthNone
	}

	if parsed.Type != purlTypeOCI && parsed.Type != purlTypeDocker {
		return KindPackage, StrengthName
	}

	purlTag := parsed.Qualifiers[qualifierTag]

	if parsed.Version != "" {
		algo, hexValue := types.ParseDigest(strings.ToLower(parsed.Version))
		if algo != "" {
			if img.digestEquals(algo, hexValue) {
				return KindImage, StrengthDigest
			}

			return KindOtherImage, StrengthNone
		}

		// A tag version cannot be compared with a digest. The document is
		// bound to the image digest, so fall back to name matching.
		purlTag = parsed.Version
	}

	if img.nameMatches(&parsed, purlTag) {
		return KindImage, StrengthName
	}

	return KindOtherImage, StrengthNone
}

// nameMatches compares a versionless (or tag-versioned) OCI/docker purl with
// the image name, namespace, tag, and, when present, the repository_url
// qualifier.
func (img *Image) nameMatches(parsed *purl.PURL, purlTag string) bool {
	if img.Name == "" {
		return false
	}

	if !strings.EqualFold(parsed.Name, img.Name) {
		return false
	}

	if !img.namespaceMatches(parsed.Namespace) {
		return false
	}

	if img.Tag != "" && purlTag != "" && !strings.EqualFold(purlTag, img.Tag) {
		return false
	}

	repoURL := parsed.Qualifiers[qualifierRepositoryURL]
	if repoURL == "" {
		return true
	}

	return img.repositoryURLMatches(repoURL)
}

// namespaceMatches compares a purl namespace with the image repository
// namespace. An empty purl namespace does not constrain the match. The purl
// namespace may also be prefixed with the registry host
// ("docker.io/library").
func (img *Image) namespaceMatches(namespace string) bool {
	namespace = strings.ToLower(strings.Trim(namespace, "/"))
	imageNamespace := strings.ToLower(img.Namespace)

	if namespace == "" || namespace == imageNamespace {
		return true
	}

	registry, rest, found := strings.Cut(namespace, "/")
	if !found {
		// A single segment may be the registry of a namespace-less image.
		return imageNamespace == "" && imageref.NormalizeRegistry(namespace) == img.Registry
	}

	return imageref.NormalizeRegistry(registry) == img.Registry && rest == imageNamespace
}

// repositoryURLMatches accepts the specification form, which includes the
// image name ("docker.io/library/nginx"), the legacy form without it
// ("docker.io/library"), and a registry-only form ("docker.io").
func (img *Image) repositoryURLMatches(repoURL string) bool {
	normalized := strings.ToLower(strings.TrimRight(stripScheme(repoURL), "/"))

	registry, path, _ := strings.Cut(normalized, "/")
	if imageref.NormalizeRegistry(registry) != strings.ToLower(img.Registry) {
		return false
	}

	repository := strings.ToLower(img.Repository)

	return path == "" || path == repository || strings.EqualFold(path, img.Namespace)
}

func (img *Image) digestEquals(algo, hexValue string) bool {
	for _, candidate := range img.digests {
		if algo == candidate.algorithm && hexValue == candidate.hex {
			return true
		}
	}

	return false
}

// explicitTag extracts the tag written in an image reference, ignoring any
// digest. It returns "" when the reference has no tag.
func explicitTag(ref string) string {
	base, _, _ := strings.Cut(ref, "@")

	lastSegment := base
	if idx := strings.LastIndex(base, "/"); idx >= 0 {
		lastSegment = base[idx+1:]
	}

	_, tag, found := strings.Cut(lastSegment, ":")
	if !found {
		return ""
	}

	return tag
}

func stripScheme(raw string) string {
	if _, after, found := strings.Cut(raw, "://"); found {
		return after
	}

	return raw
}

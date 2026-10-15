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

package registry

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// ErrNoPlatformMatch indicates that no image in a manifest list matches the current platform.
var ErrNoPlatformMatch = errors.New("no matching platform image in manifest list")

// ErrAmbiguousPlatform indicates that several images in a manifest list match
// the current platform, so the image the runtime runs is not known.
var ErrAmbiguousPlatform = errors.New(
	"several platform images in manifest list match the node, the runtime may run any of them",
)

const (
	archAMD64 = "amd64"
	archARM64 = "arm64"
	archARM   = "arm"
	// armV8 is the newest arm variant, which arm64 nodes also run.
	armV8 = 8
	// armV5 is the oldest arm variant the runtimes fall back to.
	armV5 = 5
)

// nodePlatform is the platform of the node as the container runtimes see it.
type nodePlatform struct {
	os   string
	arch string
	// variant is the arm CPU variant the runtimes read from /proc/cpuinfo,
	// empty when it is unknown. The runtimes detect no variant for other
	// architectures (amd64 microarchitecture levels in particular).
	variant string
}

// platformKey is an index entry platform as a runtime compares it.
type platformKey struct {
	os, arch, variant string
}

// hostPlatform returns the platform of the node the plugin runs on.
func hostPlatform() nodePlatform {
	node := nodePlatform{os: runtime.GOOS, arch: runtime.GOARCH, variant: ""}
	if node.arch == archARM {
		node.variant = hostARMVariant()
	}

	return node
}

// hostARMVariant reads the arm CPU variant of the node once.
var hostARMVariant = sync.OnceValue(func() string { //nolint:gochecknoglobals // read once
	cpuinfo, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return ""
	}

	defer func() { _ = cpuinfo.Close() }()

	return armVariantFromCPUInfo(cpuinfo)
})

// armVariantFromCPUInfo returns the arm CPU variant in a /proc/cpuinfo
// listing as containerd and CRI-O (containers/image) derive it, or an empty
// string when the runtimes could disagree about it.
func armVariantFromCPUInfo(cpuinfo io.Reader) string {
	fields := cpuInfoFields(cpuinfo, "cpu architecture", "model name")

	switch arch := strings.ToLower(fields["cpu architecture"]); arch {
	case "8", "aarch64":
		return "v8"
	case "7":
		// Raspberry Pi ARMv6 devices report architecture 7; without the
		// model name the runtimes fall back differently.
		model, ok := fields["model name"]
		if !ok {
			return ""
		}

		if strings.HasPrefix(strings.ToLower(model), "armv6-compatible") {
			return "v6"
		}

		return "v7"
	case "7m", "?(12)", "?(13)", "?(14)", "?(15)", "?(16)", "?(17)":
		return "v7"
	case "6", "6tej":
		return "v6"
	case "5", "5t", "5te", "5tej":
		return "v5"
	default:
		return ""
	}
}

// cpuInfoFields returns the first value of each of the given (lower case)
// fields of a /proc/cpuinfo listing.
func cpuInfoFields(cpuinfo io.Reader, names ...string) map[string]string {
	fields := make(map[string]string, len(names))
	scanner := bufio.NewScanner(cpuinfo)

	for scanner.Scan() {
		key, value, found := strings.Cut(scanner.Text(), ":")
		if !found {
			continue
		}

		key = strings.ToLower(strings.TrimSpace(key))
		if _, seen := fields[key]; !seen && slices.Contains(names, key) {
			fields[key] = strings.TrimSpace(value)
		}
	}

	return fields
}

// entryRanker ranks the index entries a runtime runs on the node: lower ranks
// are preferred, and ok is false for an entry the runtime never runs.
type entryRanker func(platform *v1.Platform) (rank int, ok bool)

// selectPlatformDigest returns the digest of the index entry the runtime
// runs on the node. containerd and CRI-O (containers/image) select entries
// differently, so the candidates are the best entries of each:
//
//   - containerd normalizes the entry platforms (case, architecture aliases
//     such as x86_64, an empty OS, arm64 v8 and v8.0, amd64 v1, an empty arm
//     variant as v7), ignores entries with OS features, falls back to 386 on
//     amd64 nodes and to arm v8 to v5 on arm64 nodes, and runs the first of
//     several equally good entries;
//   - CRI-O compares the platforms as written, prefers arm64 v8 over an
//     empty variant (or the reverse when it cannot read the CPU variant) and
//     a zstd compressed entry over a gzip one;
//   - an arm node runs older arm variants down to v5, preferring the newest;
//   - neither detects amd64 microarchitecture levels, so amd64 v2, v3 and v4
//     entries never run on amd64 nodes;
//   - an entry without a platform is a last resort for both.
//
// When the candidates have different digests, the runtime may run any of
// them (for example the gzip and zstd entries podman push --add-compression
// writes for one platform), so verifying one would not cover the image the
// runtime runs, and the index is rejected as ambiguous.
func selectPlatformDigest(manifests []v1.Descriptor, node nodePlatform) (string, error) {
	var candidates []*v1.Descriptor

	for _, rank := range platformRankers(node) {
		for _, entry := range bestEntries(manifests, rank) {
			if !slices.ContainsFunc(candidates, func(other *v1.Descriptor) bool {
				return other.Digest == entry.Digest
			}) {
				candidates = append(candidates, entry)
			}
		}
	}

	switch len(candidates) {
	case 0:
		if node.variant != "" {
			return "", fmt.Errorf(
				"%w for %s/%s/%s", ErrNoPlatformMatch, node.os, node.arch, node.variant,
			)
		}

		return "", fmt.Errorf("%w for %s/%s", ErrNoPlatformMatch, node.os, node.arch)
	case 1:
		slog.Debug("Resolved manifest list to platform image",
			"platform", entryPlatformString(candidates[0].Platform),
			"digest", candidates[0].Digest.String(),
		)

		return candidates[0].Digest.String(), nil
	default:
		names := make([]string, 0, len(candidates))
		for _, candidate := range candidates {
			names = append(names, fmt.Sprintf(
				"%s (%s)", entryPlatformString(candidate.Platform), candidate.Digest.String(),
			))
		}

		return "", fmt.Errorf("%w: %s", ErrAmbiguousPlatform, strings.Join(names, ", "))
	}
}

// entryPlatformString describes the platform of an index entry.
func entryPlatformString(platform *v1.Platform) string {
	if platform == nil {
		return "no platform"
	}

	return platform.String()
}

// bestEntries returns the index entries of the best rank.
func bestEntries(manifests []v1.Descriptor, rank entryRanker) []*v1.Descriptor {
	bestRank := -1
	best := make([]*v1.Descriptor, 0, len(manifests))

	for idx := range manifests {
		entryRank, ok := rank(manifests[idx].Platform)

		switch {
		case !ok || (bestRank >= 0 && entryRank > bestRank):
			continue
		case entryRank < bestRank || bestRank < 0:
			bestRank, best = entryRank, best[:0]
		}

		best = append(best, &manifests[idx])
	}

	return best
}

// platformRankers returns how containerd and CRI-O rank index entries on the
// node. On an arm node whose CPU variant is unknown, the runtimes may run any
// arm entry.
func platformRankers(node nodePlatform) []entryRanker {
	if node.arch == archARM && node.variant == "" {
		return []entryRanker{anyARMRanker(node)}
	}

	return []entryRanker{containerdRanker(node), crioRanker(node)}
}

// anyARMRanker ranks every arm entry the same.
func anyARMRanker(node nodePlatform) entryRanker {
	return func(platform *v1.Platform) (int, bool) {
		if platform == nil {
			return 1, true
		}

		key := containerdPlatformKey(platform, node.os)

		return 0, key.os == node.os && key.arch == archARM
	}
}

// containerdRanker ranks index entries like containerd's platforms.Only
// matcher for the node's default platform.
func containerdRanker(node nodePlatform) entryRanker {
	vector := containerdPlatformVector(node)

	return func(platform *v1.Platform) (int, bool) {
		if platform == nil {
			return len(vector), true
		}

		// The node platform has no OS features, so entries that require
		// some never match.
		if len(platform.OSFeatures) > 0 {
			return 0, false
		}

		rank := slices.Index(vector, containerdPlatformKey(platform, node.os))

		return rank, rank >= 0
	}
}

// containerdPlatformVector returns the normalized platforms containerd runs
// on the node, in order of preference.
func containerdPlatformVector(node nodePlatform) []platformKey {
	switch node.arch {
	case archAMD64:
		return []platformKey{{node.os, archAMD64, ""}, {node.os, "386", ""}}
	case archARM64:
		return append(
			[]platformKey{{node.os, archARM64, ""}},
			armPlatformVector(node.os, armV8)...,
		)
	case archARM:
		version, err := strconv.Atoi(strings.TrimPrefix(node.variant, "v"))
		if err != nil || version < armV5 || version > armV8 {
			return []platformKey{{node.os, archARM, node.variant}}
		}

		return armPlatformVector(node.os, version)
	default:
		return []platformKey{{node.os, node.arch, ""}}
	}
}

// armPlatformVector returns the arm platforms from version down to v5.
func armPlatformVector(goos string, version int) []platformKey {
	vector := []platformKey{{goos, archARM, "v" + strconv.Itoa(version)}}

	for older := version - 1; older >= armV5; older-- {
		vector = append(vector, platformKey{goos, archARM, "v" + strconv.Itoa(older)})
	}

	return vector
}

// containerdPlatformKey normalizes an entry platform like containerd's
// platforms.Normalize does.
func containerdPlatformKey(platform *v1.Platform, nodeOS string) platformKey {
	goos := strings.ToLower(platform.OS)
	if goos == "" {
		goos = nodeOS
	}

	arch, variant := containerdArch(
		strings.ToLower(platform.Architecture), strings.ToLower(platform.Variant),
	)

	return platformKey{os: goos, arch: arch, variant: variant}
}

// containerdArchAliases are the architecture aliases containerd normalizes,
// with the variant they imply ("-" keeps the entry's variant).
//
//nolint:gochecknoglobals // static lookup
var containerdArchAliases = map[string][2]string{
	"i386":    {"386", ""},
	"x86_64":  {archAMD64, "-"},
	"x86-64":  {archAMD64, "-"},
	"aarch64": {archARM64, "-"},
	"armhf":   {archARM, "v7"},
	"armel":   {archARM, "v6"},
}

// containerdArch normalizes a lower case architecture and variant like
// containerd's platforms.Normalize does.
func containerdArch(arch, variant string) (normalizedArch, normalizedVariant string) {
	if alias, ok := containerdArchAliases[arch]; ok {
		arch = alias[0]
		if alias[1] != "-" {
			return arch, alias[1]
		}
	}

	switch arch {
	case archAMD64:
		if variant == "v1" {
			variant = ""
		}
	case archARM64:
		if slices.Contains([]string{"8", "v8", "v8.0"}, variant) {
			variant = ""
		}
	case archARM:
		switch variant {
		case "", "7":
			variant = "v7"
		case "5", "6", "8":
			variant = "v" + variant
		}
	}

	return arch, variant
}

// crioRanker ranks index entries like containers/image's WantedPlatforms
// for the node, which compares the platforms as written. The arm64 v8 and
// empty variants share a rank: CRI-O prefers the one it detects first.
func crioRanker(node nodePlatform) entryRanker {
	groups := crioVariantGroups(node)

	return func(platform *v1.Platform) (int, bool) {
		if platform == nil {
			return len(groups), true
		}

		if platform.OS != node.os || platform.Architecture != node.arch {
			return 0, false
		}

		rank := slices.IndexFunc(groups, func(group []string) bool {
			return slices.Contains(group, platform.Variant)
		})

		return rank, rank >= 0
	}
}

// crioVariantGroups returns the variants CRI-O runs on the node, grouped by
// rank.
func crioVariantGroups(node nodePlatform) [][]string {
	switch node.arch {
	case archARM64:
		return [][]string{{"v8", ""}}
	case archARM:
		armVariants := []string{"v8", "v7", "v6", "v5"}

		var groups [][]string

		if idx := slices.Index(armVariants, node.variant); idx >= 0 {
			for _, variant := range armVariants[idx:] {
				groups = append(groups, []string{variant})
			}
		} else {
			groups = append(groups, []string{node.variant})
		}

		return append(groups, []string{""})
	default:
		return [][]string{{""}}
	}
}

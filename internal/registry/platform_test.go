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

package registry_test

import (
	"errors"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/saschagrunert/nri-supply-chain/internal/registry"
)

const (
	testHashAlgorithm = "sha256"
	// wantNoMatch and wantAmbiguous are the expected outcomes of
	// selections that fail.
	wantNoMatch   = "no match"
	wantAmbiguous = "ambiguous"
)

// platformEntry returns an index entry for the platform whose digest repeats
// hex.
func platformEntry(goos, arch, variant, hex string) v1.Descriptor {
	return v1.Descriptor{
		Digest:   v1.Hash{Algorithm: testHashAlgorithm, Hex: strings.Repeat(hex, 64)},
		Platform: &v1.Platform{OS: goos, Architecture: arch, Variant: variant},
	}
}

// linuxEntry returns an index entry for a linux platform.
func linuxEntry(arch, variant, hex string) v1.Descriptor {
	return platformEntry(testOSLinux, arch, variant, hex)
}

// TestSelectPlatformDigest checks that the selected index entry is the one
// containerd and CRI-O both run on the node, and that indexes for which they
// may run different entries are rejected.
func TestSelectPlatformDigest(t *testing.T) {
	t.Parallel()

	noPlatform := v1.Descriptor{
		Digest: v1.Hash{Algorithm: testHashAlgorithm, Hex: strings.Repeat("9", 64)},
	}

	withFeatures := linuxEntry(testArchAMD64, "", "f")
	withFeatures.Platform.OSFeatures = []string{"feature"}

	zstd := linuxEntry(testArchAMD64, "", "b")
	zstd.Annotations = map[string]string{"io.github.containers.compression.zstd": "true"}

	tests := []struct {
		name      string
		arch      string
		variant   string
		manifests []v1.Descriptor
		// want is the hex digit of the selected digest, wantNoMatch or
		// wantAmbiguous.
		want string
	}{
		{
			name:    "arm64 entry without variant",
			arch:    testArchARM64,
			variant: "",
			manifests: []v1.Descriptor{
				linuxEntry(testArchAMD64, "", "a"),
				linuxEntry(testArchARM64, "", "b"),
			},
			want: "b",
		},
		{
			name:      "arm64 entry with v8",
			arch:      testArchARM64,
			variant:   "",
			manifests: []v1.Descriptor{linuxEntry(testArchARM64, "v8", "b")},
			want:      "b",
		},
		{
			name:      "arm64 entry with unprefixed variant",
			arch:      testArchARM64,
			variant:   "",
			manifests: []v1.Descriptor{linuxEntry(testArchARM64, "8", "b")},
			want:      "b",
		},
		{
			name:      "arm64 entry with v8.0",
			arch:      testArchARM64,
			variant:   "",
			manifests: []v1.Descriptor{linuxEntry(testArchARM64, "v8.0", "b")},
			want:      "b",
		},
		{
			name:    "arm64 node does not run newer arm64 variants",
			arch:    testArchARM64,
			variant: "",
			manifests: []v1.Descriptor{
				linuxEntry(testArchARM64, "v8.2", "b"),
				linuxEntry(testArchARM64, "v9", "c"),
			},
			want: wantNoMatch,
		},
		{
			name:    "arm64 entries spelled differently",
			arch:    testArchARM64,
			variant: "",
			manifests: []v1.Descriptor{
				linuxEntry(testArchARM64, "v8", "a"),
				linuxEntry(testArchARM64, "", "b"),
			},
			want: wantAmbiguous,
		},
		{
			name:    "arm64 node prefers arm64 over arm entries",
			arch:    testArchARM64,
			variant: "",
			manifests: []v1.Descriptor{
				linuxEntry(testArchARM, "v7", "a"), linuxEntry(testArchARM64, "v8", "b"),
			},
			want: "b",
		},
		{
			name:    "arm64 node falls back to arm like containerd",
			arch:    testArchARM64,
			variant: "",
			manifests: []v1.Descriptor{
				linuxEntry(testArchARM, "v6", "a"),
				linuxEntry(testArchARM, "v7", "b"),
			},
			want: "b",
		},
		{
			name:    "arm v7 node runs an arm v6 entry",
			arch:    testArchARM,
			variant: "v7",
			manifests: []v1.Descriptor{
				linuxEntry(testArchARM, "v5", "a"),
				linuxEntry(testArchARM, "v6", "b"),
			},
			want: "b",
		},
		{
			name:    "arm v7 node prefers the v7 entry",
			arch:    testArchARM,
			variant: "v7",
			manifests: []v1.Descriptor{
				linuxEntry(testArchARM, "v6", "a"),
				linuxEntry(testArchARM, "v7", "c"),
			},
			want: "c",
		},
		{
			name:      "arm v7 node with an entry without variant",
			arch:      testArchARM,
			variant:   "v7",
			manifests: []v1.Descriptor{linuxEntry(testArchARM, "", "c")},
			want:      "c",
		},
		{
			// containerd reads the empty variant as v7, CRI-O prefers v6.
			name:    "arm v7 node with v6 and variantless entries",
			arch:    testArchARM,
			variant: "v7",
			manifests: []v1.Descriptor{
				linuxEntry(testArchARM, "v6", "a"),
				linuxEntry(testArchARM, "", "c"),
			},
			want: wantAmbiguous,
		},
		{
			name:    "arm v6 node runs the v6 entry",
			arch:    testArchARM,
			variant: "v6",
			manifests: []v1.Descriptor{
				linuxEntry(testArchARM, "v7", "a"),
				linuxEntry(testArchARM, "v6", "b"),
			},
			want: "b",
		},
		{
			name:      "arm v6 node does not run v7 entries",
			arch:      testArchARM,
			variant:   "v6",
			manifests: []v1.Descriptor{linuxEntry(testArchARM, "v7", "a")},
			want:      wantNoMatch,
		},
		{
			name:    "arm v8 node prefers the v8 entry",
			arch:    testArchARM,
			variant: "v8",
			manifests: []v1.Descriptor{
				linuxEntry(testArchARM, "v7", "a"),
				linuxEntry(testArchARM, "v8", "b"),
			},
			want: "b",
		},
		{
			name:    "arm node of unknown variant",
			arch:    testArchARM,
			variant: "",
			manifests: []v1.Descriptor{
				linuxEntry(testArchARM, "v6", "a"),
				linuxEntry(testArchARM, "v7", "b"),
			},
			want: wantAmbiguous,
		},
		{
			name:    "arm node of unknown variant with a single arm entry",
			arch:    testArchARM,
			variant: "",
			manifests: []v1.Descriptor{
				linuxEntry(testArchAMD64, "", "a"),
				linuxEntry(testArchARM, "v5", "b"),
			},
			want: "b",
		},
		{
			name:    "ambiguous entries of a worse rank",
			arch:    testArchARM,
			variant: "v7",
			manifests: []v1.Descriptor{
				linuxEntry(testArchARM, "v6", "a"),
				linuxEntry(testArchARM, "v6", "b"),
				linuxEntry(testArchARM, "v7", "c"),
			},
			want: "c",
		},
		{
			name:    "amd64 node does not run amd64 microarchitecture levels",
			arch:    testArchAMD64,
			variant: "",
			manifests: []v1.Descriptor{
				linuxEntry(testArchARM64, "", "a"),
				linuxEntry(testArchAMD64, "v3", "d"),
			},
			want: wantNoMatch,
		},
		{
			name:    "amd64 node prefers the baseline over v2 and v3 entries",
			arch:    testArchAMD64,
			variant: "",
			manifests: []v1.Descriptor{
				linuxEntry(testArchAMD64, "v3", "d"), linuxEntry(testArchAMD64, "", "e"),
				linuxEntry(testArchAMD64, "v2", "f"),
			},
			want: "e",
		},
		{
			name:      "amd64 v1 is the baseline",
			arch:      testArchAMD64,
			variant:   "",
			manifests: []v1.Descriptor{linuxEntry(testArchAMD64, "v1", "e")},
			want:      "e",
		},
		{
			name:    "amd64 entries spelled differently",
			arch:    testArchAMD64,
			variant: "",
			manifests: []v1.Descriptor{
				linuxEntry(testArchAMD64, "v1", "a"),
				linuxEntry(testArchAMD64, "", "b"),
			},
			want: wantAmbiguous,
		},
		{
			// containerd normalizes x86_64 and runs the first entry.
			name:    "amd64 entries with an architecture alias",
			arch:    testArchAMD64,
			variant: "",
			manifests: []v1.Descriptor{
				linuxEntry("x86_64", "", "a"),
				linuxEntry(testArchAMD64, "", "b"),
			},
			want: wantAmbiguous,
		},
		{
			name:      "upper case platform",
			arch:      testArchAMD64,
			variant:   "",
			manifests: []v1.Descriptor{platformEntry("Linux", "AMD64", "", "a")},
			want:      "a",
		},
		{
			name:    "entry without OS",
			arch:    testArchAMD64,
			variant: "",
			manifests: []v1.Descriptor{
				platformEntry("", testArchAMD64, "", "a"),
				linuxEntry(testArchAMD64, "", "b"),
			},
			want: wantAmbiguous,
		},
		{
			// containerd skips the entry with OS features, CRI-O runs it.
			name:      "entry with OS features",
			arch:      testArchAMD64,
			variant:   "",
			manifests: []v1.Descriptor{withFeatures, linuxEntry(testArchAMD64, "", "b")},
			want:      wantAmbiguous,
		},
		{
			name:      "entries of one platform with different compression",
			arch:      testArchAMD64,
			variant:   "",
			manifests: []v1.Descriptor{linuxEntry(testArchAMD64, "", "a"), zstd},
			want:      wantAmbiguous,
		},
		{
			name:    "duplicate entries of one digest",
			arch:    testArchAMD64,
			variant: "",
			manifests: []v1.Descriptor{
				linuxEntry(testArchAMD64, "", "a"),
				linuxEntry(testArchAMD64, "v1", "a"),
			},
			want: "a",
		},
		{
			name:    "amd64 node falls back to 386 like containerd",
			arch:    testArchAMD64,
			variant: "",
			manifests: []v1.Descriptor{
				linuxEntry(testArchARM64, "", "a"),
				linuxEntry("386", "", "b"),
			},
			want: "b",
		},
		{
			// containerd runs the 386 entry, CRI-O the entry without a
			// platform.
			name:      "386 entry and an entry without platform",
			arch:      testArchAMD64,
			variant:   "",
			manifests: []v1.Descriptor{linuxEntry("386", "", "b"), noPlatform},
			want:      wantAmbiguous,
		},
		{
			name:      "entry without platform as the last resort",
			arch:      testArchAMD64,
			variant:   "",
			manifests: []v1.Descriptor{linuxEntry(testArchARM64, "", "a"), noPlatform},
			want:      "9",
		},
		{
			name:      "matching entry before an entry without platform",
			arch:      testArchAMD64,
			variant:   "",
			manifests: []v1.Descriptor{noPlatform, linuxEntry(testArchAMD64, "", "a")},
			want:      "a",
		},
		{
			name:      "other architectures match entries without variant",
			arch:      "s390x",
			variant:   "",
			manifests: []v1.Descriptor{linuxEntry("s390x", "", "a")},
			want:      "a",
		},
		{
			name:      "other OS",
			arch:      testArchAMD64,
			variant:   "",
			manifests: []v1.Descriptor{platformEntry("windows", testArchAMD64, "", "a")},
			want:      wantNoMatch,
		},
		{
			name:      "empty index",
			arch:      testArchAMD64,
			variant:   "",
			manifests: nil,
			want:      wantNoMatch,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := registry.SelectPlatformDigest(
				test.manifests, testOSLinux, test.arch, test.variant,
			)

			switch test.want {
			case wantNoMatch:
				if !errors.Is(err, registry.ErrNoPlatformMatch) {
					t.Fatalf("error = %v, want %v", err, registry.ErrNoPlatformMatch)
				}
			case wantAmbiguous:
				if !errors.Is(err, registry.ErrAmbiguousPlatform) {
					t.Fatalf("error = %v, want %v", err, registry.ErrAmbiguousPlatform)
				}
			default:
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				if want := "sha256:" + strings.Repeat(test.want, 64); got != want {
					t.Errorf("SelectPlatformDigest() = %q, want %q", got, want)
				}
			}
		})
	}
}

// TestSelectPlatformDigestAmbiguousError checks that the error of an
// ambiguous index names the candidate entries.
func TestSelectPlatformDigestAmbiguousError(t *testing.T) {
	t.Parallel()

	manifests := []v1.Descriptor{
		linuxEntry(testArchAMD64, "", "a"), linuxEntry(testArchAMD64, "", "b"),
	}

	_, err := registry.SelectPlatformDigest(manifests, testOSLinux, testArchAMD64, "")
	if !errors.Is(err, registry.ErrAmbiguousPlatform) {
		t.Fatalf("error = %v, want %v", err, registry.ErrAmbiguousPlatform)
	}

	for _, hex := range []string{"a", "b"} {
		if digest := "sha256:" + strings.Repeat(hex, 64); !strings.Contains(err.Error(), digest) {
			t.Errorf("error %q does not name %s", err, digest)
		}
	}
}

// TestSelectPlatformDigestDockerLibraryIndex checks the selection from an
// index laid out like the Docker official images: one entry per platform,
// arm/v5, arm/v7 and arm64/v8 entries, and BuildKit attestation manifests
// with the platform unknown/unknown.
func TestSelectPlatformDigestDockerLibraryIndex(t *testing.T) {
	t.Parallel()

	manifests := []v1.Descriptor{
		linuxEntry(testArchAMD64, "", "1"),
		linuxEntry(testArchARM, "v5", "2"),
		linuxEntry(testArchARM, "v7", "3"),
		linuxEntry(testArchARM64, "v8", "4"),
		linuxEntry("386", "", "5"),
		linuxEntry("ppc64le", "", "6"),
		platformEntry("unknown", "unknown", "", "7"),
		platformEntry("unknown", "unknown", "", "8"),
		platformEntry("unknown", "unknown", "", "9"),
		platformEntry("unknown", "unknown", "", "a"),
	}

	for _, node := range []struct{ arch, variant, want string }{
		{testArchAMD64, "", "1"},
		{testArchARM, "v7", "3"},
		{testArchARM, "v6", "2"},
		{testArchARM64, "", "4"},
		{"ppc64le", "", "6"},
	} {
		got, err := registry.SelectPlatformDigest(manifests, testOSLinux, node.arch, node.variant)
		if err != nil {
			t.Fatalf("%s/%s: unexpected error: %v", node.arch, node.variant, err)
		}

		if want := "sha256:" + strings.Repeat(node.want, 64); got != want {
			t.Errorf(
				"%s/%s: SelectPlatformDigest() = %q, want %q",
				node.arch,
				node.variant,
				got,
				want,
			)
		}
	}
}

// TestARMVariantFromCPUInfo checks that the arm CPU variant is read from
// /proc/cpuinfo like the runtimes read it, and is unknown when they could
// disagree.
func TestARMVariantFromCPUInfo(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cpuinfo string
		want    string
	}{
		{
			name:    "armv7",
			cpuinfo: "processor\t: 0\nmodel name\t: ARMv7 Processor rev 4 (v7l)\nCPU architecture: 7\n",
			want:    "v7",
		},
		{
			name:    "Raspberry Pi ARMv6",
			cpuinfo: "model name\t: ARMv6-compatible processor rev 7 (v6l)\nCPU architecture: 7\n",
			want:    "v6",
		},
		{
			name:    "architecture 7 without model name",
			cpuinfo: "CPU architecture: 7\n",
			want:    "",
		},
		{
			name:    "32-bit userland on an armv8 CPU",
			cpuinfo: "CPU architecture: 8\n",
			want:    "v8",
		},
		{
			name:    "armv6",
			cpuinfo: "CPU architecture: 6TEJ\n",
			want:    "v6",
		},
		{
			name:    "armv5",
			cpuinfo: "CPU architecture: 5TE\n",
			want:    "v5",
		},
		{
			name:    "first core decides",
			cpuinfo: "CPU architecture: 7\nmodel name: ARMv7\nCPU architecture: 6\n",
			want:    "v7",
		},
		{
			name:    "missing architecture",
			cpuinfo: "processor\t: 0\n",
			want:    "",
		},
		{
			name:    "unknown architecture",
			cpuinfo: "CPU architecture: 4T\n",
			want:    "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := registry.ARMVariantFromCPUInfo(
				strings.NewReader(test.cpuinfo),
			); got != test.want {
				t.Errorf("ARMVariantFromCPUInfo() = %q, want %q", got, test.want)
			}
		})
	}
}

// FuzzSelectPlatformDigest checks that platform selection never panics and
// returns a digest of the index or an error.
func FuzzSelectPlatformDigest(f *testing.F) {
	f.Add("linux", testArchAMD64, "", "linux", testArchAMD64, "v1", "arm", "v7")
	f.Add("", "x86_64", "V1", "Linux", "aarch64", "8", testArchARM, "v6")

	f.Fuzz(
		func(t *testing.T, os1, arch1, variant1, os2, arch2, variant2, nodeArch, nodeVariant string) {
			manifests := []v1.Descriptor{
				platformEntry(os1, arch1, variant1, "a"),
				platformEntry(os2, arch2, variant2, "b"),
				{Digest: v1.Hash{Algorithm: testHashAlgorithm, Hex: strings.Repeat("c", 64)}},
			}

			got, err := registry.SelectPlatformDigest(manifests, testOSLinux, nodeArch, nodeVariant)
			if err != nil {
				if !errors.Is(err, registry.ErrNoPlatformMatch) &&
					!errors.Is(err, registry.ErrAmbiguousPlatform) {
					t.Fatalf("unexpected error: %v", err)
				}

				return
			}

			for i := range manifests {
				if manifests[i].Digest.String() == got {
					return
				}
			}

			t.Fatalf("selected digest %q is not in the index", got)
		},
	)
}

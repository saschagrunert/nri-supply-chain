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

package imagematch_test

import (
	"strings"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/vex/imagematch"
)

const (
	testHex         = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	testDigest      = "sha256:" + testHex
	testPackagePURL = "pkg:npm/lodash@4.17.21"
)

func TestClassify(t *testing.T) {
	t.Parallel()

	img := imagematch.New("nginx:latest", testDigest, nil)
	otherHex := strings.Repeat("0", 64)

	tests := []struct {
		identifier string
		want       imagematch.Kind
	}{
		{testDigest, imagematch.KindImage},
		{strings.ToUpper(testDigest), imagematch.KindImage},
		{"sha256%3A" + testHex, imagematch.KindImage},
		{"index.docker.io/library/nginx@" + testDigest, imagematch.KindImage},
		{"sha256:" + otherHex, imagematch.KindOtherImage},
		{
			"pkg:oci/nginx@sha256%3A" + testHex + "?repository_url=docker.io/library/nginx",
			imagematch.KindImage,
		},
		{
			"pkg:oci/nginx@" + testDigest + "?repository_url=index.docker.io%2Flibrary",
			imagematch.KindImage,
		},
		{"pkg:oci/renamed-mirror@" + testDigest, imagematch.KindImage},
		{"pkg:oci/nginx@sha256:" + otherHex, imagematch.KindOtherImage},
		{"pkg:oci/nginx", imagematch.KindImage},
		{"pkg:oci/nginx?repository_url=registry-1.docker.io/library/nginx", imagematch.KindImage},
		{"pkg:oci/nginx?repository_url=ghcr.io/evil/nginx", imagematch.KindOtherImage},
		{"pkg:oci/other", imagematch.KindOtherImage},
		{"pkg:oci/nginx@latest", imagematch.KindImage},
		{"pkg:docker/library/nginx@" + testDigest, imagematch.KindImage},
		{testPackagePURL, imagematch.KindPackage},
		{"comp-ref-1", imagematch.KindUnrelated},
		{"", imagematch.KindUnrelated},
	}

	for _, test := range tests {
		if got := img.Classify(test.identifier); got != test.want {
			t.Errorf("Classify(%q) = %d, want %d", test.identifier, got, test.want)
		}
	}
}

func TestMatchLenient(t *testing.T) {
	t.Parallel()

	img := imagematch.New("docker.io/library/nginx:1.27", testDigest, nil)
	otherDigest := "sha256:" + strings.Repeat("0", 64)

	tests := []struct {
		identifier string
		want       imagematch.Kind
	}{
		{"pkg:docker/bitnami/nginx@1.25", imagematch.KindImage},
		{"pkg:oci/nginx?tag=build-42", imagematch.KindImage},
		{"pkg:oci/nginx?repository_url=ghcr.io/mirror/nginx", imagematch.KindImage},
		{"pkg:oci/nginx@" + otherDigest, imagematch.KindOtherImage},
		{"pkg:oci/redis?tag=1.27", imagematch.KindOtherImage},
		{testPackagePURL, imagematch.KindPackage},
		{otherDigest, imagematch.KindOtherImage},
	}

	for _, test := range tests {
		strictKind, _ := img.Match(test.identifier)

		got, strength := img.MatchLenient(test.identifier)
		if got != test.want {
			t.Errorf("MatchLenient(%q) = %v, want %v (strict %v)",
				test.identifier, got, test.want, strictKind)
		}

		if got == imagematch.KindImage && strictKind != imagematch.KindImage &&
			strength != imagematch.StrengthName {
			t.Errorf(
				"MatchLenient(%q) strength = %v, want name strength",
				test.identifier,
				strength,
			)
		}
	}
}

func TestMatchesHash(t *testing.T) {
	t.Parallel()

	img := imagematch.New("", testDigest, nil)

	tests := []struct {
		algorithm, value string
		want             bool
	}{
		{"SHA-256", testHex, true},
		{"sha256", testDigest, true},
		{"sha_256", strings.ToUpper(testHex), true},
		{"SHA-512", testHex, false},
		{"SHA-256", strings.Repeat("0", 64), false},
	}

	for _, test := range tests {
		if got := img.MatchesHash(test.algorithm, test.value); got != test.want {
			t.Errorf(
				"MatchesHash(%q, %q) = %v, want %v",
				test.algorithm,
				test.value,
				got,
				test.want,
			)
		}
	}
}

func TestUnparsableReferenceMatchesByDigestOnly(t *testing.T) {
	t.Parallel()

	img := imagematch.New("::invalid::", testDigest, nil)

	if got := img.Classify(testDigest); got != imagematch.KindImage {
		t.Errorf("expected digest match, got %d", got)
	}

	if got := img.Classify("pkg:oci/invalid"); got != imagematch.KindOtherImage {
		t.Errorf("expected name match to fail without a parsed reference, got %d", got)
	}
}

func TestClassifyTagAndNamespace(t *testing.T) {
	t.Parallel()

	img := imagematch.New("docker.io/library/nginx:1.27@"+testDigest, testDigest, nil)

	tests := []struct {
		identifier string
		want       imagematch.Kind
	}{
		{"pkg:docker/bitnami/nginx@1.25", imagematch.KindOtherImage},
		{"pkg:docker/evilcorp/nginx", imagematch.KindOtherImage},
		{"pkg:oci/nginx?tag=1.25", imagematch.KindOtherImage},
		{"pkg:oci/nginx@1.25", imagematch.KindOtherImage},
		{"pkg:docker/library/nginx@1.27", imagematch.KindImage},
		{"pkg:docker/nginx", imagematch.KindImage},
		{"pkg:docker/library/nginx", imagematch.KindImage},
		{"pkg:oci/nginx?tag=1.27", imagematch.KindImage},
		{"pkg:oci/nginx", imagematch.KindImage},
		{"pkg:docker/library/nginx?repository_url=docker.io", imagematch.KindImage},
		{"pkg:docker/library/nginx?repository_url=ghcr.io", imagematch.KindOtherImage},
	}

	for _, test := range tests {
		if got := img.Classify(test.identifier); got != test.want {
			t.Errorf("Classify(%q) = %d, want %d", test.identifier, got, test.want)
		}
	}
}

func TestClassifyUntaggedImageIgnoresPURLTag(t *testing.T) {
	t.Parallel()

	img := imagematch.New("ghcr.io/org/app@"+testDigest, testDigest, nil)

	if got := img.Classify("pkg:oci/app@v2"); got != imagematch.KindImage {
		t.Errorf("expected tag purl to match a digest-only reference by name, got %d", got)
	}

	if got := img.Classify("pkg:docker/other/app"); got != imagematch.KindOtherImage {
		t.Errorf("expected namespace mismatch to be another image, got %d", got)
	}
}

func TestMatchStrength(t *testing.T) {
	t.Parallel()

	img := imagematch.New("quay.io/org/app:v1", testDigest, nil)

	tests := []struct {
		identifier   string
		wantKind     imagematch.Kind
		wantStrength imagematch.Strength
	}{
		{testDigest, imagematch.KindImage, imagematch.StrengthDigest},
		{"pkg:oci/app@" + testDigest, imagematch.KindImage, imagematch.StrengthDigest},
		{"pkg:oci/app", imagematch.KindImage, imagematch.StrengthName},
		{"pkg:oci/app@v1", imagematch.KindImage, imagematch.StrengthName},
		{testPackagePURL, imagematch.KindPackage, imagematch.StrengthName},
		{"pkg:oci/other", imagematch.KindOtherImage, imagematch.StrengthNone},
		{"comp-ref-1", imagematch.KindUnrelated, imagematch.StrengthNone},
	}

	for _, test := range tests {
		kind, strength := img.Match(test.identifier)
		if kind != test.wantKind || strength != test.wantStrength {
			t.Errorf("Match(%q) = (%d, %d), want (%d, %d)",
				test.identifier, kind, strength, test.wantKind, test.wantStrength)
		}
	}
}

func TestRelatedDigestsMatch(t *testing.T) {
	t.Parallel()

	platformHex := strings.Repeat("b", 64)
	platformDigest := "sha256:" + platformHex

	img := imagematch.New("quay.io/org/app:v1", testDigest, nil, platformDigest)

	if got := img.Classify(platformDigest); got != imagematch.KindImage {
		t.Errorf("expected related digest to match, got %d", got)
	}

	if got := img.Classify("pkg:oci/app@" + platformDigest); got != imagematch.KindImage {
		t.Errorf("expected purl with related digest to match, got %d", got)
	}

	if !img.MatchesHash("SHA-256", platformHex) {
		t.Error("expected hash of related digest to match")
	}

	if got := img.Classify("sha256:" + strings.Repeat("c", 64)); got != imagematch.KindOtherImage {
		t.Errorf("expected unrelated digest to be another image, got %d", got)
	}
}

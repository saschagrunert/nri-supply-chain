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

package purl_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/purl"
)

const (
	testNPMFoo = "pkg:npm/foo@1.0"
	testGlibc  = "glibc"
)

func TestParse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input   string
		want    purl.PURL
		wantKey string
	}{
		{
			input: "pkg:npm/@angular/core@12.0.0",
			want: purl.PURL{
				Type: "npm", Namespace: "@angular", Name: "core", Version: "12.0.0",
				Qualifiers: nil, Subpath: "",
			},
			wantKey: "npm/@angular/core",
		},
		{
			input: "pkg:npm/%40angular/core",
			want: purl.PURL{
				Type: "npm", Namespace: "@angular", Name: "core", Version: "",
				Qualifiers: nil, Subpath: "",
			},
			wantKey: "npm/@angular/core",
		},
		{
			input: "pkg:oci/debian@sha256%3Aabc?repository_url=docker.io%2Flibrary%2Fdebian&arch=amd64",
			want: purl.PURL{
				Type: "oci", Namespace: "", Name: "debian", Version: "sha256:abc",
				Qualifiers: map[string]string{
					"repository_url": "docker.io/library/debian",
					"arch":           "amd64",
				},
				Subpath: "",
			},
			wantKey: "oci//debian",
		},
		{
			input: "pkg:golang/github.com/Foo/Bar@v1.2.3#sub/dir",
			// golang namespaces and names are lowercased by the purl type rules.
			want: purl.PURL{
				Type: "golang", Namespace: "github.com/foo", Name: "bar", Version: "v1.2.3",
				Qualifiers: nil, Subpath: "sub/dir",
			},
			wantKey: "golang/github.com/foo/bar",
		},
		{
			input: "PKG:PyPI/requests@2.0",
			want: purl.PURL{
				Type: "pypi", Namespace: "", Name: "requests", Version: "2.0",
				Qualifiers: nil, Subpath: "",
			},
			wantKey: "pypi//requests",
		},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			t.Parallel()

			parsed, err := purl.Parse(test.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !reflect.DeepEqual(parsed, test.want) {
				t.Errorf("Parse(%q) = %+v, want %+v", test.input, parsed, test.want)
			}

			if got := parsed.Key(); got != test.wantKey {
				t.Errorf("expected key %q, got %q", test.wantKey, got)
			}
		})
	}
}

func TestKeyNormalizesPyPINames(t *testing.T) {
	t.Parallel()

	for _, input := range []string{
		"pkg:pypi/typing_extensions@4.0.0",
		"pkg:pypi/Typing.Extensions",
		"pkg:pypi/typing--_extensions",
	} {
		parsed, err := purl.Parse(input)
		if err != nil {
			t.Fatalf("Parse(%q): %v", input, err)
		}

		if got := parsed.Key(); got != "pypi//typing-extensions" {
			t.Errorf("Key(%q) = %q, want %q", input, got, "pypi//typing-extensions")
		}
	}

	parsed, err := purl.Parse("pkg:npm/typing_extensions")
	if err != nil {
		t.Fatal(err)
	}

	if got := parsed.Key(); got != "npm//typing_extensions" {
		t.Errorf("expected non-pypi names to keep underscores, got %q", got)
	}
}

func TestUpstream(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input       string
		wantName    string
		wantVersion string
		wantOK      bool
	}{
		{"pkg:deb/debian/libc6@2.36-9?upstream=glibc", testGlibc, "2.36-9", true},
		{"pkg:deb/debian/libc6@2.36-9+deb12u4?upstream=glibc%402.36-9", testGlibc, "2.36-9", true},
		{
			"pkg:rpm/redhat/glibc-common@2.34-60.el9?upstream=glibc-2.34-60.el9.src.rpm",
			testGlibc, "2.34-60.el9", true,
		},
		{"pkg:npm/foo@1.0.0", "", "", false},
	}

	for _, test := range tests {
		parsed, err := purl.Parse(test.input)
		if err != nil {
			t.Fatalf("Parse(%q): %v", test.input, err)
		}

		upstream, ok := parsed.Upstream()
		if ok != test.wantOK {
			t.Fatalf("Upstream(%q) ok = %v, want %v", test.input, ok, test.wantOK)
		}

		if ok && (upstream.Name != test.wantName || upstream.Version != test.wantVersion) {
			t.Errorf("Upstream(%q) = %s@%s, want %s@%s",
				test.input, upstream.Name, upstream.Version, test.wantName, test.wantVersion)
		}
	}
}

func TestParseInvalid(t *testing.T) {
	t.Parallel()

	for _, input := range []string{"npm/foo@1", "pkg:npm", "pkg:npm/", ""} {
		_, err := purl.Parse(input)
		if !errors.Is(err, purl.ErrInvalid) {
			t.Errorf("Parse(%q): expected ErrInvalid, got %v", input, err)
		}
	}
}

func TestStripQualifiers(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		testNPMFoo + "?arch=x#sub": testNPMFoo,
		testNPMFoo + "#sub":        testNPMFoo,
		testNPMFoo:                 testNPMFoo,
		"not a purl":               "not a purl",
	}

	for input, want := range tests {
		if got := purl.StripQualifiers(input); got != want {
			t.Errorf("StripQualifiers(%q) = %q, want %q", input, got, want)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add("pkg:npm/@angular/core@12.0.0")
	f.Add("pkg:oci/debian@sha256%3Aabc?repository_url=docker.io%2Flibrary%2Fdebian")
	f.Add("pkg:golang/github.com/foo/bar@v1#sub")
	f.Add("pkg:")

	f.Fuzz(func(t *testing.T, input string) {
		parsed, err := purl.Parse(input)
		if err != nil {
			return
		}

		if parsed.Type == "" || parsed.Name == "" {
			t.Errorf("parsed purl missing type or name: %+v", parsed)
		}
	})
}

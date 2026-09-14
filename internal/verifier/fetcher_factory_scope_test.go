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

package verifier_test

import (
	"strings"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/testutil"
	"github.com/saschagrunert/nri-supply-chain/internal/verifier"
)

const (
	scopeTestIssuerA = "https://issuer-a.example.com"
	scopeTestIssuerB = "https://issuer-b.example.com"
	scopeTestMirror  = "https://tuf.internal.example.com"
	scopeTestPrivate = "private-root"
	scopeTestPublic  = "public-root"
)

func scopeSummary(fetcherScopes map[string][]string) string {
	parts := make([]string, 0, len(fetcherScopes))

	for name, issuers := range fetcherScopes {
		parts = append(parts, name+"="+strings.Join(issuers, "|"))
	}

	return strings.Join(parts, ";")
}

func TestCreateFetcherAppliesRootIssuerScopes(t *testing.T) {
	t.Parallel()

	falseVal := false

	tests := []struct {
		name          string
		roots         []config.SigstoreRootSource
		includePublic *bool
		want          map[string][]string
	}{
		{
			name: "single scoped root without public root",
			roots: []config.SigstoreRootSource{
				{
					Name:      scopeTestPrivate,
					TUFMirror: scopeTestMirror,
					TUFRoot:   "",
					Issuers:   []string{scopeTestIssuerA},
				},
			},
			includePublic: &falseVal,
			want:          map[string][]string{scopeTestPrivate: {scopeTestIssuerA}},
		},
		{
			name: "public root entry with issuers scopes the included public root",
			roots: []config.SigstoreRootSource{
				{
					Name:      scopeTestPublic,
					TUFMirror: "",
					TUFRoot:   "",
					Issuers:   []string{scopeTestIssuerB},
				},
				{
					Name:      scopeTestPrivate,
					TUFMirror: scopeTestMirror,
					TUFRoot:   "",
					Issuers:   []string{scopeTestIssuerA},
				},
			},
			includePublic: nil,
			want: map[string][]string{
				"public-sigstore": {scopeTestIssuerB},
				scopeTestPrivate:  {scopeTestIssuerA},
			},
		},
		{
			name: "public root entry with issuers without included public root",
			roots: []config.SigstoreRootSource{
				{
					Name:      scopeTestPublic,
					TUFMirror: "",
					TUFRoot:   "",
					Issuers:   []string{scopeTestIssuerB},
				},
			},
			includePublic: &falseVal,
			want:          map[string][]string{scopeTestPublic: {scopeTestIssuerB}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := config.DefaultConfig()
			cfg.Sigstore.Roots = tt.roots
			cfg.Sigstore.IncludePublicRoot = tt.includePublic

			fetcher, err := verifier.ExportCreateFetcher(cfg)
			testutil.AssertNoError(t, err)

			got := make(map[string][]string)

			for _, scope := range fetcher.RootScopes() {
				got[scope.Name] = scope.Issuers
			}

			testutil.AssertEqual(t, len(tt.want), len(got))

			for name, issuers := range tt.want {
				testutil.AssertEqual(
					t, strings.Join(issuers, "|"), strings.Join(got[name], "|"),
				)
			}

			if t.Failed() {
				t.Logf("root scopes: %s", scopeSummary(got))
			}
		})
	}
}

func TestScopeOfflineRoot(t *testing.T) {
	t.Parallel()

	falseVal := false
	privateRoot := config.SigstoreRootSource{
		Name: scopeTestPrivate, TUFMirror: scopeTestMirror, TUFRoot: "",
		Issuers: []string{scopeTestIssuerA},
	}
	publicScoped := config.SigstoreRootSource{
		Name: scopeTestPublic, TUFMirror: "", TUFRoot: "", Issuers: []string{scopeTestIssuerB},
	}

	tests := []struct {
		name            string
		roots           []config.SigstoreRootSource
		includePublic   *bool
		rootName        string
		wantIssuers     []string
		wantKeylessOff  bool
		wantKnownSource bool
	}{
		{
			name:            "no roots configured keeps embedded roots unscoped",
			roots:           nil,
			includePublic:   nil,
			rootName:        "",
			wantIssuers:     nil,
			wantKeylessOff:  false,
			wantKnownSource: true,
		},
		{
			name:            "named private root keeps its own issuers",
			roots:           []config.SigstoreRootSource{privateRoot, publicScoped},
			includePublic:   nil,
			rootName:        scopeTestPrivate,
			wantIssuers:     []string{scopeTestIssuerA},
			wantKeylessOff:  false,
			wantKnownSource: true,
		},
		{
			name:            "named public root does not inherit private issuers",
			roots:           []config.SigstoreRootSource{privateRoot, publicScoped},
			includePublic:   nil,
			rootName:        "public-sigstore",
			wantIssuers:     []string{scopeTestIssuerB},
			wantKeylessOff:  false,
			wantKnownSource: true,
		},
		{
			name:            "unnamed root with disjoint scopes is not trusted for certificates",
			roots:           []config.SigstoreRootSource{privateRoot, publicScoped},
			includePublic:   nil,
			rootName:        "",
			wantIssuers:     []string{},
			wantKeylessOff:  true,
			wantKnownSource: false,
		},
		{
			name:            "unnamed root with an unscoped public root gets the private scope",
			roots:           []config.SigstoreRootSource{privateRoot},
			includePublic:   nil,
			rootName:        "",
			wantIssuers:     []string{scopeTestIssuerA},
			wantKeylessOff:  false,
			wantKnownSource: false,
		},
		{
			name: "unknown name with every root unscoped stays unscoped",
			roots: []config.SigstoreRootSource{
				{Name: "other", TUFMirror: scopeTestMirror, TUFRoot: "", Issuers: nil},
			},
			includePublic:   &falseVal,
			rootName:        "renamed",
			wantIssuers:     nil,
			wantKeylessOff:  false,
			wantKnownSource: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := config.DefaultConfig()
			cfg.Sigstore.Roots = tt.roots
			cfg.Sigstore.IncludePublicRoot = tt.includePublic

			issuers, keylessOff, known := verifier.ExportScopeOfflineRoot(cfg, tt.rootName)

			testutil.AssertEqual(t, strings.Join(tt.wantIssuers, "|"), strings.Join(issuers, "|"))
			testutil.AssertEqual(t, tt.wantKeylessOff, keylessOff)
			testutil.AssertEqual(t, tt.wantKnownSource, known)
		})
	}
}

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

package config_test

import (
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
)

func TestSigstoreConfigChangedDetectsRootIssuers(t *testing.T) {
	t.Parallel()

	newConfig := func(issuers []string) *config.SigstoreConfig {
		return &config.SigstoreConfig{
			TUFMirror: "",
			TUFRoot:   "",
			Roots: []config.SigstoreRootSource{{
				Name:      "private",
				TUFMirror: "https://tuf.example.com",
				TUFRoot:   "",
				Issuers:   issuers,
			}},
			IncludePublicRoot: nil,
		}
	}

	if config.SigstoreConfigChanged(newConfig(nil), newConfig(nil)) {
		t.Error("expected identical root configs to be unchanged")
	}

	if !config.SigstoreConfigChanged(
		newConfig(nil),
		newConfig([]string{"https://issuer.example.com"}),
	) {
		t.Error("expected a root issuers change to be detected")
	}
}

func TestSigstoreRootIssuersParsed(t *testing.T) {
	t.Parallel()

	cfg, err := config.LoadFromString(`
[[sigstore.roots]]
name = "private"
tuf_mirror = "https://tuf.example.com"
issuers = ["https://issuer.example.com"]
`)
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}

	if len(cfg.Sigstore.Roots) != 1 || len(cfg.Sigstore.Roots[0].Issuers) != 1 {
		t.Fatalf("expected one root with one issuer, got %+v", cfg.Sigstore.Roots)
	}
}

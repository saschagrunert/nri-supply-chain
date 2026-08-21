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
	"encoding/json"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/registry"
)

func FuzzHost(f *testing.F) {
	f.Add("ghcr.io/org/repo:latest")
	f.Add("docker.io/library/nginx:1.25")
	f.Add("myregistry.azurecr.io/app:v1")
	f.Add("localhost:5000/test")
	f.Add("invalid://ref")
	f.Add("")

	f.Fuzz(func(_ *testing.T, imageRef string) {
		registry.Host(imageRef)
	})
}

func FuzzIsACRHost(f *testing.F) {
	f.Add("myregistry.azurecr.io")
	f.Add("myregistry.azurecr.cn")
	f.Add("myregistry.azurecr.us")
	f.Add("ghcr.io")
	f.Add("docker.io")
	f.Add("myregistry.azurecr.io:443")
	f.Add("https://myregistry.azurecr.io")
	f.Add("")

	f.Fuzz(func(_ *testing.T, host string) {
		registry.IsACRHost(host)
	})
}

func FuzzStripScheme(f *testing.F) {
	f.Add("https://ghcr.io")
	f.Add("http://localhost:5000")
	f.Add("ghcr.io")
	f.Add("://malformed")
	f.Add("")

	f.Fuzz(func(_ *testing.T, serverURL string) {
		registry.StripScheme(serverURL)
	})
}

// acrExchangeResponse mirrors the unexported type for fuzz testing.
type acrExchangeResponse struct {
	RefreshToken string `json:"refresh_token"` //nolint:tagliatelle // ACR API uses snake_case
}

func FuzzACRExchangeResponseParse(f *testing.F) {
	f.Add([]byte(`{"refresh_token":"eyJ0eX..."}`))
	f.Add([]byte(`{"refresh_token":""}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(``))

	f.Fuzz(func(_ *testing.T, data []byte) {
		var resp acrExchangeResponse

		_ = json.Unmarshal(data, &resp)
	})
}

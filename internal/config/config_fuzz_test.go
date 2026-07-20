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

func FuzzLoadFromString(f *testing.F) {
	f.Add(`verification = "warn"
fetch_timeout = "10s"
policy_dir = "/tmp/policies"
`)
	f.Add(`verification = "enforce"
fetch_failure_policy = "deny"
cache_ttl = "1h"
policy_dir = "/etc/policies"
metrics_addr = ":8080"
`)
	f.Add(``)
	f.Add(`[[[invalid`)
	f.Add(`verification = "unknown"`)

	f.Fuzz(func(_ *testing.T, data string) {
		config.LoadFromString(data)
	})
}

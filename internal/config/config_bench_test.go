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

func BenchmarkDefaultConfig(b *testing.B) {
	for range b.N {
		_ = config.DefaultConfig()
	}
}

func BenchmarkLoadFromString(b *testing.B) {
	const tomlData = `
verification = "warn"
fetch_timeout = "30s"
cache_ttl = "24h"
cache_failure_ttl = "5m"
policy_dir = "/etc/nri-supply-chain/policies"
metrics_addr = "127.0.0.1:9090"
circuit_breaker_threshold = 5
circuit_breaker_cooldown = "30s"

[guac]
endpoint = "https://guac.internal:8443"
timeout = "5s"
`

	for range b.N {
		_, _ = config.LoadFromString(tomlData)
	}
}

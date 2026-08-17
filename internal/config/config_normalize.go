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

package config

import (
	"log/slog"
	"strings"
)

// Normalize clamps fields to valid ranges. Call after Validate.
func (c *Config) Normalize() {
	if c.CacheTTL.Duration == 0 && c.Enabled() {
		slog.Warn("cache_ttl is zero, verification result caching is disabled")
	}

	c.normalizeCacheTTLs()

	if c.Sigstore.TUFMirror != "" && len(c.Sigstore.Roots) == 0 {
		slog.Warn("sigstore.tuf_mirror is deprecated, use [[sigstore.roots]] instead",
			"tuf_mirror", c.Sigstore.TUFMirror)
	}

	if c.Sigstore.TUFRoot != "" && len(c.Sigstore.Roots) == 0 {
		slog.Warn("sigstore.tuf_root is deprecated, use [[sigstore.roots]] instead",
			"tuf_root", c.Sigstore.TUFRoot)
	}

	if c.Sigstore.IncludePublicRoot != nil && len(c.Sigstore.Roots) == 0 {
		slog.Warn("include_public_root has no effect without [[sigstore.roots]]")
	}

	c.normalizeRegistryPrefixes()
}

// normalizeCacheTTLs clamps cache TTL fields and warns about edge cases.
func (c *Config) normalizeCacheTTLs() {
	if c.CacheTTL.Duration == 0 && c.CacheFailureTTL.Duration > 0 {
		slog.Warn("cache_failure_ttl reset to zero because cache_ttl is zero",
			"cache_failure_ttl", c.CacheFailureTTL.Duration,
		)

		c.CacheFailureTTL.Duration = 0
	}

	if c.CacheTTL.Duration > 0 && c.CacheFailureTTL.Duration > c.CacheTTL.Duration {
		slog.Warn("cache_failure_ttl exceeds cache_ttl, clamping to cache_ttl",
			"cache_failure_ttl", c.CacheFailureTTL.Duration,
			"cache_ttl", c.CacheTTL.Duration,
		)

		c.CacheFailureTTL.Duration = c.CacheTTL.Duration
	}

	if c.CacheFailureTTL.Duration == 0 && c.CacheTTL.Duration > 0 {
		slog.Warn("cache_failure_ttl is zero; failure results will use full cache_ttl",
			"cache_ttl", c.CacheTTL.Duration,
		)
	}
}

func normalizePrefix(prefix string) string {
	lower := strings.ToLower(prefix)

	if lower == "docker.io" {
		return "index.docker.io"
	}

	return lower
}

func (c *Config) normalizeRegistryPrefixes() {
	for idx := range c.Registries {
		c.Registries[idx].Prefix = normalizePrefix(c.Registries[idx].Prefix)
		c.Registries[idx].Mirror = normalizePrefix(c.Registries[idx].Mirror)
	}
}

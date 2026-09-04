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
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/registry"
)

func BenchmarkHost(b *testing.B) {
	const imageRef = "ghcr.io/saschagrunert/nri-supply-chain:v0.5.3"

	b.ResetTimer()

	for range b.N {
		registry.Host(imageRef)
	}
}

func BenchmarkHostWithDigest(b *testing.B) {
	const imageRef = "ghcr.io/saschagrunert/nri-supply-chain@sha256:" +
		"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

	b.ResetTimer()

	for range b.N {
		registry.Host(imageRef)
	}
}

func BenchmarkFindMatchingRegistry(b *testing.B) {
	registries := []config.Registry{
		{Prefix: testRegistryDockerHub, Mirror: "", CACert: "", Insecure: false},
		{Prefix: testRegistryQuay, Mirror: "", CACert: "", Insecure: false},
		{Prefix: testRegistryGHCR, Mirror: "", CACert: "", Insecure: false},
		{Prefix: "registry.k8s.io", Mirror: "", CACert: "", Insecure: false},
		{Prefix: "mcr.microsoft.com", Mirror: "", CACert: "", Insecure: false},
	}

	const imageRef = "ghcr.io/saschagrunert/nri-supply-chain:v0.5.3"

	b.ResetTimer()

	for range b.N {
		registry.FindMatchingRegistry(registries, imageRef)
	}
}

func BenchmarkFindMatchingRegistryMiss(b *testing.B) {
	registries := []config.Registry{
		{Prefix: testRegistryDockerHub, Mirror: "", CACert: "", Insecure: false},
		{Prefix: testRegistryQuay, Mirror: "", CACert: "", Insecure: false},
		{Prefix: "registry.k8s.io", Mirror: "", CACert: "", Insecure: false},
	}

	const imageRef = "ghcr.io/saschagrunert/nri-supply-chain:v0.5.3"

	b.ResetTimer()

	for range b.N {
		registry.FindMatchingRegistry(registries, imageRef)
	}
}

func BenchmarkRewriteReference(b *testing.B) {
	const imageRef = "ghcr.io/saschagrunert/nri-supply-chain:v0.5.3"

	b.ResetTimer()

	for range b.N {
		_, _ = registry.RewriteReference(imageRef, "ghcr.io", "mirror.internal")
	}
}

func BenchmarkRewriteReferenceNoMatch(b *testing.B) {
	const imageRef = "docker.io/library/nginx:latest"

	b.ResetTimer()

	for range b.N {
		_, _ = registry.RewriteReference(imageRef, "ghcr.io", "mirror.internal")
	}
}

func BenchmarkPlatformVariant(b *testing.B) {
	b.ResetTimer()

	for range b.N {
		registry.PlatformVariant("arm64")
	}
}

func BenchmarkTransportCacheLookup(b *testing.B) {
	registries := []config.Registry{
		{Prefix: testRegistryGHCR, Mirror: "", CACert: "", Insecure: false},
		{Prefix: testRegistryDockerHub, Mirror: "", CACert: "", Insecure: false},
		{Prefix: testRegistryQuay, Mirror: "", CACert: "", Insecure: false},
	}

	tc := registry.NewTransportCache(registries)

	b.ResetTimer()

	for range b.N {
		_, _ = tc.GetCachedTransport("ghcr.io")
	}
}

func BenchmarkIsConnectionError(b *testing.B) {
	err := &testNetError{timeout: true}

	b.ResetTimer()

	for range b.N {
		registry.IsConnectionError(err)
	}
}

type testNetError struct {
	timeout bool
}

func (e *testNetError) Error() string   { return "test error" }
func (e *testNetError) Timeout() bool   { return e.timeout }
func (e *testNetError) Temporary() bool { return false }

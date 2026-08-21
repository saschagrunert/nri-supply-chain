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

package registry

import (
	"context"
	"net/http"

	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
)

// GetCachedTransport exposes getTransport for testing.
func (tc *TransportCache) GetCachedTransport(prefix string) (http.RoundTripper, error) {
	return tc.getTransport(prefix)
}

// Exported constants for testing.
const (
	TransportMaxIdleConns  = transportMaxIdleConns
	TransportIdlePerHost   = transportIdlePerHost
	TransportIdleTimeout   = transportIdleTimeout
	TransportTLSTimeout    = transportTLSTimeout
	TransportExpectTimeout = transportExpectTimeout
)

//nolint:gochecknoglobals // test exports
var (
	// IsACRHost exports isACRHost for testing.
	IsACRHost = isACRHost

	// ExchangeACRToken exports exchangeACRToken for testing.
	ExchangeACRToken = exchangeACRToken

	// NewACRHelper exports newACRHelper for testing.
	NewACRHelper = newACRHelper

	// ErrNotACR exports errNotACR for testing.
	ErrNotACR = errNotACR

	// StripScheme exports stripScheme for testing.
	StripScheme = stripScheme
)

// ResolveDigest exports resolveDigest for testing.
func ResolveDigest(
	ctx context.Context, imageRef string, opts ...remote.Option,
) (digest, indexDigest string, err error) {
	return resolveDigest(ctx, imageRef, opts...)
}

// ResolveIndexDigest exports resolveIndexDigest for testing.
func ResolveIndexDigest(desc *remote.Descriptor) (string, error) {
	return resolveIndexDigest(desc)
}

// PlatformVariant exports platformVariant for testing.
func PlatformVariant(arch string) string {
	return platformVariant(arch)
}

// BuildTransport exports buildTransport for testing.
func BuildTransport(caCertPath string, insecure bool) (http.RoundTripper, error) {
	return buildTransport(caCertPath, insecure)
}

// RewriteReference exports rewriteReference for testing.
func RewriteReference(imageRef, prefix, mirror string) (string, error) {
	return rewriteReference(imageRef, prefix, mirror)
}

// FindMatchingRegistry exports findMatchingRegistry for testing.
func FindMatchingRegistry(
	registries []config.Registry, imageRef string,
) *config.Registry {
	return findMatchingRegistry(registries, imageRef)
}

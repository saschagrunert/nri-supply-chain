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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
)

var (
	// ErrCACertRead indicates a failure reading a CA certificate file.
	ErrCACertRead = errors.New("failed to read CA certificate")

	// ErrCACertParse indicates a failure parsing a CA certificate file.
	ErrCACertParse = errors.New("failed to parse CA certificate")
)

const (
	transportDialTimeout   = 30 * time.Second
	transportTLSTimeout    = 10 * time.Second
	transportIdleTimeout   = 90 * time.Second
	transportMaxIdleConns  = 100
	transportIdlePerHost   = 10
	transportKeepAlive     = 30 * time.Second
	transportExpectTimeout = time.Second
)

// TransportCache builds and caches HTTP transports per registry prefix.
// Transports are created lazily on first use and reused for subsequent
// requests, providing connection pooling and TLS session reuse.
type TransportCache struct {
	mu         sync.RWMutex
	registries []config.Registry
	transports map[string]http.RoundTripper
}

// NewTransportCache creates a TransportCache for the given registries.
// Transports are built lazily on first access.
func NewTransportCache(registries []config.Registry) *TransportCache {
	return &TransportCache{
		mu:         sync.RWMutex{},
		registries: registries,
		transports: make(map[string]http.RoundTripper, len(registries)),
	}
}

// NewTransportCacheOrNil returns a new TransportCache when registries is
// non-empty, or nil otherwise.
func NewTransportCacheOrNil(registries []config.Registry) *TransportCache {
	if len(registries) == 0 {
		return nil
	}

	return NewTransportCache(registries)
}

// Registries returns a copy of the registry configurations held by this cache.
func (tc *TransportCache) Registries() []config.Registry {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	return slices.Clone(tc.registries)
}

// CloseIdleConnections closes idle connections on all cached transports.
func (tc *TransportCache) CloseIdleConnections() {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	for _, rt := range tc.transports {
		if t, ok := rt.(*http.Transport); ok {
			t.CloseIdleConnections()
		}
	}
}

// getTransport returns the cached transport for the given prefix, building
// it on first access. Returns nil when the registry needs no custom transport.
func (tc *TransportCache) getTransport(prefix string) (http.RoundTripper, error) {
	tc.mu.RLock()

	if t, ok := tc.transports[prefix]; ok {
		tc.mu.RUnlock()

		return t, nil
	}

	tc.mu.RUnlock()

	tc.mu.Lock()
	defer tc.mu.Unlock()

	// Double-check after acquiring write lock.
	if t, ok := tc.transports[prefix]; ok {
		return t, nil
	}

	var reg *config.Registry

	for idx := range tc.registries {
		if tc.registries[idx].Prefix == prefix {
			reg = &tc.registries[idx]

			break
		}
	}

	if reg == nil {
		return nil, nil //nolint:nilnil // nil signals "use default transport"
	}

	transport, err := BuildTransport(reg.CACert, reg.Insecure)
	if err != nil {
		return nil, err
	}

	tc.transports[prefix] = transport

	return transport, nil
}

// BuildTransport creates an http.RoundTripper configured with the given
// CA certificate and insecure TLS settings. If caCertPath is empty and
// insecure is false, nil is returned (use the default transport).
func BuildTransport(caCertPath string, insecure bool) (http.RoundTripper, error) {
	if caCertPath == "" && !insecure {
		return nil, nil //nolint:nilnil // nil signals "use default transport"
	}

	tlsCfg := newTLSConfig(insecure)

	if caCertPath != "" {
		pool, err := loadCACertPool(caCertPath)
		if err != nil {
			return nil, err
		}

		tlsCfg.RootCAs = pool
	}

	return newHTTPTransport(tlsCfg), nil
}

func newTLSConfig(insecure bool) *tls.Config {
	return &tls.Config{ //nolint:exhaustruct // only setting relevant fields
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: insecure, //nolint:gosec // controlled by user config
	}
}

func newHTTPTransport(tlsCfg *tls.Config) *http.Transport {
	dialer := &net.Dialer{ //nolint:exhaustruct // only setting relevant fields
		Timeout:   transportDialTimeout,
		KeepAlive: transportKeepAlive,
	}

	return &http.Transport{ //nolint:exhaustruct // only setting relevant fields
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		TLSClientConfig:       tlsCfg,
		TLSHandshakeTimeout:   transportTLSTimeout,
		MaxIdleConns:          transportMaxIdleConns,
		MaxIdleConnsPerHost:   transportIdlePerHost,
		IdleConnTimeout:       transportIdleTimeout,
		ExpectContinueTimeout: transportExpectTimeout,
		ForceAttemptHTTP2:     true,
	}
}

func loadCACertPool(path string) (*x509.CertPool, error) {
	pemData, err := os.ReadFile(path) //nolint:gosec // path is validated by config
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrCACertRead, path, err)
	}

	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}

	if !pool.AppendCertsFromPEM(pemData) {
		return nil, fmt.Errorf("%w: no valid certificates in %s", ErrCACertParse, path)
	}

	return pool, nil
}

// RewriteReference rewrites an image reference to use a mirror registry.
// If the image's registry host matches prefix, it is replaced with mirror.
// Returns the original reference unchanged if mirror is empty or the prefix
// does not match.
func RewriteReference(imageRef, prefix, mirror string) (string, error) {
	if mirror == "" || prefix == "" {
		return imageRef, nil
	}

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return imageRef, fmt.Errorf("parsing reference for mirror rewrite: %w", err)
	}

	host := strings.ToLower(ref.Context().RegistryStr())
	if host != prefix {
		return imageRef, nil
	}

	// Replace the registry host with the mirror.
	repo := ref.Context().RepositoryStr()
	newRepo := mirror + "/" + repo

	switch typed := ref.(type) {
	case name.Digest:
		newRef, parseErr := name.NewDigest(newRepo + "@" + typed.DigestStr())
		if parseErr != nil {
			return imageRef, fmt.Errorf("building mirror digest ref: %w", parseErr)
		}

		return newRef.String(), nil

	case name.Tag:
		newRef, parseErr := name.NewTag(newRepo + ":" + typed.TagStr())
		if parseErr != nil {
			return imageRef, fmt.Errorf("building mirror tag ref: %w", parseErr)
		}

		return newRef.String(), nil

	default:
		return imageRef, nil
	}
}

// FindMatchingRegistry returns the first registry config whose prefix matches
// the given image reference's registry host exactly. Returns nil if no match
// is found.
func FindMatchingRegistry(
	registries []config.Registry, imageRef string,
) *config.Registry {
	if len(registries) == 0 {
		return nil
	}

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil
	}

	host := strings.ToLower(ref.Context().RegistryStr())

	for idx := range registries {
		if host == registries[idx].Prefix {
			return &registries[idx]
		}
	}

	return nil
}

// OptionsForRegistries returns the (possibly rewritten) image reference plus
// the transport remote.Option for the matching registry. The transport option
// is nil when no custom transport is needed. If no registry matches, the
// original imageRef is returned with a nil transport option.
func OptionsForRegistries(
	cache *TransportCache, imageRef string,
) (rewrittenRef string, transportOpt remote.Option, err error) {
	if cache == nil {
		return imageRef, nil, nil
	}

	registries := cache.Registries()

	reg := FindMatchingRegistry(registries, imageRef)
	if reg == nil {
		return imageRef, nil, nil
	}

	if reg.Mirror != "" {
		rewrittenRef, err = RewriteReference(imageRef, reg.Prefix, reg.Mirror)
		if err != nil {
			return imageRef, nil, err
		}
	} else {
		rewrittenRef = imageRef
	}

	transport, transportErr := cache.getTransport(reg.Prefix)
	if transportErr != nil {
		return imageRef, nil, transportErr
	}

	if transport != nil {
		transportOpt = remote.WithTransport(transport)
	}

	return rewrittenRef, transportOpt, nil
}

// ResolveWithRegistries resolves an image reference to its digest using
// per-registry transport configuration. Falls back to the default keychain
// when no registry matches.
func ResolveWithRegistries(
	ctx context.Context, imageRef string, cache *TransportCache,
) (digest, indexDigest string, err error) {
	if cache == nil {
		return ResolveWithDefaultKeychain(ctx, imageRef)
	}

	rewrittenRef, transportOpt, err := OptionsForRegistries(cache, imageRef)
	if err != nil {
		return "", "", fmt.Errorf("building registry options: %w", err)
	}

	opts := []remote.Option{remote.WithAuthFromKeychain(authn.DefaultKeychain)}
	if transportOpt != nil {
		opts = append(opts, transportOpt)
	}

	return ResolveDigest(ctx, rewrittenRef, opts...)
}

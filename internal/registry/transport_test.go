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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/v1/remote/transport"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/registry"
)

const (
	testRegistryDockerIO    = "index.docker.io"
	testRegistryGHCR        = "ghcr.io"
	testMirrorInternal      = "mirror.internal"
	testImageGHCR           = "ghcr.io/myorg/myimage:v1.0"
	testImageDockerNginx    = "docker.io/library/nginx:latest"
	testImageEvilGHCR       = "ghcr.io.evil.com/myorg/myimage:v1.0"
	testMirrorRewrittenGHCR = "mirror.internal/myorg/myimage:v1.0"
)

var (
	errConnRefused = errors.New("connection refused")
	errGeneric     = errors.New("generic error")
)

func writeSelfSignedCACert(tb testing.TB, dir string) string {
	tb.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("generating key: %v", err)
	}

	subject := pkix.Name{CommonName: "test-ca"}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		tb.Fatalf("creating certificate: %v", err)
	}

	certPath := filepath.Join(dir, "ca.pem")

	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}

	writeErr := os.WriteFile(
		certPath, pem.EncodeToMemory(pemBlock), 0o600,
	)
	if writeErr != nil {
		tb.Fatalf("writing PEM: %v", writeErr)
	}

	return certPath
}

func TestBuildTransportNoConfig(t *testing.T) {
	t.Parallel()

	roundTripper, err := registry.BuildTransport("", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if roundTripper == nil {
		t.Fatal("expected non-nil default transport")
	}

	httpTransport, ok := roundTripper.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", roundTripper)
	}

	if httpTransport.TLSClientConfig == nil {
		t.Fatal("expected TLSClientConfig to be set on default transport")
	}

	if httpTransport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want %d",
			httpTransport.TLSClientConfig.MinVersion, tls.VersionTLS12)
	}
}

func TestBuildTransportDefaultShared(t *testing.T) {
	t.Parallel()

	rt1, err := registry.BuildTransport("", false)
	if err != nil {
		t.Fatalf("first call: unexpected error: %v", err)
	}

	rt2, err := registry.BuildTransport("", false)
	if err != nil {
		t.Fatalf("second call: unexpected error: %v", err)
	}

	if rt1 != rt2 {
		t.Error("expected same transport instance for default config (singleton broken)")
	}
}

func TestDefaultTransportPoolSettings(t *testing.T) {
	t.Parallel()

	roundTripper, err := registry.BuildTransport("", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	httpTransport, ok := roundTripper.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", roundTripper)
	}

	if httpTransport.MaxIdleConns != registry.TransportMaxIdleConns {
		t.Errorf("MaxIdleConns = %d, want %d",
			httpTransport.MaxIdleConns, registry.TransportMaxIdleConns)
	}

	if httpTransport.MaxIdleConnsPerHost != registry.TransportIdlePerHost {
		t.Errorf("MaxIdleConnsPerHost = %d, want %d",
			httpTransport.MaxIdleConnsPerHost, registry.TransportIdlePerHost)
	}

	if httpTransport.IdleConnTimeout != registry.TransportIdleTimeout {
		t.Errorf("IdleConnTimeout = %v, want %v",
			httpTransport.IdleConnTimeout, registry.TransportIdleTimeout)
	}

	if httpTransport.TLSHandshakeTimeout != registry.TransportTLSTimeout {
		t.Errorf("TLSHandshakeTimeout = %v, want %v",
			httpTransport.TLSHandshakeTimeout, registry.TransportTLSTimeout)
	}

	if !httpTransport.ForceAttemptHTTP2 {
		t.Error("expected ForceAttemptHTTP2 to be true")
	}

	if httpTransport.ExpectContinueTimeout != registry.TransportExpectTimeout {
		t.Errorf("ExpectContinueTimeout = %v, want %v",
			httpTransport.ExpectContinueTimeout, registry.TransportExpectTimeout)
	}
}

func TestBuildTransportInsecure(t *testing.T) {
	t.Parallel()

	roundTripper, err := registry.BuildTransport("", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if roundTripper == nil {
		t.Fatal("expected non-nil transport for insecure mode")
	}

	httpTransport, ok := roundTripper.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", roundTripper)
	}

	if httpTransport.TLSClientConfig == nil {
		t.Fatal("expected TLSClientConfig to be set")
	}

	if !httpTransport.TLSClientConfig.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify to be true")
	}
}

func TestBuildTransportCustomCA(t *testing.T) {
	t.Parallel()

	certPath := writeSelfSignedCACert(t, t.TempDir())

	roundTripper, err := registry.BuildTransport(certPath, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if roundTripper == nil {
		t.Fatal("expected non-nil transport for custom CA")
	}

	httpTransport, ok := roundTripper.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", roundTripper)
	}

	if httpTransport.TLSClientConfig == nil {
		t.Fatal("expected TLSClientConfig to be set")
	}

	if httpTransport.TLSClientConfig.RootCAs == nil {
		t.Error("expected RootCAs to be set")
	}
}

func TestBuildTransportCustomCAAndInsecure(t *testing.T) {
	t.Parallel()

	certPath := writeSelfSignedCACert(t, t.TempDir())

	roundTripper, err := registry.BuildTransport(certPath, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if roundTripper == nil {
		t.Fatal("expected non-nil transport")
	}

	httpTransport, ok := roundTripper.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", roundTripper)
	}

	if !httpTransport.TLSClientConfig.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify to be true")
	}

	if httpTransport.TLSClientConfig.RootCAs == nil {
		t.Error("expected RootCAs to be set even with insecure")
	}
}

func TestBuildTransportMissingCAFile(t *testing.T) {
	t.Parallel()

	_, err := registry.BuildTransport("/nonexistent/ca.pem", false)
	if err == nil {
		t.Fatal("expected error for missing CA file")
	}

	if !errors.Is(err, registry.ErrCACertRead) {
		t.Errorf("expected ErrCACertRead, got: %v", err)
	}
}

func TestBuildTransportInvalidPEM(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	certPath := filepath.Join(dir, "bad.pem")

	err := os.WriteFile(certPath, []byte("not a valid PEM"), 0o600)
	if err != nil {
		t.Fatalf("writing file: %v", err)
	}

	_, buildErr := registry.BuildTransport(certPath, false)
	if buildErr == nil {
		t.Fatal("expected error for invalid PEM data")
	}

	if !errors.Is(buildErr, registry.ErrCACertParse) {
		t.Errorf("expected ErrCACertParse, got: %v", buildErr)
	}
}

func TestRewriteReferenceWithMirror(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		imageRef string
		prefix   string
		mirror   string
		want     string
	}{
		{
			name:     "tag reference rewritten",
			imageRef: testImageGHCR,
			prefix:   testRegistryGHCR,
			mirror:   testMirrorInternal,
			want:     testMirrorRewrittenGHCR,
		},
		{
			name: "digest reference rewritten",
			imageRef: "ghcr.io/myorg/myimage@sha256:" +
				"abc123def456abc123def456abc123def456abc123def456abc123def456abcd",
			prefix: testRegistryGHCR,
			mirror: testMirrorInternal,
			want: "mirror.internal/myorg/myimage@sha256:" +
				"abc123def456abc123def456abc123def456abc123def456abc123def456abcd",
		},
		{
			name:     "no match returns original",
			imageRef: testImageDockerNginx,
			prefix:   testRegistryGHCR,
			mirror:   testMirrorInternal,
			want:     testImageDockerNginx,
		},
		{
			name:     "empty mirror returns original",
			imageRef: testImageGHCR,
			prefix:   testRegistryGHCR,
			mirror:   "",
			want:     testImageGHCR,
		},
		{
			name:     "empty prefix returns original",
			imageRef: testImageGHCR,
			prefix:   "",
			mirror:   testMirrorInternal,
			want:     testImageGHCR,
		},
		{
			name:     "partial prefix does not match",
			imageRef: testImageEvilGHCR,
			prefix:   testRegistryGHCR,
			mirror:   testMirrorInternal,
			want:     testImageEvilGHCR,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got, err := registry.RewriteReference(
				testCase.imageRef, testCase.prefix, testCase.mirror,
			)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got != testCase.want {
				t.Errorf("RewriteReference() = %q, want %q", got, testCase.want)
			}
		})
	}
}

func TestRewriteReferenceInvalidRef(t *testing.T) {
	t.Parallel()

	got, err := registry.RewriteReference(
		":::invalid", testRegistryGHCR, testMirrorInternal,
	)
	if err == nil {
		t.Fatal("expected error for invalid reference")
	}

	if got != ":::invalid" {
		t.Errorf("expected original ref returned on error, got %q", got)
	}
}

func TestFindMatchingRegistry(t *testing.T) {
	t.Parallel()

	registries := []config.Registry{
		{
			Prefix:   testRegistryGHCR,
			Mirror:   testMirrorInternal,
			CACert:   "",
			Insecure: false,
		},
		{
			Prefix:   "registry.internal.example.com",
			Mirror:   "",
			CACert:   "/etc/ssl/ca.pem",
			Insecure: false,
		},
	}

	tests := []struct {
		name     string
		imageRef string
		wantNil  bool
		wantPfx  string
	}{
		{
			name:     "matches first registry",
			imageRef: testImageGHCR,
			wantNil:  false,
			wantPfx:  testRegistryGHCR,
		},
		{
			name:     "matches second registry",
			imageRef: "registry.internal.example.com/myorg/myimage:latest",
			wantNil:  false,
			wantPfx:  "registry.internal.example.com",
		},
		{
			name:     "no match",
			imageRef: testImageDockerNginx,
			wantNil:  true,
			wantPfx:  "",
		},
		{
			name:     "invalid ref returns nil",
			imageRef: ":::invalid",
			wantNil:  true,
			wantPfx:  "",
		},
		{
			name:     "partial prefix does not match",
			imageRef: testImageEvilGHCR,
			wantNil:  true,
			wantPfx:  "",
		},
		{
			name:     "case-insensitive match",
			imageRef: "GHCR.IO/myorg/myimage:v1",
			wantNil:  false,
			wantPfx:  testRegistryGHCR,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			reg := registry.FindMatchingRegistry(registries, testCase.imageRef)

			if testCase.wantNil {
				if reg != nil {
					t.Errorf("expected nil, got registry with prefix %q", reg.Prefix)
				}

				return
			}

			if reg == nil {
				t.Fatal("expected non-nil registry")
			}

			if reg.Prefix != testCase.wantPfx {
				t.Errorf("Prefix = %q, want %q", reg.Prefix, testCase.wantPfx)
			}
		})
	}
}

func TestFindMatchingRegistryEmpty(t *testing.T) {
	t.Parallel()

	reg := registry.FindMatchingRegistry(nil, "ghcr.io/test:v1")
	if reg != nil {
		t.Error("expected nil for empty registries")
	}
}

func TestOptionsForRegistriesNoMatch(t *testing.T) {
	t.Parallel()

	tc := registry.NewTransportCache([]config.Registry{
		{
			Prefix:   testRegistryGHCR,
			Mirror:   "",
			CACert:   "",
			Insecure: false,
		},
	})

	ref, transportOpt, _, err := registry.OptionsForRegistries(
		tc, "docker.io/nginx:latest",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ref != "docker.io/nginx:latest" {
		t.Errorf("ref = %q, want original", ref)
	}

	if transportOpt != nil {
		t.Error("expected nil transport option for no-match")
	}
}

func TestOptionsForRegistriesWithMirror(t *testing.T) {
	t.Parallel()

	tc := registry.NewTransportCache([]config.Registry{
		{
			Prefix:   testRegistryGHCR,
			Mirror:   testMirrorInternal,
			CACert:   "",
			Insecure: false,
		},
	})

	ref, transportOpt, _, err := registry.OptionsForRegistries(tc, testImageGHCR)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ref != testMirrorRewrittenGHCR {
		t.Errorf("ref = %q, want mirror rewrite", ref)
	}

	// Default pool transport is always returned for matching registries.
	if transportOpt == nil {
		t.Error("expected non-nil transport option (default pool transport)")
	}
}

func TestOptionsForRegistriesWithTransport(t *testing.T) {
	t.Parallel()

	certPath := writeSelfSignedCACert(t, t.TempDir())

	tc := registry.NewTransportCache([]config.Registry{
		{
			Prefix:   "registry.internal",
			Mirror:   "",
			CACert:   certPath,
			Insecure: false,
		},
	})

	ref, transportOpt, _, err := registry.OptionsForRegistries(
		tc, "registry.internal/myorg/myimage:v1.0",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ref != "registry.internal/myorg/myimage:v1.0" {
		t.Errorf("ref = %q, expected unchanged (no mirror)", ref)
	}

	if transportOpt == nil {
		t.Error("expected non-nil transport option for custom CA")
	}
}

func TestOptionsForRegistriesEmptyCache(t *testing.T) {
	t.Parallel()

	tc := registry.NewTransportCache(nil)

	ref, transportOpt, _, err := registry.OptionsForRegistries(tc, testImageDockerNginx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ref != testImageDockerNginx {
		t.Errorf("ref = %q, want original", ref)
	}

	if transportOpt != nil {
		t.Error("expected nil transport option for empty cache")
	}
}

func TestOptionsForRegistriesNilCache(t *testing.T) {
	t.Parallel()

	ref, transportOpt, _, err := registry.OptionsForRegistries(nil, testImageDockerNginx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ref != testImageDockerNginx {
		t.Errorf("ref = %q, want original", ref)
	}

	if transportOpt != nil {
		t.Error("expected nil transport option for nil cache")
	}
}

func TestTransportCacheCachesTransport(t *testing.T) {
	t.Parallel()

	certPath := writeSelfSignedCACert(t, t.TempDir())

	tc := registry.NewTransportCache([]config.Registry{
		{
			Prefix:   "registry.internal",
			Mirror:   "",
			CACert:   certPath,
			Insecure: false,
		},
	})

	rt1, err := tc.GetCachedTransport("registry.internal")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if rt1 == nil {
		t.Fatal("expected non-nil transport")
	}

	rt2, err := tc.GetCachedTransport("registry.internal")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if rt1 != rt2 {
		t.Error("expected same transport instance on second call (caching broken)")
	}
}

func TestTransportCacheRegistries(t *testing.T) {
	t.Parallel()

	regs := []config.Registry{
		{
			Prefix: testRegistryGHCR, Mirror: "", CACert: "", Insecure: false,
		},
	}

	tc := registry.NewTransportCache(regs)
	got := tc.Registries()

	if len(got) != 1 {
		t.Fatalf("expected 1 registry, got %d", len(got))
	}

	if got[0].Prefix != testRegistryGHCR {
		t.Errorf("expected prefix %q, got %q", testRegistryGHCR, got[0].Prefix)
	}
}

func TestTransportCacheCloseIdleConnections(t *testing.T) {
	t.Parallel()

	certPath := writeSelfSignedCACert(t, t.TempDir())

	cache := registry.NewTransportCache([]config.Registry{
		{
			Prefix: testMirrorInternal, Mirror: "", CACert: certPath,
			Insecure: false,
		},
	})

	// Build a transport so the cache has something to close.
	_, err := cache.GetCachedTransport(testMirrorInternal)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should not panic on populated cache.
	cache.CloseIdleConnections()

	// Should not panic on empty cache (no transports built).
	empty := registry.NewTransportCache([]config.Registry{
		{Prefix: "other.io", Mirror: "", CACert: "", Insecure: false},
	})
	empty.CloseIdleConnections()
}

func TestCloseIdleConnectionsSkipsDefaultTransport(t *testing.T) {
	t.Parallel()

	cache := registry.NewTransportCache([]config.Registry{
		{Prefix: testMirrorInternal, Mirror: "", CACert: "", Insecure: false},
	})

	// Trigger a lookup so the default transport gets cached.
	rt, err := cache.GetCachedTransport(testMirrorInternal)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	defaultRT, err := registry.BuildTransport("", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if rt != defaultRT {
		t.Fatal("expected default transport singleton for no-CA no-insecure registry")
	}

	// CloseIdleConnections should not panic and should skip the default.
	cache.CloseIdleConnections()
}

func TestTransportCacheConcurrentAccess(t *testing.T) {
	t.Parallel()

	certPath := writeSelfSignedCACert(t, t.TempDir())

	cache := registry.NewTransportCache([]config.Registry{
		{
			Prefix: testMirrorInternal, Mirror: "", CACert: certPath,
			Insecure: false,
		},
	})

	const goroutines = 50

	transports := make([]http.RoundTripper, goroutines)

	var wg sync.WaitGroup

	for i := range goroutines {
		wg.Go(func() {
			rt, err := cache.GetCachedTransport(testMirrorInternal)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if rt == nil {
				t.Error("expected non-nil transport for custom CA")
			}

			transports[i] = rt
		})
	}

	wg.Wait()

	first := transports[0]
	for i, rt := range transports[1:] {
		if rt != first {
			t.Errorf("goroutine %d got different transport instance (dedup broken)", i+1)
		}
	}
}

func TestFindMatchingRegistryBareImage(t *testing.T) {
	t.Parallel()

	registries := []config.Registry{
		{
			Prefix: testRegistryDockerIO, Mirror: testMirrorInternal,
			CACert: "", Insecure: false,
		},
	}

	reg := registry.FindMatchingRegistry(registries, "nginx:latest")
	if reg == nil {
		t.Fatal("expected nginx:latest to match index.docker.io prefix")
	}

	if reg.Prefix != testRegistryDockerIO {
		t.Errorf("expected prefix %q, got %q", testRegistryDockerIO, reg.Prefix)
	}
}

func TestResolveWithRegistriesNilCache(t *testing.T) {
	t.Parallel()

	// nil cache should not panic; it falls back to default keychain.
	// The actual resolution will fail (no real registry), but it should
	// not panic on nil dereference.
	_, _, _, err := registry.ResolveWithRegistries(
		t.Context(), "invalid-ref-that-wont-resolve:tag", nil,
	)
	if err == nil {
		t.Error("expected error for unresolvable ref, got nil")
	}
}

func TestNewTransportCacheOrNil(t *testing.T) {
	t.Parallel()

	t.Run("nil for empty registries", func(t *testing.T) {
		t.Parallel()

		cache := registry.NewTransportCacheOrNil(nil)
		if cache != nil {
			t.Error("expected nil cache for empty registries")
		}
	})

	t.Run("non-nil for populated registries", func(t *testing.T) {
		t.Parallel()

		cache := registry.NewTransportCacheOrNil([]config.Registry{
			{
				Prefix: testRegistryGHCR, Mirror: "", CACert: "", Insecure: false,
			},
		})
		if cache == nil {
			t.Error("expected non-nil cache for populated registries")
		}
	})
}

func TestOptionsForRegistriesCAError(t *testing.T) {
	t.Parallel()

	cache := registry.NewTransportCache([]config.Registry{
		{
			Prefix:   testRegistryGHCR,
			Mirror:   "",
			CACert:   "/nonexistent/ca.pem",
			Insecure: false,
		},
	})

	_, _, _, err := registry.OptionsForRegistries(cache, testImageGHCR)
	if err == nil {
		t.Fatal("expected error for missing CA cert file")
	}

	if !errors.Is(err, registry.ErrCACertRead) {
		t.Errorf("expected ErrCACertRead, got %v", err)
	}
}

func TestIsConnectionError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "DNS error",
			err: &net.DNSError{ //nolint:exhaustruct // test only needs Err+Name
				Err: "no such host", Name: "mirror.example.com",
			},
			want: true,
		},
		{
			name: "OpError (connection refused)",
			err: &net.OpError{ //nolint:exhaustruct // test only needs Op+Err
				Op: "dial", Err: errConnRefused,
			},
			want: true,
		},
		{
			name: "TLS record header error",
			err:  &tls.RecordHeaderError{}, //nolint:exhaustruct // zero value suffices
			want: true,
		},
		{
			name: "x509 CertificateInvalidError",
			//nolint:exhaustruct // test needs Reason
			err:  &x509.CertificateInvalidError{Reason: x509.Expired},
			want: true,
		},
		{
			name: "x509 UnknownAuthorityError",
			err:  &x509.UnknownAuthorityError{}, //nolint:exhaustruct // zero value suffices
			want: true,
		},
		{
			name: "x509 HostnameError",
			err:  &x509.HostnameError{Host: "example.com"}, //nolint:exhaustruct // test needs Host
			want: true,
		},
		{
			name: "timeout error",
			err:  &fakeTimeoutError{},
			want: true,
		},
		{
			name: "non-timeout net.Error",
			err:  &fakeNonTimeoutError{},
			want: false,
		},
		{
			name: "transport error 500",
			err:  &transport.Error{StatusCode: http.StatusInternalServerError},
			want: true,
		},
		{
			name: "transport error 502",
			err:  &transport.Error{StatusCode: http.StatusBadGateway},
			want: true,
		},
		{
			name: "transport error 503",
			err:  &transport.Error{StatusCode: http.StatusServiceUnavailable},
			want: true,
		},
		{
			name: "transport error 401 (NOT connection error)",
			err:  &transport.Error{StatusCode: http.StatusUnauthorized},
			want: false,
		},
		{
			name: "transport error 403 (NOT connection error)",
			err:  &transport.Error{StatusCode: http.StatusForbidden},
			want: false,
		},
		{
			name: "transport error 404 (NOT connection error)",
			err:  &transport.Error{StatusCode: http.StatusNotFound},
			want: false,
		},
		{
			name: "transport error 400 (NOT connection error)",
			err:  &transport.Error{StatusCode: http.StatusBadRequest},
			want: false,
		},
		{
			name: "io.EOF",
			err:  io.EOF,
			want: true,
		},
		{
			name: "io.ErrUnexpectedEOF",
			err:  io.ErrUnexpectedEOF,
			want: true,
		},
		{
			name: "plain error",
			err:  errGeneric,
			want: false,
		},
		{
			name: "wrapped DNS error",
			err: fmt.Errorf("resolving: %w", &net.DNSError{ //nolint:exhaustruct // test
				Err: "no such host", Name: "x",
			}),
			want: true,
		},
		{
			name: "wrapped EOF",
			err:  fmt.Errorf("reading response: %w", io.EOF),
			want: true,
		},
		{
			name: "context.DeadlineExceeded",
			err:  fmt.Errorf("interrupted: %w", context.DeadlineExceeded),
			want: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := registry.IsConnectionError(test.err)
			if got != test.want {
				t.Errorf("IsConnectionError() = %v, want %v", got, test.want)
			}
		})
	}
}

type fakeTimeoutError struct{}

func (e *fakeTimeoutError) Error() string   { return "timeout" }
func (e *fakeTimeoutError) Timeout() bool   { return true }
func (e *fakeTimeoutError) Temporary() bool { return true }

type fakeNonTimeoutError struct{}

func (e *fakeNonTimeoutError) Error() string   { return "not timeout" }
func (e *fakeNonTimeoutError) Timeout() bool   { return false }
func (e *fakeNonTimeoutError) Temporary() bool { return false }

func TestOptionsForRegistriesReturnsFallback(t *testing.T) {
	t.Parallel()

	t.Run("fallback returned when mirror configured", func(t *testing.T) {
		t.Parallel()

		tc := registry.NewTransportCache([]config.Registry{
			{
				Prefix:   testRegistryGHCR,
				Mirror:   testMirrorInternal,
				CACert:   "",
				Insecure: false,
			},
		})

		ref, _, fallback, err := registry.OptionsForRegistries(tc, testImageGHCR)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if ref != testMirrorRewrittenGHCR {
			t.Errorf("ref = %q, want mirror rewrite", ref)
		}

		if fallback == nil {
			t.Fatal("expected non-nil fallback")
		}

		if fallback.OriginalRef != testImageGHCR {
			t.Errorf("OriginalRef = %q, want %q", fallback.OriginalRef, testImageGHCR)
		}
	})

	t.Run("no fallback when no mirror", func(t *testing.T) {
		t.Parallel()

		tc := registry.NewTransportCache([]config.Registry{
			{
				Prefix:   testRegistryGHCR,
				Mirror:   "",
				CACert:   "",
				Insecure: false,
			},
		})

		_, _, fallback, err := registry.OptionsForRegistries(tc, testImageGHCR)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if fallback != nil {
			t.Error("expected nil fallback when no mirror")
		}
	})

	t.Run("no fallback when no registry match", func(t *testing.T) {
		t.Parallel()

		tc := registry.NewTransportCache([]config.Registry{
			{
				Prefix:   testRegistryGHCR,
				Mirror:   testMirrorInternal,
				CACert:   "",
				Insecure: false,
			},
		})

		_, _, fallback, err := registry.OptionsForRegistries(tc, testImageDockerNginx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if fallback != nil {
			t.Error("expected nil fallback for non-matching registry")
		}
	})
}

const testUnreachableRegistry = "localhost:19999"

func TestResolveWithRegistriesFallbackPaths(t *testing.T) {
	t.Parallel()

	t.Run("connection refused mirror triggers fallback", func(t *testing.T) {
		t.Parallel()

		cache := registry.NewTransportCache([]config.Registry{
			{
				Prefix:   testUnreachableRegistry,
				Mirror:   "localhost:1",
				CACert:   "",
				Insecure: false,
			},
		})

		_, _, fallbackUsed, err := registry.ResolveWithRegistries(
			t.Context(), testUnreachableRegistry+"/test/image:v1", cache,
		)
		if err == nil {
			t.Fatal("expected error when both mirror and fallback fail")
		}

		if !fallbackUsed {
			t.Error("expected fallbackUsed=true when mirror has connection error")
		}

		if !strings.Contains(err.Error(), "fallback to") {
			t.Errorf("error should mention fallback attempt, got: %v", err)
		}
	})

	t.Run("context cancellation prevents fallback", func(t *testing.T) {
		t.Parallel()

		cache := registry.NewTransportCache([]config.Registry{
			{
				Prefix:   testUnreachableRegistry,
				Mirror:   "localhost:1",
				CACert:   "",
				Insecure: false,
			},
		})

		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		_, _, fallbackUsed, err := registry.ResolveWithRegistries(
			ctx, testUnreachableRegistry+"/test/image:v1", cache,
		)
		if err == nil {
			t.Fatal("expected error with cancelled context")
		}

		if fallbackUsed {
			t.Error("expected fallbackUsed=false when context is cancelled")
		}
	})

	t.Run("no mirror means no fallback", func(t *testing.T) {
		t.Parallel()

		cache := registry.NewTransportCache([]config.Registry{
			{
				Prefix:   testUnreachableRegistry,
				Mirror:   "",
				CACert:   "",
				Insecure: false,
			},
		})

		_, _, fallbackUsed, err := registry.ResolveWithRegistries(
			t.Context(), testUnreachableRegistry+"/test/image:v1", cache,
		)
		if err == nil {
			t.Fatal("expected error for unreachable registry")
		}

		if fallbackUsed {
			t.Error("expected fallbackUsed=false when no mirror is configured")
		}
	})

	t.Run("non-connection error does not trigger fallback", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()

		// Extract port and use localhost for HTTP scheme in go-containerregistry.
		host := strings.TrimPrefix(srv.URL, "http://")
		_, port, _ := net.SplitHostPort(host)
		mirrorHost := "localhost:" + port

		cache := registry.NewTransportCache([]config.Registry{
			{
				Prefix:   testRegistryGHCR,
				Mirror:   mirrorHost,
				CACert:   "",
				Insecure: false,
			},
		})

		_, _, fallbackUsed, err := registry.ResolveWithRegistries(
			t.Context(), testImageGHCR, cache,
		)
		if err == nil {
			t.Fatal("expected error from mirror returning 404")
		}

		if fallbackUsed {
			t.Error("expected fallbackUsed=false for non-connection error")
		}
	})
}

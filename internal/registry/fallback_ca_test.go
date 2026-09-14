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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/registry"
)

const (
	// unreachableMirror is a mirror address nothing listens on.
	unreachableMirror  = "127.0.0.1:1"
	pemCertificateType = "CERTIFICATE"
)

// TestMirrorFallbackKeepsConfiguredCA verifies that falling back from an
// unreachable mirror to the original registry still trusts the configured
// ca_cert (for example an enterprise CA), while TLS verification stays on even
// though the entry is marked insecure.
func TestMirrorFallbackKeepsConfiguredCA(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)

	caPath := filepath.Join(t.TempDir(), "ca.pem")

	err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{
		Type: pemCertificateType, Headers: nil, Bytes: server.Certificate().Raw,
	}), 0o600)
	if err != nil {
		t.Fatalf("writing CA certificate: %v", err)
	}

	originalHost := strings.TrimPrefix(server.URL, "https://")

	cache := registry.NewTransportCache([]config.Registry{{
		Prefix:   originalHost,
		Mirror:   unreachableMirror,
		CACert:   caPath,
		Insecure: true,
	}})

	_, _, fallbackUsed, err := registry.ResolveWithRegistries(
		t.Context(), originalHost+"/test/image:v1", cache,
	)
	if err == nil {
		t.Fatal("expected an error because the registry has no such image")
	}

	if !fallbackUsed {
		t.Fatal("expected fallback to the original registry")
	}

	if strings.Contains(err.Error(), "certificate") {
		t.Errorf("fallback must trust the configured ca_cert, got TLS error: %v", err)
	}
}

// TestMirrorFallbackForcesTLSVerification verifies that the fallback from an
// insecure mirror entry to the original registry verifies the registry's
// certificate against the configured ca_cert: a certificate that the CA did
// not issue is rejected even though the entry is marked insecure.
func TestMirrorFallbackForcesTLSVerification(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)

	caPath := filepath.Join(t.TempDir(), "unrelated-ca.pem")

	err := os.WriteFile(caPath, unrelatedCACertificatePEM(t), 0o600)
	if err != nil {
		t.Fatalf("writing CA certificate: %v", err)
	}

	originalHost := strings.TrimPrefix(server.URL, "https://")

	cache := registry.NewTransportCache([]config.Registry{{
		Prefix:   originalHost,
		Mirror:   unreachableMirror,
		CACert:   caPath,
		Insecure: true,
	}})

	_, _, fallbackUsed, err := registry.ResolveWithRegistries(
		t.Context(), originalHost+"/test/image:v1", cache,
	)
	if !fallbackUsed {
		t.Fatal("expected fallback to the original registry")
	}

	if _, ok := errors.AsType[*tls.CertificateVerificationError](err); !ok {
		t.Fatalf("expected a certificate verification error on fallback, got: %v", err)
	}
}

// unrelatedCACertificatePEM returns a self-signed CA certificate that did not
// issue the httptest server certificate.
func unrelatedCACertificatePEM(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "unrelated test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating CA certificate: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: pemCertificateType, Headers: nil, Bytes: der})
}

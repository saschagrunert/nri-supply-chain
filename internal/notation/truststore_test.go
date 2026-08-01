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

//nolint:testpackage // testing unexported functions
package notation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/notaryproject/notation-go/verifier/truststore"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
)

const (
	testCertPath       = "/path/to/cert.pem"
	testTrustStoreName = "mystore"
)

func generateTestCert(t *testing.T) (certPEM []byte, certPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-cert",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	certPath = filepath.Join(t.TempDir(), "test-cert.pem")

	err = os.WriteFile(certPath, certPEM, 0o600)
	if err != nil {
		t.Fatalf("writing certificate: %v", err)
	}

	return certPEM, certPath
}

// writeTempCert is a convenience helper that returns only the file path.
func writeTempCert(t *testing.T) string {
	t.Helper()

	_, path := generateTestCert(t)

	return path
}

func TestNewTrustStore(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		stores  []policy.NotationTrustStore
		wantErr bool
		wantLen int
	}{
		{
			name: "valid CA trust store",
			stores: []policy.NotationTrustStore{
				{
					Name:         "myca",
					Type:         "ca",
					Certificates: []string{testCertPath},
				},
			},
			wantErr: false,
			wantLen: 1,
		},
		{
			name: "valid signingAuthority trust store",
			stores: []policy.NotationTrustStore{
				{
					Name:         "mysa",
					Type:         "signingAuthority",
					Certificates: []string{testCertPath},
				},
			},
			wantErr: false,
			wantLen: 1,
		},
		{
			name: "invalid store type returns error",
			stores: []policy.NotationTrustStore{
				{
					Name:         "bad",
					Type:         "invalid",
					Certificates: []string{testCertPath},
				},
			},
			wantErr: true,
			wantLen: 0,
		},
		{
			name:    "empty stores map",
			stores:  nil,
			wantErr: false,
			wantLen: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ts, err := newTrustStore(tc.stores)

			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				if !errors.Is(err, ErrUnknownStoreType) {
					t.Errorf("expected ErrUnknownStoreType, got: %v", err)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(ts.stores) != tc.wantLen {
				t.Errorf("store count = %d, want %d", len(ts.stores), tc.wantLen)
			}
		})
	}
}

func TestGetCertificatesUnknownStore(t *testing.T) {
	t.Parallel()

	ts, err := newTrustStore(nil)
	if err != nil {
		t.Fatalf("creating trust store: %v", err)
	}

	ctx := context.Background()

	_, err = ts.GetCertificates(ctx, truststore.TypeCA, "nonexistent")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestGetCertificatesWrongType(t *testing.T) {
	t.Parallel()

	ts, err := newTrustStore([]policy.NotationTrustStore{
		{
			Name:         testTrustStoreName,
			Type:         "ca",
			Certificates: []string{testCertPath},
		},
	})
	if err != nil {
		t.Fatalf("creating trust store: %v", err)
	}

	ctx := context.Background()

	_, err = ts.GetCertificates(ctx, truststore.TypeSigningAuthority, testTrustStoreName)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestGetCertificatesValidPEM(t *testing.T) {
	t.Parallel()

	certPath := writeTempCert(t)

	ts, err := newTrustStore([]policy.NotationTrustStore{
		{
			Name:         "teststore",
			Type:         "ca",
			Certificates: []string{certPath},
		},
	})
	if err != nil {
		t.Fatalf("creating trust store: %v", err)
	}

	ctx := context.Background()

	certs, err := ts.GetCertificates(ctx, truststore.TypeCA, "teststore")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(certs) != 1 {
		t.Errorf("certificate count = %d, want 1", len(certs))
	}
}

func TestGetCertificatesCached(t *testing.T) {
	t.Parallel()

	certPath := writeTempCert(t)

	ts, err := newTrustStore([]policy.NotationTrustStore{
		{
			Name:         "cached",
			Type:         "ca",
			Certificates: []string{certPath},
		},
	})
	if err != nil {
		t.Fatalf("creating trust store: %v", err)
	}

	ctx := context.Background()

	// First call loads certificates.
	_, err = ts.GetCertificates(ctx, truststore.TypeCA, "cached")
	if err != nil {
		t.Fatalf("first GetCertificates: %v", err)
	}

	// Delete the file so second call must use cache.
	entry := ts.stores["cached"]

	for _, p := range entry.certPaths {
		removeErr := os.Remove(p)
		if removeErr != nil {
			t.Fatalf("removing cert file: %v", removeErr)
		}
	}

	certs, err := ts.GetCertificates(ctx, truststore.TypeCA, "cached")
	if err != nil {
		t.Fatalf("cached GetCertificates: %v", err)
	}

	if len(certs) != 1 {
		t.Errorf("certificate count = %d, want 1", len(certs))
	}
}

func TestGetCertificatesNoCertsInPEM(t *testing.T) {
	t.Parallel()

	// Write a PEM file with a non-CERTIFICATE block.
	dir := t.TempDir()
	pemPath := filepath.Join(dir, "empty.pem")

	data := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte("fake-key-data"),
	})

	err := os.WriteFile(pemPath, data, 0o600)
	if err != nil {
		t.Fatalf("writing PEM: %v", err)
	}

	ts, err := newTrustStore([]policy.NotationTrustStore{
		{
			Name:         "nocerts",
			Type:         "ca",
			Certificates: []string{pemPath},
		},
	})
	if err != nil {
		t.Fatalf("creating trust store: %v", err)
	}

	ctx := context.Background()

	_, err = ts.GetCertificates(ctx, truststore.TypeCA, "nocerts")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestLoadPEMCertificates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		setup     func(t *testing.T) string
		wantErr   error
		wantCount int
	}{
		{
			name: "valid PEM file with single cert",
			setup: func(t *testing.T) string {
				t.Helper()

				return writeTempCert(t)
			},
			wantErr:   nil,
			wantCount: 1,
		},
		{
			name: "valid PEM file with multiple certs",
			setup: func(t *testing.T) string {
				t.Helper()

				cert1, _ := generateTestCert(t)
				cert2, _ := generateTestCert(t)

				combined := make([]byte, 0, len(cert1)+len(cert2))
				combined = append(combined, cert1...)
				combined = append(combined, cert2...)

				dir := t.TempDir()
				path := filepath.Join(dir, "multi.pem")

				err := os.WriteFile(path, combined, 0o600)
				if err != nil {
					t.Fatalf("writing multi-cert PEM: %v", err)
				}

				return path
			},
			wantErr:   nil,
			wantCount: 2,
		},
		{
			name: "empty file returns ErrNoCertificates",
			setup: func(t *testing.T) string {
				t.Helper()

				dir := t.TempDir()
				path := filepath.Join(dir, "empty.pem")

				err := os.WriteFile(path, []byte{}, 0o600)
				if err != nil {
					t.Fatalf("writing empty PEM: %v", err)
				}

				return path
			},
			wantErr:   ErrNoCertificates,
			wantCount: 0,
		},
		{
			name: "non-existent file returns error",
			setup: func(t *testing.T) string {
				t.Helper()

				return filepath.Join(t.TempDir(), "does-not-exist.pem")
			},
			wantErr:   os.ErrNotExist,
			wantCount: 0,
		},
		{
			name: "file with non-CERTIFICATE blocks is skipped",
			setup: func(t *testing.T) string {
				t.Helper()

				dir := t.TempDir()
				path := filepath.Join(dir, "private.pem")

				data := pem.EncodeToMemory(&pem.Block{
					Type:  "EC PRIVATE KEY",
					Bytes: []byte("fake-key-data"),
				})

				err := os.WriteFile(path, data, 0o600)
				if err != nil {
					t.Fatalf("writing private key PEM: %v", err)
				}

				return path
			},
			wantErr:   ErrNoCertificates,
			wantCount: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			path := tc.setup(t)

			certs, err := loadPEMCertificates(path)

			if tc.wantErr != nil {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				if !errors.Is(err, tc.wantErr) {
					t.Errorf("error = %v, want %v", err, tc.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(certs) != tc.wantCount {
				t.Errorf("certificate count = %d, want %d", len(certs), tc.wantCount)
			}
		})
	}
}

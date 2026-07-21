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

package attestation_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	ociV1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/saschagrunert/nri-supply-chain/internal/attestation"
)

const nonexistentKey = "/nonexistent/key.pub"

func writeTestKey(t *testing.T) string {
	t.Helper()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating test key: %v", err)
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("marshalling public key: %v", err)
	}

	keyPath := filepath.Join(t.TempDir(), "test.pub")

	err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{
		Type:    "PUBLIC KEY",
		Headers: nil,
		Bytes:   pubBytes,
	}), 0o600)
	if err != nil {
		t.Fatalf("writing test key: %v", err)
	}

	return keyPath
}

func TestDefaultVerifyBundle(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		ctx       func() context.Context
		data      []byte
		opts      *attestation.FetchOptions
		wantErr   bool
		wantInErr string
	}{
		{
			name:      "invalid JSON",
			ctx:       context.Background,
			data:      []byte("not json"),
			opts:      &attestation.FetchOptions{},
			wantErr:   true,
			wantInErr: "",
		},
		{
			name:      "invalid bundle content",
			ctx:       context.Background,
			data:      []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`),
			opts:      &attestation.FetchOptions{},
			wantErr:   true,
			wantInErr: "",
		},
		{
			name: "canceled context",
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()

				return ctx
			},
			data:      []byte("{}"),
			opts:      &attestation.FetchOptions{},
			wantErr:   true,
			wantInErr: "context canceled",
		},
		{
			name: "nonexistent key path",
			ctx:  context.Background,
			data: []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`),
			opts: &attestation.FetchOptions{
				TrustedKeys: []string{nonexistentKey},
			},
			wantErr:   true,
			wantInErr: "",
		},
		{
			name:      "no trusted material configured",
			ctx:       context.Background,
			data:      []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`),
			opts:      &attestation.FetchOptions{},
			wantErr:   true,
			wantInErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := attestation.ExportDefaultVerifyBundle(tt.ctx(), tt.data, tt.opts)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				if tt.wantInErr != "" && !strings.Contains(err.Error(), tt.wantInErr) {
					t.Errorf("expected error containing %q, got: %v", tt.wantInErr, err)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestBuildCertificateIdentity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		issuers         []string
		sanPatterns     []string
		wantIssuer      string
		wantIssuerRegex string
		wantSANRegex    string
		wantErr         bool
	}{
		{
			name:            "empty issuers returns error",
			issuers:         nil,
			sanPatterns:     nil,
			wantIssuer:      "",
			wantIssuerRegex: "",
			wantSANRegex:    "",
			wantErr:         true,
		},
		{
			name:            "single issuer",
			issuers:         []string{testIssuerGoogle},
			sanPatterns:     nil,
			wantIssuer:      testIssuerGoogle,
			wantIssuerRegex: "",
			wantSANRegex:    ".*",
			wantErr:         false,
		},
		{
			name: "multiple issuers anchored",
			issuers: []string{
				testIssuerGoogle,
				"https://token.actions.githubusercontent.com",
			},
			sanPatterns:     nil,
			wantIssuer:      "",
			wantIssuerRegex: `^(?:https://accounts\.google\.com|https://token\.actions\.githubusercontent\.com)$`,
			wantSANRegex:    ".*",
			wantErr:         false,
		},
		{
			name:    "single issuer with SAN patterns",
			issuers: []string{testIssuerGoogle},
			sanPatterns: []string{
				testSANUser,
				"ci@build.internal",
			},
			wantIssuer:      testIssuerGoogle,
			wantIssuerRegex: "",
			wantSANRegex:    `^(?:user@example\.com|ci@build\.internal)$`,
			wantErr:         false,
		},
		{
			name:            "single issuer no SAN uses wildcard",
			issuers:         []string{testIssuerExample},
			sanPatterns:     nil,
			wantIssuer:      testIssuerExample,
			wantIssuerRegex: "",
			wantSANRegex:    ".*",
			wantErr:         false,
		},
		{
			name:            "single SAN pattern",
			issuers:         []string{testIssuerGoogle},
			sanPatterns:     []string{"admin@corp.example.com"},
			wantIssuer:      testIssuerGoogle,
			wantIssuerRegex: "",
			wantSANRegex:    `^(?:admin@corp\.example\.com)$`,
			wantErr:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			certID, err := attestation.ExportBuildCertificateID(tt.issuers, tt.sanPatterns)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.wantIssuer != "" && certID.Issuer.Issuer != tt.wantIssuer {
				t.Errorf("expected issuer %q, got %q", tt.wantIssuer, certID.Issuer.Issuer)
			}

			if tt.wantIssuerRegex != "" && certID.Issuer.Regexp.String() != tt.wantIssuerRegex {
				t.Errorf("expected issuer regex %q, got %q",
					tt.wantIssuerRegex, certID.Issuer.Regexp.String())
			}

			if tt.wantSANRegex != "" {
				sanRegex := certID.SubjectAlternativeName.Regexp.String()
				if sanRegex != tt.wantSANRegex {
					t.Errorf("expected SAN regex %q, got %q", tt.wantSANRegex, sanRegex)
				}
			}
		})
	}
}

func TestBuildCertificateIdentityRegexSAN(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		issuers      []string
		sanPatterns  []string
		wantSANRegex string
	}{
		{
			name:         "glob wildcard in SAN",
			issuers:      []string{testIssuerGoogle},
			sanPatterns:  []string{"*@example.com"},
			wantSANRegex: `^(?:[^/]*@example\.com)$`,
		},
		{
			name:         "question mark in SAN",
			issuers:      []string{testIssuerGoogle},
			sanPatterns:  []string{"user?.example.com"},
			wantSANRegex: `^(?:user[^/]\.example\.com)$`,
		},
		{
			name:    "multiple regex SAN patterns",
			issuers: []string{testIssuerGoogle},
			sanPatterns: []string{
				"*@corp.example.com",
				"ci-bot@build.internal",
			},
			wantSANRegex: `^(?:[^/]*@corp\.example\.com|ci-bot@build\.internal)$`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			certID, err := attestation.ExportBuildCertificateID(tt.issuers, tt.sanPatterns)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			sanRegex := certID.SubjectAlternativeName.Regexp.String()
			if sanRegex != tt.wantSANRegex {
				t.Errorf("expected SAN regex %q, got %q", tt.wantSANRegex, sanRegex)
			}
		})
	}
}

func TestBuildKeylessConfigTransparencyLog(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                   string
		requireTransparencyLog bool
		wantErr                bool
	}{
		{
			name:                   "transparency log disabled",
			requireTransparencyLog: false,
			wantErr:                false,
		},
		{
			name:                   "transparency log enabled",
			requireTransparencyLog: true,
			wantErr:                false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cache := attestation.NewTestTrustedRootCacheWithRoot(
				func() (*root.TrustedRoot, error) {
					return fakeTrustedRoot(), nil
				},
				fakeTrustedRoot(),
				time.Now(),
			)

			opts := &attestation.FetchOptions{
				TrustedIssuers:         []string{testIssuerGoogle},
				RequireTransparencyLog: tt.requireTransparencyLog,
			}

			err := attestation.ExportBuildVerificationCfgWithCache(
				context.Background(), opts, cache,
			)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestBuildCertificateIdentityMissingSANFallback(t *testing.T) {
	t.Parallel()

	// When no SAN patterns are provided, the SAN regex should be ".*".
	certID, err := attestation.ExportBuildCertificateID(
		[]string{testIssuerExample}, nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sanRegex := certID.SubjectAlternativeName.Regexp.String()
	if sanRegex != ".*" {
		t.Errorf("expected SAN regex %q for nil sanPatterns, got %q", ".*", sanRegex)
	}

	// Same for empty slice.
	certID, err = attestation.ExportBuildCertificateID(
		[]string{testIssuerExample}, []string{},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sanRegex = certID.SubjectAlternativeName.Regexp.String()
	if sanRegex != ".*" {
		t.Errorf("expected SAN regex %q for empty sanPatterns, got %q", ".*", sanRegex)
	}
}

func TestBuildKeyMaterial(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		keys    func(t *testing.T) []string
		wantErr bool
	}{
		{
			name: "nonexistent key",
			keys: func(_ *testing.T) []string {
				return []string{nonexistentKey}
			},
			wantErr: true,
		},
		{
			name: "invalid PEM",
			keys: func(t *testing.T) []string {
				t.Helper()

				tmpDir := t.TempDir()
				keyPath := filepath.Join(tmpDir, "bad.pub")

				err := os.WriteFile(keyPath, []byte("not a PEM file"), 0o600)
				if err != nil {
					t.Fatalf("writing test file: %v", err)
				}

				return []string{keyPath}
			},
			wantErr: true,
		},
		{
			name: "valid ECDSA key",
			keys: func(t *testing.T) []string {
				t.Helper()

				return []string{writeTestKey(t)}
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			keys := tt.keys(t)
			_, err := attestation.ExportBuildKeyMaterial(keys)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestBuildVerificationConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		opts      func(t *testing.T) *attestation.FetchOptions
		wantErr   error
		wantInErr string
	}{
		{
			name: "no trusted material",
			opts: func(_ *testing.T) *attestation.FetchOptions {
				return &attestation.FetchOptions{}
			},
			wantErr:   attestation.ExportErrNoTrustedMaterial(),
			wantInErr: "",
		},
		{
			name: "nonexistent key",
			opts: func(_ *testing.T) *attestation.FetchOptions {
				return &attestation.FetchOptions{
					TrustedKeys: []string{nonexistentKey},
				}
			},
			wantErr:   nil,
			wantInErr: "loading public key",
		},
		{
			name: "valid key only",
			opts: func(t *testing.T) *attestation.FetchOptions {
				t.Helper()

				return &attestation.FetchOptions{
					TrustedKeys: []string{writeTestKey(t)},
				}
			},
			wantErr:   nil,
			wantInErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			opts := tt.opts(t)
			err := attestation.ExportBuildVerificationCfgErr(context.Background(), opts)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("expected error %v, got %v", tt.wantErr, err)
				}

				return
			}

			if tt.wantInErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantInErr) {
					t.Errorf("expected error containing %q, got: %v", tt.wantInErr, err)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestBuildVerificationConfigWithCache(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		opts      func(t *testing.T) *attestation.FetchOptions
		wantErr   bool
		wantInErr string
	}{
		{
			name: "issuers only with cache",
			opts: func(_ *testing.T) *attestation.FetchOptions {
				return &attestation.FetchOptions{
					TrustedIssuers: []string{testIssuerGoogle},
				}
			},
			wantErr:   false,
			wantInErr: "",
		},
		{
			name: "issuers and keys with cache",
			opts: func(t *testing.T) *attestation.FetchOptions {
				t.Helper()

				return &attestation.FetchOptions{
					TrustedKeys:    []string{writeTestKey(t)},
					TrustedIssuers: []string{testIssuerGoogle},
				}
			},
			wantErr:   false,
			wantInErr: "",
		},
		{
			name: "issuers with transparency log",
			opts: func(_ *testing.T) *attestation.FetchOptions {
				return &attestation.FetchOptions{
					TrustedIssuers:         []string{testIssuerGoogle},
					RequireTransparencyLog: true,
				}
			},
			wantErr:   false,
			wantInErr: "",
		},
		{
			name: "issuers with SAN patterns",
			opts: func(_ *testing.T) *attestation.FetchOptions {
				return &attestation.FetchOptions{
					TrustedIssuers: []string{testIssuerGoogle},
					SANPatterns:    []string{testSANUser},
				}
			},
			wantErr:   false,
			wantInErr: "",
		},
		{
			name: "cache fetch error",
			opts: func(_ *testing.T) *attestation.FetchOptions {
				return &attestation.FetchOptions{
					TrustedIssuers: []string{testIssuerGoogle},
				}
			},
			wantErr:   true,
			wantInErr: "root fetch failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			opts := tt.opts(t)

			var cache *attestation.TrustedRootCacheForTest

			if tt.wantErr {
				cache = attestation.NewTestTrustedRootCache(func() (*root.TrustedRoot, error) {
					return nil, errRootFetchFailed
				})
			} else {
				cache = attestation.NewTestTrustedRootCacheWithRoot(
					func() (*root.TrustedRoot, error) {
						return fakeTrustedRoot(), nil
					},
					fakeTrustedRoot(),
					time.Now(),
				)
			}

			err := attestation.ExportBuildVerificationCfgWithCache(
				context.Background(), opts, cache,
			)

			if tt.wantErr || tt.wantInErr != "" {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				if tt.wantInErr != "" && !strings.Contains(err.Error(), tt.wantInErr) {
					t.Errorf("expected error containing %q, got: %v", tt.wantInErr, err)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestOCIFetcherConstructors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		create  func() *attestation.OCIFetcher
		verify  bool
		payload string
	}{
		{
			name:    "default constructor",
			create:  attestation.NewOCIFetcher,
			verify:  false,
			payload: "",
		},
		{
			name: "custom verifier",
			create: func() *attestation.OCIFetcher {
				return attestation.NewOCIFetcherWithVerifier(
					func(_ context.Context, _ []byte, _ *attestation.FetchOptions) ([]byte, error) {
						return []byte(`{"custom": true}`), nil
					},
				)
			},
			verify:  true,
			payload: `{"custom": true}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fetcher := tt.create()
			if fetcher == nil {
				t.Fatal("expected non-nil fetcher")
			}

			if tt.verify {
				result, err := fetcher.VerifyBundle(
					context.Background(),
					nil,
					&attestation.FetchOptions{},
				)
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				if string(result) != tt.payload {
					t.Errorf("expected %q, got %q", tt.payload, string(result))
				}
			}
		})
	}
}

func TestParseDigestRef(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		imageRef   string
		digest     string
		wantErr    bool
		wantDigest string
	}{
		{
			name:       "invalid reference",
			imageRef:   ":::invalid",
			digest:     "sha256:abc",
			wantErr:    true,
			wantDigest: "",
		},
		{
			name:       "valid reference",
			imageRef:   "docker.io/library/nginx:latest",
			digest:     "sha256:abc123",
			wantErr:    false,
			wantDigest: "sha256:abc123",
		},
		{
			name:       "short reference",
			imageRef:   "nginx:latest",
			digest:     "sha256:def456",
			wantErr:    false,
			wantDigest: "sha256:def456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ref, err := attestation.ExportParseDigestRef(tt.imageRef, tt.digest)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if ref.DigestStr() != tt.wantDigest {
				t.Errorf("expected digest %q, got %q", tt.wantDigest, ref.DigestStr())
			}
		})
	}
}

func TestErrSentinels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
	}{
		{"ErrEmptyAttestation", attestation.ExportErrEmptyAttestation()},
		{"ErrAttestationTooLarge", attestation.ExportErrAttestationTooLarge()},
		{"ErrInvalidPayloadType", attestation.ExportErrInvalidPayloadType()},
		{"ErrNoTrustedMaterial", attestation.ExportErrNoTrustedMaterial()},
		{"ErrAllBundlesFailed", attestation.ExportErrAllBundlesFailed()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if tt.err == nil {
				t.Errorf("expected non-nil error for %s", tt.name)
			}
		})
	}
}

func TestParseDigestRefContextPreserved(t *testing.T) {
	t.Parallel()

	ref, err := attestation.ExportParseDigestRef("quay.io/myorg/myimage:v1.0", "sha256:abc123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := ref.Context().RegistryStr()
	if got != "quay.io" {
		t.Errorf("expected registry quay.io, got %q", got)
	}
}

func TestExtractVerifiedPayload(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		run        func() ([]byte, error)
		wantErr    bool
		wantErrMsg string
		wantData   string
	}{
		{
			name: "valid DSSE envelope",
			run: func() ([]byte, error) {
				bndl := attestation.NewTestBundle(attestation.DSSEPayloadType, `{"test": true}`)

				return attestation.ExportExtractVerifiedPayload(bndl)
			},
			wantErr:    false,
			wantErrMsg: "",
			wantData:   `{"test": true}`,
		},
		{
			name: "wrong payload type",
			run: func() ([]byte, error) {
				bndl := attestation.NewTestBundle("application/octet-stream", `{"test": true}`)

				return attestation.ExportExtractVerifiedPayload(bndl)
			},
			wantErr:    true,
			wantErrMsg: "invalid DSSE payload type",
			wantData:   "",
		},
		{
			name: "no envelope (message signature bundle)",
			run: func() ([]byte, error) {
				bndl := attestation.NewTestMessageSignatureBundle()

				return attestation.ExportExtractVerifiedPayload(bndl)
			},
			wantErr:    true,
			wantErrMsg: "extracting DSSE envelope",
			wantData:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := tt.run()

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				if tt.wantErrMsg != "" && !strings.Contains(err.Error(), tt.wantErrMsg) {
					t.Errorf("expected error containing %q, got: %v", tt.wantErrMsg, err)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if string(result) != tt.wantData {
				t.Errorf("expected payload %q, got %q", tt.wantData, string(result))
			}
		})
	}
}

func TestVerifyBundleWithCacheNilCanceledCtx(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := attestation.ExportDefaultVerifyBundle(
		ctx,
		[]byte(`{}`),
		&attestation.FetchOptions{},
	)
	if err == nil {
		t.Fatal("expected error for canceled context")
	}

	if !strings.Contains(err.Error(), "context canceled") {
		t.Errorf("expected context canceled error, got: %v", err)
	}
}

func TestNewOCIFetcherWithCacheVerifyBundleCanceledCtx(t *testing.T) {
	t.Parallel()

	fetcher := attestation.NewOCIFetcher()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := fetcher.VerifyBundle(ctx, []byte(`{}`), &attestation.FetchOptions{})
	if err == nil {
		t.Fatal("expected error for canceled context")
	}

	if !strings.Contains(err.Error(), "context canceled") {
		t.Errorf("expected context canceled error, got: %v", err)
	}
}

func TestNewOCIFetcherWithCacheInvalidBundle(t *testing.T) {
	t.Parallel()

	fetcher := attestation.NewOCIFetcher()

	_, err := fetcher.VerifyBundle(
		context.Background(),
		[]byte(`not json`),
		&attestation.FetchOptions{},
	)
	if err == nil {
		t.Fatal("expected error for invalid bundle")
	}

	if !strings.Contains(err.Error(), "parsing sigstore bundle") {
		t.Errorf("expected parsing error, got: %v", err)
	}
}

func TestNewTestOCIFetcherInjectsBoth(t *testing.T) {
	t.Parallel()

	var (
		verifyCalled bool
		fetchCalled  bool
	)

	fetcher := attestation.NewTestOCIFetcher(
		func(_ context.Context, _ []byte, _ *attestation.FetchOptions) ([]byte, error) {
			verifyCalled = true

			return []byte("ok"), nil
		},
		func(_ name.Reference, _ ...remote.Option) (ociV1.Image, error) {
			fetchCalled = true

			return fakeImageWithPayload([]byte("test")), nil
		},
	)

	baseRef, err := name.NewDigest(
		"docker.io/library/nginx@sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abcd",
	)
	if err != nil {
		t.Fatalf("creating test digest ref: %v", err)
	}

	manifests := []ociV1.Descriptor{
		{
			ArtifactType: attestation.BundleMediaType,
			Digest: ociV1.Hash{
				Algorithm: "sha256",
				Hex:       "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
			},
			Annotations: map[string]string{
				attestation.AnnotationPredicateType: attestation.PredicateSLSAProvenanceV1,
			},
		},
	}

	result, _ := fetcher.CollectAttestations(
		context.Background(), manifests, baseRef, "sha256:test", nil, &attestation.FetchOptions{},
	)

	if !fetchCalled {
		t.Error("image fetch function was not called")
	}

	if !verifyCalled {
		t.Error("verify function was not called")
	}

	if len(result) != 1 {
		t.Errorf("expected 1 attestation, got %d", len(result))
	}
}

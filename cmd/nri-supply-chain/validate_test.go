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

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	ociTypes "github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/policy"
)

// pushPolicyArtifact pushes an unsigned OCI policy artifact holding
// default.json to a new in-process registry and returns its reference.
func pushPolicyArtifact(t *testing.T) string {
	t.Helper()

	server := httptest.NewServer(registry.New())

	t.Cleanup(server.Close)

	layer := static.NewLayer(
		[]byte(`{"slsa": {"missingPolicy": "warn"}}`),
		ociTypes.MediaType(policy.PolicyMediaType),
	)

	img, err := mutate.Append(empty.Image, mutate.Addendum{
		Layer:       layer,
		Annotations: map[string]string{"org.opencontainers.image.title": "default.json"},
	})
	if err != nil {
		t.Fatalf("creating policy artifact: %v", err)
	}

	ref := strings.TrimPrefix(server.URL, "http://") + "/policies:v1"

	err = crane.Push(img, ref, crane.Insecure)
	if err != nil {
		t.Fatalf("pushing policy artifact: %v", err)
	}

	return ref
}

func writePublicKey(t *testing.T) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshaling public key: %v", err)
	}

	path := filepath.Join(t.TempDir(), "policy.pub")

	err = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600)
	if err != nil {
		t.Fatalf("writing public key: %v", err)
	}

	return path
}

func TestLoadPoliciesVerifiesOCIPolicySignatures(t *testing.T) {
	t.Parallel()

	ref := pushPolicyArtifact(t)

	cfg := config.DefaultConfig()
	cfg.Policy.Source = config.PolicySourceOCI
	cfg.Policy.OCIRef = ref

	policies, _, err := loadPolicies(cfg)
	if err != nil {
		t.Fatalf("loading unsigned policies without trust material: %v", err)
	}

	if len(policies) != 1 {
		t.Fatalf("loaded %d policies, want 1", len(policies))
	}

	// With trust material, the plugin refuses the unsigned artifact, and so
	// must validate and effective-policy.
	cfg.Policy.Keys = []string{writePublicKey(t)}

	_, _, err = loadPolicies(cfg)
	if err == nil || !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("expected a signature verification error for an unsigned artifact, got %v", err)
	}
}

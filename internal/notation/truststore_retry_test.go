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
	"os"
	"path/filepath"
	"testing"

	"github.com/notaryproject/notation-go/verifier/truststore"

	"github.com/saschagrunert/nri-supply-chain/internal/policy"
)

func TestGetCertificatesDoesNotCacheLoadErrors(t *testing.T) {
	t.Parallel()

	certPEM, _ := generateTestCert(t)
	certPath := filepath.Join(t.TempDir(), "later.pem")

	store, err := newTrustStore([]policy.NotationTrustStore{{
		Name:         testTrustStoreName,
		Type:         "ca",
		Certificates: []string{certPath},
	}})
	if err != nil {
		t.Fatalf("creating trust store: %v", err)
	}

	_, err = store.GetCertificates(t.Context(), truststore.TypeCA, testTrustStoreName)
	if err == nil {
		t.Fatal("expected an error while the certificate file is missing")
	}

	// The file becomes readable after a transient failure. The store must
	// load it instead of returning the cached error.
	err = os.WriteFile(certPath, certPEM, 0o600)
	if err != nil {
		t.Fatalf("writing certificate: %v", err)
	}

	certs, err := store.GetCertificates(t.Context(), truststore.TypeCA, testTrustStoreName)
	if err != nil {
		t.Fatalf("expected certificates after the file became readable, got: %v", err)
	}

	if len(certs) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(certs))
	}
}

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

package httputil_test

import (
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/saschagrunert/nri-supply-chain/internal/httputil"
)

func TestNewTLSTransportNilPool(t *testing.T) {
	t.Parallel()

	tr := httputil.NewTLSTransport(nil)

	if tr.TLSClientConfig == nil {
		t.Fatal("expected non-nil TLS config")
	}

	if tr.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf(
			"expected TLS 1.2 minimum, got %d",
			tr.TLSClientConfig.MinVersion,
		)
	}

	if tr.TLSClientConfig.RootCAs != nil {
		t.Error("expected nil RootCAs when pool is nil")
	}

	if tr.MaxIdleConns != httputil.MaxIdleConns {
		t.Errorf(
			"MaxIdleConns = %d, want %d",
			tr.MaxIdleConns, httputil.MaxIdleConns,
		)
	}

	if !tr.ForceAttemptHTTP2 {
		t.Error("expected ForceAttemptHTTP2 to be true")
	}
}

func TestNewTLSTransportWithPool(t *testing.T) {
	t.Parallel()

	pool := x509.NewCertPool()
	tr := httputil.NewTLSTransport(pool)

	if tr.TLSClientConfig.RootCAs != pool {
		t.Error("expected RootCAs to match the provided pool")
	}
}

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
	"net/http"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/saschagrunert/nri-supply-chain/internal/config"
	"github.com/saschagrunert/nri-supply-chain/internal/registry"
)

// TestFallbackRoundTripperKeepsTLSSettings checks that the transport for the
// original registry behind a mirror is the one carrying the registry's CA
// with verification enabled, whichever way callers read it.
func TestFallbackRoundTripperKeepsTLSSettings(t *testing.T) {
	t.Parallel()

	tc := registry.NewTransportCache([]config.Registry{{
		Prefix:   testRegistryGHCR,
		Mirror:   testMirrorInternal,
		CACert:   writeSelfSignedCACert(t, t.TempDir()),
		Insecure: true,
	}})

	_, _, fallback, err := registry.TransportForRegistries(tc, testImageGHCR)
	if err != nil {
		t.Fatalf("TransportForRegistries() error: %v", err)
	}

	if fallback == nil {
		t.Fatal("expected fallback info for a mirrored registry")
	}

	httpTransport, ok := fallback.RoundTripper().(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", fallback.RoundTripper())
	}

	if httpTransport.TLSClientConfig == nil || httpTransport.TLSClientConfig.RootCAs == nil {
		t.Error("expected the fallback transport to carry the registry CA")
	}

	if httpTransport.TLSClientConfig != nil && httpTransport.TLSClientConfig.InsecureSkipVerify {
		t.Error("expected the fallback transport to verify TLS")
	}

	empty := &registry.FallbackInfo{OriginalRef: testImageGHCR, Transport: nil}
	if empty.RoundTripper() != remote.DefaultTransport {
		t.Error("expected remote.DefaultTransport without a transport")
	}
}

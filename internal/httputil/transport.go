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

// Package httputil provides shared HTTP transport construction with security defaults.
package httputil

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"time"
)

// Transport tuning constants shared across GUAC and ACR HTTP clients.
const (
	MaxIdleConns      = 100
	IdleConnTimeout   = 90 * time.Second
	TLSTimeout        = 10 * time.Second
	ExpectContTimeout = 1 * time.Second
)

// NewTLSTransport creates an HTTP transport with TLS 1.2 minimum and the
// given root CA pool. Pass nil for pool to use system defaults.
func NewTLSTransport(pool *x509.CertPool) *http.Transport {
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          MaxIdleConns,
		IdleConnTimeout:       IdleConnTimeout,
		TLSHandshakeTimeout:   TLSTimeout,
		ExpectContinueTimeout: ExpectContTimeout,
		TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS12,
		},
	}
}
